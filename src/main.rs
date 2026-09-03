//! SupplyGuard CLI entry point: argument parsing, configuration loading,
//! subcommand dispatch, report rendering, and error-to-exit-code mapping.
//!
//! Business logic lives in the library modules and the runtime orchestrator.

use clap::{Parser, Subcommand, ValueEnum};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use supplyguard::audit::AuditChain;
use supplyguard::config::Config;
use supplyguard::mcp::{NpmLocal, OsvLocal, SpdxLocal};
use supplyguard::models::ids::SessionId;
use supplyguard::models::messages::{EventSource, Verdict};
use supplyguard::runtime::orchestrator::{GuardOutcome, LocalOrchestrator, RuntimeTools};
use supplyguard::security::injection::InjectionDetector;
use supplyguard::mcp_transport::run_stdio;

/// Exit code: verdict allow (or informational success).
const EXIT_ALLOW: i32 = 0;
/// Exit code: operational error (bad input, IO failure).
const EXIT_ERROR: i32 = 1;
/// Exit code: verdict require_human_review.
const EXIT_REVIEW: i32 = 3;
/// Exit code: verdict block.
const EXIT_BLOCK: i32 = 4;

/// Report output format for scan / guard results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Machine-readable JSON report.
    Json,
    /// Human-readable Markdown report.
    Markdown,
}

/// SupplyGuard CLI surface.
#[derive(Debug, Parser)]
#[command(
    name = "supplyguard",
    version,
    about = "Multi-Agent supply chain security defense for the AI coding era"
)]
pub struct Cli {
    /// Selected subcommand.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands of the SupplyGuard CLI.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan a project directory's npm dependencies (proactive inventory).
    ///
    /// Exit codes: 0 allow, 3 human review, 4 block, 1 operational error.
    Scan {
        /// Project directory containing package.json / package-lock.json.
        path: PathBuf,
        /// Include devDependencies in the analysis.
        #[arg(long)]
        include_dev: bool,
        /// Report output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
        /// Audit chain database path (default: ./supplyguard-audit.db).
        #[arg(long)]
        audit_db: Option<PathBuf>,
    },
    /// Arbitrate a dependency-change diff against policy (guard mode).
    ///
    /// Exit codes: 0 allow, 3 human review, 4 block, 1 operational error.
    Guard {
        /// Path to a unified diff of dependency manifests.
        #[arg(long)]
        diff: PathBuf,
        /// Report output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
        /// Audit chain database path (default: ./supplyguard-audit.db).
        #[arg(long)]
        audit_db: Option<PathBuf>,
    },
    /// Start the MCP server over stdio (for AI assistants).
    Mcp {},
    /// Start the local web console (default bind 127.0.0.1:7878).
    Serve {
        /// Socket address to bind; override only with an explicit flag.
        #[arg(long, default_value = "127.0.0.1:7878")]
        bind: String,
    },
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            path,
            include_dev,
            format,
            audit_db,
        } => match run_scan(&path, include_dev, audit_db) {
            Ok(outcome) => {
                print_report(&outcome, format);
                exit_code_for(&outcome.verdict)
            }
            Err(message) => {
                eprintln!("supplyguard: error: {message}");
                EXIT_ERROR
            }
        },
        Command::Guard {
            diff,
            format,
            audit_db,
        } => match run_guard(&diff, audit_db) {
            Ok(outcome) => {
                print_report(&outcome, format);
                exit_code_for(&outcome.verdict)
            }
            Err(message) => {
                eprintln!("supplyguard: error: {message}");
                EXIT_ERROR
            }
        },
        Command::Serve { bind } => run_serve(bind),
        Command::Mcp {} => run_mcp(),
    }
}

/// Boots the MCP server over stdio.
fn run_mcp() -> ! {
    eprintln!("supplyguard: starting MCP server on stdio",);
    run_stdio()
}

/// Boots the web console: sync runtime + broadcast bridge + axum server.
fn run_serve(bind: String) -> i32 {
        Ok(config) => config,
        Err(err) => {
            eprintln!("supplyguard: error: configuration invalid: {err}");
            return EXIT_ERROR;
        }
    };
    let chain = match AuditChain::open(&config.audit_db, &config.signing_key) {
        Ok(chain) => chain,
        Err(err) => {
            eprintln!("supplyguard: error: cannot open audit chain: {err}");
            return EXIT_ERROR;
        }
    };
    let injection = match InjectionDetector::with_builtin_rules() {
        Ok(detector) => detector,
        Err(err) => {
            eprintln!("supplyguard: error: injection corpus invalid: {err}");
            return EXIT_ERROR;
        }
    };
    let registry = NpmLocal::new();
    let vuln = OsvLocal::new();
    let spdx = SpdxLocal::new();
    let (registry, vuln, spdx) = match (registry, vuln, spdx) {
        (Ok(r), Ok(v), Ok(s)) => (r, v, s),
        (Err(err), ..) => {
            eprintln!("supplyguard: error: {err}");
            return EXIT_ERROR;
        }
        (_, Err(err), _) => {
            eprintln!("supplyguard: error: {err}");
            return EXIT_ERROR;
        }
        (_, _, Err(err)) => {
            eprintln!("supplyguard: error: {err}");
            return EXIT_ERROR;
        }
    };

    let (event_tx, _) = tokio::sync::broadcast::channel(256);
    let sink_tx = event_tx.clone();
    let orchestrator = LocalOrchestrator::with_sink(
        RuntimeTools {
            registry: Arc::new(registry),
            vuln_source: Arc::new(vuln),
            license_db: Arc::new(spdx),
            audit_chain: Arc::new(chain),
            injection,
            license_policy: config.license_policy.clone(),
        },
        Arc::new(move |event| {
            let _ = sink_tx.send(event.clone());
        }),
    );

    let bind = if bind.is_empty() {
        config.bind.clone()
    } else {
        bind
    };
    if bind.starts_with("0.0.0.0") {
        eprintln!("supplyguard: error: 0.0.0.0 bind is not allowed");
        return EXIT_ERROR;
    }

    let state = supplyguard::web::AppState {
        orchestrator: Arc::new(orchestrator),
        events: event_tx,
    };
    let router = supplyguard::web::router(state);

    println!("SupplyGuard console listening on http://{bind}");
    println!("Press Ctrl+C to exit.");

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("supplyguard: error: async runtime: {err}");
            return EXIT_ERROR;
        }
    };
    runtime.block_on(async move {
        let listener = match tokio::net::TcpListener::bind(&bind).await {
            Ok(listener) => listener,
            Err(err) => {
                eprintln!("supplyguard: error: cannot bind {bind}: {err}");
                std::process::exit(EXIT_ERROR);
            }
        };
        let shutdown = async {
            let _ = tokio::signal::ctrl_c().await;
            println!("\nShutting down gracefully…");
        };
        if let Err(err) = axum::serve(listener, router)
            .with_graceful_shutdown(shutdown)
            .await
        {
            eprintln!("supplyguard: error: server: {err}");
        }
    });
    EXIT_ALLOW
}

fn load_config(audit_db: Option<PathBuf>) -> Result<Config, String> {
    let mut config = Config::load().map_err(|err| format!("configuration invalid: {err}"))?;
    if let Some(path) = audit_db {
        config.audit_db = path;
    }
    Ok(config)
}

fn build_orchestrator(config: &Config) -> Result<LocalOrchestrator, String> {
    let chain = AuditChain::open(&config.audit_db, &config.signing_key)
        .map_err(|err| format!("cannot open audit chain: {err}"))?;
    let injection = InjectionDetector::with_builtin_rules()
        .map_err(|err| format!("injection corpus invalid: {err}"))?;
    Ok(LocalOrchestrator::new(RuntimeTools {
        registry: Arc::new(NpmLocal::new().map_err(|err| err.to_string())?),
        vuln_source: Arc::new(OsvLocal::new().map_err(|err| err.to_string())?),
        license_db: Arc::new(SpdxLocal::new().map_err(|err| err.to_string())?),
        audit_chain: Arc::new(chain),
        injection,
        license_policy: config.license_policy.clone(),
    }))
}

fn run_scan(
    path: &std::path::Path,
    include_dev: bool,
    audit_db: Option<PathBuf>,
) -> Result<GuardOutcome, String> {
    if !path.is_dir() {
        return Err(format!("project directory not found: {}", path.display()));
    }
    let config = load_config(audit_db)?;
    let orchestrator = build_orchestrator(&config)?;
    orchestrator
        .run_scan(path, include_dev)
        .map_err(|err| err.to_string())
}

fn run_guard(diff: &std::path::Path, audit_db: Option<PathBuf>) -> Result<GuardOutcome, String> {
    let diff_text =
        std::fs::read_to_string(diff).map_err(|err| format!("cannot read diff file: {err}"))?;
    let config = load_config(audit_db)?;
    let orchestrator = build_orchestrator(&config)?;
    let changes = supplyguard::agents::Sentinel.parse_diff(&diff_text);
    let session_id = SessionId::new(format!("guard-{}", now_suffix()));
    let cwd = std::env::current_dir()
        .map(|dir| dir.display().to_string())
        .unwrap_or_else(|_| ".".to_string());
    orchestrator
        .run_guard(
            session_id,
            EventSource::Manual,
            format!("file://{cwd}"),
            "local-diff".to_string(),
            changes,
        )
        .map_err(|err| err.to_string())
}

fn now_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn exit_code_for(verdict: &Verdict) -> i32 {
    match verdict {
        Verdict::Allow => EXIT_ALLOW,
        Verdict::RequireHumanReview => EXIT_REVIEW,
        Verdict::Block => EXIT_BLOCK,
    }
}

fn print_report(outcome: &GuardOutcome, format: OutputFormat) {
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(outcome).unwrap_or_default()
        ),
        OutputFormat::Markdown => print!("{}", markdown_report(outcome)),
    }
}

/// Renders the human-readable Markdown report (system-generated text only).
fn markdown_report(outcome: &GuardOutcome) -> String {
    let mut report = String::new();
    report.push_str("# SupplyGuard Report\n\n");
    report.push_str(&format!(
        "| Field | Value |\n| --- | --- |\n\
         | Session | `{}` |\n\
         | Verdict | **{}** |\n\
         | Risk level | {} |\n\
         | Strategy | {} |\n\
         | Audit sealed | {} (head `{}`) |\n\n",
        outcome.session_id,
        verdict_label(&outcome.verdict),
        risk_label(&outcome.risk_level),
        outcome
            .remediation
            .artifacts
            .get("strategy")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("n/a"),
        if outcome.seal.verified {
            "✓ verified"
        } else {
            "✗ BROKEN"
        },
        &outcome.seal.head_hash[..16.min(outcome.seal.head_hash.len())],
    ));
    if !outcome.risk_profile.human_review_reasons.is_empty() {
        report.push_str("## Reasons\n\n");
        for reason in &outcome.risk_profile.human_review_reasons {
            report.push_str(&format!("- {reason}\n"));
        }
        report.push('\n');
    }
    report.push_str("## Evidence chain\n\n| Skill | Source | Confidence | Summary |\n| --- | --- | --- | --- |\n");
    for evidence in &outcome.risk_profile.evidence_chain {
        report.push_str(&format!(
            "| {} | {} | {:.2} | {} |\n",
            evidence.skill, evidence.source, evidence.confidence, evidence.summary
        ));
    }
    if let Some(snapshot) = &outcome.snapshot {
        report.push_str(&format!("\n## Dependencies ({})\n\n| Package | Version | License | Direct |\n| --- | --- | --- | --- |\n", snapshot.packages.len()));
        for package in &snapshot.packages {
            report.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                package.name,
                package.version,
                package.license.as_deref().unwrap_or("unknown"),
                if package.direct { "yes" } else { "no" }
            ));
        }
    }
    report.push_str(&format!(
        "\n## Remediation\n\n**Action:** {}\n\n",
        outcome
            .remediation
            .artifacts
            .get("action_taken")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("n/a")
    ));
    if let Some(comment) = outcome
        .remediation
        .artifacts
        .get("comment_body")
        .and_then(serde_json::Value::as_str)
    {
        report.push_str(comment);
        report.push('\n');
    }
    report
}

fn verdict_label(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Block => "BLOCK",
        Verdict::RequireHumanReview => "REQUIRE HUMAN REVIEW",
    }
}

fn risk_label(level: &supplyguard::models::messages::RiskLevel) -> &'static str {
    use supplyguard::models::messages::RiskLevel;
    match level {
        RiskLevel::Critical => "critical",
        RiskLevel::High => "high",
        RiskLevel::Medium => "medium",
        RiskLevel::Low => "low",
        RiskLevel::Safe => "safe",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn scan_parses_positional_path_and_flags() {
        let cli =
            Cli::try_parse_from(["supplyguard", "scan", "fixtures/demo-app", "--include-dev"])
                .expect("parse");
        match cli.command {
            Command::Scan {
                path,
                include_dev,
                format,
                audit_db,
            } => {
                assert_eq!(path, PathBuf::from("fixtures/demo-app"));
                assert!(include_dev);
                assert_eq!(format, OutputFormat::Json);
                assert!(audit_db.is_none());
            }
            other => panic!("expected scan, got {other:?}"),
        }
    }

    #[test]
    fn guard_parses_diff_flag_and_markdown_format() {
        let cli = Cli::try_parse_from([
            "supplyguard",
            "guard",
            "--diff",
            "change.diff",
            "--format",
            "markdown",
        ])
        .expect("parse");
        match cli.command {
            Command::Guard { diff, format, .. } => {
                assert_eq!(diff, PathBuf::from("change.diff"));
                assert_eq!(format, OutputFormat::Markdown);
            }
            other => panic!("expected guard, got {other:?}"),
        }
    }

    #[test]
    fn serve_defaults_to_local_loopback_bind() {
        let cli = Cli::try_parse_from(["supplyguard", "serve"]).expect("parse");
        match cli.command {
            Command::Serve { bind } => assert_eq!(bind, "127.0.0.1:7878"),
            other => panic!("expected serve, got {other:?}"),
        }
    }

    #[test]
    fn unknown_subcommand_is_rejected() {
        let parsed = Cli::try_parse_from(["supplyguard", "deploy"]);
        assert!(parsed.is_err(), "unknown subcommand must fail parsing");
    }

    #[test]
    fn version_flag_is_wired() {
        let command = Cli::command();
        let version = command
            .get_version()
            .expect("version metadata from Cargo.toml");
        assert!(version.contains('0'), "version string present: {version}");
    }

    #[test]
    fn exit_codes_map_verdicts() {
        assert_eq!(exit_code_for(&Verdict::Allow), EXIT_ALLOW);
        assert_eq!(exit_code_for(&Verdict::RequireHumanReview), EXIT_REVIEW);
        assert_eq!(exit_code_for(&Verdict::Block), EXIT_BLOCK);
    }
}

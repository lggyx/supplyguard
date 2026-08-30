//! SupplyGuard CLI entry point: argument parsing and subcommand dispatch.
//!
//! Business logic lives in the library modules; this binary only parses
//! arguments, loads configuration, and maps errors to exit codes.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

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
    Scan {
        /// Project directory containing package.json / package-lock.json.
        path: PathBuf,
        /// Include devDependencies in the analysis.
        #[arg(long)]
        include_dev: bool,
        /// Report output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
    /// Arbitrate a dependency-change diff against policy (guard mode).
    Guard {
        /// Path to a file describing the dependency change (unified diff).
        #[arg(long)]
        diff: PathBuf,
        /// Report output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
    /// Start the local web console (default bind 127.0.0.1:7878).
    Serve {
        /// Socket address to bind; override only with an explicit flag.
        #[arg(long, default_value = "127.0.0.1:7878")]
        bind: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            path,
            include_dev,
            format,
        } => {
            println!(
                "scan (placeholder): path={}, include_dev={include_dev}, format={format:?}",
                path.display()
            );
        }
        Command::Guard { diff, format } => {
            println!(
                "guard (placeholder): diff={}, format={format:?}",
                diff.display()
            );
        }
        Command::Serve { bind } => {
            println!("serve (placeholder): bind={bind}");
        }
    }
}

#[cfg(test)]
mod tests {
    // Test code may panic on assertion failure; production code may not.
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
            } => {
                assert_eq!(path, PathBuf::from("fixtures/demo-app"));
                assert!(include_dev);
                assert_eq!(format, OutputFormat::Json);
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
            Command::Guard { diff, format } => {
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
}

//! MCP transport: stdio-based JSON-RPC interface for AI assistants.
//!
//! This is a minimal MCP-compatible transport that reads JSON-RPC requests
//! from stdin and writes responses to stdout. It wraps the existing
//! LocalOrchestrator without modifying any business logic.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::exit;
use std::sync::Arc;

use supplyguard::audit::AuditChain;
use supplyguard::config::Config;
use supplyguard::mcp::{NpmLocal, OsvLocal, SpdxLocal};
use supplyguard::models::ids::SessionId;
use supplyguard::models::messages::{EventSource, DependencyChange};
use supplyguard::runtime::orchestrator::{GuardOutcome, LocalOrchestrator, RuntimeTools};
use supplyguard::security::injection::InjectionDetector;

/// MCP method handlers
const METHOD_SCAN: &str = "scan";
const METHOD_GUARD: &str = "guard";
const METHOD_OVERVIEW: &str = "overview";
const METHOD_TOOLS_LIST: &str = "tools/list";

/// Runs the MCP server over stdio.
pub fn run_stdio() -> ! {
    let orchestrator = match build_orchestrator() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("supplyguard: mcp init error: {}", e);
            exit(1);
        }
    };

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let request: Value = match serde_json::from_str(line) {
                    Ok(req) => req,
                    Err(_) => continue,
                };

                let response = handle_request(&request, &orchestrator);
                let response_str = serde_json::to_string(&response).unwrap_or_default();
                let _ = writeln!(writer, "{}", response_str);
                let _ = writer.flush();
            }
            Err(_) => break,
        }
    }

    exit(0);
}

/// Builds the orchestrator from config (shared with CLI).
fn build_orchestrator() -> Result<LocalOrchestrator, String> {
    let config = Config::load().map_err(|err| format!("configuration invalid: {}", err))?;
    let chain = AuditChain::open(&config.audit_db, &config.signing_key)
        .map_err(|err| format!("cannot open audit chain: {}", err))?;
    let injection = InjectionDetector::with_builtin_rules()
        .map_err(|err| format!("injection corpus invalid: {}", err))?;
    Ok(LocalOrchestrator::new(RuntimeTools {
        registry: Arc::new(NpmLocal::new().map_err(|err| err.to_string())?),
        vuln_source: Arc::new(OsvLocal::new().map_err(|err| err.to_string())?),
        license_db: Arc::new(SpdxLocal::new().map_err(|err| err.to_string())?),
        audit_chain: Arc::new(chain),
        injection,
        license_policy: config.license_policy.clone(),
    }))
}

/// Handles a single JSON-RPC request and returns a response.
fn handle_request(request: &Value, orchestrator: &LocalOrchestrator) -> Value {
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");

    let result = match method {
        METHOD_TOOLS_LIST => list_tools(),
        METHOD_SCAN => scan(request.get("params"), orchestrator),
        METHOD_GUARD => guard(request.get("params"), orchestrator),
        METHOD_OVERVIEW => overview(orchestrator),
        _ => Err(serde_json::json!({"error": format!("unknown method: {}", method)})),
    };

    match result {
        Ok(data) => {
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": data
            })
        }
        Err(err) => {
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32600, "message": err.to_string()}
            })
        }
    }
}

fn list_tools() -> Result<Value, Value> {
    Ok(serde_json::json!({
        "tools": [
            {
                "name": "scan",
                "description": "Scan a project directory's npm dependencies",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Project directory path"},
                        "include_dev": {"type": "boolean", "description": "Include devDependencies"}
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "guard",
                "description": "Arbitrate a dependency-change diff against policy",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "diff": {"type": "string", "description": "Path to diff file"}
                    },
                    "required": ["diff"]
                }
            },
            {
                "name": "overview",
                "description": "Get current session status and statistics",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]
    }))
}

fn scan(params: Option<&Value>, orchestrator: &LocalOrchestrator) -> Result<Value, Value> {
    let path = params
        .and_then(|p| p.get("path"))
        .and_then(|p| p.as_str())
        .ok_or_else(|| serde_json::json!({"error": "missing required param: path"}))?;

    let include_dev = params
        .and_then(|p| p.get("include_dev"))
        .and_then(|p| p.as_bool())
        .unwrap_or(false);

    let outcome = orchestrator
        .run_scan(std::path::Path::new(path), include_dev)
        .map_err(|e| serde_json::json!({"error": e.to_string()}))?;

    Ok(serde_json::to_value(outcome).unwrap_or_default())
}

fn guard(params: Option<&Value>, orchestrator: &LocalOrchestrator) -> Result<Value, Value> {
    let diff = params
        .and_then(|p| p.get("diff"))
        .and_then(|p| p.as_str())
        .ok_or_else(|| serde_json::json!({"error": "missing required param: diff"}))?;

    let diff_text = std::fs::read_to_string(diff)
        .map_err(|e| serde_json::json!({"error": format!("cannot read diff: {}", e)}))?;

    let changes = Sentinel::parse_diff(&diff_text);
    let session_id = SessionId::new(format!("guard-{}", now_suffix()));
    let cwd = std::env::current_dir()
        .map(|dir| dir.display().to_string())
        .unwrap_or_else(|_| ".".to_string());

    let outcome = orchestrator
        .run_guard(
            session_id,
            EventSource::Manual,
            format!("file://{}", cwd),
            "local-diff".to_string(),
            changes,
        )
        .map_err(|e| serde_json::json!({"error": e.to_string()}))?;

    Ok(serde_json::to_value(outcome).unwrap_or_default())
}

fn overview(orchestrator: &LocalOrchestrator) -> Result<Value, Value> {
    let summary = orchestrator.overview();
    Ok(serde_json::to_value(summary).unwrap_or_default())
}

fn now_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

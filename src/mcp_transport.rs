//! MCP transport: stdio-based JSON-RPC interface for AI assistants.
//!
//! This is a minimal MCP-compatible transport that reads JSON-RPC requests
//! from stdin and writes responses to stdout. It wraps the existing
//! LocalOrchestrator without modifying any business logic.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::exit;

/// MCP method handlers
const METHOD_SCAN: &str = "scan";
const METHOD_GUARD: &str = "guard";
const METHOD_OVERVIEW: &str = "overview";
const METHOD_TOOLS_LIST: &str = "tools/list";

/// Runs the MCP server over stdio.
pub fn run_stdio() -> ! {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let request: Value = match serde_json::from_str(line) {
                    Ok(req) => req,
                    Err(_) => continue,
                };

                let response = handle_request(&request);
                let response_str = serde_json::to_string(&response).unwrap_or_default();
                let _ = writeln!(writer, "{}", response_str);
                let _ = writer.flush();
            }
            Err(_) => break,
        }
    }

    exit(0);
}

/// Handles a single JSON-RPC request and returns a response.
fn handle_request(request: &Value) -> Value {
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");

    let result = match method {
        METHOD_TOOLS_LIST => list_tools(),
        METHOD_SCAN => scan(request.get("params")),
        METHOD_GUARD => guard(request.get("params")),
        METHOD_OVERVIEW => overview(),
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

fn scan(params: Option<&Value>) -> Result<Value, Value> {
    let path = params
        .and_then(|p| p.get("path"))
        .and_then(|p| p.as_str())
        .ok_or_else(|| serde_json::json!({"error": "missing required param: path"}))?;

    let include_dev = params
        .and_then(|p| p.get("include_dev"))
        .and_then(|p| p.as_bool())
        .unwrap_or(false);

    // TODO: 调用 orchestrator.run_scan
    Ok(serde_json::json!({
        "session_id": format!("scan-{}", now_suffix()),
        "status": "completed",
        "path": path,
        "include_dev": include_dev,
        "message": "scan completed (placeholder)"
    }))
}

fn guard(params: Option<&Value>) -> Result<Value, Value> {
    let diff = params
        .and_then(|p| p.get("diff"))
        .and_then(|p| p.as_str())
        .ok_or_else(|| serde_json::json!({"error": "missing required param: diff"}))?;

    // TODO: 调用 orchestrator.run_guard
    Ok(serde_json::json!({
        "session_id": format!("guard-{}", now_suffix()),
        "status": "completed",
        "diff": diff,
        "message": "guard completed (placeholder)"
    }))
}

fn overview() -> Result<Value, Value> {
    // TODO: 从 orchestrator 获取状态
    Ok(serde_json::json!({
        "active_sessions": [],
        "stats": {
            "total_scans": 0,
            "total_findings": 0,
            "blocked": 0,
            "review": 0
        }
    }))
}

fn now_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

//! REST handlers: thin wrappers over runtime public API.

use crate::skills::Skill;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;

use super::AppState;

/// Builds the unified error response body.
fn error_body(code: &str, message: &str) -> serde_json::Value {
    json!({"error": {"code": code, "message": message}})
}

/// Builds an error `Response` with the given status and code.
pub fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    let body = error_body(code, message).to_string();
    let mut response = Response::new(axum::body::Body::from(body));
    *response.status_mut() = status;
    if let Ok(value) = "application/json".parse() {
        response
            .headers_mut()
            .insert(axum::http::header::CONTENT_TYPE, value);
    }
    response
}

/// GET /api/overview — aggregated counts and recent sessions.
pub async fn overview(State(state): State<AppState>) -> Response {
    let summary = state.orchestrator.overview();
    Json(summary).into_response()
}

/// GET /api/scans — all finished sessions, newest first.
pub async fn scans(State(state): State<AppState>) -> Response {
    Json(state.orchestrator.store().list()).into_response()
}

/// GET /api/scans/:id — one session with evidence (no untrusted raw text).
pub async fn scan_detail(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    match state.orchestrator.store().get(&id) {
        Some(outcome) => Json(outcome).into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "no session with this id",
        ),
    }
}

/// GET /api/scans/:id/timeline — state-machine traversal with timestamps.
pub async fn scan_timeline(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    match state.orchestrator.store().get(&id) {
        Some(outcome) => {
            let steps: Vec<serde_json::Value> = outcome
                .timeline
                .iter()
                .map(|(state, at)| json!({"state": state, "timestamp": at}))
                .collect();
            Json(json!({"session_id": id, "steps": steps})).into_response()
        }
        None => error_response(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "no session with this id",
        ),
    }
}

/// GET /api/audit — entries plus chain verification (via runtime wrapper).
pub async fn audit(State(state): State<AppState>) -> Response {
    match state.orchestrator.audit_entries() {
        Ok(entries) => match state.orchestrator.audit_verification() {
            Ok(verification) => Json(json!({
                "verification": verification,
                "entries": entries,
            }))
            .into_response(),
            Err(err) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "audit_verification_failed",
                &err.to_string(),
            ),
        },
        Err(err) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "audit_unreadable",
            &err.to_string(),
        ),
    }
}

/// Request body of POST /api/scan.
#[derive(Debug, Deserialize)]
pub struct ScanTrigger {
    /// Project directory to scan.
    pub path: String,
    /// Include devDependencies.
    #[serde(default)]
    pub include_dev: bool,
}

/// POST /api/scan — trigger a scan; answers 202 with the session id.
pub async fn trigger_scan(
    State(state): State<AppState>,
    Json(body): Json<ScanTrigger>,
) -> Response {
    let project_dir = std::path::PathBuf::from(&body.path);
    if !project_dir.is_dir() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_path",
            "path is not a directory",
        );
    }
    let session_id = crate::models::ids::SessionId::new(format!("web-scan-{}", now_suffix()));
    let orchestrator = state.orchestrator.clone();
    let path = project_dir.clone();
    let closure_session = session_id.clone();
    let include_dev = body.include_dev;
    // Sync pipeline on a worker thread; events reach SSE via the sink.
    // A fatally-unparseable lockfile simply never yields a session (the
    // caller sees no progress; use the CLI for the precise error).
    std::thread::spawn(move || {
        let snapshot = crate::skills::sbom_build::SbomBuildSkill.run(
            &crate::skills::sbom_build::SbomBuildInput {
                lockfile_path: path.join("package-lock.json").display().to_string(),
                include_dev,
            },
        );
        if let Ok(snapshot) = snapshot {
            let _ = orchestrator.run_scan_with_session(closure_session, &path, snapshot);
        }
    });
    (
        StatusCode::ACCEPTED,
        Json(json!({"session_id": session_id.as_str()})),
    )
        .into_response()
}

/// Request body of POST /api/guard.
#[derive(Debug, Deserialize)]
pub struct GuardTrigger {
    /// Path to a diff file describing the dependency change.
    pub path: String,
}

/// POST /api/guard — trigger a guard run; answers 202 with the session id.
pub async fn trigger_guard(
    State(state): State<AppState>,
    Json(body): Json<GuardTrigger>,
) -> Response {
    let diff_path = std::path::PathBuf::from(&body.path);
    if !diff_path.is_file() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_path",
            "path is not a file",
        );
    }
    let diff_text = match std::fs::read_to_string(&diff_path) {
        Ok(text) => text,
        Err(err) => {
            return error_response(StatusCode::BAD_REQUEST, "unreadable_diff", &err.to_string());
        }
    };
    let session_id = crate::models::ids::SessionId::new(format!("web-guard-{}", now_suffix()));
    let orchestrator = state.orchestrator.clone();
    let closure_session = session_id.clone();
    std::thread::spawn(move || {
        let changes = crate::agents::Sentinel.parse_diff(&diff_text);
        let _ = orchestrator.run_guard(
            closure_session,
            crate::models::messages::EventSource::Manual,
            format!("file://{}", diff_path.display()),
            "web-diff".to_string(),
            changes,
        );
    });
    (
        StatusCode::ACCEPTED,
        Json(json!({"session_id": session_id.as_str()})),
    )
        .into_response()
}

fn now_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

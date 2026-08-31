//! Web console: axum router over the runtime's public API plus the embedded
//! single-page frontend.
//!
//! Layering rules (PROMPT 4.2/5.10): handlers are stateless wrappers over
//! `LocalOrchestrator` public methods; no business rules, no direct skills /
//! audit access, loopback-only default bind, JSON in/out with unified error
//! shape `{"error": {"code", "message"}}`.

pub mod api;
pub mod sse;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use rust_embed::RustEmbed;
use tokio::sync::broadcast;

use crate::runtime::orchestrator::LocalOrchestrator;

/// Embedded frontend assets (compiled into the binary).
#[derive(RustEmbed)]
#[folder = "ui/"]
struct UiAssets;

/// Shared web state.
#[derive(Clone)]
pub struct AppState {
    /// The orchestrator behind every view.
    pub orchestrator: Arc<LocalOrchestrator>,
    /// Broadcast bus bridging runtime events to SSE subscribers.
    pub events: broadcast::Sender<crate::runtime::orchestrator::OrchestratorEvent>,
}

/// Builds the full application router (static UI + API + SSE).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/css/app.css", get(css))
        .route("/assets/js/app.js", get(app_js))
        .route("/vendor/alpine.min.js", get(vendor_alpine))
        .route("/vendor/echarts.min.js", get(vendor_echarts))
        .route("/api/overview", get(api::overview))
        .route("/api/scans", get(api::scans))
        .route("/api/scans/{id}", get(api::scan_detail))
        .route("/api/scans/{id}/timeline", get(api::scan_timeline))
        .route("/api/audit", get(api::audit))
        .route("/api/scan", post(api::trigger_scan))
        .route("/api/guard", post(api::trigger_guard))
        .route("/api/response", post(api::trigger_response))
        .route("/api/events", get(sse::events))
        .fallback(get(not_found))
        .with_state(state)
}

/// GET / — the single-page console.
async fn index() -> axum::response::Response {
    serve_asset("index.html", "text/html; charset=utf-8")
}

/// GET /assets/css/app.css.
async fn css() -> axum::response::Response {
    serve_asset("assets/css/app.css", "text/css; charset=utf-8")
}

/// GET /assets/js/app.js.
async fn app_js() -> axum::response::Response {
    serve_asset("assets/js/app.js", "text/javascript; charset=utf-8")
}

/// GET /vendor/alpine.min.js.
async fn vendor_alpine() -> axum::response::Response {
    serve_asset("vendor/alpine.min.js", "text/javascript; charset=utf-8")
}

/// GET /vendor/echarts.min.js.
async fn vendor_echarts() -> axum::response::Response {
    serve_asset("vendor/echarts.min.js", "text/javascript; charset=utf-8")
}

/// Fallback for unknown paths: 404 with the unified error body.
async fn not_found() -> axum::response::Response {
    api::error_response(
        axum::http::StatusCode::NOT_FOUND,
        "not_found",
        "unknown resource",
    )
}

fn serve_asset(path: &str, content_type: &'static str) -> axum::response::Response {
    match UiAssets::get(path) {
        Some(asset) => {
            let body = asset.data;
            axum::response::Response::builder()
                .status(axum::http::StatusCode::OK)
                .header(axum::http::header::CONTENT_TYPE, content_type)
                .header(axum::http::header::CONTENT_LENGTH, body.len().to_string())
                .body(axum::body::Body::from(body.into_owned()))
                .unwrap_or_else(|_| internal_error_body())
        }
        None => api::error_response(
            axum::http::StatusCode::NOT_FOUND,
            "asset_missing",
            "embedded asset not found",
        ),
    }
}

fn internal_error_body() -> axum::response::Response {
    api::error_response(
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "internal error",
    )
}

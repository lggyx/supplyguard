//! Web smoke tests: route status codes and JSON shapes via tower oneshot.
// Test code may panic on assertion failure.
// Test code may panic on assertion failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use supplyguard::audit::AuditChain;
use supplyguard::mcp::{NpmLocal, OsvLocal, SpdxLocal};
use supplyguard::runtime::orchestrator::{LocalOrchestrator, RuntimeTools};
use supplyguard::security::injection::InjectionDetector;
use supplyguard::skills::license_check::LicensePolicy;
use supplyguard::web::{AppState, router};

fn fixture(relative: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(relative)
}

fn app() -> (axum::Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let chain = AuditChain::open(&dir.path().join("audit.db"), b"web-smoke-key").expect("chain");
    let policy: LicensePolicy = serde_json::from_str(
        &std::fs::read_to_string(fixture("policies/license_policy.json")).expect("policy"),
    )
    .expect("policy parses");
    let state = AppState {
        orchestrator: std::sync::Arc::new(LocalOrchestrator::new(RuntimeTools {
            registry: std::sync::Arc::new(NpmLocal::new().expect("npm")),
            vuln_source: std::sync::Arc::new(OsvLocal::new().expect("osv")),
            license_db: std::sync::Arc::new(SpdxLocal::new().expect("spdx")),
            audit_chain: std::sync::Arc::new(chain),
            injection: InjectionDetector::with_builtin_rules().expect("detector"),
            license_policy: policy,
        })),
        events: tokio::sync::broadcast::channel(64).0,
    };
    (router(state), dir)
}

async fn get(router: &axum::Router, path: &str) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&body).to_string())
}

#[tokio::test]
async fn index_and_static_assets_are_served() {
    let (router, _dir) = app();
    let (status, body) = get(&router, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("SupplyGuard"));
    let (status, body) = get(&router, "/assets/css/app.css").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("--bg-0"), "design tokens present in CSS");
    let (status, body) = get(&router, "/assets/js/app.js").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("EventSource"));
    let (status, body) = get(&router, "/vendor/alpine.min.js").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Alpine.js"), "vendored header comment");
    let (status, body) = get(&router, "/vendor/echarts.min.js").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Apache ECharts"), "vendored header comment");
}

#[tokio::test]
async fn overview_json_shape() {
    let (router, _dir) = app();
    let (status, body) = get(&router, "/api/overview").await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body).expect("json");
    for key in [
        "total_sessions",
        "critical",
        "high",
        "medium",
        "low",
        "recent_sessions",
    ] {
        assert!(value.get(key).is_some(), "missing {key}");
    }
}

#[tokio::test]
async fn scans_list_starts_empty_and_detail_404s() {
    let (router, _dir) = app();
    let (status, body) = get(&router, "/api/scans").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.trim(), "[]");
    let (status, body) = get(&router, "/api/scans/does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let value: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(value["error"]["code"], "session_not_found");
    let (status, _) = get(&router, "/api/scans/does-not-exist/timeline").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn audit_endpoint_reports_empty_intact_chain() {
    let (router, _dir) = app();
    let (status, body) = get(&router, "/api/audit").await;
    assert_eq!(status, StatusCode::OK);
    let value: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(value["verification"]["intact"], true);
    assert_eq!(value["entries"].as_array().expect("entries").len(), 0);
}

#[tokio::test]
async fn trigger_scan_returns_202_with_session_id() {
    let (router, _dir) = app();
    let body = serde_json::json!({"path": fixture("demo-app").display().to_string()});
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scan")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert!(
        value["session_id"]
            .as_str()
            .expect("id")
            .starts_with("web-scan-")
    );
}

#[tokio::test]
async fn trigger_scan_with_bad_path_is_400() {
    let (router, _dir) = app();
    let body = serde_json::json!({"path": "definitely/not/here"});
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scan")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(value["error"]["code"], "invalid_path");
}

#[tokio::test]
async fn trigger_guard_accepts_diff_path() {
    let (router, _dir) = app();
    let body =
        serde_json::json!({"path": fixture("diffs/add_lodos_v3.diff").display().to_string()});
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/guard")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert!(
        value["session_id"]
            .as_str()
            .expect("id")
            .starts_with("web-guard-")
    );
}

#[tokio::test]
async fn sse_endpoint_streams_content_type() {
    let (router, _dir) = app();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(content_type.starts_with("text/event-stream"));
}

#[tokio::test]
async fn trigger_response_returns_202_with_session_id() {
    let (router, _dir) = app();
    let body = serde_json::json!({
        "cve": "CVE-2019-10744",
        "path": fixture("demo-app").display().to_string()
    });
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/response")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert!(
        value["session_id"]
            .as_str()
            .expect("id")
            .starts_with("web-response-")
    );
}

#[tokio::test]
async fn trigger_response_with_bad_path_is_400() {
    let (router, _dir) = app();
    let body = serde_json::json!({"cve": "CVE-2020-8203", "path": "definitely/not/here"});
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/response")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(value["error"]["code"], "invalid_path");
}

#[tokio::test]
async fn unknown_route_is_unified_404() {
    let (router, _dir) = app();
    let (status, body) = get(&router, "/api/unknown").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let value: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(value["error"]["code"], "not_found");
}

//! CLI end-to-end tests for `scan` (assert_cmd drives the real binary).

// Test code may panic on assertion failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use assert_cmd::Command;
use predicates::boolean::PredicateBooleanExt;
use predicates::str::contains;

fn supplyguard() -> Command {
    Command::cargo_bin("supplyguard").expect("binary builds")
}

#[test]
fn scan_of_demo_app_blocks_with_json_report() {
    let demo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/demo-app");
    let audit_db = tempfile::tempdir().expect("tempdir");
    supplyguard()
        .arg("scan")
        .arg(&demo)
        .arg("--audit-db")
        .arg(audit_db.path().join("audit.db"))
        .assert()
        .failure() // block verdict -> exit code 4
        .code(4)
        .stdout(contains("\"verdict\": \"block\""))
        .stdout(contains("\"risk_level\": \"critical\""))
        .stdout(contains("lodos"))
        .stderr(contains("error").not());
}

#[test]
fn scan_supports_markdown_report() {
    let demo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/demo-app");
    let audit_db = tempfile::tempdir().expect("tempdir");
    supplyguard()
        .arg("scan")
        .arg(&demo)
        .arg("--format")
        .arg("markdown")
        .arg("--audit-db")
        .arg(audit_db.path().join("audit.db"))
        .assert()
        .failure()
        .code(4)
        .stdout(contains("# SupplyGuard Report"))
        .stdout(contains("BLOCK"))
        .stdout(contains("## Evidence chain"))
        .stdout(contains("hallucination-check"));
}

#[test]
fn scan_missing_directory_is_an_operational_error() {
    let audit_db = tempfile::tempdir().expect("tempdir");
    supplyguard()
        .arg("scan")
        .arg("definitely/not/a/dir")
        .arg("--audit-db")
        .arg(audit_db.path().join("audit.db"))
        .assert()
        .failure()
        .code(1)
        .stderr(contains("project directory not found"));
}

#[test]
fn scan_writes_an_audit_database() {
    let demo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/demo-app");
    let audit_db = tempfile::tempdir().expect("tempdir");
    let db_path = audit_db.path().join("audit.db");
    supplyguard()
        .arg("scan")
        .arg(&demo)
        .arg("--audit-db")
        .arg(&db_path)
        .assert()
        .failure()
        .code(4);
    assert!(db_path.exists(), "audit database file must be created");
}

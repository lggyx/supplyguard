//! CLI end-to-end tests for `response` (assert_cmd drives the real binary).

// Test code may panic on assertion failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use assert_cmd::Command;
use predicates::str::contains;

fn supplyguard() -> Command {
    Command::cargo_bin("supplyguard").expect("binary builds")
}

fn fixture(relative: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(relative)
}

#[test]
fn response_blocks_for_critical_cve() {
    let audit_db = tempfile::tempdir().expect("tempdir");
    supplyguard()
        .arg("response")
        .arg("CVE-2019-10744")
        .arg(fixture("demo-app"))
        .arg("--audit-db")
        .arg(audit_db.path().join("audit.db"))
        .assert()
        .failure()
        .code(4)
        .stdout(contains("\"verdict\": \"block\""))
        .stdout(contains("\"cve_id\": \"CVE-2019-10744\""));
}

#[test]
fn response_requires_review_for_high_cve() {
    let audit_db = tempfile::tempdir().expect("tempdir");
    // lodash 4.17.4 matches both CVE-2019-10744 (critical) and CVE-2020-8203
    // (high); critical dominates -> block.
    supplyguard()
        .arg("response")
        .arg("CVE-2020-8203")
        .arg(fixture("demo-app"))
        .arg("--audit-db")
        .arg(audit_db.path().join("audit.db"))
        .assert()
        .failure()
        .code(4)
        .stdout(contains("\"affected_count\": 1"))
        .stdout(contains("lodash"));
}

#[test]
fn response_allows_when_cve_not_found() {
    let audit_db = tempfile::tempdir().expect("tempdir");
    supplyguard()
        .arg("response")
        .arg("CVE-9999-9999")
        .arg(fixture("demo-app"))
        .arg("--audit-db")
        .arg(audit_db.path().join("audit.db"))
        .assert()
        .success()
        .code(0)
        .stdout(contains("\"verdict\": \"allow\""));
}

#[test]
fn response_missing_directory_is_operational_error() {
    let audit_db = tempfile::tempdir().expect("tempdir");
    supplyguard()
        .arg("response")
        .arg("CVE-2020-8203")
        .arg("definitely/not/a/dir")
        .arg("--audit-db")
        .arg(audit_db.path().join("audit.db"))
        .assert()
        .failure()
        .code(1)
        .stderr(contains("project directory not found"));
}

#[test]
fn response_supports_markdown_report() {
    let audit_db = tempfile::tempdir().expect("tempdir");
    supplyguard()
        .arg("response")
        .arg("CVE-2019-10744")
        .arg(fixture("demo-app"))
        .arg("--format")
        .arg("markdown")
        .arg("--audit-db")
        .arg(audit_db.path().join("audit.db"))
        .assert()
        .failure()
        .code(4)
        .stdout(contains("# SupplyGuard Response Report"))
        .stdout(contains("CVE-2019-10744"))
        .stdout(contains("Affected packages"));
}

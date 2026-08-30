//! CLI end-to-end tests for `guard` (assert_cmd drives the real binary).

// Test code may panic on assertion failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use assert_cmd::Command;
use predicates::str::contains;

fn fixture(relative: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(relative)
}

fn supplyguard() -> Command {
    Command::cargo_bin("supplyguard").expect("binary builds")
}

#[test]
fn guard_blocks_the_lodos_addition_diff() {
    let audit_db = tempfile::tempdir().expect("tempdir");
    supplyguard()
        .arg("guard")
        .arg("--diff")
        .arg(fixture("diffs/add_lodos_v3.diff"))
        .arg("--audit-db")
        .arg(audit_db.path().join("audit.db"))
        .assert()
        .failure()
        .code(4)
        .stdout(contains("\"verdict\": \"block\""))
        .stdout(contains("lodos"));
}

#[test]
fn guard_allows_a_noop_readme_diff() {
    let audit_db = tempfile::tempdir().expect("tempdir");
    supplyguard()
        .arg("guard")
        .arg("--diff")
        .arg(fixture("diffs/no_dependency_change.diff"))
        .arg("--audit-db")
        .arg(audit_db.path().join("audit.db"))
        .assert()
        .success()
        .code(0)
        .stdout(contains("\"verdict\": \"allow\""));
}

#[test]
fn guard_upgrades_to_fixed_versions_allow() {
    let audit_db = tempfile::tempdir().expect("tempdir");
    supplyguard()
        .arg("guard")
        .arg("--diff")
        .arg(fixture("diffs/upgrade_two_packages.diff"))
        .arg("--audit-db")
        .arg(audit_db.path().join("audit.db"))
        .assert()
        .success()
        .code(0)
        .stdout(contains("\"verdict\": \"allow\""))
        .stdout(contains("express"))
        .stdout(contains("lodash"));
}

#[test]
fn guard_package_json_addition_blocks() {
    let audit_db = tempfile::tempdir().expect("tempdir");
    supplyguard()
        .arg("guard")
        .arg("--diff")
        .arg(fixture("diffs/add_dependency_packagejson.diff"))
        .arg("--audit-db")
        .arg(audit_db.path().join("audit.db"))
        .assert()
        .failure()
        .code(4)
        .stdout(contains("lodos"));
}

#[test]
fn guard_markdown_report_includes_evidence_and_seal() {
    let audit_db = tempfile::tempdir().expect("tempdir");
    supplyguard()
        .arg("guard")
        .arg("--diff")
        .arg(fixture("diffs/add_lodos_v3.diff"))
        .arg("--format")
        .arg("markdown")
        .arg("--audit-db")
        .arg(audit_db.path().join("audit.db"))
        .assert()
        .failure()
        .code(4)
        .stdout(contains("Audit sealed | ✓ verified"))
        .stdout(contains("typosquatting"));
}

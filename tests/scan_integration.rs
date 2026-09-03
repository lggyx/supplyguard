use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_scan_basic() {
    let mut cmd = Command::cargo_bin("supplyguard").unwrap();
    cmd.arg("scan")
        .arg("fixtures/demo-app")
        .assert()
        .success()
        .stdout(predicate::str::contains("session_id"))
        .stdout(predicate::str::contains("express"))
        .stdout(predicate::str::contains("fictional-pkg-xyz"));
}

#[test]
fn test_scan_nonexistent_path() {
    let mut cmd = Command::cargo_bin("supplyguard").unwrap();
    cmd.arg("scan")
        .arg("fixtures/nonexistent")
        .assert()
        .failure()
        .stderr(predicate::str::contains("lockfile 不存在"));
}

use thiserror::Error;

/// CVE 匹配错误
#[derive(Debug, Error)]
pub enum CveMatchError {
    #[error("vuln query failed: {0}")]
    QueryFailed(String),
}

pub struct CveMatchSkill;

impl CveMatchSkill {
    pub fn new() -> Self {
        Self
    }

    pub async fn match_vulns(&self, package: &str, version: &str) -> Result<(), CveMatchError> {
        // TODO: 匹配 CVE
        Ok(())
    }
}

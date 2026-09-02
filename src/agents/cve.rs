use thiserror::Error;

/// CVE 错误
#[derive(Debug, Error)]
pub enum CveError {
    #[error("vuln query failed: {0}")]
    QueryFailed(String),
}

pub struct CveAgent;

impl CveAgent {
    pub fn new() -> Self {
        Self
    }

    pub async fn check(&self, package: &str, version: &str) -> Result<(), CveError> {
        // TODO: 查询 OSV 本地数据库
        Ok(())
    }
}

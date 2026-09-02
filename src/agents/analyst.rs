use thiserror::Error;

/// Analyst 错误
#[derive(Debug, Error)]
pub enum AnalystError {
    #[error("invalid lockfile: {0}")]
    InvalidLockfile(String),
}

pub struct Analyst;

impl Analyst {
    pub fn new() -> Self {
        Self
    }

    pub async fn build_sbom(&self, path: &str) -> Result<(), AnalystError> {
        // TODO: 解析 package-lock.json，构建 SBOM
        Ok(())
    }
}

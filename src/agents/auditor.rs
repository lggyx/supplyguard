use thiserror::Error;

/// Auditor 错误
#[derive(Debug, Error)]
pub enum AuditorError {
    #[error("verdict failed: {0}")]
    VerdictFailed(String),
}

pub struct Auditor;

impl Auditor {
    pub fn new() -> Self {
        Self
    }

    pub async fn issue_verdict(&self) -> Result<(), AuditorError> {
        // TODO: 综合多信号，生成裁决
        Ok(())
    }
}

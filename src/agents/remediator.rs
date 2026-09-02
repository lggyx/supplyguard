use thiserror::Error;

/// Remediator 错误
#[derive(Debug, Error)]
pub enum RemediatorError {
    #[error("remediation failed: {0}")]
    RemediationFailed(String),
}

pub struct Remediator;

impl Remediator {
    pub fn new() -> Self {
        Self
    }

    pub async fn suggest(&self) -> Result<(), RemediatorError> {
        // TODO: 生成修复策略
        Ok(())
    }
}

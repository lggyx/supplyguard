use thiserror::Error;

/// License 错误
#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("license check failed: {0}")]
    CheckFailed(String),
}

pub struct LicenseAgent;

impl LicenseAgent {
    pub fn new() -> Self {
        Self
    }

    pub async fn check(&self, package: &str) -> Result<(), LicenseError> {
        // TODO: 检查 SPDX 许可证
        Ok(())
    }
}

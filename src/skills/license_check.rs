use thiserror::Error;

/// 许可证检查错误
#[derive(Debug, Error)]
pub enum LicenseCheckError {
    #[error("license check failed: {0}")]
    CheckFailed(String),
}

pub struct LicenseCheckSkill;

impl LicenseCheckSkill {
    pub fn new() -> Self {
        Self
    }

    pub async fn check(&self, package: &str) -> Result<(), LicenseCheckError> {
        // TODO: 检查许可证
        Ok(())
    }
}

use thiserror::Error;

/// 幻觉包检测错误
#[derive(Debug, Error)]
pub enum HallucinationCheckError {
    #[error("registry query failed: {0}")]
    RegistryQueryFailed(String),
}

pub struct HallucinationCheckSkill;

impl HallucinationCheckSkill {
    pub fn new() -> Self {
        Self
    }

    pub async fn check(&self, package: &str) -> Result<(), HallucinationCheckError> {
        // TODO: 检测 AI 幻觉包
        Ok(())
    }
}

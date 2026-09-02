use thiserror::Error;

/// Hallucination 错误
#[derive(Debug, Error)]
pub enum HallucinationError {
    #[error("registry query failed: {0}")]
    RegistryQueryFailed(String),
}

pub struct HallucinationAgent;

impl HallucinationAgent {
    pub fn new() -> Self {
        Self
    }

    pub async fn check(&self, package: &str) -> Result<(), HallucinationError> {
        // TODO: 检查词频异常、注册时间、registry 记录
        Ok(())
    }
}

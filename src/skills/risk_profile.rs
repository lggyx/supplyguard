use thiserror::Error;

/// 风险画像错误
#[derive(Debug, Error)]
pub enum RiskProfileError {
    #[error("profile generation failed: {0}")]
    ProfileFailed(String),
}

pub struct RiskProfileSkill;

impl RiskProfileSkill {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate(&self) -> Result<(), RiskProfileError> {
        // TODO: 生成综合风险画像
        Ok(())
    }
}

use crate::mcp::{McpError, RegistryClient};
use thiserror::Error;

/// Hallucination 错误
#[derive(Debug, Error)]
pub enum HallucinationError {
    #[error("registry query failed: {0}")]
    RegistryQueryFailed(String),

    #[error("mcp error: {0}")]
    Mcp(#[from] McpError),
}

pub struct HallucinationAgent {
    registry: Box<dyn RegistryClient>,
}

impl HallucinationAgent {
    pub fn new(registry: Box<dyn RegistryClient>) -> Self {
        Self { registry }
    }

    /// 检查包是否可能是 AI 幻觉包
    /// 检测信号：
    /// 1. 包名词频异常（与流行包相似但不完全相同）
    /// 2. 注册时间 < 7 天
    /// 3. npm registry 无有效记录
    pub async fn check(&self, package: &str) -> Result<HallucinationResult, HallucinationError> {
        // 1. 检查 registry 是否存在
        let exists = self.registry.exists(package).map_err(|e| HallucinationError::Mcp(e))?;

        if !exists {
            return Ok(HallucinationResult {
                package: package.to_string(),
                is_hallucination: true,
                confidence: 0.95,
                reasoning: format!("{} 在 npm registry 中不存在，极大概率是 AI 幻觉包抢注", package),
                evidence: vec!["registry_miss".to_string()],
            });
        }

        // TODO: 检查注册时间、词频异常
        Ok(HallucinationResult {
            package: package.to_string(),
            is_hallucination: false,
            confidence: 0.1,
            reasoning: format!("{} 在 registry 中存在，低风险", package),
            evidence: vec!["registry_exists".to_string()],
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HallucinationResult {
    pub package: String,
    pub is_hallucination: bool,
    pub confidence: f64,
    pub reasoning: String,
    pub evidence: Vec<String>,
}

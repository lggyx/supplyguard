use crate::agents::remediator::RemediatorError;
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

    /// 生成修复策略
    pub fn suggest(&self, verdict: &crate::agents::auditor::Verdict) -> Result<Remediation, RemediatorError> {
        match verdict.decision.as_str() {
            "BLOCK" => {
                // 幻觉包：直接移除
                Ok(Remediation {
                    strategy: "remove".to_string(),
                    description: format!("移除包 {}，它是 AI 幻觉包", verdict.package),
                    target_version: None,
                    alternative_packages: Vec::new(),
                })
            }
            "REVIEW" => {
                // CVE / License：建议升级到安全版本
                Ok(Remediation {
                    strategy: "upgrade".to_string(),
                    description: format!("升级 {} 到安全版本", verdict.package),
                    target_version: None,
                    alternative_packages: Vec::new(),
                })
            }
            "ALLOW" => {
                // 无风险：无需修复
                Ok(Remediation {
                    strategy: "none".to_string(),
                    description: format!("{} 无风险，无需修复", verdict.package),
                    target_version: None,
                    alternative_packages: Vec::new(),
                })
            }
            _ => Ok(Remediation {
                strategy: "unknown".to_string(),
                description: format!("未知决策: {}", verdict.decision),
                target_version: None,
                alternative_packages: Vec::new(),
            }),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Remediation {
    pub strategy: String,
    pub description: String,
    pub target_version: Option<String>,
    pub alternative_packages: Vec<String>,
}

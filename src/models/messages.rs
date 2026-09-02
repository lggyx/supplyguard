use serde::{Deserialize, Serialize};

/// 依赖变更
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyChange {
    pub package: String,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub change_type: ChangeType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Added,
    Removed,
    Updated,
}

/// 事件源
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Scan,
    Guard,
    Monitor,
}

/// 风险等级
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// 风险画像
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskProfile {
    pub package: String,
    pub version: String,
    pub risk_level: RiskLevel,
    pub cves: Vec<String>,
    pub license: Option<String>,
    pub hallucination_score: f64,
    pub reasoning: String,
}

/// 裁决结果
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Review,
    Block,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Allow => write!(f, "ALLOW"),
            Verdict::Review => write!(f, "REVIEW"),
            Verdict::Block => write!(f, "BLOCK"),
        }
    }
}

/// 修复策略
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationResult {
    pub strategy: RemediationStrategy,
    pub description: String,
    pub target_version: Option<String>,
    pub alternative_packages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStrategy {
    Upgrade,
    Downgrade,
    Replace,
    Remove,
}

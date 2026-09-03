use serde::{Deserialize, Serialize};

/// 会话状态机
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Created,
    Scanning,
    Analyzing,
    AwaitingVerdict,
    Decided,
    Sealed,
    Failed,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionState::Created => write!(f, "created"),
            SessionState::Scanning => write!(f, "scanning"),
            SessionState::Analyzing => write!(f, "analyzing"),
            SessionState::AwaitingVerdict => write!(f, "awaiting_verdict"),
            SessionState::Decided => write!(f, "decided"),
            SessionState::Sealed => write!(f, "sealed"),
            SessionState::Failed => write!(f, "failed"),
        }
    }
}

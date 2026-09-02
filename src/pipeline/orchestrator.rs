use thiserror::Error;

/// 编排层错误
#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("skill failure: {0}")]
    Skill(String),

    #[error("audit failure: {0}")]
    Audit(String),

    #[error("state machine failure: {0}")]
    State(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub struct Orchestrator {
    // TODO: 初始化 SessionStore、AuditChain、Agent 管道
}

impl Orchestrator {
    pub async fn new() -> anyhow::Result<Self> {
        // TODO: 初始化组件
        Ok(Self {})
    }

    // TODO: scan / guard / monitor / overview / timeline / audit 方法
}

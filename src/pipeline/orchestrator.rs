use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

use crate::agents::analyst::Analyst;
use crate::agents::auditor::{Auditor, Verdict};
use crate::agents::cve::CveAgent;
use crate::agents::hallucination::HallucinationAgent;
use crate::agents::license::LicenseAgent;
use crate::agents::sentinel::Sentinel;
use crate::audit::chain::AuditChain;
use crate::mcp::{NpmLocal, OsvLocal, SpdxLocal};
use crate::models::session::SessionState;
use crate::store::session::SessionStore;

/// 编排层错误
#[derive(Debug, Error)]
pub enum OrchestratorError {
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
    store: Arc<SessionStore>,
    audit_chain: Arc<RwLock<AuditChain>>,
}

impl Orchestrator {
    pub fn new() -> Result<Self, OrchestratorError> {
        // TODO: 初始化 SessionStore 和 AuditChain
        Ok(Self {
            store: Arc::new(
                SessionStore::new(".supplyguard/sessions.db")
                    .map_err(|e| OrchestratorError::Skill(e.to_string()))?,
            ),
            audit_chain: Arc::new(RwLock::new(AuditChain::new(b"supplyguard-secret-key"))),
        })
    }

    // TODO: 实现 scan / guard / monitor / overview / timeline / audit 方法
}

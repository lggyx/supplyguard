use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// 审计链错误
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("chain corruption: {0}")]
    Corruption(String),
    #[error("entry not found: {0}")]
    NotFound(String),
}

pub struct AuditChain {
    // TODO: 审计链状态
}

impl AuditChain {
    pub fn new() -> Self {
        Self {}
    }

    pub fn append(&mut self, entry: AuditEntry) -> Result<(), AuditError> {
        // TODO: 追加审计条目，计算链式哈希
        Ok(())
    }

    pub fn verify(&self) -> Result<bool, AuditError> {
        // TODO: 验证哈希链完整性
        Ok(true)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    pub index: u64,
    pub session_id: String,
    pub timestamp: i64,
    pub decision: String,
    pub target: String,
    pub hash: String,
    pub prev_hash: String,
}

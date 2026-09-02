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

pub struct AuditChain {
    entries: Vec<AuditEntry>,
    secret: Vec<u8>,
}

impl AuditChain {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            entries: Vec::new(),
            secret: secret.to_vec(),
        }
    }

    /// 追加审计条目，计算链式哈希
    pub fn append(
        &mut self,
        session_id: &str,
        decision: &str,
        target: &str,
    ) -> Result<AuditEntry, AuditError> {
        let prev_hash = self.entries.last().map(|e| e.hash.clone()).unwrap_or_default();
        let timestamp = chrono::Utc::now().timestamp_millis();
        let index = self.entries.len() as u64 + 1;

        let entry_data = format!(
            "{}{}{}{}{}",
            index, session_id, timestamp, decision, target
        );

        let hash = self.compute_hash(&entry_data, &prev_hash)?;

        let entry = AuditEntry {
            index,
            session_id: session_id.to_string(),
            timestamp,
            decision: decision.to_string(),
            target: target.to_string(),
            hash,
            prev_hash,
        };

        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// 验证哈希链完整性
    pub fn verify(&self) -> Result<bool, AuditError> {
        let mut prev_hash = String::new();

        for (i, entry) in self.entries.iter().enumerate() {
            let expected_index = i as u64 + 1;
            if entry.index != expected_index {
                return Err(AuditError::Corruption(format!(
                    "index mismatch at position {}: expected {}, got {}",
                    i, expected_index, entry.index
                )));
            }

            if entry.prev_hash != prev_hash {
                return Err(AuditError::Corruption(format!(
                    "prev_hash mismatch at index {}",
                    entry.index
                )));
            }

            let entry_data = format!(
                "{}{}{}{}{}",
                entry.index, entry.session_id, entry.timestamp, entry.decision, entry.target
            );
            let expected_hash = self.compute_hash(&entry_data, &entry.prev_hash)?;

            if entry.hash != expected_hash {
                return Err(AuditError::Corruption(format!(
                    "hash mismatch at index {}",
                    entry.index
                )));
            }

            prev_hash = entry.hash.clone();
        }

        Ok(true)
    }

    /// 获取所有审计条目
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// 获取审计链长度
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 审计链是否为空
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 计算 HMAC-SHA256 哈希
    fn compute_hash(&self, data: &str, prev_hash: &str) -> Result<String, AuditError> {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|e| AuditError::Corruption(e.to_string()))?;

        mac.update(data.as_bytes());
        mac.update(prev_hash.as_bytes());

        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }
}

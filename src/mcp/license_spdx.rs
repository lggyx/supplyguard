use crate::mcp::{LicenseDb, McpError};
use thiserror::Error;

/// SpdxLocal 错误
#[derive(Debug, Error)]
pub enum SpdxError {
    #[error("license check failed: {0}")]
    CheckFailed(String),
}

pub struct SpdxLocal;

impl SpdxLocal {
    pub fn new() -> Self {
        Self
    }

    /// 规范化许可证（简化版：返回原值）
    pub fn normalize(&self, license: &str) -> Result<Option<String>, SpdxError> {
        if license.is_empty() {
            return Ok(None);
        }
        Ok(Some(license.to_string()))
    }

    /// 检查是否为已知 SPDX 许可证（简化版：所有非空都返回 true）
    pub fn is_known(&self, license: &str) -> bool {
        !license.is_empty()
    }
}

impl LicenseDb for SpdxLocal {
    fn normalize(&self, raw_license: &str) -> Option<String> {
        self.normalize(raw_license).ok().flatten()
    }

    fn is_known(&self, canonical: &str) -> bool {
        self.is_known(canonical)
    }
}

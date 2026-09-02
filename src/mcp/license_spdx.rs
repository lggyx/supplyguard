use thiserror::Error;

/// SPDX 许可证数据库错误
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

    pub async fn normalize(&self, license: &str) -> Result<Option<String>, SpdxError> {
        // TODO: 规范化许可证
        Ok(Some(license.to_string()))
    }
}

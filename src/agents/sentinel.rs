use thiserror::Error;

/// Sentinel 错误
#[derive(Debug, Error)]
pub enum SentinelError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
}

pub struct Sentinel;

impl Sentinel {
    pub fn new() -> Self {
        Self
    }

    pub async fn initialize(&self, target: &str) -> Result<(), SentinelError> {
        // TODO: 标记目标目录为 UNTRUSTED，剥离零宽字符
        Ok(())
    }
}

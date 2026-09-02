use thiserror::Error;

/// OSV 本地数据库错误
#[derive(Debug, Error)]
pub enum OsvError {
    #[error("dataset corrupt: {0}")]
    DatasetCorrupt(String),
    #[error("unavailable: {0}")]
    Unavailable(String),
}

pub struct OsvLocal;

impl OsvLocal {
    pub fn new() -> Self {
        Self
    }

    pub async fn query(&self, package: &str, version: &str) -> Result<(), OsvError> {
        // TODO: 查询本地 OSV 数据库
        Ok(())
    }
}

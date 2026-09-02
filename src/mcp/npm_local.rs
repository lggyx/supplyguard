use thiserror::Error;

/// npm registry 客户端错误
#[derive(Debug, Error)]
pub enum NpmError {
    #[error("registry query failed: {0}")]
    QueryFailed(String),
}

pub struct NpmLocal;

impl NpmLocal {
    pub fn new() -> Self {
        Self
    }

    pub async fn exists(&self, package: &str) -> Result<bool, NpmError> {
        // TODO: 查询 npm registry
        Ok(true)
    }
}

use crate::mcp::{McpError, RegistryClient};
use thiserror::Error;

/// NpmLocal 错误
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

    /// 检查包是否存在（简化版：返回 true）
    pub fn exists(&self, package: &str) -> Result<bool, NpmError> {
        // TODO: 实现真实的 npm registry 查询
        // 当前占位：假设所有包都存在
        Ok(true)
    }
}

impl RegistryClient for NpmLocal {
    fn exists(&self, package_name: &str) -> Result<bool, McpError> {
        self.exists(package_name)
            .map_err(|e| McpError::Unavailable(e.to_string()))
    }
}

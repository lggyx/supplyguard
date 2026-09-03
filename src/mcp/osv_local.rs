use crate::mcp::{McpError, VulnRecord, VulnSource};
use thiserror::Error;

/// OsvLocal 错误
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

    /// 查询漏洞（简化版：返回空列表）
    pub fn query(&self, _package: &str, _version: &str) -> Result<(), OsvError> {
        // TODO: 实现真实的 OSV 查询
        Ok(())
    }
}

impl VulnSource for OsvLocal {
    fn query_vulns(
        &self,
        _package_name: &str,
        _version: &str,
        _ecosystem: &str,
    ) -> Result<Vec<VulnRecord>, McpError> {
        // TODO: 实现真实的 OSV 查询
        // 当前占位：返回空列表（离线模式）
        Ok(Vec::new())
    }
}

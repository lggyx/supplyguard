use thiserror::Error;

/// MCP 数据层错误
#[derive(Debug, Error)]
pub enum McpError {
    #[error("dataset corrupt: {0}")]
    DatasetCorrupt(String),

    #[error("source unavailable: {0}")]
    Unavailable(String),
}

/// 漏洞记录
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VulnRecord {
    pub advisory_id: String,
    pub cves: Vec<String>,
    pub severity: String,
    pub fixed_versions: Vec<String>,
}

/// npm registry 客户端 trait
pub trait RegistryClient: Send + Sync {
    fn exists(&self, package_name: &str) -> Result<bool, McpError>;
}

/// 漏洞数据库 trait
pub trait VulnSource: Send + Sync {
    fn query_vulns(
        &self,
        package_name: &str,
        version: &str,
        ecosystem: &str,
    ) -> Result<Vec<VulnRecord>, McpError>;
}

/// 许可证数据库 trait
pub trait LicenseDb: Send + Sync {
    fn normalize(&self, raw_license: &str) -> Option<String>;

    fn is_known(&self, canonical: &str) -> bool;
}

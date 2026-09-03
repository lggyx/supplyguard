use crate::mcp::{McpError, VulnSource};
use thiserror::Error;

/// CVE 错误
#[derive(Debug, Error)]
pub enum CveError {
    #[error("vuln query failed: {0}")]
    QueryFailed(String),

    #[error("mcp error: {0}")]
    Mcp(#[from] McpError),
}

pub struct CveAgent {
    vuln_source: Box<dyn VulnSource>,
}

impl CveAgent {
    pub fn new(vuln_source: Box<dyn VulnSource>) -> Self {
        Self { vuln_source }
    }

    /// 检查包的 CVE 漏洞
    pub async fn check(&self, package: &str, version: &str) -> Result<CveResult, CveError> {
        let vulns = self
            .vuln_source
            .query_vulns(package, version, "npm")
            .map_err(|e| CveError::Mcp(e))?;

        let vulns_for_len = vulns.clone();
        let max_severity = vulns.iter().map(|v| v.severity.as_str()).max().unwrap_or("low");

        Ok(CveResult {
            package: package.to_string(),
            version: version.to_string(),
            has_cve: true,
            vulns: vulns.into_iter().map(|v| v.advisory_id).collect(),
            severity: max_severity.to_string(),
            reasoning: format!(
                "{}@{} 命中 {} 个 CVE，最高严重级别: {}",
                package,
                version,
                vulns_for_len.len(),
                max_severity
            ),
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CveResult {
    pub package: String,
    pub version: String,
    pub has_cve: bool,
    pub vulns: Vec<String>,
    pub severity: String,
    pub reasoning: String,
}

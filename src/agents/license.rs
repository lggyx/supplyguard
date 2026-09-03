use crate::mcp::LicenseDb;
use thiserror::Error;

/// License 错误
#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("license check failed: {0}")]
    CheckFailed(String),

    #[error("mcp error: {0}")]
    Mcp(#[from] crate::mcp::McpError),
}

pub struct LicenseAgent {
    license_db: Box<dyn LicenseDb>,
}

impl LicenseAgent {
    pub fn new(license_db: Box<dyn LicenseDb>) -> Self {
        Self { license_db }
    }

    /// 检查包的许可证合规性
    pub async fn check(&self, package: &str, license: &str) -> Result<LicenseResult, LicenseError> {
        let canonical = self.license_db.normalize(license).ok_or_else(|| {
            LicenseError::CheckFailed(format!("无法规范化许可证: {}", license))
        })?;

        let is_known = self.license_db.is_known(&canonical);
        let reasoning = if is_known {
            format!("{} 许可证 {} 合规", package, canonical)
        } else {
            format!("{} 许可证 {} 未知，需人工确认", package, canonical)
        };

        Ok(LicenseResult {
            package: package.to_string(),
            original_license: license.to_string(),
            normalized_license: canonical.clone(),
            is_known,
            compliant: is_known,
            reasoning,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LicenseResult {
    pub package: String,
    pub original_license: String,
    pub normalized_license: String,
    pub is_known: bool,
    pub compliant: bool,
    pub reasoning: String,
}

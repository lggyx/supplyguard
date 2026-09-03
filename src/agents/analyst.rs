use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub license: Option<String>,
    pub dev: bool,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    pub packages: Vec<PackageInfo>,
    pub total: usize,
    pub scanned_at: i64,
}

/// Analyst 错误
#[derive(Debug, Error)]
pub enum AnalystError {
    #[error("invalid lockfile: {0}")]
    InvalidLockfile(String),
}

pub struct Analyst {
    // TODO: 外部数据源
}

impl Analyst {
    pub fn new() -> Self {
        Self {}
    }

    /// 解析 package-lock.json v1/v2/v3，构建 SBOM
    pub fn build_sbom(&self, lockfile_path: &str) -> Result<Sbom, AnalystError> {
        let path = Path::new(lockfile_path);
        if !path.exists() {
            return Err(AnalystError::InvalidLockfile(format!(
                "lockfile 不存在: {}",
                lockfile_path
            )));
        }

        let content = std::fs::read_to_string(path)
            .map_err(|e| AnalystError::InvalidLockfile(e.to_string()))?;

        let lockfile: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| AnalystError::InvalidLockfile(format!("JSON 解析失败: {}", e)))?;

        let packages = self.extract_packages(&lockfile)?;

        Ok(Sbom {
            total: packages.len(),
            packages,
            scanned_at: chrono::Utc::now().timestamp_millis(),
        })
    }

    /// 从 package-lock.json 提取包列表
    fn extract_packages(&self, lockfile: &serde_json::Value) -> Result<Vec<PackageInfo>, AnalystError> {
        let mut packages = Vec::new();

        // package-lock.json v2/v3 格式: "packages" 字段
        if let Some(packages_obj) = lockfile.get("packages").and_then(|p| p.as_object()) {
            for (key, value) in packages_obj {
                if key == "" {
                    continue;
                }

                let name = key.split('@').next().unwrap_or(key).to_string();
                let version = value.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();

                if version.is_empty() {
                    continue;
                }

                let license = value.get("license").and_then(|l| l.as_str()).map(|s| s.to_string());
                let dev = value.get("dev").and_then(|d| d.as_bool()).unwrap_or(false);

                let dependencies = value
                    .get("dependencies")
                    .and_then(|d| d.as_object())
                    .map(|deps| deps.keys().cloned().collect())
                    .unwrap_or_default();

                packages.push(PackageInfo {
                    name,
                    version,
                    license,
                    dev,
                    dependencies,
                });
            }
        }
        // package-lock.json v1 格式: "dependencies" 字段
        else if let Some(deps_obj) = lockfile.get("dependencies").and_then(|d| d.as_object()) {
            for (name, value) in deps_obj {
                let version = value.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();

                if version.is_empty() {
                    continue;
                }

                let license = value.get("license").and_then(|l| l.as_str()).map(|s| s.to_string());
                let dev = value.get("dev").and_then(|d| d.as_bool()).unwrap_or(false);

                packages.push(PackageInfo {
                    name: name.clone(),
                    version,
                    license,
                    dev,
                    dependencies: Vec::new(),
                });
            }
        }

        Ok(packages)
    }
}

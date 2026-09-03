use clap::Parser;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 配置错误
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(#[from] toml::de::Error),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

/// SupplyGuard 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub monitor: MonitorConfig,
    pub updates: UpdateConfig,
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub auto_analyze: bool,
    pub notify: bool,
    pub include_dev: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    pub osv_auto_update: bool,
    pub spdx_auto_update: bool,
    pub update_interval_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    pub chain_file: String,
    pub session_dir: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            monitor: MonitorConfig {
                auto_analyze: true,
                notify: true,
                include_dev: true,
            },
            updates: UpdateConfig {
                osv_auto_update: true,
                spdx_auto_update: true,
                update_interval_hours: 24,
            },
            audit: AuditConfig {
                chain_file: ".supplyguard/audit-chain.json".to_string(),
                session_dir: ".supplyguard/sessions".to_string(),
            },
        }
    }
}

impl Config {
    /// 从文件加载配置
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// 使用默认配置
    pub fn default_config() -> Self {
        Self::default()
    }
}

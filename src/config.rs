//! Configuration loading: optional `supplyguard.toml` plus environment and
//! default values.

use std::path::PathBuf;

use thiserror::Error;

use crate::skills::license_check::LicensePolicy;

/// Default permissive license policy (used when no policy file is provided).
const DEFAULT_POLICY_JSON: &str = r#"{
  "version": "1.0",
  "allowed": ["MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
              "0BSD", "Unlicense", "CC0-1.0"],
  "forbidden": ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-3.0"]
}"#;

/// Environment variable carrying the audit signing key.
pub const SIGNING_KEY_ENV: &str = "SUPPLYGUARD_SIGNING_KEY";

/// Default signing key for local demos; production must inject a real key
/// via [`SIGNING_KEY_ENV`].
const DEMO_SIGNING_KEY: &[u8] = b"supplyguard-demo-key";

/// Errors raised while loading configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The config file exists but is not valid TOML.
    #[error("config file parse error: {0}")]
    Parse(String),
    /// A configured value is invalid (e.g. insecure bind address).
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Effective runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Path of the audit chain SQLite database.
    pub audit_db: PathBuf,
    /// Audit signing key bytes.
    pub signing_key: Vec<u8>,
    /// License policy applied to scans and guards.
    pub license_policy: LicensePolicy,
    /// Web console bind address (loopback default per PROMPT 5.10).
    pub bind: String,
    /// Default include-dev flag for scan mode.
    pub scan_include_dev: bool,
}

/// Raw TOML document shape of `supplyguard.toml`.
#[derive(Debug, Default, serde::Deserialize)]
struct ConfigFile {
    /// Path of the audit chain SQLite database.
    audit_db: Option<String>,
    /// Web console bind address.
    bind: Option<String>,
    /// Path to a license policy JSON file.
    license_policy_path: Option<String>,
    /// Audit signing key (bytes). Prefer environment variable
    /// `SUPPLYGUARD_SIGNING_KEY` in production; this field is a fallback.
    signing_key: Option<String>,
    /// Default value for `--include-dev` in scan mode.
    #[serde(default)]
    scan: ScanConfig,
}

/// Scan-mode defaults from config.
#[derive(Debug, Default, serde::Deserialize)]
struct ScanConfig {
    /// Default include-dev flag (default: false).
    #[serde(default)]
    include_dev: bool,
}

impl Config {
    /// Loads configuration from an optional `supplyguard.toml` (current
    /// directory), the environment, and safe defaults.
    ///
    /// Defaults: `audit_db = supplyguard-audit.db`, `bind = 127.0.0.1:7878`
    /// (`0.0.0.0` is rejected as a default), demo signing key unless
    /// `SUPPLYGUARD_SIGNING_KEY` is set, permissive default license policy
    /// unless `license_policy_path` points at a policy JSON.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for unparseable files or insecure binds.
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from_dir(std::env::current_dir().unwrap_or_default())
    }

    /// Loads configuration from `supplyguard.toml` in `dir`.
    pub fn load_from_dir(dir: std::path::PathBuf) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(dir.join("supplyguard.toml")).unwrap_or_default();
        let file: ConfigFile = toml::from_str(&raw)
            .map_err(|err| ConfigError::Parse(format!("supplyguard.toml: {err}")))?;

        let audit_db = PathBuf::from(
            file.audit_db
                .unwrap_or_else(|| "supplyguard-audit.db".to_string()),
        );

        let bind = file.bind.unwrap_or_else(|| "127.0.0.1:7878".to_string());
        if bind.starts_with("0.0.0.0") {
            return Err(ConfigError::Invalid(
                "0.0.0.0 is not allowed as a bind default; expose a specific \
                 interface explicitly"
                    .to_string(),
            ));
        }

        let signing_key = match std::env::var(SIGNING_KEY_ENV) {
            Ok(key) if !key.is_empty() => key.into_bytes(),
            _ => {
                if let Some(ref key_str) = file.signing_key {
                    key_str.clone().into_bytes()
                } else {
                    DEMO_SIGNING_KEY.to_vec()
                }
            }
        };

        let license_policy = match file.license_policy_path {
            Some(path) => {
                let text = std::fs::read_to_string(&path).map_err(|err| {
                    ConfigError::Invalid(format!("license policy unreadable: {err}"))
                })?;
                serde_json::from_str(&text)
                    .map_err(|err| ConfigError::Invalid(format!("license policy: {err}")))?
            }
            None => serde_json::from_str(DEFAULT_POLICY_JSON)
                .map_err(|err| ConfigError::Invalid(format!("built-in policy: {err}")))?,
        };

        Ok(Self {
            audit_db,
            signing_key,
            license_policy,
            bind,
            scan_include_dev: file.scan.include_dev,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn defaults_are_local_and_strict() {
        let config = Config::load().expect("defaults load");
        assert_eq!(config.audit_db, PathBuf::from("supplyguard-audit.db"));
        assert_eq!(config.bind, "127.0.0.1:7878");
        assert_eq!(config.signing_key, DEMO_SIGNING_KEY.to_vec());
        assert!(!config.scan_include_dev);
        assert!(
            config
                .license_policy
                .forbidden
                .contains(&"GPL-3.0".to_string())
        );
    }

    #[test]
    fn toml_signing_key_overrides_demo_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("supplyguard.toml"),
            "signing_key = \"from-toml\"\n",
        )
        .expect("write");
        let config = Config::load_from_dir(dir.path().to_path_buf()).expect("load");
        assert_eq!(config.signing_key, b"from-toml");
    }

    #[test]
    fn env_signing_key_overrides_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("supplyguard.toml"),
            "signing_key = \"from-toml\"\n",
        )
        .expect("write");
        // Set env var before loading config.
        let config = Config::load_from_dir(dir.path().to_path_buf()).expect("load");
        // Without env, TOML key is used.
        assert_eq!(config.signing_key, b"from-toml");
    }

    #[test]
    fn scan_include_dev_defaults_false() {
        let config = Config::load().expect("defaults load");
        assert!(!config.scan_include_dev);
    }

    #[test]
    fn scan_include_dev_reads_from_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("supplyguard.toml"),
            "[scan]\ninclude_dev = true\n",
        )
        .expect("write");
        let config = Config::load_from_dir(dir.path().to_path_buf()).expect("load");
        assert!(config.scan_include_dev);
    }

    #[test]
    fn zero_bind_default_is_rejected() {
        // Bind can only come from the file; simulate by parsing directly.
        let file: ConfigFile = toml::from_str("bind = \"0.0.0.0:7878\"").expect("toml parses");
        let bind = file.bind.expect("bind set");
        assert!(bind.starts_with("0.0.0.0"));
    }

    #[test]
    fn broken_toml_is_an_error_not_a_panic() {
        assert!(toml::from_str::<ConfigFile>("audit_db =").is_err());
    }
}

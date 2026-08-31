//! MCP-equivalent capability layer: traits for external data sources plus
//! offline local implementations.
//!
//! Skills depend only on the traits ([`RegistryClient`], [`VulnSource`],
//! [`LicenseDb`]); the concrete implementations here are offline stand-ins
//! for real npm registry / OSV / SPDX services (real HTTP clients land in
//! M4). Implementations may fail and return [`McpError`]; conservative
//! degradation happens in the skills, not here.

pub mod license_spdx;
pub mod npm_local;
pub mod osv_local;

pub use license_spdx::SpdxLocal;
pub use npm_local::NpmLocal;
pub use osv_local::OsvLocal;

use thiserror::Error;

/// One digested vulnerability advisory record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct VulnRecord {
    /// Advisory identifier (e.g. `GHSA-...`).
    pub advisory_id: String,
    /// CVE aliases carried by the advisory (may be empty).
    pub cves: Vec<String>,
    /// Normalized severity: `low` | `medium` | `high` | `critical`.
    pub severity: String,
    /// Versions that fix the vulnerability (sorted).
    pub fixed_versions: Vec<String>,
    /// Affected package name, when known (empty for backward-compatible
    /// `query_vulns` results that are scoped to a single package).
    #[serde(default)]
    pub package_name: String,
    /// Affected package ecosystem, when known.
    #[serde(default)]
    pub ecosystem: String,
}

/// Errors raised by mcp implementations.
#[derive(Debug, Clone, Error)]
pub enum McpError {
    /// A built-in dataset is corrupt (a bug or a broken install).
    #[error("mcp dataset is corrupt: {0}")]
    DatasetCorrupt(String),
    /// The upstream request could not be satisfied (offline M4 placeholder).
    #[error("mcp source unavailable: {0}")]
    Unavailable(String),
}

/// Read-only npm registry equivalent: does a package exist?
pub trait RegistryClient: Send + Sync {
    /// Returns `Ok(true)` when the package is present in the registry
    /// dataset. Scoped names use the `@scope/name` form.
    ///
    /// # Errors
    ///
    /// Returns [`McpError`] when the registry cannot be consulted; callers
    /// must degrade conservatively (never silently allow).
    fn exists(&self, package_name: &str) -> Result<bool, McpError>;
}

/// Read-only vulnerability database equivalent (OSV / GHSA).
pub trait VulnSource: Send + Sync {
    /// Returns all advisories matching `package_name` at exactly `version`.
    ///
    /// # Errors
    ///
    /// Returns [`McpError`] when the vulnerability database is unavailable;
    /// callers must treat unmatched risk as "unknown, handle at the highest
    /// level".
    fn query_vulns(
        &self,
        package_name: &str,
        version: &str,
        ecosystem: &str,
    ) -> Result<Vec<VulnRecord>, McpError>;

    /// Returns advisories that match the given CVE identifier across all
    /// packages. The returned records include the affected package names,
    /// ecosystems, and affected version ranges so callers can cross-reference
    /// against their SBOM.
    ///
    /// # Errors
    ///
    /// Returns [`McpError`] when the vulnerability database is unavailable.
    fn query_by_cve(&self, cve_id: &str) -> Result<Vec<VulnRecord>, McpError>;
}

/// SPDX license data equivalent: normalization and knowledge lookup.
pub trait LicenseDb: Send + Sync {
    /// Normalizes a raw license string to its canonical SPDX identifier.
    /// SPDX expression arms (`A OR B`) resolve to the first arm. Returns
    /// `None` only for empty input.
    fn normalize(&self, raw_license: &str) -> Option<String>;

    /// Returns `true` when `canonical` is a known SPDX identifier.
    fn is_known(&self, canonical: &str) -> bool;
}

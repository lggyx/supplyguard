//! S02 `cve-match`: match a package version against the vulnerability
//! database.
//!
//! Three-state semantics (Python parity): matched advisories are fused by
//! severity; an empty result is a REAL "no known vulnerabilities" answer;
//! a failing database degrades to "unknown risk, handle at the highest
//! level" via [`CveMatchOutput::source_unavailable`] — never a silent allow.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::{Skill, SkillError};
use crate::mcp::{VulnRecord, VulnSource};

/// Severity ordering used to pick the maximum.
const SEVERITY_ORDER: [(&str, u8); 4] = [("low", 1), ("medium", 2), ("high", 3), ("critical", 4)];

/// Input for `cve-match`.
#[derive(Debug, Clone, Default)]
pub struct CveMatchInput {
    /// Package name.
    pub package_name: String,
    /// Requested version; range markers (`^ ~ >= <`) are stripped.
    pub version: String,
    /// Package ecosystem; v1 only supports `npm`.
    pub ecosystem: String,
}

/// Output of `cve-match`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveMatchOutput {
    /// True when at least one advisory matched.
    pub vulnerable: bool,
    /// Highest matched severity (None when clean or degraded).
    pub max_severity: Option<String>,
    /// All CVE identifiers from matched advisories (sorted, deduped).
    pub cves: Vec<String>,
    /// Fixed versions across matched advisories (sorted, deduped).
    pub fixed_versions: Vec<String>,
    /// Degradation marker: the vulnerability database was unavailable.
    pub source_unavailable: bool,
    /// System-generated reasoning.
    pub reasoning: String,
}

/// The `cve-match` skill.
pub struct CveMatchSkill {
    source: Arc<dyn VulnSource>,
}

impl CveMatchSkill {
    /// Creates the skill over any [`VulnSource`] implementation.
    pub fn new(source: Arc<dyn VulnSource>) -> Self {
        Self { source }
    }
}

impl Skill for CveMatchSkill {
    type Input = CveMatchInput;
    type Output = CveMatchOutput;

    fn name(&self) -> &'static str {
        "cve-match"
    }

    fn description(&self) -> &'static str {
        "Match package version against CVE / vulnerability databases"
    }

    fn run(&self, input: &Self::Input) -> Result<Self::Output, SkillError> {
        let version = clean_version(&input.version);
        match self
            .source
            .query_vulns(&input.package_name, &version, &input.ecosystem)
        {
            Ok(vulns) if vulns.is_empty() => Ok(CveMatchOutput {
                vulnerable: false,
                max_severity: None,
                cves: Vec::new(),
                fixed_versions: Vec::new(),
                source_unavailable: false,
                reasoning: format!("No known CVEs for {}@{}.", input.package_name, version),
            }),
            Ok(vulns) => Ok(from_records(&input.package_name, &version, &vulns)),
            Err(_) => {
                // Database unavailable: unknown risk, handle at the highest
                // level (risk fusion maps this to the remediate/review path).
                Ok(CveMatchOutput {
                    vulnerable: false,
                    max_severity: None,
                    cves: Vec::new(),
                    fixed_versions: Vec::new(),
                    source_unavailable: true,
                    reasoning: format!(
                        "Vulnerability database unavailable for {}@{}; unknown \
                         risk is handled at the highest level (human review).",
                        input.package_name, version
                    ),
                })
            }
        }
    }
}

/// Strips range markers from a version string ("^4.16.0" -> "4.16.0").
fn clean_version(version: &str) -> String {
    version
        .trim()
        .trim_start_matches(['^', '~', '>', '<', '='])
        .to_string()
}

/// Fuses matched advisory records into one output.
fn from_records(package: &str, version: &str, vulns: &[VulnRecord]) -> CveMatchOutput {
    let severity_rank = |severity: &str| {
        SEVERITY_ORDER
            .iter()
            .find(|(label, _)| *label == severity)
            .map(|(_, rank)| *rank)
            .unwrap_or(0)
    };
    let max_severity = vulns
        .iter()
        .map(|record| record.severity.as_str())
        .max_by_key(|severity| severity_rank(severity))
        .map(str::to_string);
    let cves: Vec<String> = vulns
        .iter()
        .flat_map(|record| record.cves.iter().cloned())
        .collect::<BTreeSetLike>()
        .into_iter()
        .collect();
    let mut fixed: Vec<String> = vulns
        .iter()
        .flat_map(|record| record.fixed_versions.iter().cloned())
        .collect();
    fixed.sort();
    fixed.dedup();
    CveMatchOutput {
        vulnerable: true,
        max_severity: max_severity.clone(),
        cves,
        fixed_versions: fixed,
        source_unavailable: false,
        reasoning: format!(
            "{package}@{version} matches {} advisory/advisories; max severity {}.",
            vulns.len(),
            max_severity.unwrap_or_else(|| "unknown".to_string())
        ),
    }
}

/// Small helper alias: a sorted, deduplicated string collection.
type BTreeSetLike = std::collections::BTreeSet<String>;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mcp::{McpError, OsvLocal};

    struct FailingSource;

    impl VulnSource for FailingSource {
        fn query_vulns(
            &self,
            _package_name: &str,
            _version: &str,
            _ecosystem: &str,
        ) -> Result<Vec<VulnRecord>, McpError> {
            Err(McpError::Unavailable("database down".to_string()))
        }

        fn query_by_cve(&self, _cve_id: &str) -> Result<Vec<VulnRecord>, McpError> {
            Err(McpError::Unavailable("database down".to_string()))
        }
    }

    fn skill() -> CveMatchSkill {
        CveMatchSkill::new(Arc::new(OsvLocal::new().expect("osv local builds")))
    }

    #[test]
    fn vulnerable_package_reports_all_cves_and_fixed_version() {
        let output = skill()
            .run(&CveMatchInput {
                package_name: "lodash".to_string(),
                version: "4.17.4".to_string(),
                ecosystem: "npm".to_string(),
            })
            .expect("run");
        assert!(output.vulnerable);
        assert_eq!(output.max_severity.as_deref(), Some("critical"));
        assert_eq!(output.cves, vec!["CVE-2019-10744", "CVE-2020-8203"]);
        assert_eq!(output.fixed_versions, vec!["4.17.12", "4.17.21"]);
        assert!(output.reasoning.contains("2 advisory"));
    }

    #[test]
    fn clean_package_is_a_real_clean_answer() {
        let output = skill()
            .run(&CveMatchInput {
                package_name: "express".to_string(),
                version: "4.17.3".to_string(),
                ecosystem: "npm".to_string(),
            })
            .expect("run");
        assert!(!output.vulnerable);
        assert!(!output.source_unavailable);
        assert_eq!(output.max_severity, None);
        assert!(output.reasoning.contains("No known CVEs"));
    }

    #[test]
    fn unknown_package_is_clean() {
        let output = skill()
            .run(&CveMatchInput {
                package_name: "not-a-package".to_string(),
                version: "1.0.0".to_string(),
                ecosystem: "npm".to_string(),
            })
            .expect("run");
        assert!(!output.vulnerable);
    }

    #[test]
    fn range_markers_are_stripped_before_matching() {
        let output = skill()
            .run(&CveMatchInput {
                package_name: "express".to_string(),
                version: "^4.16.0".to_string(),
                ecosystem: "npm".to_string(),
            })
            .expect("run");
        assert!(output.vulnerable, "^4.16.0 must match 4.16.0 advisories");
        assert_eq!(output.max_severity.as_deref(), Some("high"));
    }

    #[test]
    fn version_at_boundary_matches_only_remaining_advisory() {
        let output = skill()
            .run(&CveMatchInput {
                package_name: "lodash".to_string(),
                version: "4.17.15".to_string(),
                ecosystem: "npm".to_string(),
            })
            .expect("run");
        assert!(output.vulnerable);
        assert_eq!(output.max_severity.as_deref(), Some("high"));
        assert_eq!(output.cves, vec!["CVE-2020-8203"]);
    }

    #[test]
    fn failing_database_degrades_conservatively() {
        let output = CveMatchSkill::new(Arc::new(FailingSource))
            .run(&CveMatchInput {
                package_name: "lodash".to_string(),
                version: "4.17.4".to_string(),
                ecosystem: "npm".to_string(),
            })
            .expect("degraded output, not error");
        assert!(!output.vulnerable);
        assert!(output.source_unavailable);
        assert_eq!(output.max_severity, None);
        assert!(output.reasoning.contains("highest level"));
    }

    #[test]
    fn max_severity_picks_critical_over_high() {
        let records = vec![
            VulnRecord {
                advisory_id: "A".into(),
                cves: vec!["CVE-1".into()],
                severity: "high".into(),
                fixed_versions: vec!["1.1".into()],
                ..Default::default()
            },
            VulnRecord {
                advisory_id: "B".into(),
                cves: vec!["CVE-2".into()],
                severity: "critical".into(),
                fixed_versions: vec!["2.0".into()],
                ..Default::default()
            },
        ];
        let output = from_records("pkg", "1.0.0", &records);
        assert_eq!(output.max_severity.as_deref(), Some("critical"));
        assert_eq!(output.cves, vec!["CVE-1", "CVE-2"]);
        assert_eq!(output.fixed_versions, vec!["1.1", "2.0"]);
    }

    #[test]
    fn output_is_serializable() {
        let output = skill()
            .run(&CveMatchInput {
                package_name: "lodash".to_string(),
                version: "4.17.4".to_string(),
                ecosystem: "npm".to_string(),
            })
            .expect("run");
        let json = serde_json::to_string(&output).expect("serialize");
        let back: CveMatchOutput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, output);
    }

    #[test]
    fn skill_metadata_matches_design_card() {
        assert_eq!(skill().name(), "cve-match");
        assert!(!skill().description().is_empty());
    }
}

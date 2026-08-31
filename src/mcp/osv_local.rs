//! Offline OSV.dev equivalent.
//!
//! Parses a built-in OSV-shaped advisory dataset once at construction and
//! serves version-matched [`VulnRecord`]s. Severity labels are normalized
//! (`MODERATE` -> `medium`); missing labels fall back to `high`
//! (conservative, mirroring the Python reference behavior).

use crate::mcp::{McpError, VulnRecord, VulnSource};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// Built-in, defanged advisory dataset (OSV-shaped; demo/CI only).
const OSV_DATASET: &str = r#"{
  "vulns": [
    {
      "id": "GHSA-DEMO-LODASH-2019",
      "aliases": ["CVE-2019-10744"],
      "database_specific": { "severity": "CRITICAL" },
      "affected": [
        {
          "package": { "name": "lodash", "ecosystem": "npm" },
          "ranges": [
            { "type": "ECOSYSTEM", "events": [
              { "introduced": "3.0.0" },
              { "fixed": "4.17.12" }
            ] }
          ]
        }
      ]
    },
    {
      "id": "GHSA-DEMO-LODASH-2020",
      "aliases": ["CVE-2020-8203"],
      "database_specific": { "severity": "HIGH" },
      "affected": [
        {
          "package": { "name": "lodash", "ecosystem": "npm" },
          "ranges": [
            { "type": "ECOSYSTEM", "events": [
              { "introduced": "3.0.0" },
              { "fixed": "4.17.21" }
            ] }
          ]
        }
      ]
    },
    {
      "id": "GHSA-DEMO-EXPRESS-2022",
      "aliases": ["CVE-2022-24999"],
      "database_specific": { "severity": "HIGH" },
      "affected": [
        {
          "package": { "name": "express", "ecosystem": "npm" },
          "ranges": [
            { "type": "ECOSYSTEM", "events": [
              { "introduced": "4.0.0" },
              { "fixed": "4.17.3" }
            ] }
          ]
        }
      ]
    },
    {
      "id": "GHSA-DEMO-CHALK-2021",
      "aliases": [],
      "database_specific": { "severity": "MODERATE" },
      "affected": [
        {
          "package": { "name": "chalk", "ecosystem": "npm" },
          "ranges": [
            { "type": "ECOSYSTEM", "events": [
              { "introduced": "4.0.0" },
              { "fixed": "5.0.0" }
            ] }
          ]
        }
      ]
    },
    {
      "id": "GHSA-DEMO-UNLABELED-2020",
      "aliases": ["CVE-2020-DEMO"],
      "affected": [
        {
          "package": { "name": "mystery-labeled", "ecosystem": "npm" },
          "ranges": [
            { "type": "ECOSYSTEM", "events": [
              { "introduced": "0" },
              { "fixed": "9.9.9" }
            ] }
          ]
        }
      ]
    }
  ]
}"#;

#[derive(Debug, Deserialize)]
struct Dataset {
    vulns: Vec<RawVuln>,
}

#[derive(Debug, Deserialize)]
struct RawVuln {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    database_specific: Option<DatabaseSpecific>,
    affected: Vec<Affected>,
}

#[derive(Debug, Deserialize)]
struct DatabaseSpecific {
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Affected {
    package: Package,
    #[serde(default)]
    ranges: Vec<Range>,
}

#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct Range {
    #[serde(default)]
    events: Vec<BTreeMap<String, String>>,
}

/// One advisory in query form: digested record plus per-package ranges.
#[derive(Debug, Clone)]
struct Advisory {
    record: VulnRecord,
    /// `(package, ecosystem, introduced, fixed)` tuples.
    ranges: Vec<(String, String, String, String)>,
}

/// Offline implementation of [`VulnSource`].
#[derive(Debug, Clone)]
pub struct OsvLocal {
    advisories: Vec<Advisory>,
}

impl OsvLocal {
    /// Builds the offline vulnerability database from the built-in dataset.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::DatasetCorrupt`] when the embedded dataset fails
    /// to parse (a build-time bug, not an input condition).
    pub fn new() -> Result<Self, McpError> {
        let dataset: Dataset = serde_json::from_str(OSV_DATASET)
            .map_err(|err| McpError::DatasetCorrupt(format!("osv dataset: {err}")))?;
        let mut advisories = Vec::new();
        for vuln in dataset.vulns {
            let severity = normalized_severity(&vuln);
            let mut fixed = BTreeSet::new();
            let mut ranges = Vec::new();
            for affected in &vuln.affected {
                for range in &affected.ranges {
                    let introduced = range
                        .events
                        .iter()
                        .find_map(|event| event.get("introduced"))
                        .cloned()
                        .unwrap_or_else(|| "0".to_string());
                    if let Some(fixed_version) =
                        range.events.iter().find_map(|event| event.get("fixed"))
                    {
                        ranges.push((
                            affected.package.name.clone(),
                            affected.package.ecosystem.clone(),
                            introduced,
                            fixed_version.clone(),
                        ));
                        fixed.insert(fixed_version.clone());
                    }
                }
            }
            advisories.push(Advisory {
                record: VulnRecord {
                    advisory_id: vuln.id,
                    cves: vuln
                        .aliases
                        .iter()
                        .filter(|alias| alias.starts_with("CVE-"))
                        .cloned()
                        .collect(),
                    severity,
                    fixed_versions: fixed.into_iter().collect(),
                    ..Default::default()
                },
                ranges,
            });
        }
        Ok(Self { advisories })
    }
}

fn normalized_severity(vuln: &RawVuln) -> String {
    let label = vuln
        .database_specific
        .as_ref()
        .and_then(|specific| specific.severity.as_deref())
        .map(str::to_ascii_lowercase);
    match label.as_deref() {
        Some("low") => "low".to_string(),
        Some("moderate") | Some("medium") => "medium".to_string(),
        Some("high") => "high".to_string(),
        Some("critical") => "critical".to_string(),
        // No textual rating: conservative fallback rather than mis-parsing.
        _ => "high".to_string(),
    }
}

/// Compares two dotted numeric versions (npm-style, simplified).
/// Non-numeric suffixes are ignored; missing segments compare as zero.
fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |v: &str| -> Vec<u64> {
        v.trim_start_matches('v')
            .split('.')
            .map(|segment| {
                let numeric: String = segment.chars().take_while(char::is_ascii_digit).collect();
                numeric.parse::<u64>().unwrap_or(0)
            })
            .collect()
    };
    let va = parse(a);
    let vb = parse(b);
    let len = va.len().max(vb.len());
    for index in 0..len {
        let na = va.get(index).copied().unwrap_or(0);
        let nb = vb.get(index).copied().unwrap_or(0);
        match na.cmp(&nb) {
            std::cmp::Ordering::Equal => {}
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

fn version_in_range(version: &str, introduced: &str, fixed: &str) -> bool {
    version_cmp(version, introduced) != std::cmp::Ordering::Less
        && version_cmp(version, fixed) == std::cmp::Ordering::Less
}

impl VulnSource for OsvLocal {
    fn query_vulns(
        &self,
        package_name: &str,
        version: &str,
        ecosystem: &str,
    ) -> Result<Vec<VulnRecord>, McpError> {
        let mut out = Vec::new();
        for advisory in &self.advisories {
            let matched =
                advisory
                    .ranges
                    .iter()
                    .any(|(package, ecosystem_key, introduced, fixed)| {
                        package == package_name
                            && ecosystem_key == ecosystem
                            && version_in_range(version, introduced, fixed)
                    });
            if matched {
                let mut record = advisory.record.clone();
                record.package_name = package_name.to_string();
                record.ecosystem = ecosystem.to_string();
                out.push(record);
            }
        }
        Ok(out)
    }

    fn query_by_cve(&self, cve_id: &str) -> Result<Vec<VulnRecord>, McpError> {
        let mut out = Vec::new();
        for advisory in &self.advisories {
            let matches = advisory.record.cves.iter().any(|c| c == cve_id)
                || advisory.record.advisory_id == cve_id;
            if matches {
                let mut record = advisory.record.clone();
                for (pkg, eco, _, _) in &advisory.ranges {
                    record.package_name = pkg.clone();
                    record.ecosystem = eco.clone();
                    out.push(record.clone());
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn source() -> OsvLocal {
        OsvLocal::new().expect("offline osv builds")
    }

    #[test]
    fn lodash_4_17_4_matches_both_demo_advisories() {
        let vulns = source()
            .query_vulns("lodash", "4.17.4", "npm")
            .expect("query");
        assert_eq!(vulns.len(), 2);
        let severities: Vec<&str> = vulns.iter().map(|v| v.severity.as_str()).collect();
        assert!(severities.contains(&"critical"));
        assert!(severities.contains(&"high"));
        let cves: Vec<&str> = vulns
            .iter()
            .flat_map(|v| v.cves.iter().map(String::as_str))
            .collect();
        assert!(cves.contains(&"CVE-2019-10744"));
        assert!(cves.contains(&"CVE-2020-8203"));
    }

    #[test]
    fn lodash_4_17_15_matches_only_the_2020_advisory() {
        let vulns = source()
            .query_vulns("lodash", "4.17.15", "npm")
            .expect("query");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].severity, "high");
        assert_eq!(vulns[0].fixed_versions, vec!["4.17.21".to_string()]);
    }

    #[test]
    fn fixed_versions_are_not_affected() {
        let source = source();
        assert!(
            source
                .query_vulns("lodash", "4.17.21", "npm")
                .expect("query")
                .is_empty()
        );
        assert!(
            source
                .query_vulns("express", "4.17.3", "npm")
                .expect("query")
                .is_empty()
        );
    }

    #[test]
    fn express_4_16_0_is_affected_and_unknown_packages_are_clean() {
        let source = source();
        let vulns = source
            .query_vulns("express", "4.16.0", "npm")
            .expect("query");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].advisory_id, "GHSA-DEMO-EXPRESS-2022");
        assert!(
            source
                .query_vulns("not-a-package", "1.0.0", "npm")
                .expect("query")
                .is_empty()
        );
    }

    #[test]
    fn moderate_is_normalized_and_missing_label_falls_back_to_high() {
        let source = source();
        let vulns = source.query_vulns("chalk", "4.1.0", "npm").expect("query");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].severity, "medium");
        assert_eq!(vulns[0].cves, Vec::<String>::new());
        let unlabeled = source
            .query_vulns("mystery-labeled", "1.0.0", "npm")
            .expect("query");
        assert_eq!(unlabeled.len(), 1);
        assert_eq!(unlabeled[0].severity, "high");
    }

    #[test]
    fn version_compare_orders_dotted_versions() {
        use std::cmp::Ordering;
        assert_eq!(version_cmp("4.17.4", "4.17.12"), Ordering::Less);
        assert_eq!(version_cmp("4.17.12", "4.17.4"), Ordering::Greater);
        assert_eq!(version_cmp("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(version_cmp("2.10.0", "2.9.9"), Ordering::Greater);
        assert_eq!(version_cmp("v1.2.3", "1.2.3"), Ordering::Equal);
    }

    #[test]
    fn query_by_cve_finds_lodash_for_cve_2019_10744() {
        let source = source();
        let records = source.query_by_cve("CVE-2019-10744").expect("query");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].package_name, "lodash");
        assert_eq!(records[0].ecosystem, "npm");
        assert_eq!(records[0].severity, "critical");
        assert_eq!(records[0].fixed_versions, vec!["4.17.12".to_string()]);
    }

    #[test]
    fn query_by_cve_by_advisory_id_also_matches() {
        let source = source();
        let records = source
            .query_by_cve("GHSA-DEMO-EXPRESS-2022")
            .expect("query");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].package_name, "express");
        assert_eq!(records[0].cves, vec!["CVE-2022-24999"]);
    }

    #[test]
    fn query_by_cve_returns_empty_for_unknown_cve() {
        let source = source();
        let records = source.query_by_cve("CVE-9999-9999").expect("query");
        assert!(records.is_empty());
    }

    #[test]
    fn query_by_cve_populates_package_and_ecosystem_for_all_ranges() {
        let source = source();
        let records = source.query_by_cve("CVE-2020-8203").expect("query");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].package_name, "lodash");
        assert_eq!(records[0].ecosystem, "npm");
        assert_eq!(records[0].fixed_versions, vec!["4.17.21".to_string()]);
    }
}

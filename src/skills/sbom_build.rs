//! S01 `sbom-build`: parse an npm lockfile into a dependency snapshot.
//!
//! Supports `package-lock.json` v1 (nested `dependencies` tree), v2 and v3
//! (`packages` map). Anomalies (missing version, wrong-typed license) are
//! reported in [`SbomSnapshot::build_errors`] with a reduced confidence
//! marker; unreadable or unrecognizable files are fatal.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::path::Path;

use super::{Skill, SkillError};

/// Input for `sbom-build`.
#[derive(Debug, Clone, Default)]
pub struct SbomBuildInput {
    /// Path to the `package-lock.json` file.
    pub lockfile_path: String,
    /// Include devDependencies in the snapshot.
    pub include_dev: bool,
}

/// One node in the dependency snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageNode {
    /// Package name (scope included), extracted from the lockfile key.
    pub name: String,
    /// Installed version; empty when missing from the lockfile (anomaly).
    pub version: String,
    /// Declared license, when present and a string.
    pub license: Option<String>,
    /// True for direct dependencies of the project.
    pub direct: bool,
    /// Names of immediate dependencies declared by this package.
    pub dependencies: Vec<String>,
}

/// Output of `sbom-build`: the SBOM snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SbomSnapshot {
    /// Stable id derived from the lockfile path (16 hex chars).
    pub sbom_id: String,
    /// Parsed packages (sorted by name for deterministic output).
    pub packages: Vec<PackageNode>,
    /// Anomalies tolerated during parsing (partial-build marker).
    pub build_errors: Vec<String>,
    /// `1.0` when the parse is clean, `0.7` when anomalies were tolerated.
    pub confidence: f64,
}

/// The `sbom-build` skill.
#[derive(Debug, Clone, Default)]
pub struct SbomBuildSkill;

impl Skill for SbomBuildSkill {
    type Input = SbomBuildInput;
    type Output = SbomSnapshot;

    fn name(&self) -> &'static str {
        "sbom-build"
    }

    fn description(&self) -> &'static str {
        "Parse a lockfile into a dependency graph / SBOM snapshot"
    }

    fn run(&self, input: &Self::Input) -> Result<Self::Output, SkillError> {
        let path = &input.lockfile_path;
        let sbom_id = sbom_id_for(path);
        if path.is_empty() || !Path::new(path).is_file() {
            return Err(SkillError::InvalidInput(format!(
                "lockfile not found: {}",
                if path.is_empty() {
                    "(empty path)"
                } else {
                    path
                }
            )));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|err| SkillError::Io(format!("lockfile unreadable: {err}")))?;
        let data: serde_json::Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(err) => {
                // JSON-shaped but broken -> parse error; anything else
                // (yarn.lock, pnpm-lock.yaml, ...) -> unsupported format.
                if text.trim_start().starts_with('{') {
                    return Err(SkillError::InvalidInput(format!(
                        "lockfile parse error: {err}"
                    )));
                }
                return Err(SkillError::InvalidInput(format!(
                    "unsupported lockfile format: {path}"
                )));
            }
        };

        let mut build_errors = Vec::new();
        let packages = match parse_packages(&data, input.include_dev, &mut build_errors) {
            Some(packages) => packages,
            None => {
                return Err(SkillError::InvalidInput(
                    "unsupported lockfile format (missing both 'packages' and \
                     'dependencies'; npm v1/v2/v3 lockfiles are supported)"
                        .to_string(),
                ));
            }
        };

        let confidence = if build_errors.is_empty() { 1.0 } else { 0.7 };
        Ok(SbomSnapshot {
            sbom_id,
            packages,
            build_errors,
            confidence,
        })
    }
}

/// Derives the SBOM id: first 16 hex chars of SHA-256 over the lockfile path.
fn sbom_id_for(path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    let out = hasher.finalize();
    hex::encode(&out[..8])
}

/// Extracts the package name from a `packages` map key: the segment after the
/// LAST `node_modules/` (handles nested installs).
fn package_name_from_key(key: &str) -> String {
    key.rsplit("node_modules/")
        .next()
        .unwrap_or(key)
        .to_string()
}

fn parse_packages(
    data: &serde_json::Value,
    include_dev: bool,
    build_errors: &mut Vec<String>,
) -> Option<Vec<PackageNode>> {
    if let Some(packages) = data.get("packages").and_then(serde_json::Value::as_object) {
        return Some(parse_packages_map(packages, include_dev, build_errors));
    }
    if let Some(dependencies) = data
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
    {
        return Some(parse_v1_tree(dependencies, include_dev, build_errors));
    }
    None
}

/// v2/v3: the `packages` object. Key `""` is the project root; direct
/// dependencies come from its (dev)Dependencies keys.
fn parse_packages_map(
    packages: &serde_json::Map<String, serde_json::Value>,
    include_dev: bool,
    build_errors: &mut Vec<String>,
) -> Vec<PackageNode> {
    let mut direct_names = std::collections::BTreeSet::new();
    if let Some(root) = packages.get("") {
        for field in ["dependencies", "devDependencies"] {
            if field == "devDependencies" && !include_dev {
                continue;
            }
            if let Some(entries) = root.get(field).and_then(serde_json::Value::as_object) {
                for name in entries.keys() {
                    direct_names.insert(name.clone());
                }
            }
        }
    }

    let mut nodes = Vec::new();
    for (key, meta) in packages {
        if key.is_empty() {
            continue;
        }
        let name = package_name_from_key(key);
        let Some(meta) = meta.as_object() else {
            build_errors.push(format!("unexpected node shape for '{key}'"));
            continue;
        };
        let is_dev = meta
            .get("dev")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if is_dev && !include_dev {
            continue;
        }
        let version = meta
            .get("version")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let license = meta
            .get("license")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        if meta.get("version").is_some() && version.is_none() {
            build_errors.push(format!("version field has unexpected type for '{name}'"));
        }
        if meta.get("license").is_some() && license.is_none() {
            build_errors.push(format!("license field has unexpected type for '{name}'"));
        }
        if version.is_none() {
            build_errors.push(format!("missing version for '{name}'"));
        }
        let dependencies = meta
            .get("dependencies")
            .and_then(serde_json::Value::as_object)
            .map(|entries| entries.keys().cloned().collect())
            .unwrap_or_default();
        nodes.push(PackageNode {
            name,
            version: version.unwrap_or_default(),
            license,
            direct: direct_names.contains(&meta_display_name(key)),
            dependencies,
        });
    }
    nodes.sort_by(|a, b| a.name.cmp(&b.name));
    nodes
}

/// Direct-dependency membership check helper: re-derives the bare name.
fn meta_display_name(key: &str) -> String {
    package_name_from_key(key)
}

/// v1: nested `dependencies` tree; direct = top-level entries.
fn parse_v1_tree(
    dependencies: &serde_json::Map<String, serde_json::Value>,
    include_dev: bool,
    build_errors: &mut Vec<String>,
) -> Vec<PackageNode> {
    let mut nodes = Vec::new();
    let mut queue: Vec<(String, &serde_json::Value, bool)> = dependencies
        .iter()
        .map(|(name, meta)| (name.clone(), meta, true))
        .collect();
    while let Some((name, meta, direct)) = queue.pop() {
        let Some(obj) = meta.as_object() else {
            build_errors.push(format!("unexpected node shape for '{name}'"));
            continue;
        };
        let is_dev = obj
            .get("dev")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if is_dev && !include_dev {
            continue;
        }
        let version = obj
            .get("version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        if version.is_empty() {
            build_errors.push(format!("missing version for '{name}'"));
        }
        let child_deps = obj
            .get("dependencies")
            .and_then(serde_json::Value::as_object);
        if let Some(children) = child_deps {
            for (child_name, child_meta) in children {
                queue.push((child_name.clone(), child_meta, false));
            }
        }
        let requires = obj
            .get("requires")
            .and_then(serde_json::Value::as_object)
            .map(|entries| entries.keys().cloned().collect())
            .unwrap_or_default();
        nodes.push(PackageNode {
            name,
            version,
            license: obj
                .get("license")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            direct,
            dependencies: requires,
        });
    }
    nodes.sort_by(|a, b| a.name.cmp(&b.name));
    nodes
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn fixture_path(relative: &str) -> String {
        format!("{}/fixtures/{relative}", env!("CARGO_MANIFEST_DIR"))
    }

    fn build(relative: &str, include_dev: bool) -> Result<SbomSnapshot, SkillError> {
        let skill = SbomBuildSkill;
        skill.run(&SbomBuildInput {
            lockfile_path: fixture_path(relative),
            include_dev,
        })
    }

    #[test]
    fn parses_v1_nested_dependency_tree() {
        let snapshot = build("lockfiles/v1_basic.json", false).expect("v1 parses");
        assert_eq!(snapshot.packages.len(), 3);
        assert!(snapshot.build_errors.is_empty());
        assert_eq!(snapshot.confidence, 1.0);
        let lodash = snapshot
            .packages
            .iter()
            .find(|node| node.name == "lodash")
            .expect("lodash present");
        assert_eq!(lodash.version, "4.17.4");
        assert!(lodash.direct);
    }

    #[test]
    fn parses_v2_and_excludes_dev_dependencies_by_default() {
        let snapshot = build("lockfiles/v2_with_dev.json", false).expect("v2 parses");
        let names: Vec<&str> = snapshot.packages.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"lodash"));
        assert!(names.contains(&"chalk"));
        assert!(!names.contains(&"jest"), "dev deps excluded by default");
        let lodash = snapshot
            .packages
            .iter()
            .find(|n| n.name == "lodash")
            .expect("lodash");
        assert_eq!(lodash.license.as_deref(), Some("MIT"));
        assert!(lodash.direct);
    }

    #[test]
    fn v2_includes_dev_dependencies_when_requested() {
        let snapshot = build("lockfiles/v2_with_dev.json", true).expect("v2 parses");
        let names: Vec<&str> = snapshot.packages.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"jest"));
        let jest = snapshot
            .packages
            .iter()
            .find(|n| n.name == "jest")
            .expect("jest");
        assert!(jest.direct, "jest is a root devDependency");
    }

    #[test]
    fn parses_v3_nested_node_modules_paths() {
        let snapshot = build("lockfiles/v3_nested.json", false).expect("v3 parses");
        let debug = snapshot
            .packages
            .iter()
            .find(|node| node.name == "debug")
            .expect("nested debug present");
        assert_eq!(debug.version, "2.6.9");
        assert!(!debug.direct, "nested transitive is not direct");
        let express = snapshot
            .packages
            .iter()
            .find(|node| node.name == "express")
            .expect("express present");
        assert!(express.direct);
        assert!(express.dependencies.contains(&"debug".to_string()));
    }

    #[test]
    fn corrupted_lockfile_is_fatal() {
        let result = build("lockfiles/corrupted.json", false);
        assert!(matches!(result, Err(SkillError::InvalidInput(_))));
    }

    #[test]
    fn unsupported_format_is_fatal() {
        let result = build("lockfiles/unsupported_format.txt", false);
        assert!(
            matches!(result, Err(SkillError::InvalidInput(msg)) if msg.contains("unsupported"))
        );
    }

    #[test]
    fn empty_lockfile_yields_clean_empty_snapshot() {
        let snapshot = build("lockfiles/empty.json", false).expect("empty parses");
        assert!(snapshot.packages.is_empty());
        assert!(snapshot.build_errors.is_empty());
        assert_eq!(snapshot.confidence, 1.0);
    }

    #[test]
    fn missing_fields_yield_partial_snapshot_with_reduced_confidence() {
        let snapshot = build("lockfiles/missing_fields.json", false).expect("partial parse");
        assert!(!snapshot.build_errors.is_empty());
        assert_eq!(snapshot.confidence, 0.7);
        let lodash = snapshot
            .packages
            .iter()
            .find(|node| node.name == "lodash")
            .expect("lodash present despite missing version");
        assert_eq!(lodash.version, "");
        let mystery = snapshot
            .packages
            .iter()
            .find(|node| node.name == "mystery-pkg")
            .expect("mystery present");
        assert_eq!(mystery.license, None, "wrong-typed license becomes None");
    }

    #[test]
    fn missing_lockfile_file_is_fatal() {
        let skill = SbomBuildSkill;
        let result = skill.run(&SbomBuildInput {
            lockfile_path: String::new(),
            include_dev: false,
        });
        assert!(matches!(result, Err(SkillError::InvalidInput(_))));
    }

    #[test]
    fn sbom_id_is_deterministic_and_hex16() {
        let first = build("lockfiles/v3_nested.json", false).expect("parse");
        let second = build("lockfiles/v3_nested.json", false).expect("parse");
        assert_eq!(first.sbom_id, second.sbom_id);
        assert_eq!(first.sbom_id.len(), 16);
        assert!(first.sbom_id.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn demo_app_snapshot_has_expected_mix() {
        let snapshot = build("demo-app/package-lock.json", false).expect("demo-app parses");
        assert_eq!(snapshot.packages.len(), 6);
        assert!(snapshot.build_errors.is_empty());
        let lodos = snapshot
            .packages
            .iter()
            .find(|node| node.name == "lodos")
            .expect("lodos present");
        assert!(lodos.direct);
        assert_eq!(lodos.license, None);
    }

    #[test]
    fn snapshot_is_serializable() {
        let snapshot = build("lockfiles/v3_nested.json", false).expect("parse");
        let json = serde_json::to_string(&snapshot).expect("serialize");
        let back: SbomSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, snapshot);
    }

    #[test]
    fn skill_metadata_matches_design_card() {
        assert_eq!(SbomBuildSkill.name(), "sbom-build");
        assert!(!SbomBuildSkill.description().is_empty());
    }
}

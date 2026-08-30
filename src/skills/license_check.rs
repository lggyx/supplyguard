//! S05 `license-check`: license-policy conflict detection.
//!
//! Pure rule matching over a normalized license set: forbidden licenses are
//! hard violations; anything not explicitly allowed (or unknown to SPDX) is
//! routed to human confirmation instead of auto-blocked. `review_required`
//! gives risk fusion a single conservative flag covering both cases.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::Skill;
use crate::mcp::LicenseDb;

/// A dependency whose license is being checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageLicense {
    /// Package name.
    pub name: String,
    /// Package version (informational).
    #[serde(default)]
    pub version: String,
    /// Raw declared license, when the lockfile carries one.
    pub license: Option<String>,
}

/// An organization's allow/deny license policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LicensePolicy {
    /// Canonical SPDX ids explicitly allowed.
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Canonical SPDX ids explicitly forbidden.
    #[serde(default)]
    pub forbidden: Vec<String>,
    /// Policy document version.
    #[serde(default = "default_policy_version")]
    pub version: String,
}

fn default_policy_version() -> String {
    "1.0".to_string()
}

/// Input for `license-check`.
#[derive(Debug, Clone, Default)]
pub struct LicenseCheckInput {
    /// Packages to evaluate.
    pub packages: Vec<PackageLicense>,
    /// The organization policy to apply.
    pub project_license_policy: LicensePolicy,
}

/// One hard policy conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseViolation {
    /// Package that conflicts.
    pub package: String,
    /// Raw license string as declared.
    pub license: String,
    /// System-generated reason.
    pub reason: String,
}

/// Output of `license-check`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LicenseCheckOutput {
    /// True when no hard violations were found (unknown licenses still
    /// require confirmation and are reported separately).
    pub compatible: bool,
    /// Hard policy conflicts.
    pub violations: Vec<LicenseViolation>,
    /// Packages whose license is missing or not explicitly allowed.
    pub unknown_licenses: Vec<PackageLicense>,
    /// Single conservative flag: human review is required.
    pub review_required: bool,
    /// Policy document version applied.
    pub policy_version: String,
}

/// The `license-check` skill.
pub struct LicenseCheckSkill {
    license_db: Arc<dyn LicenseDb>,
}

impl LicenseCheckSkill {
    /// Creates the skill over any [`LicenseDb`] implementation.
    pub fn new(license_db: Arc<dyn LicenseDb>) -> Self {
        Self { license_db }
    }
}

impl Skill for LicenseCheckSkill {
    type Input = LicenseCheckInput;
    type Output = LicenseCheckOutput;

    fn name(&self) -> &'static str {
        "license-check"
    }

    fn description(&self) -> &'static str {
        "Detect license conflicts against an organization policy"
    }

    fn run(&self, input: &Self::Input) -> Result<Self::Output, super::SkillError> {
        let policy = &input.project_license_policy;
        let allowed: std::collections::BTreeSet<String> = policy
            .allowed
            .iter()
            .filter_map(|raw| self.license_db.normalize(raw))
            .collect();
        let forbidden: std::collections::BTreeSet<String> = policy
            .forbidden
            .iter()
            .filter_map(|raw| self.license_db.normalize(raw))
            .collect();

        let mut violations = Vec::new();
        let mut unknown = Vec::new();
        for package in &input.packages {
            let normalized = package
                .license
                .as_deref()
                .and_then(|raw| self.license_db.normalize(raw));
            let Some(normalized) = normalized else {
                unknown.push(package.clone());
                continue;
            };
            if forbidden.contains(&normalized) {
                violations.push(LicenseViolation {
                    package: package.name.clone(),
                    license: package.license.clone().unwrap_or_default(),
                    reason: format!(
                        "License '{}' ({}) is forbidden by policy.",
                        package.license.clone().unwrap_or_default(),
                        normalized
                    ),
                });
            } else if !allowed.contains(&normalized) {
                unknown.push(package.clone());
            }
        }

        let compatible = violations.is_empty();
        let review_required = !compatible || !unknown.is_empty();
        Ok(LicenseCheckOutput {
            compatible,
            violations,
            unknown_licenses: unknown,
            review_required,
            policy_version: policy.version.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mcp::SpdxLocal;

    const POLICY_JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/policies/license_policy.json"
    ));

    fn skill() -> LicenseCheckSkill {
        LicenseCheckSkill::new(Arc::new(SpdxLocal::new().expect("spdx builds")))
    }

    fn fixture_policy() -> LicensePolicy {
        serde_json::from_str(POLICY_JSON).expect("policy fixture parses")
    }

    fn packages(list: &[(&str, &str, Option<&str>)]) -> Vec<PackageLicense> {
        list.iter()
            .map(|(name, version, license)| PackageLicense {
                name: (*name).to_string(),
                version: (*version).to_string(),
                license: license.map(|raw| raw.to_string()),
            })
            .collect()
    }

    #[test]
    fn permitted_licenses_pass_without_review() {
        let output = skill()
            .run(&LicenseCheckInput {
                packages: packages(&[
                    ("lodash", "4.17.21", Some("MIT")),
                    ("express", "4.17.3", Some("MIT")),
                    ("ansi-regex", "6.0.1", Some("isc")),
                ]),
                project_license_policy: fixture_policy(),
            })
            .expect("run");
        assert!(output.compatible);
        assert!(!output.review_required);
        assert!(output.violations.is_empty());
        assert!(output.unknown_licenses.is_empty());
        assert_eq!(output.policy_version, "1.0");
    }

    #[test]
    fn forbidden_license_is_a_violation_regardless_of_spelling() {
        let output = skill()
            .run(&LicenseCheckInput {
                packages: packages(&[
                    ("gpl-example", "2.0.0", Some("GPL-3.0")),
                    ("legacy-gpl", "1.0.0", Some("gpl-3.0")),
                ]),
                project_license_policy: fixture_policy(),
            })
            .expect("run");
        assert!(!output.compatible);
        assert!(output.review_required);
        assert_eq!(output.violations.len(), 2);
        assert!(output.violations[0].reason.contains("forbidden by policy"));
    }

    #[test]
    fn expression_resolves_to_conservative_first_arm() {
        let output = skill()
            .run(&LicenseCheckInput {
                packages: packages(&[("dual", "1.0.0", Some("(GPL-3.0 OR MIT)"))]),
                project_license_policy: fixture_policy(),
            })
            .expect("run");
        assert!(!output.compatible, "first arm GPL-3.0 is forbidden");
    }

    #[test]
    fn unknown_license_needs_human_confirmation_not_autoblock() {
        let output = skill()
            .run(&LicenseCheckInput {
                packages: packages(&[
                    ("mystery", "1.0.0", Some("SuperLicense-9.9")),
                    ("bare", "2.0.0", None),
                ]),
                project_license_policy: fixture_policy(),
            })
            .expect("run");
        assert!(output.compatible, "unknown is not a hard violation");
        assert!(output.review_required);
        assert_eq!(output.unknown_licenses.len(), 2);
        assert!(output.violations.is_empty());
    }

    #[test]
    fn unlisted_but_known_license_goes_to_review() {
        let output = skill()
            .run(&LicenseCheckInput {
                packages: packages(&[("odd", "1.0.0", Some("LGPL-2.1"))]),
                project_license_policy: fixture_policy(),
            })
            .expect("run");
        // LGPL-2.1 is a known SPDX id but neither allowed nor forbidden here.
        assert!(output.compatible);
        assert!(output.review_required);
        assert_eq!(output.unknown_licenses.len(), 1);
    }

    #[test]
    fn empty_package_list_is_compatible_and_review_free() {
        let output = skill()
            .run(&LicenseCheckInput {
                packages: Vec::new(),
                project_license_policy: fixture_policy(),
            })
            .expect("run");
        assert!(output.compatible);
        assert!(!output.review_required);
    }

    #[test]
    fn empty_policy_defaults_strict() {
        let output = skill()
            .run(&LicenseCheckInput {
                packages: packages(&[("lodash", "4.17.21", Some("MIT"))]),
                project_license_policy: LicensePolicy::default(),
            })
            .expect("run");
        assert!(output.compatible, "no forbidden list -> no violations");
        assert!(
            output.review_required,
            "strict: nothing is allowed up front"
        );
        assert_eq!(output.unknown_licenses.len(), 1);
    }

    #[test]
    fn output_is_serializable() {
        let output = skill()
            .run(&LicenseCheckInput {
                packages: packages(&[("gpl-example", "2.0.0", Some("GPL-3.0"))]),
                project_license_policy: fixture_policy(),
            })
            .expect("run");
        let json = serde_json::to_string(&output).expect("serialize");
        let back: LicenseCheckOutput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, output);
    }

    #[test]
    fn skill_metadata_matches_design_card() {
        assert_eq!(skill().name(), "license-check");
        assert!(!skill().description().is_empty());
    }
}

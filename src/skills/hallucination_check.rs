//! S03 `hallucination-check`: detect AI-hallucinated / typosquatted package
//! names.
//!
//! Strategy (heuristic, v1 — mirrors the Python reference):
//! 1. Does the package exist in the registry (via [`RegistryClient`])?
//! 2. If not, is there a very similar popular package (typosquatting)?
//! 3. If the registry is unreachable, degrade conservatively: known popular
//!    names pass with a `registry_error` marker (risk fusion escalates the
//!    session), typosquats are flagged, everything else goes to human review.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::Skill;
use crate::mcp::RegistryClient;

/// Popular npm package names used as the similarity reference set.
const POPULAR_NPM_PACKAGES: &[&str] = &[
    "lodash",
    "axios",
    "react",
    "express",
    "typescript",
    "next",
    "vue",
    "webpack",
    "jest",
    "prettier",
    "eslint",
    "moment",
    "date-fns",
    "commander",
    "chalk",
    "semver",
    "uuid",
    "dotenv",
    "jsonwebtoken",
    "bcrypt",
    "mongoose",
    "prisma",
    "zod",
    "tailwindcss",
    "@types/node",
];

/// Similarity cutoff mirroring `difflib.get_close_matches(..., cutoff=0.7)`.
const CLOSE_MATCH_CUTOFF: f64 = 0.7;

/// Maximum number of suggested alternatives.
const MAX_ALTERNATIVES: usize = 3;

/// Input for `hallucination-check`.
#[derive(Debug, Clone, Default)]
pub struct HallucinationCheckInput {
    /// Candidate package name to evaluate.
    pub candidate_package_name: String,
    /// Untrusted context text; only its hash is retained.
    pub context_text: String,
    /// Package ecosystem; v1 only supports `npm`.
    pub ecosystem: String,
}

/// Structured evidence for the hallucination verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HallucinationEvidence {
    /// `Some(true/false)` when the registry answered; `None` when unreachable.
    pub registry_exists: Option<bool>,
    /// True when the registry could not be consulted (degradation marker).
    pub registry_error: bool,
    /// True when the offline popular-name fallback was used.
    pub local_fallback: bool,
    /// Similar popular package names (possible typosquat targets).
    pub similar_popular_packages: Vec<String>,
    /// Non-reversible fingerprint of the untrusted context text.
    pub context_text_hash: String,
}

/// Output of `hallucination-check`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HallucinationCheckOutput {
    /// True when the package is a hallucination / typosquat risk.
    pub is_hallucination_risk: bool,
    /// System-generated reasoning (never contains untrusted raw text).
    pub reasoning: String,
    /// Suggested replacements (similar popular packages).
    pub recommended_alternatives: Vec<String>,
    /// Structured evidence.
    pub evidence: HallucinationEvidence,
}

/// The `hallucination-check` skill.
pub struct HallucinationCheckSkill {
    registry: Arc<dyn RegistryClient>,
}

impl HallucinationCheckSkill {
    /// Creates the skill over any [`RegistryClient`] implementation.
    pub fn new(registry: Arc<dyn RegistryClient>) -> Self {
        Self { registry }
    }
}

impl Skill for HallucinationCheckSkill {
    type Input = HallucinationCheckInput;
    type Output = HallucinationCheckOutput;

    fn name(&self) -> &'static str {
        "hallucination-check"
    }

    fn description(&self) -> &'static str {
        "Detect AI-hallucinated or typosquatted package names"
    }

    fn run(&self, input: &Self::Input) -> Result<Self::Output, super::SkillError> {
        let name = input.candidate_package_name.as_str();
        let context_hash = fingerprint(&input.context_text);
        match self.registry.exists(name) {
            Ok(true) => Ok(HallucinationCheckOutput {
                is_hallucination_risk: false,
                reasoning: format!("Package '{name}' exists in npm registry."),
                recommended_alternatives: Vec::new(),
                evidence: HallucinationEvidence {
                    registry_exists: Some(true),
                    registry_error: false,
                    local_fallback: false,
                    similar_popular_packages: close_matches(name),
                    context_text_hash: context_hash,
                },
            }),
            Ok(false) => {
                let similar = close_matches(name);
                let mut reasoning = format!("Package '{name}' was not found in npm registry.");
                let alternatives = if similar.is_empty() {
                    reasoning.push_str(" No close popular match found; likely LLM hallucination.");
                    Vec::new()
                } else {
                    reasoning.push_str(&format!(
                        " It closely resembles popular package(s): {}. Possible \
                         typosquatting or LLM hallucination.",
                        similar.join(", ")
                    ));
                    similar.clone()
                };
                Ok(HallucinationCheckOutput {
                    is_hallucination_risk: true,
                    reasoning,
                    recommended_alternatives: alternatives,
                    evidence: HallucinationEvidence {
                        registry_exists: Some(false),
                        registry_error: false,
                        local_fallback: false,
                        similar_popular_packages: similar,
                        context_text_hash: context_hash,
                    },
                })
            }
            Err(_) => {
                // Registry unreachable: conservative offline fallback.
                let similar = close_matches(name);
                let is_known_popular = POPULAR_NPM_PACKAGES.contains(&name);
                let risk = !similar.is_empty() && !is_known_popular;
                let (reasoning, alternatives) = if risk {
                    (
                        format!(
                            "Registry unreachable; local popular-package fallback found \
                             a likely typo of: {}. Possible typosquatting or LLM \
                             hallucination.",
                            similar.join(", ")
                        ),
                        similar.clone(),
                    )
                } else {
                    (
                        "Registry unreachable; fail-safe policy requires human review.".to_string(),
                        Vec::new(),
                    )
                };
                Ok(HallucinationCheckOutput {
                    is_hallucination_risk: risk,
                    reasoning,
                    recommended_alternatives: alternatives,
                    evidence: HallucinationEvidence {
                        registry_exists: None,
                        registry_error: true,
                        local_fallback: true,
                        similar_popular_packages: similar,
                        context_text_hash: context_hash,
                    },
                })
            }
        }
    }
}

/// Returns up to 3 popular names whose difflib-style ratio with `name` is
/// at least 0.7, sorted by descending similarity (ties: name order).
fn close_matches(name: &str) -> Vec<String> {
    let mut scored: Vec<(f64, &str)> = POPULAR_NPM_PACKAGES
        .iter()
        .filter(|popular| **popular != name)
        .map(|popular| (similarity_ratio(name, popular), *popular))
        .filter(|(ratio, _)| *ratio >= CLOSE_MATCH_CUTOFF)
        .collect();
    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.cmp(b.1))
    });
    scored.truncate(MAX_ALTERNATIVES);
    scored
        .into_iter()
        .map(|(_, popular)| popular.to_string())
        .collect()
}

/// difflib-style similarity ratio: `2*M / (len_a + len_b)` where `M` is the
/// total length of all matching blocks (recursive longest common substring).
fn similarity_ratio(a: &str, b: &str) -> f64 {
    let total = a.chars().count() + b.chars().count();
    if total == 0 {
        return 1.0;
    }
    let matched = total_matching_chars(a, b);
    (2.0 * matched as f64) / total as f64
}

/// Recursively sums matching-block lengths, mirroring SequenceMatcher.
fn total_matching_chars(a: &str, b: &str) -> usize {
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    let (best_i, best_j, best_len) = longest_common_block(a, b);
    if best_len == 0 {
        return 0;
    }
    let left = (a[..best_i].to_string(), b[..best_j].to_string());
    let right = (
        a[best_i + best_len..].to_string(),
        b[best_j + best_len..].to_string(),
    );
    best_len + total_matching_chars(&left.0, &left.1) + total_matching_chars(&right.0, &right.1)
}

/// Finds the longest common contiguous block via a simple DP table.
/// Returns `(index_in_a, index_in_b, length)`; first-best on ties.
fn longest_common_block(a: &str, b: &str) -> (usize, usize, usize) {
    let av: Vec<char> = a.chars().collect();
    let bv: Vec<char> = b.chars().collect();
    let mut best = (0usize, 0usize, 0usize);
    let mut table = vec![vec![0usize; bv.len() + 1]; av.len() + 1];
    for i in 0..av.len() {
        for j in 0..bv.len() {
            if av[i] == bv[j] {
                table[i + 1][j + 1] = table[i][j] + 1;
                if table[i + 1][j + 1] > best.2 {
                    best = (
                        i + 1 - table[i + 1][j + 1],
                        j + 1 - table[i + 1][j + 1],
                        table[i + 1][j + 1],
                    );
                }
            }
        }
    }
    best
}

/// Stable, non-reversible 16-hex fingerprint for untrusted text.
fn fingerprint(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let out = hasher.finalize();
    hex::encode(&out[..8])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::mcp::{McpError, RegistryClient};

    struct MockRegistry {
        result: Result<bool, McpError>,
    }

    impl RegistryClient for MockRegistry {
        fn exists(&self, _package_name: &str) -> Result<bool, McpError> {
            self.result.clone()
        }
    }

    fn skill(result: Result<bool, McpError>) -> HallucinationCheckSkill {
        HallucinationCheckSkill::new(Arc::new(MockRegistry { result }))
    }

    fn check(skill: &HallucinationCheckSkill, name: &str) -> HallucinationCheckOutput {
        skill
            .run(&HallucinationCheckInput {
                candidate_package_name: name.to_string(),
                context_text: "import { cloneDeep } from 'secret-context-marker';".to_string(),
                ecosystem: "npm".to_string(),
            })
            .expect("hallucination check degrades, never fails")
    }

    #[test]
    fn existing_package_is_not_a_risk() {
        let output = check(&skill(Ok(true)), "lodash");
        assert!(!output.is_hallucination_risk);
        assert!(output.recommended_alternatives.is_empty());
        assert_eq!(output.evidence.registry_exists, Some(true));
        assert!(!output.evidence.registry_error);
    }

    #[test]
    fn typosquat_of_popular_package_is_flagged_with_alternative() {
        let output = check(&skill(Ok(false)), "lodos");
        assert!(output.is_hallucination_risk);
        assert_eq!(output.recommended_alternatives, vec!["lodash".to_string()]);
        assert!(
            output
                .reasoning
                .contains("typosquatting or LLM hallucination")
        );
    }

    #[test]
    fn unrelated_unknown_package_is_flagged_without_alternatives() {
        let output = check(&skill(Ok(false)), "zzzqqq-xyz-plugh");
        assert!(output.is_hallucination_risk);
        assert!(output.recommended_alternatives.is_empty());
        assert!(output.reasoning.contains("likely LLM hallucination"));
    }

    #[test]
    fn offline_fallback_allows_known_popular_but_marks_registry_error() {
        let output = check(
            &skill(Err(McpError::Unavailable("offline".into()))),
            "lodash",
        );
        assert!(!output.is_hallucination_risk);
        assert!(output.evidence.registry_error);
        assert!(output.evidence.local_fallback);
        assert!(
            output
                .reasoning
                .contains("fail-safe policy requires human review")
        );
    }

    #[test]
    fn offline_fallback_flags_typosquat_with_alternatives() {
        let output = check(
            &skill(Err(McpError::Unavailable("offline".into()))),
            "lodos",
        );
        assert!(output.is_hallucination_risk);
        assert_eq!(output.recommended_alternatives, vec!["lodash".to_string()]);
        assert!(output.reasoning.contains("likely typo of: lodash"));
    }

    #[test]
    fn offline_fallback_routes_unknown_names_to_human_review() {
        let output = check(
            &skill(Err(McpError::Unavailable("offline".into()))),
            "zzzqqq-xyz-plugh",
        );
        assert!(
            !output.is_hallucination_risk,
            "risk fusion escalates via registry_error"
        );
        assert!(output.evidence.registry_error);
        assert!(output.reasoning.contains("human review"));
    }

    #[test]
    fn untrusted_context_is_fingerprinted_never_echoed() {
        let output = check(&skill(Ok(false)), "lodos");
        assert_eq!(output.evidence.context_text_hash.len(), 16);
        assert!(
            output
                .evidence
                .context_text_hash
                .chars()
                .all(|ch| ch.is_ascii_hexdigit())
        );
        let json = serde_json::to_string(&output).expect("serialize");
        assert!(
            !json.contains("secret-context-marker"),
            "raw context must not leak"
        );
    }

    #[test]
    fn context_hash_differs_for_different_contexts() {
        let skill = skill(Ok(true));
        let first = skill
            .run(&HallucinationCheckInput {
                candidate_package_name: "lodash".to_string(),
                context_text: "one".to_string(),
                ecosystem: "npm".to_string(),
            })
            .expect("ok");
        let second = skill
            .run(&HallucinationCheckInput {
                candidate_package_name: "lodash".to_string(),
                context_text: "two".to_string(),
                ecosystem: "npm".to_string(),
            })
            .expect("ok");
        assert_ne!(
            first.evidence.context_text_hash,
            second.evidence.context_text_hash
        );
    }

    #[test]
    fn similarity_ratio_matches_difflib_semantics() {
        assert!((similarity_ratio("lodos", "lodash") - 8.0 / 11.0).abs() < 1e-9);
        assert!((similarity_ratio("lodash", "lodash") - 1.0).abs() < 1e-9);
        assert!(similarity_ratio("zzzqqq-xyz-plugh", "lodash") < CLOSE_MATCH_CUTOFF);
        assert!(similarity_ratio("express", "react") < CLOSE_MATCH_CUTOFF);
    }

    #[test]
    fn close_matches_respect_cutoff_count_and_ordering() {
        let matches = close_matches("lodos");
        assert_eq!(matches.first().map(String::as_str), Some("lodash"));
        assert!(matches.len() <= MAX_ALTERNATIVES);
        assert!(close_matches("zzzqqq-xyz-plugh").is_empty());
    }

    #[test]
    fn output_is_serializable() {
        let output = check(&skill(Ok(false)), "lodos");
        let json = serde_json::to_string(&output).expect("serialize");
        let back: HallucinationCheckOutput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, output);
    }

    #[test]
    fn skill_metadata_matches_design_card() {
        let skill = skill(Ok(true));
        assert_eq!(skill.name(), "hallucination-check");
        assert!(!skill.description().is_empty());
    }
}

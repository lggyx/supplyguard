//! Inter-agent message types (the five-type protocol) plus shared enums.

use crate::models::ids::{SessionId, TimestampMillis};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Where a task originates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    /// GitHub pull-request event.
    #[serde(rename = "github_pr")]
    GitHubPr,
    /// GitLab merge-request event.
    #[serde(rename = "gitlab_pr")]
    GitLabPr,
    /// OSV vulnerability feed event (response mode; backlog).
    OsvFeed,
    /// GitHub Security Advisory feed event (response mode; backlog).
    GhsaFeed,
    /// Locally triggered scan.
    Manual,
}

/// Aggregate risk assessment produced by the fusion rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Highest risk: meta-attack or hallucinated package.
    Critical,
    /// High: critical CVE signal or policy violation path.
    High,
    /// Medium: elevated but not blocking signals.
    Medium,
    /// Low: benign with minor signals.
    Low,
    /// No signals at all.
    Safe,
}

/// Final decision issued by the Auditor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Change is safe to proceed.
    Allow,
    /// Change is rejected.
    Block,
    /// A human must review before the change proceeds.
    RequireHumanReview,
}

/// Action the fusion rules recommend for a risk profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    /// Reject the dependency change.
    Block,
    /// Escalate to human review.
    Review,
    /// Proceed without further action.
    Allow,
    /// Apply an automated remediation first.
    Remediate,
}

/// Remediation strategy attached to a remediation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemediationStrategy {
    /// Upgrade the dependency to a fixed version.
    BumpVersion,
    /// Replace the dependency with an alternative package.
    SwapDependency,
    /// Only report; no repository mutation.
    CommentOnly,
    /// Quarantine the package.
    Quarantine,
}

/// One dependency change detected in a diff, lockfile, or event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DependencyChange {
    /// Package name (npm scope included, e.g. `@scope/name`).
    pub package_name: String,
    /// Previous version, when this is an upgrade.
    #[serde(default)]
    pub old_version: Option<String>,
    /// Newly requested version.
    #[serde(default)]
    pub new_version: Option<String>,
    /// True when the package is newly introduced.
    #[serde(default)]
    pub is_new: bool,
    /// Package ecosystem; v1 only supports `npm`.
    #[serde(default = "default_ecosystem")]
    pub ecosystem: String,
    /// Untrusted context text; Sentinel wraps it in boundary markers.
    #[serde(default)]
    pub context_text: String,
}

fn default_ecosystem() -> String {
    "npm".to_string()
}

/// Sentinel -> Analyst payload: a task to analyze.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisRequest {
    /// Session this request belongs to.
    pub session_id: SessionId,
    /// Entry mode of the event.
    pub source: EventSource,
    /// Repository URL or local file URI.
    pub repo_url: String,
    /// Commit SHA or `local-working-tree` for local scans.
    pub commit_sha: String,
    /// Dependency changes to analyze.
    pub changes: Vec<DependencyChange>,
    /// Creation time (ms since epoch).
    pub created_at: TimestampMillis,
}

/// A piece of evidence with provenance; consumed by Auditor and audit chain.
///
/// `summary` is system-generated reasoning, never untrusted raw text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Skill that produced the evidence.
    pub skill: String,
    /// Data source behind the skill (e.g. `osv`, `npm-registry`).
    pub source: String,
    /// System-generated summary of the finding.
    pub summary: String,
    /// Confidence in `[0.0, 1.0]`.
    pub confidence: f64,
    /// Non-reversible fingerprint of the underlying raw input.
    pub raw_fingerprint: String,
}

/// Analyst -> Auditor payload: fused multi-signal risk assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskProfile {
    /// Session this profile belongs to.
    pub session_id: SessionId,
    /// Fused risk level.
    pub risk_level: RiskLevel,
    /// Recommended action derived from the fusion rules.
    pub recommended_action: RecommendedAction,
    /// Ordered evidence chain (one entry per signal).
    pub evidence_chain: Vec<Evidence>,
    /// Reasons why human review is required (empty when none).
    #[serde(default)]
    pub human_review_reasons: Vec<String>,
    /// Creation time (ms since epoch).
    pub generated_at: TimestampMillis,
}

/// Auditor -> Remediator payload: what to do about a risk profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemediationOrder {
    /// Session this order belongs to.
    pub session_id: SessionId,
    /// Arbitrated verdict.
    pub verdict: Verdict,
    /// The risk profile the verdict was derived from.
    pub risk_profile: RiskProfile,
    /// Remediation strategy to apply.
    pub strategy: RemediationStrategy,
    /// Human-readable arbitration notes (system-generated).
    #[serde(default)]
    pub notes: String,
}

/// Remediator -> Auditor payload: outcome of a remediation order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemediationResult {
    /// Session this result belongs to.
    pub session_id: SessionId,
    /// Whether the remediation completed successfully.
    pub success: bool,
    /// Structured artifacts (action taken, comment body reference, ...).
    #[serde(default)]
    pub artifacts: BTreeMap<String, serde_json::Value>,
    /// Hash of the produced artifacts, sealed into the audit chain.
    #[serde(default)]
    pub logs_hash: String,
    /// Whether sandbox validation detected a regression (None = not run).
    #[serde(default)]
    pub regression_detected: Option<bool>,
    /// Completion time (ms since epoch).
    pub completed_at: TimestampMillis,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::models::session::SessionState;

    fn sample_change() -> DependencyChange {
        DependencyChange {
            package_name: "lodos".to_string(),
            old_version: None,
            new_version: Some("^1.0.0".to_string()),
            is_new: true,
            ecosystem: "npm".to_string(),
            context_text: "<untrusted_source>\nimport x from 'lodos'\n</untrusted_source>"
                .to_string(),
        }
    }

    fn sample_request() -> AnalysisRequest {
        AnalysisRequest {
            session_id: SessionId::new("s-1"),
            source: EventSource::GitHubPr,
            repo_url: "https://github.com/acme/demo-app".to_string(),
            commit_sha: "deadbeef".to_string(),
            changes: vec![sample_change()],
            created_at: TimestampMillis::now(),
        }
    }

    fn sample_profile() -> RiskProfile {
        RiskProfile {
            session_id: SessionId::new("s-1"),
            risk_level: RiskLevel::Critical,
            recommended_action: RecommendedAction::Block,
            evidence_chain: vec![Evidence {
                skill: "hallucination-check".to_string(),
                source: "npm-registry".to_string(),
                summary: "package not found; resembles lodash".to_string(),
                confidence: 0.9,
                raw_fingerprint: "0123456789abcdef".to_string(),
            }],
            human_review_reasons: vec![
                "Hallucinated or typosquatted package detected.".to_string(),
            ],
            generated_at: TimestampMillis::now(),
        }
    }

    fn roundtrip<
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    >(
        value: &T,
    ) -> T {
        let json = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    #[test]
    fn analysis_request_survives_roundtrip() {
        let request = sample_request();
        let back = roundtrip(&request);
        assert_eq!(back, request);
    }

    #[test]
    fn risk_profile_survives_roundtrip() {
        let profile = sample_profile();
        let back = roundtrip(&profile);
        assert_eq!(back, profile);
    }

    #[test]
    fn remediation_order_and_result_survive_roundtrip() {
        let profile = sample_profile();
        let order = RemediationOrder {
            session_id: SessionId::new("s-1"),
            verdict: Verdict::RequireHumanReview,
            risk_profile: profile.clone(),
            strategy: RemediationStrategy::BumpVersion,
            notes: "Verdict: require_human_review.".to_string(),
        };
        let result = RemediationResult {
            session_id: SessionId::new("s-1"),
            success: true,
            artifacts: BTreeMap::from([(
                "action_taken".to_string(),
                serde_json::json!("created_upgrade_pr"),
            )]),
            logs_hash: "sha256:abcd".to_string(),
            regression_detected: Some(false),
            completed_at: TimestampMillis::now(),
        };
        assert_eq!(roundtrip(&order), order);
        assert_eq!(roundtrip(&result), result);
    }

    #[test]
    fn dependency_change_defaults_fill_ecosystem_and_context() {
        let json = r#"{"package_name": "lodash", "new_version": "4.17.21", "is_new": false}"#;
        let change: DependencyChange = serde_json::from_str(json).expect("deserialize");
        assert_eq!(change.ecosystem, "npm");
        assert_eq!(change.context_text, "");
        assert_eq!(change.old_version, None);
    }

    #[test]
    fn enums_serialize_with_python_compatible_values() {
        assert_eq!(
            serde_json::to_string(&EventSource::GitHubPr).expect("serialize"),
            "\"github_pr\""
        );
        assert_eq!(
            serde_json::to_string(&Verdict::RequireHumanReview).expect("serialize"),
            "\"require_human_review\""
        );
        assert_eq!(
            serde_json::to_string(&RemediationStrategy::BumpVersion).expect("serialize"),
            "\"bump-version\""
        );
        assert_eq!(
            serde_json::to_string(&RiskLevel::Critical).expect("serialize"),
            "\"critical\""
        );
    }

    #[test]
    fn risk_profile_json_keys_match_protocol() {
        let profile = sample_profile();
        let json = serde_json::to_value(&profile).expect("to value");
        let obj = json.as_object().expect("object");
        for key in [
            "session_id",
            "risk_level",
            "recommended_action",
            "evidence_chain",
            "human_review_reasons",
            "generated_at",
        ] {
            assert!(obj.contains_key(key), "missing key {key}");
        }
        // Session state machine stays independent of message serialization.
        assert!(SessionState::Received.can_transition_to(SessionState::Analyzing));
    }
}

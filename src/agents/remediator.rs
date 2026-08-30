//! Remediator: remediation artifact generation (no repository writes).

use crate::models::ids::TimestampMillis;
use crate::models::messages::{RemediationOrder, RemediationResult, RemediationStrategy, Verdict};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Remediator agent: turns a remediation order into structured artifacts.
///
/// v1 produces advisory artifacts only (blocking comment text, upgrade-branch
/// names); it holds no git, no filesystem, and no network tools, so it can
/// never merge or push (decision/execution separation, onion L4).
#[derive(Debug, Clone, Default)]
pub struct Remediator;

impl Remediator {
    /// Executes a remediation order and reports what would happen.
    pub fn handle(&self, order: &RemediationOrder) -> RemediationResult {
        let mut artifacts: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        artifacts.insert(
            "verdict".to_string(),
            serde_json::json!(match order.verdict {
                Verdict::Allow => "allow",
                Verdict::Block => "block",
                Verdict::RequireHumanReview => "require_human_review",
            }),
        );
        artifacts.insert(
            "strategy".to_string(),
            serde_json::json!(match order.strategy {
                RemediationStrategy::BumpVersion => "bump-version",
                RemediationStrategy::SwapDependency => "swap-dependency",
                RemediationStrategy::CommentOnly => "comment-only",
                RemediationStrategy::Quarantine => "quarantine",
            }),
        );
        artifacts.insert("notes".to_string(), serde_json::json!(order.notes));
        artifacts.insert(
            "packages".to_string(),
            serde_json::json!(
                order
                    .risk_profile
                    .evidence_chain
                    .iter()
                    .map(|evidence| serde_json::json!({
                        "skill": evidence.skill,
                        "evidence": evidence.summary,
                    }))
                    .collect::<Vec<_>>()
            ),
        );

        let action_taken = match order.verdict {
            Verdict::Block => {
                artifacts.insert(
                    "comment_body".to_string(),
                    serde_json::json!(blocking_comment(order)),
                );
                "wrote_blocking_comment".to_string()
            }
            Verdict::RequireHumanReview if order.strategy == RemediationStrategy::BumpVersion => {
                artifacts.insert(
                    "pr_branch".to_string(),
                    serde_json::json!(format!(
                        "supplyguard/remediate-{}",
                        order.session_id.as_str()
                    )),
                );
                "created_upgrade_pr".to_string()
            }
            _ => "no_action_required".to_string(),
        };
        artifacts.insert("action_taken".to_string(), serde_json::json!(action_taken));
        let logs_hash = artifacts_hash(&artifacts);

        RemediationResult {
            session_id: order.session_id.clone(),
            success: true,
            artifacts,
            logs_hash,
            regression_detected: Some(false),
            completed_at: TimestampMillis::now(),
        }
    }
}

/// Builds the human-facing blocking comment (system-generated text only).
fn blocking_comment(order: &RemediationOrder) -> String {
    let evidence: Vec<String> = order
        .risk_profile
        .evidence_chain
        .iter()
        .map(|evidence| format!("- {}: {}", evidence.skill, evidence.summary))
        .collect();
    format!(
        "> ⚠️ SupplyGuard blocked this dependency change.\n\n{}\n\nEvidence:\n{}",
        order.notes,
        evidence.join("\n")
    )
}

/// Hash prefix for the artifacts map, sealed into the audit chain.
fn artifacts_hash(artifacts: &BTreeMap<String, serde_json::Value>) -> String {
    let encoded = serde_json::to_vec(artifacts).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&encoded);
    format!("sha256:{}", hex::encode(&hasher.finalize()[..8]))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::models::ids::SessionId;
    use crate::models::messages::RiskProfile;

    fn order(verdict: Verdict, strategy: RemediationStrategy) -> RemediationOrder {
        RemediationOrder {
            session_id: SessionId::new("s-rem"),
            verdict,
            risk_profile: RiskProfile {
                session_id: SessionId::new("s-rem"),
                risk_level: crate::models::messages::RiskLevel::Critical,
                recommended_action: crate::models::messages::RecommendedAction::Block,
                evidence_chain: vec![crate::models::messages::Evidence {
                    skill: "hallucination-check".to_string(),
                    source: "npm-registry".to_string(),
                    summary: "package resembles lodash".to_string(),
                    confidence: 0.9,
                    raw_fingerprint: "0123456789abcdef".to_string(),
                }],
                human_review_reasons: vec![
                    "Hallucinated or typosquatted package detected.".to_string(),
                ],
                generated_at: TimestampMillis::now(),
            },
            strategy,
            notes: "Verdict: block. Reasons: Hallucinated or typosquatted package detected."
                .to_string(),
        }
    }

    #[test]
    fn block_order_produces_blocking_comment_artifacts() {
        let result = Remediator.handle(&order(Verdict::Block, RemediationStrategy::CommentOnly));
        assert!(result.success);
        assert_eq!(
            result
                .artifacts
                .get("action_taken")
                .and_then(serde_json::Value::as_str),
            Some("wrote_blocking_comment")
        );
        let comment = result
            .artifacts
            .get("comment_body")
            .and_then(serde_json::Value::as_str)
            .expect("comment body");
        assert!(comment.contains("blocked this dependency change"));
        assert!(comment.contains("hallucination-check"));
    }

    #[test]
    fn remediate_order_produces_upgrade_branch_artifact() {
        let result = Remediator.handle(&order(
            Verdict::RequireHumanReview,
            RemediationStrategy::BumpVersion,
        ));
        assert_eq!(
            result
                .artifacts
                .get("action_taken")
                .and_then(serde_json::Value::as_str),
            Some("created_upgrade_pr")
        );
        assert_eq!(
            result
                .artifacts
                .get("pr_branch")
                .and_then(serde_json::Value::as_str),
            Some("supplyguard/remediate-s-rem")
        );
    }

    #[test]
    fn allow_order_requires_no_action() {
        let result = Remediator.handle(&order(Verdict::Allow, RemediationStrategy::CommentOnly));
        assert_eq!(
            result
                .artifacts
                .get("action_taken")
                .and_then(serde_json::Value::as_str),
            Some("no_action_required")
        );
    }

    #[test]
    fn logs_hash_is_deterministic_and_prefixed() {
        let first = Remediator.handle(&order(Verdict::Block, RemediationStrategy::CommentOnly));
        let second = Remediator.handle(&order(Verdict::Block, RemediationStrategy::CommentOnly));
        assert_eq!(first.logs_hash, second.logs_hash);
        assert!(first.logs_hash.starts_with("sha256:"));
    }

    #[test]
    fn artifacts_never_contain_untrusted_raw_text() {
        let result = Remediator.handle(&order(Verdict::Block, RemediationStrategy::CommentOnly));
        let json = serde_json::to_string(&result.artifacts).expect("serialize");
        assert!(!json.contains("<untrusted_source>"));
        assert!(!json.contains("raw diff"));
    }
}

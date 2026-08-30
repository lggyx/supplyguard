//! Auditor: decision arbiter and audit-chain writer.

use crate::audit::{AgentAction, AppendInput, AuditChain};
use crate::models::ids::SessionId;
use crate::models::messages::{
    RecommendedAction, RemediationOrder, RemediationResult, RemediationStrategy, RiskProfile,
    Verdict,
};
use sha2::{Digest, Sha256};

/// Auditor agent: converts risk profiles into verdicts and seals every
/// decision into the append-only audit chain.
///
/// The auditor's inputs are [`RiskProfile`] and [`RemediationResult`] —
/// structured evidence only; no untrusted raw text can reach it by
/// construction (onion L5).
pub struct Auditor {
    audit_chain: std::sync::Arc<AuditChain>,
}

/// Verdict plus the remediation order the auditor issues.
#[derive(Debug, Clone)]
pub struct Arbitration {
    /// Arbitrated verdict.
    pub verdict: Verdict,
    /// Order for the remediator (carries the risk profile).
    pub order: RemediationOrder,
}

impl Auditor {
    /// Creates the auditor over the shared audit chain.
    pub fn new(audit_chain: std::sync::Arc<AuditChain>) -> Self {
        Self { audit_chain }
    }

    /// Arbitrates a risk profile into a verdict, appending the decision to
    /// the audit chain.
    ///
    /// Mapping (Python parity): `block` -> Block; `remediate`/`review` ->
    /// RequireHumanReview (auto-remediation is high-risk); `allow` -> Allow.
    ///
    /// # Errors
    ///
    /// Returns [`crate::audit::AuditError`] when the audit append fails;
    /// callers must not close the session without a sealed verdict.
    pub fn arbitrate(
        &self,
        risk_profile: &RiskProfile,
    ) -> Result<Arbitration, crate::audit::AuditError> {
        let verdict = match risk_profile.recommended_action {
            RecommendedAction::Block => Verdict::Block,
            RecommendedAction::Remediate | RecommendedAction::Review => Verdict::RequireHumanReview,
            RecommendedAction::Allow => Verdict::Allow,
        };
        let strategy = match risk_profile.recommended_action {
            RecommendedAction::Remediate => RemediationStrategy::BumpVersion,
            RecommendedAction::Block | RecommendedAction::Review => {
                RemediationStrategy::CommentOnly
            }
            RecommendedAction::Allow => RemediationStrategy::CommentOnly,
        };

        let notes = format!(
            "Verdict: {}. Reasons: {}",
            serde_variant(&verdict),
            if risk_profile.human_review_reasons.is_empty() {
                "No issues".to_string()
            } else {
                risk_profile.human_review_reasons.join("; ")
            }
        );
        self.audit_chain.append(&AppendInput {
            session_id: risk_profile.session_id.to_string(),
            event: "verdict".to_string(),
            verdict: serde_variant(&verdict),
            evidence_hash: evidence_hash(risk_profile),
            summary: notes.clone(),
            agent_actions: vec![AgentAction {
                agent: "Auditor".to_string(),
                action: "arbitrate".to_string(),
            }],
        })?;

        Ok(Arbitration {
            verdict,
            order: RemediationOrder {
                session_id: risk_profile.session_id.clone(),
                verdict,
                risk_profile: risk_profile.clone(),
                strategy,
                notes,
            },
        })
    }

    /// Seals the session after remediation: appends the closing entry and
    /// verifies the full chain.
    ///
    /// # Errors
    ///
    /// Returns [`crate::audit::AuditError`] when the audit append fails.
    pub fn seal(&self, result: &RemediationResult) -> Result<SealReport, crate::audit::AuditError> {
        let action = result
            .artifacts
            .get("action_taken")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        self.audit_chain.append(&AppendInput {
            session_id: result.session_id.to_string(),
            event: "sealed".to_string(),
            verdict: String::new(),
            evidence_hash: result.logs_hash.clone(),
            summary: format!("session sealed after remediation ({action})"),
            agent_actions: vec![AgentAction {
                agent: "Remediator".to_string(),
                action,
            }],
        })?;
        let verification = self.audit_chain.verify()?;
        let head_hash = self.audit_chain.head_hash()?;
        Ok(SealReport {
            session_id: result.session_id.clone(),
            verified: verification.intact,
            head_hash: hex::encode(head_hash),
        })
    }
}

/// Outcome of sealing a session.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SealReport {
    /// Session that was sealed.
    pub session_id: SessionId,
    /// True when the whole audit chain verifies after the seal.
    pub verified: bool,
    /// Head hash of the audit chain (hex).
    pub head_hash: String,
}

/// Wire-format string for a verdict ("require_human_review" etc.).
fn serde_variant(verdict: &Verdict) -> String {
    serde_json::to_string(verdict)
        .map(|json| json.trim_matches('"').to_string())
        .unwrap_or_else(|_| format!("{verdict:?}"))
}

/// Evidence hash over all fingerprints in the profile.
fn evidence_hash(risk_profile: &RiskProfile) -> String {
    let mut hasher = Sha256::new();
    for evidence in &risk_profile.evidence_chain {
        hasher.update(evidence.raw_fingerprint.as_bytes());
    }
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::models::ids::TimestampMillis;
    use tempfile::TempDir;

    fn auditor() -> (Auditor, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let chain =
            AuditChain::open(&dir.path().join("audit.db"), b"test-key").expect("chain opens");
        (Auditor::new(std::sync::Arc::new(chain)), dir)
    }

    fn profile(action: RecommendedAction) -> RiskProfile {
        RiskProfile {
            session_id: SessionId::new("s-aud"),
            risk_level: crate::models::messages::RiskLevel::Critical,
            recommended_action: action,
            evidence_chain: vec![crate::models::messages::Evidence {
                skill: "cve-match".to_string(),
                source: "osv".to_string(),
                summary: "critical CVE".to_string(),
                confidence: 0.95,
                raw_fingerprint: "0123456789abcdef".to_string(),
            }],
            human_review_reasons: vec!["Critical CVE detected.".to_string()],
            generated_at: TimestampMillis::now(),
        }
    }

    #[test]
    fn block_action_maps_to_block_verdict() {
        let (auditor, _dir) = auditor();
        let arbitration = auditor
            .arbitrate(&profile(RecommendedAction::Block))
            .expect("arbitrate");
        assert_eq!(arbitration.verdict, Verdict::Block);
        assert_eq!(arbitration.order.strategy, RemediationStrategy::CommentOnly);
        assert!(arbitration.order.notes.contains("block"));
    }

    #[test]
    fn remediate_and_review_require_human_approval() {
        let (auditor, _dir) = auditor();
        for action in [RecommendedAction::Remediate, RecommendedAction::Review] {
            let arbitration = auditor.arbitrate(&profile(action)).expect("arbitrate");
            assert_eq!(arbitration.verdict, Verdict::RequireHumanReview);
        }
    }

    #[test]
    fn remediate_uses_bump_version_strategy() {
        let (auditor, _dir) = auditor();
        let arbitration = auditor
            .arbitrate(&profile(RecommendedAction::Remediate))
            .expect("arbitrate");
        assert_eq!(arbitration.order.strategy, RemediationStrategy::BumpVersion);
    }

    #[test]
    fn allow_action_maps_to_allow() {
        let (auditor, _dir) = auditor();
        let arbitration = auditor
            .arbitrate(&profile(RecommendedAction::Allow))
            .expect("arbitrate");
        assert_eq!(arbitration.verdict, Verdict::Allow);
    }

    #[test]
    fn arbitration_appends_verdict_entry_and_chain_verifies() {
        let (auditor, _dir) = auditor();
        auditor
            .arbitrate(&profile(RecommendedAction::Block))
            .expect("arbitrate");
        let entries = auditor.audit_chain.entries().expect("entries");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "verdict");
        assert_eq!(entries[0].verdict, "block");
        assert_eq!(entries[0].agent_actions[0].agent, "Auditor");
        let verification = auditor.audit_chain.verify().expect("verify");
        assert!(verification.intact);
    }

    #[test]
    fn evidence_hash_is_stable_hex() {
        let first = evidence_hash(&profile(RecommendedAction::Block));
        let second = evidence_hash(&profile(RecommendedAction::Block));
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn seal_appends_entry_and_reports_chain_integrity() {
        let (auditor, _dir) = auditor();
        let result = RemediationResult {
            session_id: SessionId::new("s-aud"),
            success: true,
            artifacts: std::collections::BTreeMap::from([(
                "action_taken".to_string(),
                serde_json::json!("wrote_blocking_comment"),
            )]),
            logs_hash: "sha256:abcd1234".to_string(),
            regression_detected: Some(false),
            completed_at: TimestampMillis::now(),
        };
        let seal = auditor.seal(&result).expect("seal");
        assert!(seal.verified);
        assert_eq!(seal.head_hash.len(), 64);
        let entries = auditor.audit_chain.entries().expect("entries");
        assert_eq!(entries[0].event, "sealed");
    }
}

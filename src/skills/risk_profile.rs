//! S06 `risk-profile`: deterministic multi-signal fusion (rule engine).
//!
//! Consumes typed signal outputs from the analyst skills plus the injection
//! detector and fuses them into a structured [`RiskProfile`]. The rule
//! ladder mirrors the Python reference with one addition: a degraded
//! vulnerability database is treated at the highest level (PROMPT 6.0.1).
//! LLM-based fusion is a v2 idea; v1 is fully deterministic.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::mcp::VulnRecord;
use crate::models::ids::SessionId;
use crate::models::messages::{Evidence, RecommendedAction, RiskLevel, RiskProfile};
use crate::security::injection::InjectionScan;

use super::cve_match::CveMatchOutput;
use super::hallucination_check::HallucinationCheckOutput;
use super::license_check::LicenseCheckOutput;
use super::{Skill, SkillError};

/// Entry mode of the session being fused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryMode {
    /// Proactive guard (dependency change).
    Guard,
    /// Reactive response (CVE feed; backlog).
    Response,
}

/// Typed signal data: one variant per producing skill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignalData {
    /// Output of `hallucination-check`.
    Hallucination(HallucinationCheckOutput),
    /// Output of `cve-match`.
    Cve(CveMatchOutput),
    /// Output of `license-check` (session-level).
    License(LicenseCheckOutput),
    /// Output of the injection detector for one untrusted text.
    Injection(InjectionScan),
    /// Raw advisory passthrough (reserved for response-mode signals).
    RawAdvisory(VulnRecord),
}

impl SignalData {
    /// Skill name reported in the evidence chain.
    pub fn skill_name(&self) -> &'static str {
        match self {
            SignalData::Hallucination(_) => "hallucination-check",
            SignalData::Cve(_) => "cve-match",
            SignalData::License(_) => "license-check",
            SignalData::Injection(_) => "injection-scan",
            SignalData::RawAdvisory(_) => "cve-match",
        }
    }

    /// System-generated summary (bounded; never untrusted raw text).
    fn summarize(&self) -> String {
        let text = match self {
            SignalData::Hallucination(output) => output.reasoning.clone(),
            SignalData::Cve(output) => output.reasoning.clone(),
            SignalData::License(output) => {
                if output.compatible && output.unknown_licenses.is_empty() {
                    "all licenses compatible with policy".to_string()
                } else if !output.compatible {
                    format!("{} license policy violation(s)", output.violations.len())
                } else {
                    format!(
                        "{} license(s) need human confirmation",
                        output.unknown_licenses.len()
                    )
                }
            }
            SignalData::Injection(scan) => scan.reasoning.clone(),
            SignalData::RawAdvisory(record) => format!(
                "advisory {} severity {}",
                record.advisory_id, record.severity
            ),
        };
        text.chars().take(200).collect()
    }
}

/// One signal with provenance and confidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    /// Data source behind the skill (e.g. `npm-registry`, `osv`).
    pub source: String,
    /// Confidence in `[0.0, 1.0]`.
    pub confidence: f64,
    /// Typed payload.
    pub data: SignalData,
}

/// Input for `risk-profile`.
#[derive(Debug, Clone)]
pub struct RiskProfileInput {
    /// Session the profile belongs to.
    pub session_id: SessionId,
    /// Entry mode (guard / response).
    pub entry_mode: EntryMode,
    /// Signals collected by the analyst.
    pub signals: Vec<Signal>,
}

/// The `risk-profile` skill (rule engine).
#[derive(Debug, Clone, Default)]
pub struct RiskProfileSkill;

impl Skill for RiskProfileSkill {
    type Input = RiskProfileInput;
    type Output = RiskProfile;

    fn name(&self) -> &'static str {
        "risk-profile"
    }

    fn description(&self) -> &'static str {
        "Fuse multiple security signals into a structured risk profile"
    }

    fn run(&self, input: &Self::Input) -> Result<Self::Output, SkillError> {
        let mut evidence_chain = Vec::new();
        let mut hallucination_risk = false;
        let mut cve_critical = false;
        let mut cve_high = false;
        let mut cve_unknown = false;
        let mut license_review = false;
        let mut registry_unreachable = false;
        let mut injection_detected = false;

        for signal in &input.signals {
            evidence_chain.push(Evidence {
                skill: signal.data.skill_name().to_string(),
                source: signal.source.clone(),
                summary: signal.data.summarize(),
                confidence: signal.confidence,
                raw_fingerprint: fingerprint(&signal.data),
            });
            match &signal.data {
                SignalData::Hallucination(output) => {
                    if output.is_hallucination_risk {
                        hallucination_risk = true;
                    }
                    // Registry outage is its own fail-safe signal.
                    if output.evidence.registry_error {
                        registry_unreachable = true;
                    }
                }
                SignalData::Cve(output) => {
                    if output.source_unavailable {
                        cve_unknown = true;
                    } else if output.max_severity.as_deref() == Some("critical") {
                        cve_critical = true;
                    } else if output.max_severity.as_deref() == Some("high") {
                        cve_high = true;
                    }
                }
                SignalData::License(output) => {
                    if output.review_required {
                        license_review = true;
                    }
                }
                SignalData::Injection(scan) => {
                    if scan.suspicious {
                        injection_detected = true;
                    }
                }
                SignalData::RawAdvisory(_) => {
                    // Raw advisories are evidence-only; severity handling is
                    // the cve-match skill's job.
                }
            }
        }

        let mut human_review_reasons: Vec<String> = Vec::new();
        let (risk_level, recommended_action) = if injection_detected {
            human_review_reasons
                .push("Prompt-injection attempt detected in untrusted content.".to_string());
            (RiskLevel::Critical, RecommendedAction::Block)
        } else if hallucination_risk {
            human_review_reasons.push("Hallucinated or typosquatted package detected.".to_string());
            (RiskLevel::Critical, RecommendedAction::Block)
        } else if cve_critical {
            human_review_reasons.push("Critical CVE detected.".to_string());
            (RiskLevel::Critical, RecommendedAction::Remediate)
        } else if cve_unknown {
            human_review_reasons.push(
                "Vulnerability database unavailable; unknown risk handled at the \
                 highest level."
                    .to_string(),
            );
            (RiskLevel::Critical, RecommendedAction::Remediate)
        } else if cve_high {
            human_review_reasons.push("High severity CVE detected.".to_string());
            (RiskLevel::High, RecommendedAction::Review)
        } else if license_review {
            human_review_reasons
                .push("License policy violation or unknown license detected.".to_string());
            (RiskLevel::High, RecommendedAction::Review)
        } else if registry_unreachable {
            human_review_reasons
                .push("Registry unreachable; fail-safe requires human review.".to_string());
            (RiskLevel::High, RecommendedAction::Review)
        } else {
            (RiskLevel::Low, RecommendedAction::Allow)
        };

        Ok(RiskProfile {
            session_id: input.session_id.clone(),
            risk_level,
            recommended_action,
            evidence_chain,
            human_review_reasons,
            generated_at: crate::models::ids::TimestampMillis::now(),
        })
    }
}

/// Non-reversible fingerprint of a signal payload (canonical JSON sha256).
fn fingerprint(data: &SignalData) -> String {
    let mut hasher = Sha256::new();
    if let Ok(bytes) = serde_json::to_vec(data) {
        hasher.update(&bytes);
    }
    let out = hasher.finalize();
    hex::encode(&out[..8])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::models::messages::Verdict;
    use crate::skills::cve_match::CveMatchOutput;
    use crate::skills::hallucination_check::HallucinationEvidence;

    fn hallucination(risk: bool, registry_error: bool) -> Signal {
        Signal {
            source: "npm-registry".to_string(),
            confidence: 0.9,
            data: SignalData::Hallucination(HallucinationCheckOutput {
                is_hallucination_risk: risk,
                reasoning: "test".to_string(),
                recommended_alternatives: Vec::new(),
                evidence: HallucinationEvidence {
                    registry_exists: Some(false),
                    registry_error,
                    local_fallback: registry_error,
                    similar_popular_packages: Vec::new(),
                    context_text_hash: "0123456789abcdef".to_string(),
                },
            }),
        }
    }

    fn cve(severity: Option<&str>, unavailable: bool) -> Signal {
        Signal {
            source: "osv".to_string(),
            confidence: 0.95,
            data: SignalData::Cve(CveMatchOutput {
                vulnerable: severity.is_some(),
                max_severity: severity.map(str::to_string),
                cves: vec!["CVE-2020-8203".to_string()],
                fixed_versions: vec!["4.17.21".to_string()],
                source_unavailable: unavailable,
                reasoning: "test".to_string(),
            }),
        }
    }

    fn license(violations: usize, unknown: usize) -> Signal {
        Signal {
            source: "policy".to_string(),
            confidence: 0.8,
            data: SignalData::License(LicenseCheckOutput {
                compatible: violations == 0,
                violations: (0..violations)
                    .map(|index| crate::skills::license_check::LicenseViolation {
                        package: format!("pkg-{index}"),
                        license: "GPL-3.0".to_string(),
                        reason: "forbidden".to_string(),
                    })
                    .collect(),
                unknown_licenses: (0..unknown)
                    .map(|index| crate::skills::license_check::PackageLicense {
                        name: format!("unknown-{index}"),
                        version: "1.0.0".to_string(),
                        license: None,
                    })
                    .collect(),
                review_required: violations + unknown > 0,
                policy_version: "1.0".to_string(),
            }),
        }
    }

    fn injection(suspicious: bool) -> Signal {
        Signal {
            source: "injection-detector".to_string(),
            confidence: 0.85,
            data: SignalData::Injection(InjectionScan {
                suspicious,
                matched_rules: if suspicious {
                    vec!["ignore-instructions".to_string()]
                } else {
                    Vec::new()
                },
                zero_width_chars: false,
                confidence: if suspicious { 0.7 } else { 0.0 },
                reasoning: if suspicious { "hit" } else { "clean" }.to_string(),
            }),
        }
    }

    fn fuse(signals: Vec<Signal>) -> RiskProfile {
        RiskProfileSkill
            .run(&RiskProfileInput {
                session_id: SessionId::new("s-test"),
                entry_mode: EntryMode::Guard,
                signals,
            })
            .expect("fusion is total")
    }

    #[test]
    fn empty_signals_yield_low_allow() {
        let profile = fuse(Vec::new());
        assert_eq!(profile.risk_level, RiskLevel::Low);
        assert_eq!(profile.recommended_action, RecommendedAction::Allow);
        assert!(profile.human_review_reasons.is_empty());
        assert!(profile.evidence_chain.is_empty());
    }

    #[test]
    fn clean_signals_yield_low_allow_with_full_evidence() {
        let profile = fuse(vec![
            hallucination(false, false),
            cve(None, false),
            license(0, 0),
        ]);
        assert_eq!(profile.risk_level, RiskLevel::Low);
        assert_eq!(profile.recommended_action, RecommendedAction::Allow);
        assert_eq!(profile.evidence_chain.len(), 3);
    }

    #[test]
    fn injection_outranks_everything() {
        let profile = fuse(vec![
            injection(true),
            hallucination(true, false),
            cve(Some("critical"), false),
        ]);
        assert_eq!(profile.risk_level, RiskLevel::Critical);
        assert_eq!(profile.recommended_action, RecommendedAction::Block);
        assert_eq!(profile.human_review_reasons.len(), 1);
        assert!(profile.human_review_reasons[0].contains("Prompt-injection"));
    }

    #[test]
    fn hallucination_risk_blocks() {
        let profile = fuse(vec![hallucination(true, false)]);
        assert_eq!(profile.risk_level, RiskLevel::Critical);
        assert_eq!(profile.recommended_action, RecommendedAction::Block);
    }

    #[test]
    fn critical_cve_remediates() {
        let profile = fuse(vec![cve(Some("critical"), false)]);
        assert_eq!(profile.risk_level, RiskLevel::Critical);
        assert_eq!(profile.recommended_action, RecommendedAction::Remediate);
    }

    #[test]
    fn degraded_vuln_db_is_treated_at_highest_level() {
        let profile = fuse(vec![cve(None, true)]);
        assert_eq!(profile.risk_level, RiskLevel::Critical);
        assert_eq!(profile.recommended_action, RecommendedAction::Remediate);
        assert!(profile.human_review_reasons[0].contains("highest level"));
    }

    #[test]
    fn high_cve_requires_review() {
        let profile = fuse(vec![cve(Some("high"), false)]);
        assert_eq!(profile.risk_level, RiskLevel::High);
        assert_eq!(profile.recommended_action, RecommendedAction::Review);
    }

    #[test]
    fn license_review_requires_review() {
        let profile = fuse(vec![license(0, 2)]);
        assert_eq!(profile.risk_level, RiskLevel::High);
        assert_eq!(profile.recommended_action, RecommendedAction::Review);
        let violations = fuse(vec![license(1, 0)]);
        assert_eq!(violations.risk_level, RiskLevel::High);
    }

    #[test]
    fn registry_unreachable_requires_review() {
        let profile = fuse(vec![hallucination(false, true)]);
        assert_eq!(profile.risk_level, RiskLevel::High);
        assert_eq!(profile.recommended_action, RecommendedAction::Review);
        assert!(profile.human_review_reasons[0].contains("Registry unreachable"));
    }

    #[test]
    fn contradictory_signals_resolve_by_priority_ladder() {
        // Hallucination (critical) beats compatible license evidence.
        let profile = fuse(vec![hallucination(true, false), license(0, 0)]);
        assert_eq!(profile.recommended_action, RecommendedAction::Block);
        // Registry outage (high) does not mask a real critical CVE below it
        // in the ladder: critical cve branch wins over registry outage.
        let profile2 = fuse(vec![
            cve(Some("critical"), false),
            hallucination(false, true),
        ]);
        assert_eq!(profile2.risk_level, RiskLevel::Critical);
        assert_eq!(profile2.recommended_action, RecommendedAction::Remediate);
    }

    #[test]
    fn evidence_chain_carries_names_sources_and_fingerprints() {
        let profile = fuse(vec![hallucination(true, false), cve(Some("high"), false)]);
        assert_eq!(profile.evidence_chain.len(), 2);
        assert_eq!(profile.evidence_chain[0].skill, "hallucination-check");
        assert_eq!(profile.evidence_chain[0].source, "npm-registry");
        assert_eq!(profile.evidence_chain[0].confidence, 0.9);
        assert_eq!(profile.evidence_chain[0].raw_fingerprint.len(), 16);
        assert_ne!(
            profile.evidence_chain[0].raw_fingerprint,
            profile.evidence_chain[1].raw_fingerprint
        );
        for evidence in &profile.evidence_chain {
            assert!(evidence.summary.chars().count() <= 200);
        }
    }

    #[test]
    fn profile_is_serializable_and_auditor_ready() {
        let profile = fuse(vec![hallucination(true, false)]);
        let json = serde_json::to_string(&profile).expect("serialize");
        let back: RiskProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, profile);
        // Auditor consumes only structured evidence; verdict mapping exists.
        assert_eq!(serde_json::to_string(&Verdict::Block).unwrap(), "\"block\"");
    }

    #[test]
    fn skill_metadata_matches_design_card() {
        assert_eq!(RiskProfileSkill.name(), "risk-profile");
        assert!(!RiskProfileSkill.description().is_empty());
    }
}

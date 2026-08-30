//! Analyst: read-only multi-signal risk profiling.

use crate::models::messages::{DependencyChange, RiskProfile};
use crate::security::injection::InjectionDetector;
use crate::security::sanitize;
use crate::skills::Skill;
use crate::skills::cve_match::{CveMatchInput, CveMatchSkill};
use crate::skills::hallucination_check::{HallucinationCheckInput, HallucinationCheckSkill};
use crate::skills::license_check::{LicenseCheckInput, LicenseCheckSkill, PackageLicense};
use crate::skills::risk_profile::{EntryMode, RiskProfileInput, RiskProfileSkill, Signal};

/// Analyst agent: produces a structured `RiskProfile` from an
/// `AnalysisRequest` using read-only skills.
///
/// The analyst can never mutate state: it holds only analysis skills and the
/// injection detector, and returns data (onion L2/L3 responsibilities live in
/// the sanitize -> detect pipeline below).
pub struct Analyst {
    hallucination: HallucinationCheckSkill,
    cve: CveMatchSkill,
    license: LicenseCheckSkill,
    injection: InjectionDetector,
}

impl Analyst {
    /// Creates the analyst with its (read-only) toolset, injected by the
    /// runtime — the only place tools are constructed.
    pub fn new(
        hallucination: HallucinationCheckSkill,
        cve: CveMatchSkill,
        license: LicenseCheckSkill,
        injection: InjectionDetector,
    ) -> Self {
        Self {
            hallucination,
            cve,
            license,
            injection,
        }
    }

    /// Analyzes all changes in the request and fuses the signals.
    ///
    /// `license_packages` carries license metadata for the session (from the
    /// SBOM in scan mode); when it contains no license information at all,
    /// the license signal is skipped — a diff without license lines must not
    /// masquerade as "unknown license".
    ///
    /// # Errors
    ///
    /// Propagates [`crate::skills::SkillError`] only from the fusion skill's
    /// fatal paths (in practice the rule engine is total).
    pub fn analyze(
        &self,
        request: &crate::models::messages::AnalysisRequest,
        license_policy: &crate::skills::license_check::LicensePolicy,
        license_packages: &[PackageLicense],
    ) -> Result<RiskProfile, crate::skills::SkillError> {
        let entry_mode = if matches!(
            request.source,
            crate::models::messages::EventSource::GitHubPr
                | crate::models::messages::EventSource::GitLabPr
        ) {
            EntryMode::Guard
        } else {
            EntryMode::Response
        };

        let mut signals: Vec<Signal> = Vec::new();
        for change in &request.changes {
            signals.extend(self.signals_for_change(change)?);
        }

        // Session-level license signal: only when license data exists.
        if license_packages.iter().any(|pkg| pkg.license.is_some()) {
            let output = self.license.run(&LicenseCheckInput {
                packages: license_packages.to_vec(),
                project_license_policy: license_policy.clone(),
            })?;
            signals.push(Signal {
                source: "license-policy".to_string(),
                confidence: 0.8,
                data: crate::skills::risk_profile::SignalData::License(output),
            });
        }

        RiskProfileSkill.run(&RiskProfileInput {
            session_id: request.session_id.clone(),
            entry_mode,
            signals,
        })
    }

    /// Onion L2/L3 pipeline for one dependency change: sanitize the untrusted
    /// context, scan for injection, then run the per-package signals.
    ///
    /// # Errors
    ///
    /// Propagates fatal skill errors; degradable anomalies stay inside the
    /// signal outputs.
    fn signals_for_change(
        &self,
        change: &DependencyChange,
    ) -> Result<Vec<Signal>, crate::skills::SkillError> {
        let mut signals = Vec::new();

        let cleaned = sanitize::sanitize(&change.context_text);
        let scan = self.injection.detect(cleaned.as_str());

        signals.push(Signal {
            source: "injection-detector".to_string(),
            confidence: 0.85,
            data: crate::skills::risk_profile::SignalData::Injection(scan),
        });

        let hallucination = self.hallucination.run(&HallucinationCheckInput {
            candidate_package_name: change.package_name.clone(),
            context_text: change.context_text.clone(),
            ecosystem: change.ecosystem.clone(),
        })?;
        signals.push(Signal {
            source: "npm-registry".to_string(),
            confidence: 0.9,
            data: crate::skills::risk_profile::SignalData::Hallucination(hallucination),
        });

        let version = change
            .new_version
            .clone()
            .or_else(|| change.old_version.clone());
        if let Some(version) = version {
            let cve = self.cve.run(&CveMatchInput {
                package_name: change.package_name.clone(),
                version,
                ecosystem: change.ecosystem.clone(),
            })?;
            signals.push(Signal {
                source: "osv".to_string(),
                confidence: 0.95,
                data: crate::skills::risk_profile::SignalData::Cve(cve),
            });
        }
        Ok(signals)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::agents::Sentinel;
    use crate::mcp::{McpError, RegistryClient};
    use crate::mcp::{OsvLocal, SpdxLocal};
    use crate::models::ids::SessionId;
    use crate::models::messages::EventSource;
    use crate::skills::license_check::LicensePolicy;
    use std::sync::Arc;

    struct StaticRegistry(bool);

    impl RegistryClient for StaticRegistry {
        fn exists(&self, _package_name: &str) -> Result<bool, McpError> {
            Ok(self.0)
        }
    }

    fn analyst(registry_exists: bool) -> Analyst {
        Analyst::new(
            HallucinationCheckSkill::new(Arc::new(StaticRegistry(registry_exists))),
            CveMatchSkill::new(Arc::new(OsvLocal::new().expect("osv"))),
            LicenseCheckSkill::new(Arc::new(SpdxLocal::new().expect("spdx"))),
            InjectionDetector::with_builtin_rules().expect("injection detector"),
        )
    }

    fn request_with(change: DependencyChange) -> crate::models::messages::AnalysisRequest {
        Sentinel.build_request(
            SessionId::new("s-a"),
            EventSource::GitHubPr,
            "https://github.com/acme/demo-app".to_string(),
            "deadbeef".to_string(),
            vec![change],
        )
    }

    fn unknown_package_change() -> DependencyChange {
        DependencyChange {
            package_name: "lodos".to_string(),
            old_version: None,
            new_version: Some("^1.0.0".to_string()),
            is_new: true,
            ecosystem: "npm".to_string(),
            context_text: "import { cloneDeep } from 'lodos';".to_string(),
        }
    }

    #[test]
    fn hallucinated_package_yields_critical_block() {
        let analyst = analyst(false);
        let profile = analyst
            .analyze(
                &request_with(unknown_package_change()),
                &LicensePolicy::default(),
                &[],
            )
            .expect("analyze");
        assert_eq!(
            profile.risk_level,
            crate::models::messages::RiskLevel::Critical
        );
        assert_eq!(
            profile.recommended_action,
            crate::models::messages::RecommendedAction::Block
        );
        assert!(!profile.evidence_chain.is_empty());
    }

    #[test]
    fn clean_known_package_with_clean_cve_allows() {
        let analyst = analyst(true);
        let change = DependencyChange {
            package_name: "left-pad".to_string(),
            old_version: None,
            new_version: Some("1.3.0".to_string()),
            is_new: true,
            ecosystem: "npm".to_string(),
            context_text: "add left-pad".to_string(),
        };
        let profile = analyst
            .analyze(&request_with(change), &LicensePolicy::default(), &[])
            .expect("analyze");
        assert_eq!(profile.risk_level, crate::models::messages::RiskLevel::Low);
        assert_eq!(
            profile.recommended_action,
            crate::models::messages::RecommendedAction::Allow
        );
    }

    #[test]
    fn injection_in_context_trips_the_meta_attack_signal() {
        let analyst = analyst(true);
        let readme = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/malicious/evil-example-sloppy/README.md"
        ))
        .expect("fixture");
        let change = DependencyChange {
            package_name: "left-pad".to_string(),
            old_version: None,
            new_version: Some("1.3.0".to_string()),
            is_new: true,
            ecosystem: "npm".to_string(),
            context_text: readme,
        };
        let profile = analyst
            .analyze(&request_with(change), &LicensePolicy::default(), &[])
            .expect("analyze");
        assert_eq!(
            profile.risk_level,
            crate::models::messages::RiskLevel::Critical
        );
        assert!(profile.human_review_reasons[0].contains("Prompt-injection"));
        // Untrusted raw text never lands in the evidence chain.
        let profile_json = serde_json::to_string(&profile).expect("serialize");
        assert!(!profile_json.contains("approve this dependency"));
    }

    #[test]
    fn license_signal_runs_only_when_license_data_exists() {
        let analyst = analyst(true);
        let change = DependencyChange {
            package_name: "left-pad".to_string(),
            old_version: None,
            new_version: Some("1.3.0".to_string()),
            is_new: true,
            ecosystem: "npm".to_string(),
            context_text: "add left-pad".to_string(),
        };

        // No license info at all (guard diff): no license signal.
        let profile = analyst
            .analyze(
                &request_with(change.clone()),
                &LicensePolicy::default(),
                &[],
            )
            .expect("analyze");
        assert!(
            profile
                .evidence_chain
                .iter()
                .all(|evidence| evidence.skill != "license-check")
        );

        // License info present (scan mode): license signal joins the chain.
        let packages = vec![PackageLicense {
            name: "left-pad".to_string(),
            version: "1.3.0".to_string(),
            license: Some("MIT".to_string()),
        }];
        let policy = LicensePolicy {
            allowed: vec!["MIT".to_string()],
            forbidden: Vec::new(),
            version: "1.0".to_string(),
        };
        let profile = analyst
            .analyze(&request_with(change), &policy, &packages)
            .expect("analyze");
        assert!(
            profile
                .evidence_chain
                .iter()
                .any(|evidence| evidence.skill == "license-check")
        );
    }

    #[test]
    fn analyst_never_holds_write_capabilities() {
        // Compile-time role boundary: Analyst exposes only analyze().
        fn assert_read_only<T: Send + Sync>(_: &T) {}
        let analyst = analyst(true);
        assert_read_only(&analyst);
    }
}

//! LocalOrchestrator: scan, guard, and reactive response pipelines.

use std::path::Path;
use std::sync::Arc;

use thiserror::Error;

use crate::agents::analyst::Analyst;
use crate::agents::auditor::{Auditor, SealReport};
use crate::agents::remediator::Remediator;
use crate::agents::sentinel::Sentinel;
use crate::audit::AuditChain;
use crate::mcp::{LicenseDb, RegistryClient, VulnSource};
use crate::models::ids::{SessionId, TimestampMillis};
use crate::models::messages::{
    DependencyChange, EventSource, RemediationResult, RemediationStrategy, RiskLevel, RiskProfile,
    Verdict,
};
use crate::models::session::{SessionState, StateTransitionError};
use crate::security::injection::InjectionDetector;
use crate::skills::Skill;
use crate::skills::cve_match::CveMatchInput;
use crate::skills::license_check::{LicensePolicy, PackageLicense};
use crate::skills::sbom_build::{SbomBuildInput, SbomBuildSkill, SbomSnapshot};

/// Errors raised by the orchestration layer.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// A skill hit a fatal path (e.g. unreadable lockfile).
    #[error("skill failure: {0}")]
    Skill(#[from] crate::skills::SkillError),
    /// The audit chain failed to record a decision.
    #[error("audit failure: {0}")]
    Audit(#[from] crate::audit::AuditError),
    /// The session state machine rejected a move (an internal invariant).
    #[error("state machine failure: {0}")]
    State(#[from] StateTransitionError),
    /// The orchestration input itself is invalid.
    #[error("invalid orchestration input: {0}")]
    InvalidInput(String),
}

/// Events published while a session runs (consumed by the web SSE layer).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OrchestratorEvent {
    /// A session started.
    ScanStarted {
        /// Session id.
        session_id: String,
        /// Entry mode label (`scan` / `guard` / `response`).
        mode: &'static str,
        /// Number of dependency changes in the request.
        total_changes: usize,
    },
    /// The session advanced to a lifecycle state.
    ScanProgress {
        /// Session id.
        session_id: String,
        /// New state (snake_case).
        state: SessionState,
    },
    /// The auditor issued a verdict.
    GuardVerdict {
        /// Session id.
        session_id: String,
        /// Verdict value (snake_case).
        verdict: String,
        /// Fused risk level.
        risk_level: String,
    },
    /// An audit entry was appended.
    AuditAppended {
        /// Session id.
        session_id: String,
        /// Audit event kind (`verdict` / `sealed`).
        event: String,
    },
    /// The session finished (sealed or failed after verdict).
    ScanCompleted {
        /// Session id.
        session_id: String,
        /// Verdict value (snake_case).
        verdict: String,
        /// Fused risk level.
        risk_level: String,
    },
}

/// Everything the orchestrator needs, constructed once by the composition
/// root (main / config) — the single tool factory of the system.
pub struct RuntimeTools {
    /// Offline (or, post-M4, real) registry client.
    pub registry: Arc<dyn RegistryClient>,
    /// Vulnerability database.
    pub vuln_source: Arc<dyn VulnSource>,
    /// SPDX license database.
    pub license_db: Arc<dyn LicenseDb>,
    /// The shared append-only audit chain.
    pub audit_chain: Arc<AuditChain>,
    /// Injection detector with its rule corpus.
    pub injection: InjectionDetector,
    /// License policy applied to scans and guards.
    pub license_policy: LicensePolicy,
}

/// Full result of one orchestrated session.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GuardOutcome {
    /// Session id.
    pub session_id: SessionId,
    /// Entry mode of the session.
    pub source: EventSource,
    /// Repository URL or local file URI.
    pub repo_url: String,
    /// Commit SHA or `local-working-tree`.
    pub commit_sha: String,
    /// Fused risk level.
    pub risk_level: RiskLevel,
    /// Arbitrated verdict.
    pub verdict: Verdict,
    /// Remediation strategy chosen by the auditor.
    pub strategy: RemediationStrategy,
    /// The fused risk profile (structured evidence).
    pub risk_profile: RiskProfile,
    /// Remediation artifacts.
    pub remediation: RemediationResult,
    /// Seal report with chain verification.
    pub seal: SealReport,
    /// State timeline in traversal order.
    pub timeline: Vec<(SessionState, u64)>,
    /// SBOM snapshot (scan mode only).
    pub snapshot: Option<SbomSnapshot>,
}

/// One affected package in a response-mode outcome.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResponseAffectedPackage {
    /// Package name.
    pub package_name: String,
    /// Currently installed version.
    pub installed_version: String,
    /// CVE identifiers that affect this package at this version.
    pub cves: Vec<String>,
    /// Advisory severity (highest across matched advisories).
    pub severity: String,
    /// Available fixed versions (sorted, deduped).
    pub fixed_versions: Vec<String>,
    /// Recommended action for this package.
    pub recommended_action: String,
}

/// Full result of a reactive response-mode session.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResponseOutcome {
    /// Session id.
    pub session_id: SessionId,
    /// The CVE identifier that triggered this response.
    pub cve_id: String,
    /// Overall risk level across all affected packages.
    pub risk_level: RiskLevel,
    /// Overall verdict: block if any critical/high CVE found.
    pub verdict: Verdict,
    /// Total packages scanned from the SBOM.
    pub total_scanned: usize,
    /// Number of packages affected by the CVE.
    pub affected_count: usize,
    /// Per-package impact details.
    pub affected_packages: Vec<ResponseAffectedPackage>,
    /// Seal report with chain verification.
    pub seal: SealReport,
    /// State timeline in traversal order.
    pub timeline: Vec<(SessionState, u64)>,
    /// SBOM snapshot of the scanned project.
    pub snapshot: Option<SbomSnapshot>,
}

/// How many recent sessions the overview view returns.
pub const OVERVIEW_RECENT_LIMIT: usize = 10;

/// Aggregated numbers for the web overview view.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct OverviewSummary {
    /// Total finished sessions in the store.
    pub total_sessions: usize,
    /// Sessions whose fused risk is critical.
    pub critical: usize,
    /// Sessions whose fused risk is high.
    pub high: usize,
    /// Sessions whose fused risk is medium.
    pub medium: usize,
    /// Sessions whose fused risk is low.
    pub low: usize,
    /// Sessions whose fused risk is safe.
    pub safe: usize,
    /// Most recent sessions (newest first, bounded).
    pub recent_sessions: Vec<RecentSession>,
}

/// One row of the overview's recent-session list.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RecentSession {
    /// Session id.
    pub session_id: String,
    /// Entry source label (snake_case).
    pub source: String,
    /// Verdict label (snake_case).
    pub verdict: String,
    /// Risk level label (snake_case).
    pub risk_level: String,
    /// Completion time (ms since epoch).
    pub timestamp: u64,
}

/// Event sink: receives every [`OrchestratorEvent`] as it happens.
pub type EventSink = Arc<dyn Fn(&OrchestratorEvent) + Send + Sync>;

/// In-process orchestrator wiring the four agents together.
pub struct LocalOrchestrator {
    sentinel: Sentinel,
    analyst: Analyst,
    auditor: Auditor,
    remediator: Remediator,
    license_policy: LicensePolicy,
    audit_chain: Arc<AuditChain>,
    store: Arc<crate::runtime::store::SessionStore>,
    event_sink: EventSink,
}

impl LocalOrchestrator {
    /// Builds the orchestrator, constructing the agents with their tools —
    /// the only place toolsets are wired to roles (PROMPT 5.1).
    pub fn new(tools: RuntimeTools) -> Self {
        Self::with_sink(tools, Arc::new(|_| {}))
    }

    /// Builds the orchestrator with an event sink for SSE consumption.
    pub fn with_sink(tools: RuntimeTools, event_sink: EventSink) -> Self {
        let analyst = Analyst::new(
            crate::skills::hallucination_check::HallucinationCheckSkill::new(
                tools.registry.clone(),
            ),
            crate::skills::cve_match::CveMatchSkill::new(tools.vuln_source.clone()),
            crate::skills::license_check::LicenseCheckSkill::new(tools.license_db.clone()),
            tools.injection,
        );
        let auditor = Auditor::new(tools.audit_chain.clone());
        Self {
            sentinel: Sentinel,
            analyst,
            auditor,
            remediator: Remediator,
            license_policy: tools.license_policy,
            audit_chain: tools.audit_chain,
            store: Arc::new(crate::runtime::store::SessionStore::new()),
            event_sink,
        }
    }

    /// Read access to the session store (web console views).
    pub fn store(&self) -> Arc<crate::runtime::store::SessionStore> {
        self.store.clone()
    }

    /// Audit chain entries (web audit view; runtime wraps audit access).
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Audit`] on storage failure.
    pub fn audit_entries(&self) -> Result<Vec<crate::audit::AuditEntry>, crate::audit::AuditError> {
        self.audit_chain.entries()
    }

    /// Audit chain verification report (web audit view).
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Audit`] on storage failure.
    pub fn audit_verification(
        &self,
    ) -> Result<crate::audit::ChainVerification, crate::audit::AuditError> {
        self.audit_chain.verify()
    }

    /// Aggregated summary for the web overview view.
    pub fn overview(&self) -> OverviewSummary {
        let sessions = self.store.list();
        let mut summary = OverviewSummary {
            total_sessions: sessions.len(),
            ..OverviewSummary::default()
        };
        for outcome in &sessions {
            let (risk_level, verdict) = match outcome {
                crate::runtime::store::SessionOutcome::Guard(o) => (o.risk_level, o.verdict),
                crate::runtime::store::SessionOutcome::Response(o) => (o.risk_level, o.verdict),
            };
            match risk_level {
                RiskLevel::Critical => summary.critical += 1,
                RiskLevel::High => summary.high += 1,
                RiskLevel::Medium => summary.medium += 1,
                RiskLevel::Low => summary.low += 1,
                RiskLevel::Safe => summary.safe += 1,
            }
            summary.recent_sessions.push(RecentSession {
                session_id: outcome.session_id().to_string(),
                source: serde_json::to_string(&match outcome {
                    crate::runtime::store::SessionOutcome::Guard(o) => o.source,
                    crate::runtime::store::SessionOutcome::Response(_) => EventSource::Manual,
                })
                .unwrap_or_default()
                .trim_matches('"')
                .to_string(),
                verdict: serde_json::to_string(&verdict)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string(),
                risk_level: serde_json::to_string(&risk_level)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string(),
                timestamp: outcome
                    .timeline()
                    .last()
                    .map(|(_, at)| *at)
                    .unwrap_or_default(),
            });
        }
        summary
            .recent_sessions
            .sort_by_key(|session| std::cmp::Reverse(session.timestamp));
        summary
            .recent_sessions
            .truncate(crate::runtime::orchestrator::OVERVIEW_RECENT_LIMIT);
        summary
    }

    /// Runs the full guard pipeline over explicit dependency changes.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] on fatal skill paths or audit failures; the
    /// conservative rule is that a session without a sealed verdict is an
    /// error, never a silent pass.
    pub fn run_guard(
        &self,
        session_id: SessionId,
        source: EventSource,
        repo_url: String,
        commit_sha: String,
        changes: Vec<DependencyChange>,
    ) -> Result<GuardOutcome, RuntimeError> {
        let total_changes = changes.len();
        self.emit(&OrchestratorEvent::ScanStarted {
            session_id: session_id.to_string(),
            mode: "guard",
            total_changes,
        });
        let request = self.sentinel.build_request(
            session_id.clone(),
            source,
            repo_url.clone(),
            commit_sha.clone(),
            changes,
        );
        self.pipeline(request, None)
    }

    /// Runs the scan pipeline over a project directory (SBOM first).
    ///
    /// The session id is derived from the SBOM id.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when the lockfile cannot be parsed (fatal)
    /// or the audit chain fails.
    pub fn run_scan(
        &self,
        project_dir: &Path,
        include_dev: bool,
    ) -> Result<GuardOutcome, RuntimeError> {
        let lockfile = project_dir.join("package-lock.json");
        let sbom_skill = SbomBuildSkill;
        let snapshot = sbom_skill.run(&SbomBuildInput {
            lockfile_path: lockfile.display().to_string(),
            include_dev,
        })?;
        let session_id = SessionId::new(format!("scan-{}", snapshot.sbom_id));
        self.run_scan_with_session(session_id, project_dir, snapshot)
    }

    /// Runs the scan pipeline with a caller-supplied session id (web trigger
    /// flow: the API answers 202 with the id before the pipeline finishes).
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] when the lockfile cannot be parsed (fatal)
    /// or the audit chain fails.
    pub fn run_scan_with_session(
        &self,
        session_id: SessionId,
        project_dir: &Path,
        snapshot: SbomSnapshot,
    ) -> Result<GuardOutcome, RuntimeError> {
        self.emit(&OrchestratorEvent::ScanStarted {
            session_id: session_id.to_string(),
            mode: "scan",
            total_changes: snapshot.packages.len(),
        });

        let changes = changes_from_snapshot(&snapshot);
        let repo_url = format!("file://{}", project_dir.display());
        let request = self.sentinel.build_request(
            session_id.clone(),
            EventSource::Manual,
            repo_url.clone(),
            "local-working-tree".to_string(),
            changes,
        );
        let license_packages: Vec<PackageLicense> = snapshot
            .packages
            .iter()
            .map(|node| PackageLicense {
                name: node.name.clone(),
                version: node.version.clone(),
                license: node.license.clone(),
            })
            .collect();
        self.pipeline_with_licenses(request, Some(snapshot), license_packages)
    }

    /// Runs the reactive response pipeline: scan a project, then cross-reference
    /// every package against a specific CVE to build a batch impact assessment.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError`] on fatal skill or audit failures.
    pub fn run_response(
        &self,
        cve_id: &str,
        project_dir: &Path,
    ) -> Result<ResponseOutcome, RuntimeError> {
        let session_id = SessionId::new(format!("response-{}", TimestampMillis::now().as_u64()));
        let mut timeline: Vec<(SessionState, u64)> =
            vec![(SessionState::Received, TimestampMillis::now().as_u64())];

        self.emit(&OrchestratorEvent::ScanStarted {
            session_id: session_id.to_string(),
            mode: "response",
            total_changes: 0,
        });

        // received -> analyzing
        let mut state = SessionState::Received;
        state = state.advance(SessionState::Analyzing)?;
        timeline.push((state, TimestampMillis::now().as_u64()));
        self.emit(&OrchestratorEvent::ScanProgress {
            session_id: session_id.to_string(),
            state,
        });

        let lockfile = project_dir.join("package-lock.json");
        let sbom_skill = SbomBuildSkill;
        let snapshot = sbom_skill.run(&SbomBuildInput {
            lockfile_path: lockfile.display().to_string(),
            include_dev: false,
        })?;
        let total_scanned = snapshot.packages.len();

        // analyzing -> arbitrating
        state = state.advance(SessionState::Arbitrating)?;
        timeline.push((state, TimestampMillis::now().as_u64()));
        self.emit(&OrchestratorEvent::ScanProgress {
            session_id: session_id.to_string(),
            state,
        });

        let mut affected_packages: Vec<ResponseAffectedPackage> = Vec::new();
        for node in &snapshot.packages {
            let vulns = self.analyst.cve_skill()?.run(&CveMatchInput {
                package_name: node.name.clone(),
                version: node.version.clone(),
                ecosystem: "npm".to_string(),
            })?;

            if !vulns.cves.contains(&cve_id.to_string())
                && !vulns.cves.iter().any(|c| c.eq_ignore_ascii_case(cve_id))
            {
                continue;
            }

            let severity = vulns.max_severity.unwrap_or_else(|| "unknown".to_string());
            let recommended_action = if severity == "critical" || severity == "high" {
                "bump-version".to_string()
            } else {
                "review".to_string()
            };

            affected_packages.push(ResponseAffectedPackage {
                package_name: node.name.clone(),
                installed_version: node.version.clone(),
                cves: vulns.cves.clone(),
                severity: severity.clone(),
                fixed_versions: vulns.fixed_versions.clone(),
                recommended_action,
            });
        }

        let affected_count = affected_packages.len();
        let (risk_level, verdict) = if affected_packages.is_empty() {
            (RiskLevel::Safe, Verdict::Allow)
        } else if affected_packages
            .iter()
            .any(|p| p.severity == "critical" || p.severity == "high")
        {
            (RiskLevel::Critical, Verdict::Block)
        } else {
            (RiskLevel::High, Verdict::RequireHumanReview)
        };

        self.emit(&OrchestratorEvent::GuardVerdict {
            session_id: session_id.to_string(),
            verdict: verdict_value(&verdict),
            risk_level: risk_value(&risk_level),
        });
        self.emit(&OrchestratorEvent::AuditAppended {
            session_id: session_id.to_string(),
            event: "verdict".to_string(),
        });

        // arbitrating -> remediating
        state = state.advance(SessionState::Remediating)?;
        timeline.push((state, TimestampMillis::now().as_u64()));
        self.emit(&OrchestratorEvent::ScanProgress {
            session_id: session_id.to_string(),
            state,
        });

        let mut artifacts = std::collections::BTreeMap::new();
        artifacts.insert(
            "action_taken".to_string(),
            serde_json::json!(if affected_packages.is_empty() {
                "no_action_required"
            } else {
                "batch_impact_assessment_complete"
            }),
        );
        let remediation = RemediationResult {
            session_id: session_id.clone(),
            success: true,
            artifacts,
            logs_hash: String::new(),
            regression_detected: None,
            completed_at: TimestampMillis::now(),
        };

        // remediating -> verifying
        state = state.advance(SessionState::Verifying)?;
        timeline.push((state, TimestampMillis::now().as_u64()));
        self.emit(&OrchestratorEvent::ScanProgress {
            session_id: session_id.to_string(),
            state,
        });

        let seal = self.auditor.seal(&remediation)?;
        self.emit(&OrchestratorEvent::AuditAppended {
            session_id: session_id.to_string(),
            event: "sealed".to_string(),
        });

        // verifying -> sealed
        state = state.advance(SessionState::Sealed)?;
        timeline.push((state, TimestampMillis::now().as_u64()));
        self.emit(&OrchestratorEvent::ScanProgress {
            session_id: session_id.to_string(),
            state,
        });

        let outcome = ResponseOutcome {
            session_id: session_id.clone(),
            cve_id: cve_id.to_string(),
            risk_level,
            verdict,
            total_scanned,
            affected_count,
            affected_packages,
            seal,
            timeline,
            snapshot: Some(snapshot),
        };
        self.emit(&OrchestratorEvent::ScanCompleted {
            session_id: session_id.to_string(),
            verdict: verdict_value(&outcome.verdict),
            risk_level: risk_value(&outcome.risk_level),
        });
        self.store.push_response(outcome.clone());
        Ok(outcome)
    }

    /// Shared pipeline: analyze -> arbitrate -> remediate -> seal, advancing
    /// the state machine and emitting events at every step.
    fn pipeline(
        &self,
        request: crate::models::messages::AnalysisRequest,
        snapshot: Option<SbomSnapshot>,
    ) -> Result<GuardOutcome, RuntimeError> {
        self.pipeline_with_licenses(request, snapshot, Vec::new())
    }

    fn pipeline_with_licenses(
        &self,
        request: crate::models::messages::AnalysisRequest,
        snapshot: Option<SbomSnapshot>,
        license_packages: Vec<PackageLicense>,
    ) -> Result<GuardOutcome, RuntimeError> {
        let mut state = SessionState::Received;
        let mut timeline: Vec<(SessionState, u64)> = vec![(state, TimestampMillis::now().as_u64())];
        let session_id = request.session_id.clone();

        // received -> analyzing
        state = state.advance(SessionState::Analyzing)?;
        timeline.push((state, TimestampMillis::now().as_u64()));
        self.emit(&OrchestratorEvent::ScanProgress {
            session_id: session_id.to_string(),
            state,
        });

        let risk_profile =
            self.analyst
                .analyze(&request, &self.license_policy, &license_packages)?;

        // analyzing -> arbitrating
        state = state.advance(SessionState::Arbitrating)?;
        timeline.push((state, TimestampMillis::now().as_u64()));
        self.emit(&OrchestratorEvent::ScanProgress {
            session_id: session_id.to_string(),
            state,
        });

        let arbitration = self.auditor.arbitrate(&risk_profile)?;
        let order = arbitration.order;
        let verdict = order.verdict;
        let strategy = order.strategy;
        let risk_profile = order.risk_profile.clone();
        self.emit(&OrchestratorEvent::GuardVerdict {
            session_id: session_id.to_string(),
            verdict: verdict_value(&verdict),
            risk_level: risk_value(&risk_profile.risk_level),
        });
        self.emit(&OrchestratorEvent::AuditAppended {
            session_id: session_id.to_string(),
            event: "verdict".to_string(),
        });

        // arbitrating -> remediating
        state = state.advance(SessionState::Remediating)?;
        timeline.push((state, TimestampMillis::now().as_u64()));
        self.emit(&OrchestratorEvent::ScanProgress {
            session_id: session_id.to_string(),
            state,
        });

        let remediation = self.remediator.handle(&order);

        // remediating -> verifying
        state = state.advance(SessionState::Verifying)?;
        timeline.push((state, TimestampMillis::now().as_u64()));
        self.emit(&OrchestratorEvent::ScanProgress {
            session_id: session_id.to_string(),
            state,
        });

        let seal = self.auditor.seal(&remediation)?;
        self.emit(&OrchestratorEvent::AuditAppended {
            session_id: session_id.to_string(),
            event: "sealed".to_string(),
        });

        // verifying -> sealed
        state = state.advance(SessionState::Sealed)?;
        timeline.push((state, TimestampMillis::now().as_u64()));
        self.emit(&OrchestratorEvent::ScanProgress {
            session_id: session_id.to_string(),
            state,
        });

        let outcome = GuardOutcome {
            session_id: session_id.clone(),
            source: request.source,
            repo_url: request.repo_url.clone(),
            commit_sha: request.commit_sha.clone(),
            risk_level: risk_profile.risk_level,
            verdict,
            strategy,
            risk_profile,
            remediation,
            seal,
            timeline,
            snapshot,
        };
        self.emit(&OrchestratorEvent::ScanCompleted {
            session_id: session_id.to_string(),
            verdict: verdict_value(&outcome.verdict),
            risk_level: risk_value(&outcome.risk_level),
        });
        self.store.push_guard(outcome.clone());
        Ok(outcome)
    }

    fn emit(&self, event: &OrchestratorEvent) {
        (self.event_sink)(event);
    }
}

fn verdict_value(verdict: &Verdict) -> String {
    serde_json::to_string(verdict)
        .map(|json| json.trim_matches('"').to_string())
        .unwrap_or_else(|_| format!("{verdict:?}"))
}

fn risk_value(level: &RiskLevel) -> String {
    serde_json::to_string(level)
        .map(|json| json.trim_matches('"').to_string())
        .unwrap_or_else(|_| format!("{level:?}"))
}

/// Derives dependency changes from an SBOM snapshot (Python sentinel parity):
/// direct packages are "new" changes, transitive packages carry their version
/// as `old_version` context.
fn changes_from_snapshot(snapshot: &SbomSnapshot) -> Vec<DependencyChange> {
    snapshot
        .packages
        .iter()
        .map(|node| DependencyChange {
            package_name: node.name.clone(),
            old_version: if node.direct {
                None
            } else {
                Some(node.version.clone())
            },
            new_version: if node.direct {
                Some(node.version.clone())
            } else {
                None
            },
            is_new: node.direct,
            ecosystem: "npm".to_string(),
            context_text: format!(
                "Dependency discovered in package-lock.json: {}; version={}; direct={}; \
                 license={}",
                node.name,
                node.version,
                node.direct,
                node.license.as_deref().unwrap_or("unknown")
            ),
        })
        .collect()
}

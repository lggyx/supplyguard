//! In-memory session store for completed outcomes.
//!
//! Local-first and single-process: the durable record of every session is
//! the audit chain; this store only serves the web console's read views
//! after restarts start empty (documented behavior, not a bug).

use crate::models::ids::SessionId;
use crate::models::messages::{RiskLevel, Verdict};
use crate::models::session::SessionState;
use crate::runtime::orchestrator::{GuardOutcome, ResponseOutcome};
use std::sync::Mutex;

/// A completed session outcome, either guard-mode or response-mode.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionOutcome {
    /// A guard-mode scan/guard session.
    Guard(GuardOutcome),
    /// A reactive response-mode session.
    Response(ResponseOutcome),
}

impl SessionOutcome {
    /// Returns the session id.
    pub fn session_id(&self) -> &SessionId {
        match self {
            SessionOutcome::Guard(outcome) => &outcome.session_id,
            SessionOutcome::Response(outcome) => &outcome.session_id,
        }
    }

    /// Returns the risk level.
    pub fn risk_level(&self) -> RiskLevel {
        match self {
            SessionOutcome::Guard(outcome) => outcome.risk_level,
            SessionOutcome::Response(outcome) => outcome.risk_level,
        }
    }

    /// Returns the verdict.
    pub fn verdict(&self) -> Verdict {
        match self {
            SessionOutcome::Guard(outcome) => outcome.verdict,
            SessionOutcome::Response(outcome) => outcome.verdict,
        }
    }

    /// Returns the state timeline.
    pub fn timeline(&self) -> &Vec<(SessionState, u64)> {
        match self {
            SessionOutcome::Guard(outcome) => &outcome.timeline,
            SessionOutcome::Response(outcome) => &outcome.timeline,
        }
    }
}

/// Thread-safe list of finished sessions (newest last).
#[derive(Default)]
pub struct SessionStore {
    sessions: Mutex<Vec<SessionOutcome>>,
}

impl SessionStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a finished guard-mode outcome.
    pub fn push_guard(&self, outcome: GuardOutcome) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sessions.push(SessionOutcome::Guard(outcome));
    }

    /// Records a finished response-mode outcome.
    pub fn push_response(&self, outcome: ResponseOutcome) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sessions.push(SessionOutcome::Response(outcome));
    }

    /// Returns all outcomes, newest first.
    pub fn list(&self) -> Vec<SessionOutcome> {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sessions.iter().rev().cloned().collect()
    }

    /// Returns one outcome by session id.
    pub fn get(&self, session_id: &str) -> Option<SessionOutcome> {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sessions
            .iter()
            .find(|outcome| outcome.session_id().as_str() == session_id)
            .cloned()
    }

    /// Number of stored sessions.
    pub fn len(&self) -> usize {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sessions.len()
    }

    /// Returns `true` when the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::models::ids::SessionId;
    use crate::models::ids::TimestampMillis;
    use crate::models::messages::{RiskLevel, Verdict};
    use std::collections::BTreeMap;

    fn guard_outcome(id: &str) -> GuardOutcome {
        GuardOutcome {
            session_id: SessionId::new(id),
            source: crate::models::messages::EventSource::Manual,
            repo_url: "file:///demo".to_string(),
            commit_sha: "local-working-tree".to_string(),
            risk_level: RiskLevel::Low,
            verdict: Verdict::Allow,
            strategy: crate::models::messages::RemediationStrategy::CommentOnly,
            risk_profile: crate::models::messages::RiskProfile {
                session_id: SessionId::new(id),
                risk_level: RiskLevel::Low,
                recommended_action: crate::models::messages::RecommendedAction::Allow,
                evidence_chain: Vec::new(),
                human_review_reasons: Vec::new(),
                generated_at: TimestampMillis::now(),
            },
            remediation: crate::models::messages::RemediationResult {
                session_id: SessionId::new(id),
                success: true,
                artifacts: BTreeMap::new(),
                logs_hash: String::new(),
                regression_detected: None,
                completed_at: TimestampMillis::now(),
            },
            seal: crate::agents::auditor::SealReport {
                session_id: SessionId::new(id),
                verified: true,
                head_hash: "00".repeat(32),
            },
            timeline: Vec::new(),
            snapshot: None,
        }
    }

    fn response_outcome(id: &str) -> ResponseOutcome {
        ResponseOutcome {
            session_id: SessionId::new(id),
            cve_id: "CVE-2020-8203".to_string(),
            risk_level: RiskLevel::High,
            verdict: Verdict::RequireHumanReview,
            total_scanned: 3,
            affected_count: 1,
            affected_packages: Vec::new(),
            seal: crate::agents::auditor::SealReport {
                session_id: SessionId::new(id),
                verified: true,
                head_hash: "00".repeat(32),
            },
            timeline: Vec::new(),
            snapshot: None,
        }
    }

    #[test]
    fn push_list_returns_newest_first() {
        let store = SessionStore::new();
        assert!(store.is_empty());
        store.push_guard(guard_outcome("s-1"));
        store.push_guard(guard_outcome("s-2"));
        assert_eq!(store.len(), 2);
        let listed = store.list();
        assert_eq!(listed[0].session_id().as_str(), "s-2");
        assert_eq!(listed[1].session_id().as_str(), "s-1");
    }

    #[test]
    fn push_response_mixed_with_guard() {
        let store = SessionStore::new();
        store.push_guard(guard_outcome("s-1"));
        store.push_response(response_outcome("s-2"));
        assert_eq!(store.len(), 2);
        let listed = store.list();
        assert_eq!(listed[0].session_id().as_str(), "s-2");
        assert_eq!(listed[1].session_id().as_str(), "s-1");
    }

    #[test]
    fn get_finds_by_session_id() {
        let store = SessionStore::new();
        store.push_guard(guard_outcome("s-42"));
        store.push_response(response_outcome("s-99"));
        assert!(store.get("s-42").is_some());
        assert!(store.get("s-99").is_some());
        assert!(store.get("missing").is_none());
    }
}

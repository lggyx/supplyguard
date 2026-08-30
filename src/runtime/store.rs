//! In-memory session store for completed outcomes.
//!
//! Local-first and single-process: the durable record of every session is
//! the audit chain; this store only serves the web console's read views
//! after restarts start empty (documented behavior, not a bug).

use crate::runtime::orchestrator::GuardOutcome;
use std::sync::Mutex;

/// Thread-safe list of finished sessions (newest last).
#[derive(Default)]
pub struct SessionStore {
    sessions: Mutex<Vec<GuardOutcome>>,
}

impl SessionStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a finished outcome.
    pub fn push(&self, outcome: GuardOutcome) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sessions.push(outcome);
    }

    /// Returns all outcomes, newest first.
    pub fn list(&self) -> Vec<GuardOutcome> {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sessions.iter().rev().cloned().collect()
    }

    /// Returns one outcome by session id.
    pub fn get(&self, session_id: &str) -> Option<GuardOutcome> {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sessions
            .iter()
            .find(|outcome| outcome.session_id.as_str() == session_id)
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

    fn outcome(id: &str) -> GuardOutcome {
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

    #[test]
    fn push_list_returns_newest_first() {
        let store = SessionStore::new();
        assert!(store.is_empty());
        store.push(outcome("s-1"));
        store.push(outcome("s-2"));
        assert_eq!(store.len(), 2);
        let listed = store.list();
        assert_eq!(listed[0].session_id.as_str(), "s-2");
        assert_eq!(listed[1].session_id.as_str(), "s-1");
    }

    #[test]
    fn get_finds_by_session_id() {
        let store = SessionStore::new();
        store.push(outcome("s-42"));
        assert!(store.get("s-42").is_some());
        assert!(store.get("missing").is_none());
    }
}

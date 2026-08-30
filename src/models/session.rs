//! Session lifecycle state machine.
//!
//! The lifecycle is the linear chain from the design doc:
//! `received -> analyzing -> arbitrating -> remediating -> verifying ->
//! sealed`. The legal transition table is defined once here; every other
//! transition is rejected with [`StateTransitionError`].

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Error returned when a session state transition is not allowed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("illegal session state transition from `{from}` to `{to}`")]
pub struct StateTransitionError {
    /// State the session was in.
    pub from: SessionState,
    /// State the session tried to enter.
    pub to: SessionState,
}

/// Lifecycle state of a guard / scan session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Task received, not yet analyzed.
    Received,
    /// Analyst is running skills.
    Analyzing,
    /// Auditor is arbitrating the risk profile.
    Arbitrating,
    /// Remediator is producing remediation artifacts.
    Remediating,
    /// Auditor is verifying the remediation result.
    Verifying,
    /// Verdict sealed into the audit chain; terminal state.
    Sealed,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            SessionState::Received => "received",
            SessionState::Analyzing => "analyzing",
            SessionState::Arbitrating => "arbitrating",
            SessionState::Remediating => "remediating",
            SessionState::Verifying => "verifying",
            SessionState::Sealed => "sealed",
        };
        f.write_str(name)
    }
}

/// The legal transition table, defined exactly once.
const TRANSITIONS: [(SessionState, SessionState); 5] = [
    (SessionState::Received, SessionState::Analyzing),
    (SessionState::Analyzing, SessionState::Arbitrating),
    (SessionState::Arbitrating, SessionState::Remediating),
    (SessionState::Remediating, SessionState::Verifying),
    (SessionState::Verifying, SessionState::Sealed),
];

impl SessionState {
    /// Returns the single legal successor state, if any.
    ///
    /// `Sealed` is terminal and returns `None`.
    pub fn next(&self) -> Option<SessionState> {
        TRANSITIONS
            .iter()
            .find(|(from, _)| from == self)
            .map(|(_, to)| *to)
    }

    /// Returns `true` only when the move to `to` is in the transition table.
    pub fn can_transition_to(&self, to: SessionState) -> bool {
        self.next() == Some(to)
    }

    /// Advances to `to`, rejecting moves that are not in the table.
    ///
    /// # Errors
    ///
    /// Returns [`StateTransitionError`] for any move absent from the legal
    /// transition table (skips, backwards moves, self-loops, leaving `Sealed`).
    pub fn advance(&self, to: SessionState) -> Result<SessionState, StateTransitionError> {
        if self.can_transition_to(to) {
            Ok(to)
        } else {
            Err(StateTransitionError { from: *self, to })
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn full_lifecycle_chain_is_accepted() {
        let states = [
            SessionState::Received,
            SessionState::Analyzing,
            SessionState::Arbitrating,
            SessionState::Remediating,
            SessionState::Verifying,
            SessionState::Sealed,
        ];
        for pair in states.windows(2) {
            let advanced = pair[0]
                .advance(pair[1])
                .expect("linear chain transition must be legal");
            assert_eq!(advanced, pair[1]);
        }
    }

    #[test]
    fn rejects_skip_and_backwards_and_self_and_terminal_transitions() {
        let cases = [
            (SessionState::Received, SessionState::Sealed),
            (SessionState::Received, SessionState::Arbitrating),
            (SessionState::Analyzing, SessionState::Received),
            (SessionState::Sealed, SessionState::Analyzing),
            (SessionState::Analyzing, SessionState::Analyzing),
        ];
        for (from, to) in cases {
            let err = from.advance(to).expect_err("transition must be rejected");
            assert_eq!(err.from, from);
            assert_eq!(err.to, to);
            assert!(!from.can_transition_to(to));
        }
    }

    #[test]
    fn next_is_none_at_sealed() {
        assert_eq!(SessionState::Sealed.next(), None);
        assert_eq!(SessionState::Received.next(), Some(SessionState::Analyzing));
    }

    #[test]
    fn session_state_serializes_to_snake_case() {
        let json = serde_json::to_string(&SessionState::Arbitrating).expect("serialize");
        assert_eq!(json, "\"arbitrating\"");
        let back: SessionState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, SessionState::Arbitrating);
    }
}

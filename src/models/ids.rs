//! Newtype identifiers used across the message protocol.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

macro_rules! string_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates a new identifier from any string-like value.
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Returns the identifier as a string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

string_id! {
    /// Unique identifier of one guard / scan session.
    SessionId
}

string_id! {
    /// Identifier of a built SBOM snapshot.
    SbomId
}

/// Milliseconds since the Unix epoch.
///
/// Used instead of a date-time library (not on the allowed dependency list);
/// lexical order equals chronological order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TimestampMillis(u64);

impl TimestampMillis {
    /// Current wall-clock time in milliseconds since the epoch.
    ///
    /// A clock set before the epoch yields `0` instead of panicking.
    pub fn now() -> Self {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self(millis)
    }

    /// Returns the raw millisecond value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for TimestampMillis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn session_id_survives_serde_roundtrip() {
        let original = SessionId::new("session-42");
        let json = serde_json::to_string(&original).expect("serialize");
        assert_eq!(json, "\"session-42\"");
        let back: SessionId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, original);
    }

    #[test]
    fn sbom_id_display_matches_inner_string() {
        let id = SbomId::new("sbom-abc");
        assert_eq!(id.to_string(), "sbom-abc");
        assert_eq!(id.as_str(), "sbom-abc");
    }

    #[test]
    fn timestamp_now_is_after_epoch_and_roundtrips() {
        let ts = TimestampMillis::now();
        assert!(ts.as_u64() > 0);
        let json = serde_json::to_string(&ts).expect("serialize");
        let back: TimestampMillis = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, ts);
    }
}

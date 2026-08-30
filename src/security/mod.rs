//! Onion L2/L3: security primitives over untrusted content.
//!
//! [`sanitize`] strips invisible and control characters; [`injection`]
//! scans cleaned text for instruction-override patterns. Both are
//! deterministic and corpus-tested.

pub mod injection;
pub mod sanitize;

pub use injection::{InjectionDetector, InjectionError, InjectionRules, InjectionScan};
pub use sanitize::{Sanitized, sanitize};

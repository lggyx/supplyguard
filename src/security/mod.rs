//! Onion L2: security primitives over untrusted content.
//!
//! [`sanitize`] strips invisible and control characters before untrusted
//! content is consumed downstream. Deterministic and corpus-tested; the
//! injection detector lands in the next unit.

pub mod sanitize;

pub use sanitize::{Sanitized, sanitize};

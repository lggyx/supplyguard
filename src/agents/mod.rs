//! The four SupplyGuard agents.
//!
//! Role boundaries (PROMPT 4.2 / 5.1-5.4):
//! - [`Sentinel`]: entry routing + UNTRUSTED tagging; holds no skills.
//! - [`Analyst`]: read-only profiling; holds analysis skills + the injection
//!   detector; can never mutate anything.
//! - [`Auditor`]: arbitration + audit chain writes; its inputs (RiskProfile /
//!   RemediationResult) carry no untrusted raw text by construction.
//! - [`Remediator`]: produces suggestion artifacts; holds no write tools.

pub mod analyst;
pub mod auditor;
pub mod remediator;
pub mod sentinel;

pub use analyst::Analyst;
pub use auditor::Auditor;
pub use remediator::Remediator;
pub use sentinel::{Sentinel, UntrustedContext};

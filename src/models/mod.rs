//! Structured message models shared by every layer.
//!
//! All types are serde-serializable and carry no business logic. They mirror
//! the inter-agent protocol: `AnalysisRequest` (Sentinel -> Analyst),
//! `RiskProfile` (Analyst -> Auditor), `RemediationOrder` (Auditor ->
//! Remediator), `RemediationResult` (Remediator -> Auditor) and `Verdict`.

pub mod ids;
pub mod messages;
pub mod session;

//! SupplyGuard - AI 编程时代的供应链安全防御 CLI 工具

pub mod config;
pub mod pipeline;
pub mod agents;
pub mod skills;
pub mod mcp;
pub mod store;
pub mod audit;
pub mod output;
pub mod models;

pub use pipeline::orchestrator::Orchestrator;
pub use agents::analyst::Analyst;
pub use agents::auditor::{Auditor, Verdict};
pub use agents::cve::CveAgent;
pub use agents::hallucination::HallucinationAgent;
pub use agents::license::LicenseAgent;
pub use agents::sentinel::Sentinel;
pub use mcp::{NpmLocal, OsvLocal, SpdxLocal};

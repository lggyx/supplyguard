//! Runtime: in-process orchestration of the guard loop.

pub mod orchestrator;
pub mod store;

pub use orchestrator::{GuardOutcome, LocalOrchestrator, OrchestratorEvent, RuntimeTools};
pub use store::SessionStore;

//! Tamper-evident audit storage (onion L7).
//!
//! `chain` implements the append-only HMAC hash chain described in the
//! master prompt: `h_n = HMAC(key, h_{n-1} ‖ entry_n)` over a SQLite
//! append-only table. Read accessors exist for reporting and the web
//! console; there is intentionally no update or delete path.

pub mod chain;

pub use chain::{AgentAction, AppendInput, AuditChain, AuditEntry, AuditError, ChainVerification};

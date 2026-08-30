//! SupplyGuard: multi-Agent supply chain security defense system.
//!
//! Guard-mode local loop: scan npm dependency changes, fuse security signals
//! into a structured risk profile, arbitrate a verdict, and seal it into a
//! tamper-evident audit chain.

#![forbid(unsafe_code)]

pub mod audit;
pub mod mcp;
pub mod models;
pub mod security;
pub mod skills;

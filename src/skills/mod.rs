//! Skill layer: reusable capabilities invoked by agents.
//!
//! Every skill implements [`Skill`] with typed input/output and explicit
//! degradation semantics: partial results carry machine-readable problems in
//! the output, fatal failures raise [`SkillError`] so the pipeline can fail
//! conservatively (never silently allow). Skills never perform network IO —
//! external data flows in through `mcp` traits.

pub mod cve_match;
pub mod hallucination_check;
pub mod license_check;
pub mod sbom_build;

use thiserror::Error;

/// Errors raised by skill implementations on fatal (non-degradable) paths.
#[derive(Debug, Error)]
pub enum SkillError {
    /// The skill input references something that does not exist.
    #[error("invalid skill input: {0}")]
    InvalidInput(String),
    /// Local IO failed while reading skill input files.
    #[error("skill io error: {0}")]
    Io(String),
    /// A skill's own capability dependency is misconfigured.
    #[error("skill internal error: {0}")]
    Internal(String),
}

/// Common shape for every SupplyGuard skill.
pub trait Skill {
    /// Input type consumed by [`Skill::run`].
    type Input;
    /// Output type produced by [`Skill::run`].
    type Output;

    /// Skill name, matching the design-doc card (e.g. `sbom-build`).
    fn name(&self) -> &'static str;

    /// One-line description of what the skill does.
    fn description(&self) -> &'static str;

    /// Executes the skill.
    ///
    /// # Errors
    ///
    /// Returns [`SkillError`] only for fatal paths; degradable anomalies are
    /// reported inside the output so the pipeline can proceed conservatively.
    fn run(&self, input: &Self::Input) -> Result<Self::Output, SkillError>;
}

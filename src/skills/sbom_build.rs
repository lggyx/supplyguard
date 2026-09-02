use thiserror::Error;

/// SBOM 构建错误
#[derive(Debug, Error)]
pub enum SbomBuildError {
    #[error("invalid lockfile: {0}")]
    InvalidLockfile(String),
}

pub struct SbomBuildSkill;

impl SbomBuildSkill {
    pub fn new() -> Self {
        Self
    }

    pub async fn build(&self, path: &str) -> Result<(), SbomBuildError> {
        // TODO: 解析 package-lock.json，构建 SBOM
        Ok(())
    }
}

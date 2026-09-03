use serde::Serialize;

/// Auditor 错误
#[derive(Debug, thiserror::Error)]
pub enum AuditorError {
    #[error("verdict failed: {0}")]
    VerdictFailed(String),
}

pub struct Auditor;

impl Auditor {
    pub fn new() -> Self {
        Self
    }

    /// 综合多信号，生成裁决
    pub fn issue_verdict(
        &self,
        package: &str,
        version: &str,
        hallucination: Option<&crate::agents::hallucination::HallucinationResult>,
        cve: Option<&crate::agents::cve::CveResult>,
        license: Option<&crate::agents::license::LicenseResult>,
    ) -> Result<Verdict, AuditorError> {
        // 优先级：幻觉包 > CVE Critical > CVE High > License > 其他

        if let Some(h) = hallucination {
            if h.is_hallucination {
                return Ok(Verdict {
                    package: package.to_string(),
                    version: version.to_string(),
                    decision: "BLOCK".to_string(),
                    reasoning: h.reasoning.clone(),
                    evidence: h.evidence.clone(),
                    confidence: h.confidence,
                    agent: "Auditor".to_string(),
                });
            }
        }

        if let Some(c) = cve {
            if c.has_cve {
                let decision = match c.severity.as_str() {
                    "critical" | "high" => "BLOCK",
                    "medium" => "REVIEW",
                    _ => "ALLOW",
                };

                return Ok(Verdict {
                    package: package.to_string(),
                    version: version.to_string(),
                    decision: decision.to_string(),
                    reasoning: c.reasoning.clone(),
                    evidence: c.vulns.clone(),
                    confidence: if decision == "BLOCK" { 0.9 } else { 0.7 },
                    agent: "Auditor".to_string(),
                });
            }
        }

        if let Some(l) = license {
            if !l.compliant {
                return Ok(Verdict {
                    package: package.to_string(),
                    version: version.to_string(),
                    decision: "REVIEW".to_string(),
                    reasoning: l.reasoning.clone(),
                    evidence: vec![l.normalized_license.clone()],
                    confidence: 0.6,
                    agent: "Auditor".to_string(),
                });
            }
        }

        Ok(Verdict {
            package: package.to_string(),
            version: version.to_string(),
            decision: "ALLOW".to_string(),
            reasoning: format!("{}@{} 无已知风险", package, version),
            evidence: Vec::new(),
            confidence: 0.95,
            agent: "Auditor".to_string(),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub package: String,
    pub version: String,
    pub decision: String,
    pub reasoning: String,
    pub evidence: Vec<String>,
    pub confidence: f64,
    pub agent: String,
}

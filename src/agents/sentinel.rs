//! Sentinel: the single entry point that tags untrusted content.

use crate::models::ids::{SessionId, TimestampMillis};
use crate::models::messages::{AnalysisRequest, DependencyChange, EventSource};

/// Sentinel agent: perceives external events and tags all external text as
/// UNTRUSTED before anything downstream can consume it (onion L1).
///
/// Stateless by design: tagging is a pure role function, so the sentinel
/// holds no tools, no IO handles, and no security judgment.
#[derive(Debug, Clone, Default)]
pub struct Sentinel;

impl Sentinel {
    /// Wraps raw external text in `<untrusted_source>` boundary markers.
    /// Already-tagged text is returned unchanged (idempotent).
    pub fn tag_untrusted(&self, text: &str) -> String {
        if text.starts_with("<untrusted_source>") {
            text.to_string()
        } else {
            format!("<untrusted_source>\n{text}\n</untrusted_source>")
        }
    }

    /// Builds an `AnalysisRequest` from session metadata and raw changes,
    /// tagging every change's context text.
    pub fn build_request(
        &self,
        session_id: SessionId,
        source: EventSource,
        repo_url: String,
        commit_sha: String,
        raw_changes: Vec<DependencyChange>,
    ) -> AnalysisRequest {
        let changes = raw_changes
            .into_iter()
            .map(|mut change| {
                change.context_text = self.tag_untrusted(&change.context_text);
                change
            })
            .collect();
        AnalysisRequest {
            session_id,
            source,
            repo_url,
            commit_sha,
            changes,
            created_at: TimestampMillis::now(),
        }
    }
}

/// Re-exported alias documenting that `context_text` fields carry wrapped
/// untrusted content once Sentinel has processed them.
pub type UntrustedContext = String;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn tags_raw_text_with_untrusted_boundaries() {
        let tagged = Sentinel.tag_untrusted("import x from 'lodos'");
        assert!(tagged.starts_with("<untrusted_source>"));
        assert!(tagged.ends_with("</untrusted_source>"));
        assert!(tagged.contains("import x from 'lodos'"));
    }

    #[test]
    fn tagging_is_idempotent() {
        let once = Sentinel.tag_untrusted("hello");
        let twice = Sentinel.tag_untrusted(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn build_request_tags_every_change_context() {
        let request = Sentinel.build_request(
            SessionId::new("s-1"),
            EventSource::GitHubPr,
            "https://github.com/acme/demo-app".to_string(),
            "deadbeef".to_string(),
            vec![
                DependencyChange {
                    package_name: "lodos".to_string(),
                    old_version: None,
                    new_version: Some("^1.0.0".to_string()),
                    is_new: true,
                    ecosystem: "npm".to_string(),
                    context_text: "raw diff text".to_string(),
                },
                DependencyChange {
                    package_name: "lodash".to_string(),
                    old_version: Some("4.16.0".to_string()),
                    new_version: Some("4.17.3".to_string()),
                    is_new: false,
                    ecosystem: "npm".to_string(),
                    context_text: "<untrusted_source>\nalready tagged\n</untrusted_source>"
                        .to_string(),
                },
            ],
        );
        assert_eq!(request.changes.len(), 2);
        assert!(
            request.changes[0]
                .context_text
                .starts_with("<untrusted_source>")
        );
        assert_eq!(
            request.changes[1].context_text,
            "<untrusted_source>\nalready tagged\n</untrusted_source>"
        );
        assert_eq!(request.session_id, SessionId::new("s-1"));
        assert!(request.created_at.as_u64() > 0);
    }
}

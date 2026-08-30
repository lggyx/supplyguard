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

    /// Parses a unified diff of dependency manifests into change candidates.
    ///
    /// Recognizes two shapes (v1):
    /// - lockfile entries: a `"node_modules/<name>": {` line (context, `+`
    ///   or `-`) selects the current node; a following `+`/`-"version": "X"`
    ///   line records the new/old version. This handles real-world diffs
    ///   where only the version line changed;
    /// - package.json dependency lines: `+"<name>": "<range>"`.
    ///
    /// Removals (`-` lines) fill `old_version` for the same package, so an
    /// upgrade yields one change with both versions; pure additions are
    /// `is_new = true`. Lines without dependency semantics are ignored.
    pub fn parse_diff(&self, diff_text: &str) -> Vec<DependencyChange> {
        #[derive(Default)]
        struct Versions {
            entries: Vec<(String, Option<String>)>,
        }
        impl Versions {
            fn record_node(&mut self, name: &str) {
                if !self.entries.iter().any(|(existing, _)| existing == name) {
                    self.entries.push((name.to_string(), None));
                }
            }
            fn record_version(&mut self, name: &str, version: &str) {
                if let Some((_, slot)) = self
                    .entries
                    .iter_mut()
                    .find(|(existing, _)| existing == name)
                {
                    *slot = Some(version.to_string());
                } else {
                    self.entries
                        .push((name.to_string(), Some(version.to_string())));
                }
            }
            fn version_of(&self, name: &str) -> Option<String> {
                self.entries
                    .iter()
                    .find(|(existing, _)| existing == name)
                    .and_then(|(_, version)| version.clone())
            }
            fn names(&self) -> impl Iterator<Item = &String> {
                self.entries.iter().map(|(name, _)| name)
            }
        }

        let mut added = Versions::default();
        let mut removed = Versions::default();
        let mut current_node: Option<String> = None;

        for raw in diff_text.lines() {
            // Unified-diff side classification: '+' added, '-' removed,
            // anything else is context (or a header we ignore).
            let (side, line) = if raw.starts_with("+++") || raw.starts_with("---") {
                continue;
            } else if let Some(rest) = raw.strip_prefix('+') {
                ('+', rest)
            } else if let Some(rest) = raw.strip_prefix('-') {
                ('-', rest)
            } else {
                (' ', raw)
            };
            let trimmed = line.trim();

            if let Some(name) = lockfile_node_name(trimmed) {
                current_node = Some(name.clone());
                match side {
                    '+' => added.record_node(&name),
                    '-' => removed.record_node(&name),
                    _ => {}
                }
                continue;
            }
            if side == ' ' {
                continue;
            }
            if let Some((field, value)) = quoted_pair(trimmed) {
                if field == "version" {
                    if let Some(name) = &current_node {
                        match side {
                            '+' => added.record_version(name, &value),
                            _ => removed.record_version(name, &value),
                        }
                    }
                    continue;
                }
                if is_reserved_manifest_field(&field) {
                    continue;
                }
                // package.json style: `"name": "range"`.
                match side {
                    '+' => added.record_version(&field, &value),
                    _ => removed.record_version(&field, &value),
                }
            }
        }

        let mut names: Vec<String> = added
            .names()
            .cloned()
            .chain(removed.names().cloned())
            .collect();
        names.sort();
        names.dedup();

        names
            .into_iter()
            .map(|name| {
                let new_version = added.version_of(&name);
                let old_version = removed.version_of(&name);
                let is_new = old_version.is_none();
                let context_text = match (&new_version, &old_version) {
                    (Some(new), Some(old)) => format!("package {name} upgraded {old} -> {new}"),
                    (Some(new), None) => format!("package {name} added at {new}"),
                    (None, Some(old)) => format!("package {name} removed (was {old})"),
                    (None, None) => format!("package {name} changed"),
                };
                DependencyChange {
                    package_name: name.clone(),
                    old_version,
                    new_version: new_version.clone(),
                    is_new,
                    ecosystem: "npm".to_string(),
                    context_text,
                }
            })
            .collect()
    }
}

/// Extracts the package name from a lockfile `packages` map key line, e.g.
/// `"node_modules/lodash": {` -> `lodash`.
fn lockfile_node_name(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("\"node_modules/")?;
    let name = rest.split_once('"')?.0;
    if trimmed.trim_end().ends_with('{') || trimmed.ends_with(':') || trimmed.ends_with("\": {") {
        Some(name.to_string())
    } else {
        None
    }
}

/// Parses `"field": "value"` (both sides quoted); returns None otherwise.
fn quoted_pair(trimmed: &str) -> Option<(String, String)> {
    let (field_part, value_part) = trimmed.split_once(':')?;
    let field = field_part.trim().trim_matches('"').to_string();
    let value = value_part.trim().trim_end_matches(',').trim();
    let value = value.strip_prefix('"')?.strip_suffix('"')?;
    if field.is_empty() || value.is_empty() {
        return None;
    }
    Some((field, value.to_string()))
}

/// Manifest structural fields that are never package names.
fn is_reserved_manifest_field(field: &str) -> bool {
    matches!(
        field,
        "version"
            | "resolved"
            | "integrity"
            | "dev"
            | "devDependencies"
            | "dependencies"
            | "peerDependencies"
            | "optionalDependencies"
            | "license"
            | "licenses"
            | "name"
            | "requires"
            | "bin"
            | "engines"
            | "funding"
            | "main"
            | "types"
    )
}

/// Re-exported alias documenting that `context_text` fields carry wrapped
/// untrusted content once Sentinel has processed them.
pub type UntrustedContext = String;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn parse_diff_reads_lockfile_addition() {
        let diff = "--- a/package-lock.json\n+++ b/package-lock.json\n@@ -1,4 +1,8 @@\n\
             \"node_modules/express\": {\n  \"version\": \"4.17.3\"\n},\n\
             +\"node_modules/lodos\": {\n+  \"version\": \"1.0.0\",\n+  \"integrity\": \"x\"\n+},\n";
        let changes = Sentinel.parse_diff(diff);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].package_name, "lodos");
        assert_eq!(changes[0].new_version.as_deref(), Some("1.0.0"));
        assert!(changes[0].is_new);
    }

    #[test]
    fn parse_diff_merges_upgrade_into_one_change() {
        let diff = "--- a/package-lock.json\n+++ b/package-lock.json\n\
            -\"node_modules/express\": {\n-  \"version\": \"4.16.0\",\n\
            +\"node_modules/express\": {\n+  \"version\": \"4.17.3\",\n";
        let changes = Sentinel.parse_diff(diff);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].package_name, "express");
        assert_eq!(changes[0].old_version.as_deref(), Some("4.16.0"));
        assert_eq!(changes[0].new_version.as_deref(), Some("4.17.3"));
        assert!(!changes[0].is_new);
    }

    #[test]
    fn parse_diff_catches_upgrades_where_node_line_is_context() {
        // Regression: real diffs show the node line as CONTEXT and only the
        // version lines as -/+; missing this silently yields no changes.
        let diff = "--- a/package-lock.json\n+++ b/package-lock.json\n@@ -10,7 +10,7 @@\n\
             },\n\
              \"node_modules/express\": {\n\
            -  \"version\": \"4.16.0\",\n\
            +  \"version\": \"4.17.3\",\n\
               \"license\": \"MIT\"\n\
             },\n\
              \"node_modules/lodash\": {\n\
            -  \"version\": \"4.17.4\",\n\
            +  \"version\": \"4.17.21\",\n";
        let changes = Sentinel.parse_diff(diff);
        assert_eq!(changes.len(), 2, "express and lodash upgrades");
        let express = changes
            .iter()
            .find(|change| change.package_name == "express")
            .expect("express");
        assert_eq!(express.old_version.as_deref(), Some("4.16.0"));
        assert_eq!(express.new_version.as_deref(), Some("4.17.3"));
        let lodash = changes
            .iter()
            .find(|change| change.package_name == "lodash")
            .expect("lodash");
        assert_eq!(lodash.new_version.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn parse_diff_reads_package_json_dependency_line() {
        let diff = "--- a/package.json\n+++ b/package.json\n\
            +    \"lodos\": \"^1.0.0\",\n";
        let changes = Sentinel.parse_diff(diff);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].package_name, "lodos");
        assert_eq!(changes[0].new_version.as_deref(), Some("^1.0.0"));
    }

    #[test]
    fn parse_diff_ignores_structural_fields_and_non_dependency_files() {
        let readme_diff = "--- a/README.md\n+++ b/README.md\n+just text here\n";
        assert!(Sentinel.parse_diff(readme_diff).is_empty());
        let lock_noise = "--- a/package-lock.json\n+++ b/package-lock.json\n\
            +  \"version\": \"3.0.0\",\n+  \"name\": \"demo-app\",\n+  \"resolved\": \"https://x\"\n";
        assert!(Sentinel.parse_diff(lock_noise).is_empty());
    }

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

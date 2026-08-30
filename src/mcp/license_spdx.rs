//! SPDX license data: built-in identifier subset plus alias normalization.
//!
//! Mirrors the Python reference semantics: SPDX expressions (`A OR B`) resolve
//! to the first arm; known aliases map to canonical SPDX ids; unknown
//! non-empty strings pass through unchanged (license-check then routes them
//! to human confirmation instead of auto-blocking).

use crate::mcp::LicenseDb;

/// Canonical SPDX identifiers known to the built-in subset.
const SPDX_KNOWN: &[&str] = &[
    "MIT",
    "ISC",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "0BSD",
    "Unlicense",
    "CC0-1.0",
    "MPL-2.0",
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
];

/// Common alias spellings mapped to canonical SPDX ids.
const ALIASES: &[(&str, &str)] = &[
    ("apache 2.0", "Apache-2.0"),
    ("apache-2", "Apache-2.0"),
    ("apache2", "Apache-2.0"),
    ("apache license 2.0", "Apache-2.0"),
    ("apache-2.0", "Apache-2.0"),
    ("bsd", "BSD-3-Clause"),
    ("bsd-2-clause", "BSD-2-Clause"),
    ("bsd-3-clause", "BSD-3-Clause"),
    ("gpl", "GPL-3.0"),
    ("gpl-2.0", "GPL-2.0"),
    ("gpl-3.0", "GPL-3.0"),
    ("gplv2", "GPL-2.0"),
    ("gplv3", "GPL-3.0"),
    ("agpl-3.0", "AGPL-3.0"),
    ("lgpl-2.1", "LGPL-2.1"),
    ("lgpl-3.0", "LGPL-3.0"),
    ("mit", "MIT"),
    ("isc", "ISC"),
    ("unlicense", "Unlicense"),
    ("cc0-1.0", "CC0-1.0"),
    ("mpl-2.0", "MPL-2.0"),
    ("mozilla public license 2.0", "MPL-2.0"),
];

/// Returns the first arm of an SPDX expression (`A OR B` / `A AND B`).
fn first_arm(raw: &str) -> &str {
    let lower = raw.to_ascii_lowercase();
    for separator in [" or ", " and "] {
        if let Some(position) = lower.find(separator) {
            return &raw[..position];
        }
    }
    raw
}

/// Built-in SPDX license database.
#[derive(Debug, Clone, Default)]
pub struct SpdxLocal;

impl SpdxLocal {
    /// Creates the built-in license database.
    ///
    /// # Errors
    ///
    /// 无 — the dataset is a compile-time constant.
    pub fn new() -> Result<Self, crate::mcp::McpError> {
        Ok(Self)
    }
}

impl LicenseDb for SpdxLocal {
    fn normalize(&self, raw_license: &str) -> Option<String> {
        if raw_license.trim().is_empty() {
            return None;
        }
        let arm = first_arm(raw_license)
            .trim()
            .trim_matches(|ch| ch == '(' || ch == ')')
            .trim();
        let key = arm.to_ascii_lowercase();
        Some(
            ALIASES
                .iter()
                .find(|(alias, _)| *alias == key)
                .map(|(_, canonical)| canonical.to_string())
                .unwrap_or_else(|| arm.to_string()),
        )
    }

    fn is_known(&self, canonical: &str) -> bool {
        SPDX_KNOWN.contains(&canonical)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn db() -> SpdxLocal {
        SpdxLocal::new().expect("spdx db builds")
    }

    #[test]
    fn aliases_normalize_to_canonical_ids() {
        let cases = [
            ("mit", "MIT"),
            ("MIT", "MIT"),
            ("gpl-3.0", "GPL-3.0"),
            ("GPLv3", "GPL-3.0"),
            ("apache2", "Apache-2.0"),
            ("Apache 2.0", "Apache-2.0"),
            ("bsd", "BSD-3-Clause"),
            ("mozilla public license 2.0", "MPL-2.0"),
        ];
        for (raw, expected) in cases {
            assert_eq!(db().normalize(raw), Some(expected.to_string()), "{raw}");
        }
    }

    #[test]
    fn spdx_expressions_resolve_to_first_arm() {
        assert_eq!(
            db().normalize("(MIT OR Apache-2.0)"),
            Some("MIT".to_string())
        );
        assert_eq!(
            db().normalize("GPL-3.0 AND MIT"),
            Some("GPL-3.0".to_string())
        );
    }

    #[test]
    fn unknown_licenses_pass_through_and_are_not_known() {
        assert_eq!(
            db().normalize("SuperLicense-9.9"),
            Some("SuperLicense-9.9".to_string())
        );
        assert!(!db().is_known("SuperLicense-9.9"));
        assert!(db().is_known("MIT"));
    }

    #[test]
    fn empty_and_whitespace_normalize_to_none() {
        assert_eq!(db().normalize(""), None);
        assert_eq!(db().normalize("   "), None);
    }
}

//! Offline npm registry equivalent.
//!
//! Holds a built-in set of well-known package names (the offline demo and
//! CI dataset). "Exists" means membership in that set — deliberately
//! conservative: anything unknown is reported as not existing, which drives
//! hallucination-check towards human review instead of silent allow.

use crate::mcp::{McpError, RegistryClient};
use std::collections::BTreeSet;

/// Well-known npm packages known to the offline registry (superset of the
/// similarity reference list; includes common transitive helpers).
const KNOWN_PACKAGES: &[&str] = &[
    "lodash",
    "axios",
    "react",
    "express",
    "typescript",
    "next",
    "vue",
    "webpack",
    "jest",
    "prettier",
    "eslint",
    "moment",
    "date-fns",
    "commander",
    "chalk",
    "semver",
    "uuid",
    "dotenv",
    "jsonwebtoken",
    "bcrypt",
    "mongoose",
    "prisma",
    "zod",
    "tailwindcss",
    "@types/node",
    "left-pad",
    "ms",
    "debug",
    "rimraf",
];

/// Offline implementation of [`RegistryClient`].
#[derive(Debug, Clone)]
pub struct NpmLocal {
    known: BTreeSet<String>,
}

impl NpmLocal {
    /// Builds the offline registry from the built-in dataset.
    ///
    /// # Errors
    ///
    /// 无 — the dataset is a compile-time constant.
    pub fn new() -> Result<Self, McpError> {
        Ok(Self {
            known: KNOWN_PACKAGES.iter().map(|name| name.to_string()).collect(),
        })
    }

    /// Builds the registry from an explicit name list (tests / extensions).
    ///
    /// # Errors
    ///
    /// 无 — an in-memory set construction cannot fail.
    pub fn from_names(names: &[&str]) -> Result<Self, McpError> {
        Ok(Self {
            known: names.iter().map(|name| name.to_string()).collect(),
        })
    }
}

impl RegistryClient for NpmLocal {
    fn exists(&self, package_name: &str) -> Result<bool, McpError> {
        Ok(self.known.contains(package_name))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn popular_packages_exist_and_unknown_do_not() {
        let registry = NpmLocal::new().expect("offline registry builds");
        assert!(registry.exists("lodash").expect("query"));
        assert!(registry.exists("@types/node").expect("query"));
        assert!(!registry.exists("lodos").expect("query"));
        assert!(!registry.exists("").expect("query"));
    }

    #[test]
    fn explicit_name_list_is_honored() {
        let registry = NpmLocal::from_names(&["only-this"]).expect("build");
        assert!(registry.exists("only-this").expect("query"));
        assert!(!registry.exists("lodash").expect("query"));
    }
}

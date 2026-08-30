//! Append-only, HMAC-signed audit chain on SQLite (onion L7).
//!
//! Every entry is hashed as `h_n = HMAC(key, h_{n-1} ‖ canonical_entry_n)`
//! with the genesis predecessor fixed to 32 zero bytes. The module exposes
//! only append and verify operations — there is no code path that updates or
//! deletes stored entries, and untrusted raw text is never stored (text
//! fields are limited to the system-generated `summary` and `evidence_hash`).

use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use std::sync::Mutex;
use thiserror::Error;

use crate::models::ids::TimestampMillis;

/// SHA-256 output width in bytes.
const HASH_LEN: usize = 32;

/// Genesis predecessor hash: 32 zero bytes.
const GENESIS_PREV: [u8; HASH_LEN] = [0u8; HASH_LEN];

/// Errors raised by the audit chain.
#[derive(Debug, Error)]
pub enum AuditError {
    /// SQLite storage failure.
    #[error("audit storage error: {0}")]
    Db(#[from] rusqlite::Error),
    /// Canonical serialization failure (a bug, not an input condition).
    #[error("audit entry serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// The internal connection mutex was poisoned by a panic elsewhere.
    #[error("audit chain lock poisoned")]
    LockPoisoned,
    /// The signing key was rejected by the HMAC implementation.
    #[error("audit signing key rejected: {0}")]
    Key(String),
}

/// One agent action recorded alongside an audit entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAction {
    /// Agent that performed the action (e.g. `Auditor`).
    pub agent: String,
    /// What the agent did (e.g. `arbitrate`).
    pub action: String,
}

/// Data for a new audit entry (everything except the derived hash fields).
#[derive(Debug, Clone)]
pub struct AppendInput {
    /// Session the entry belongs to.
    pub session_id: String,
    /// Event kind (e.g. `verdict`, `sealed`).
    pub event: String,
    /// Verdict value when the event is a decision; empty otherwise.
    pub verdict: String,
    /// Evidence fingerprint hash; never untrusted raw text.
    pub evidence_hash: String,
    /// System-generated summary; never untrusted raw text.
    pub summary: String,
    /// Agent actions to record.
    pub agent_actions: Vec<AgentAction>,
}

/// A stored, hash-chained audit entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Row id (1-based, insertion order).
    pub id: i64,
    /// Session the entry belongs to.
    pub session_id: String,
    /// Event kind.
    pub event: String,
    /// Verdict value when the event is a decision; empty otherwise.
    pub verdict: String,
    /// Evidence fingerprint hash.
    pub evidence_hash: String,
    /// System-generated summary.
    pub summary: String,
    /// Recorded agent actions.
    pub agent_actions: Vec<AgentAction>,
    /// Entry creation time (ms since epoch).
    pub timestamp: TimestampMillis,
    /// Predecessor hash (32 zero bytes for the first entry).
    pub prev_hash: [u8; HASH_LEN],
    /// `HMAC(key, prev_hash ‖ canonical_body)`.
    pub entry_hash: [u8; HASH_LEN],
}

/// Result of walking the whole chain and recomputing every hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainVerification {
    /// True when every entry's stored hash matches the recomputed chain.
    pub intact: bool,
    /// Number of entries checked.
    pub entries_checked: usize,
    /// 1-based id of the first entry whose hash does not verify.
    pub broken_at: Option<i64>,
}

/// Canonical byte encoding of an entry body (everything covered by the HMAC).
#[derive(Serialize)]
struct ChainBody<'a> {
    session_id: &'a str,
    event: &'a str,
    verdict: &'a str,
    evidence_hash: &'a str,
    summary: &'a str,
    agent_actions: &'a [AgentAction],
    timestamp: u64,
    /// Predecessor hash as lowercase hex (fixed 64 chars).
    prev_hash: &'a str,
}

/// Append-only audit chain backed by a SQLite table.
pub struct AuditChain {
    conn: Mutex<Connection>,
    key: Vec<u8>,
}

impl AuditChain {
    /// Opens (or creates) the audit database at `path` with `key` as the
    /// HMAC-SHA256 signing key.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when the database cannot be opened or the
    /// schema cannot be created.
    pub fn open(path: &Path, key: &[u8]) -> Result<Self, AuditError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_entries (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    TEXT    NOT NULL,
                event         TEXT    NOT NULL,
                verdict       TEXT    NOT NULL DEFAULT '',
                evidence_hash TEXT    NOT NULL DEFAULT '',
                summary       TEXT    NOT NULL DEFAULT '',
                agent_actions TEXT    NOT NULL DEFAULT '[]',
                timestamp     INTEGER NOT NULL,
                prev_hash     BLOB    NOT NULL,
                entry_hash    BLOB    NOT NULL
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            key: key.to_vec(),
        })
    }

    /// Appends one entry and returns it with its computed chain hash.
    ///
    /// The predecessor hash is read inside the same lock, so concurrent
    /// appends stay linearized.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] on storage or serialization failure. Callers
    /// own the retry policy (retry, then leave the task open).
    pub fn append(&self, input: &AppendInput) -> Result<AuditEntry, AuditError> {
        let conn = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let prev_hash: [u8; HASH_LEN] = conn
            .query_row(
                "SELECT entry_hash FROM audit_entries ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|bytes| bytes_try_into_32(&bytes))
            .transpose()?
            .unwrap_or(GENESIS_PREV);

        let timestamp = TimestampMillis::now();
        let body = ChainBody {
            session_id: &input.session_id,
            event: &input.event,
            verdict: &input.verdict,
            evidence_hash: &input.evidence_hash,
            summary: &input.summary,
            agent_actions: &input.agent_actions,
            timestamp: timestamp.as_u64(),
            prev_hash: &hex::encode(prev_hash),
        };
        let entry_hash = chain_hash(&self.key, &prev_hash, &body)?;

        let agent_actions_json = serde_json::to_string(&input.agent_actions)?;
        conn.execute(
            "INSERT INTO audit_entries
                (session_id, event, verdict, evidence_hash, summary,
                 agent_actions, timestamp, prev_hash, entry_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                input.session_id,
                input.event,
                input.verdict,
                input.evidence_hash,
                input.summary,
                agent_actions_json,
                i64::try_from(timestamp.as_u64()).unwrap_or(i64::MAX),
                prev_hash.to_vec(),
                entry_hash.to_vec(),
            ],
        )?;
        let id = conn.last_insert_rowid();

        Ok(AuditEntry {
            id,
            session_id: input.session_id.clone(),
            event: input.event.clone(),
            verdict: input.verdict.clone(),
            evidence_hash: input.evidence_hash.clone(),
            summary: input.summary.clone(),
            agent_actions: input.agent_actions.clone(),
            timestamp,
            prev_hash,
            entry_hash,
        })
    }

    /// Returns all entries in insertion order.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] on storage or deserialization failure.
    pub fn entries(&self) -> Result<Vec<AuditEntry>, AuditError> {
        let conn = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let mut stmt = conn.prepare(
            "SELECT id, session_id, event, verdict, evidence_hash, summary,
                    agent_actions, timestamp, prev_hash, entry_hash
             FROM audit_entries ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], row_to_entry)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Recomputes the full hash chain and reports the first broken entry.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] on storage failure (not on tampering — a
    /// tampered chain is reported through [`ChainVerification::broken_at`]).
    pub fn verify(&self) -> Result<ChainVerification, AuditError> {
        let entries = self.entries()?;
        let mut expected_prev = GENESIS_PREV;
        for entry in &entries {
            let body_ok = entry.prev_hash == expected_prev;
            let body = ChainBody {
                session_id: &entry.session_id,
                event: &entry.event,
                verdict: &entry.verdict,
                evidence_hash: &entry.evidence_hash,
                summary: &entry.summary,
                agent_actions: &entry.agent_actions,
                timestamp: entry.timestamp.as_u64(),
                prev_hash: &hex::encode(entry.prev_hash),
            };
            let recomputed = chain_hash(&self.key, &entry.prev_hash, &body)?;
            if !body_ok || recomputed != entry.entry_hash {
                return Ok(ChainVerification {
                    intact: false,
                    entries_checked: entries.len(),
                    broken_at: Some(entry.id),
                });
            }
            expected_prev = entry.entry_hash;
        }
        Ok(ChainVerification {
            intact: true,
            entries_checked: entries.len(),
            broken_at: None,
        })
    }

    /// Head hash of the chain (genesis zeros when empty).
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] on storage failure.
    pub fn head_hash(&self) -> Result<[u8; HASH_LEN], AuditError> {
        let conn = self.conn.lock().map_err(|_| AuditError::LockPoisoned)?;
        let bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT entry_hash FROM audit_entries ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        Ok(bytes
            .map(|bytes| bytes_try_into_32(&bytes))
            .transpose()?
            .unwrap_or(GENESIS_PREV))
    }
}

/// Computes `HMAC-SHA256(key, prev_hash ‖ canonical_body)`.
fn chain_hash(
    key: &[u8],
    prev_hash: &[u8; HASH_LEN],
    body: &ChainBody<'_>,
) -> Result<[u8; HASH_LEN], AuditError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|err| AuditError::Key(err.to_string()))?;
    let encoded = serde_json::to_vec(body)?;
    mac.update(prev_hash);
    mac.update(&encoded);
    let out = mac.finalize().into_bytes();
    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(&out);
    Ok(hash)
}

fn bytes_try_into_32(bytes: &[u8]) -> Result<[u8; HASH_LEN], AuditError> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidColumnType(0, "hash".into(), rusqlite::types::Type::Blob).into()
    })
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    let agent_actions_json: String = row.get(6)?;
    let agent_actions: Vec<AgentAction> =
        serde_json::from_str(&agent_actions_json).map_err(|_| {
            rusqlite::Error::InvalidColumnType(
                6,
                "agent_actions".into(),
                rusqlite::types::Type::Text,
            )
        })?;
    let prev_hash_vec: Vec<u8> = row.get(8)?;
    let entry_hash_vec: Vec<u8> = row.get(9)?;
    let prev_hash = bytes_try_into_32(&prev_hash_vec).map_err(|_| {
        rusqlite::Error::InvalidColumnType(8, "prev_hash".into(), rusqlite::types::Type::Blob)
    })?;
    let entry_hash = bytes_try_into_32(&entry_hash_vec).map_err(|_| {
        rusqlite::Error::InvalidColumnType(9, "entry_hash".into(), rusqlite::types::Type::Blob)
    })?;
    Ok(AuditEntry {
        id: row.get(0)?,
        session_id: row.get(1)?,
        event: row.get(2)?,
        verdict: row.get(3)?,
        evidence_hash: row.get(4)?,
        summary: row.get(5)?,
        agent_actions,
        timestamp: TimestampMillis::from_u64(row.get::<_, i64>(7)?.max(0) as u64),
        prev_hash,
        entry_hash,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use tempfile::TempDir;

    const KEY: &[u8] = b"test-signing-key";

    fn open_chain(dir: &TempDir, name: &str) -> AuditChain {
        let path = dir.path().join(name);
        AuditChain::open(&path, KEY).expect("open chain")
    }

    fn sample_input(session: &str, verdict: &str) -> AppendInput {
        AppendInput {
            session_id: session.to_string(),
            event: "verdict".to_string(),
            verdict: verdict.to_string(),
            evidence_hash: "0123456789abcdef".to_string(),
            summary: "hallucinated package detected".to_string(),
            agent_actions: vec![AgentAction {
                agent: "Auditor".to_string(),
                action: "arbitrate".to_string(),
            }],
        }
    }

    #[test]
    fn append_then_verify_is_intact() {
        let dir = TempDir::new().expect("tempdir");
        let chain = open_chain(&dir, "audit.db");
        chain.append(&sample_input("s-1", "block")).expect("append");
        chain
            .append(&sample_input("s-1", "sealed"))
            .expect("append");
        let report = chain.verify().expect("verify");
        assert!(report.intact);
        assert_eq!(report.entries_checked, 2);
        assert_eq!(report.broken_at, None);
    }

    #[test]
    fn empty_chain_verifies_intact_with_genesis_head() {
        let dir = TempDir::new().expect("tempdir");
        let chain = open_chain(&dir, "audit.db");
        let report = chain.verify().expect("verify");
        assert!(report.intact);
        assert_eq!(report.entries_checked, 0);
        assert_eq!(chain.head_hash().expect("head"), GENESIS_PREV);
    }

    #[test]
    fn chain_links_each_entry_to_its_predecessor() {
        let dir = TempDir::new().expect("tempdir");
        let chain = open_chain(&dir, "audit.db");
        let first = chain.append(&sample_input("s-1", "block")).expect("append");
        let second = chain
            .append(&sample_input("s-1", "sealed"))
            .expect("append");
        assert_eq!(first.prev_hash, GENESIS_PREV);
        assert_eq!(second.prev_hash, first.entry_hash);
    }

    #[test]
    fn tampered_field_breaks_verify_at_that_entry() {
        let dir = TempDir::new().expect("tempdir");
        let db_path = dir.path().join("audit.db");
        {
            let chain = AuditChain::open(&db_path, KEY).expect("open");
            chain.append(&sample_input("s-1", "block")).expect("append");
            chain.append(&sample_input("s-2", "allow")).expect("append");
        }
        // Attacker rewrites a stored field with raw SQL.
        let attacker = Connection::open(&db_path).expect("attacker connection");
        attacker
            .execute(
                "UPDATE audit_entries SET verdict = 'allow' WHERE id = 1",
                [],
            )
            .expect("tamper");
        let chain = AuditChain::open(&db_path, KEY).expect("reopen");
        let report = chain.verify().expect("verify runs");
        assert!(!report.intact);
        assert_eq!(report.broken_at, Some(1));
    }

    #[test]
    fn tampered_hash_breaks_verify_at_that_entry() {
        let dir = TempDir::new().expect("tempdir");
        let db_path = dir.path().join("audit.db");
        {
            let chain = AuditChain::open(&db_path, KEY).expect("open");
            chain.append(&sample_input("s-1", "block")).expect("append");
            chain.append(&sample_input("s-2", "allow")).expect("append");
            chain.append(&sample_input("s-3", "block")).expect("append");
        }
        let attacker = Connection::open(&db_path).expect("attacker connection");
        let forged_hex = "07".repeat(HASH_LEN);
        attacker
            .execute(
                &format!("UPDATE audit_entries SET entry_hash = x'{forged_hex}' WHERE id = 2"),
                [],
            )
            .expect("tamper");
        let chain = AuditChain::open(&db_path, KEY).expect("reopen");
        let report = chain.verify().expect("verify runs");
        assert!(!report.intact);
        assert_eq!(report.broken_at, Some(2));
    }

    #[test]
    fn wrong_key_fails_verify() {
        let dir = TempDir::new().expect("tempdir");
        let db_path = dir.path().join("audit.db");
        {
            let chain = AuditChain::open(&db_path, KEY).expect("open");
            chain.append(&sample_input("s-1", "block")).expect("append");
        }
        let chain = AuditChain::open(&db_path, b"attacker-key").expect("reopen");
        let report = chain.verify().expect("verify runs");
        assert!(!report.intact);
        assert_eq!(report.broken_at, Some(1));
    }

    #[test]
    fn entries_reader_returns_insertion_order() {
        let dir = TempDir::new().expect("tempdir");
        let chain = open_chain(&dir, "audit.db");
        chain.append(&sample_input("s-1", "block")).expect("append");
        chain.append(&sample_input("s-2", "allow")).expect("append");
        let entries = chain.entries().expect("entries");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].session_id, "s-1");
        assert_eq!(entries[1].session_id, "s-2");
        assert_eq!(entries[0].agent_actions.len(), 1);
        assert_eq!(entries[0].agent_actions[0].agent, "Auditor");
    }

    #[test]
    fn same_input_yields_deterministic_hash() {
        let dir = TempDir::new().expect("tempdir");
        let chain = open_chain(&dir, "audit.db");
        let input = sample_input("s-1", "block");
        let first = chain.append(&input).expect("append");
        // Same body + same predecessor must recompute to the stored hash.
        let body = ChainBody {
            session_id: "s-1",
            event: "verdict",
            verdict: "block",
            evidence_hash: "0123456789abcdef",
            summary: "hallucinated package detected",
            agent_actions: &input.agent_actions,
            timestamp: first.timestamp.as_u64(),
            prev_hash: &hex::encode(first.prev_hash),
        };
        let recomputed = chain_hash(KEY, &first.prev_hash, &body).expect("hash");
        assert_eq!(recomputed, first.entry_hash);
    }
}

use rusqlite::{params, Connection};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

/// SessionStore 错误
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("session not found: {0}")]
    NotFound(String),

    #[error("invalid state transition: {0}")]
    InvalidState(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub id: String,
    pub mode: String,
    pub target: String,
    pub state: String,
    pub packages_total: i64,
    pub packages_scanned: i64,
    pub verdicts_allow: i64,
    pub verdicts_review: i64,
    pub verdicts_block: i64,
    pub started_at: i64,
    pub completed_at: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub id: String,
    pub session_id: String,
    pub package: String,
    pub version: String,
    pub verdict: String,
    pub reasoning: String,
    pub evidence: Vec<String>,
    pub confidence: f64,
    pub agent: String,
    pub created_at: i64,
}

#[derive(Debug)]
pub struct SessionStore {
    conn: Connection,
}

impl SessionStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                target TEXT NOT NULL,
                state TEXT NOT NULL,
                packages_total INTEGER DEFAULT 0,
                packages_scanned INTEGER DEFAULT 0,
                verdicts_allow INTEGER DEFAULT 0,
                verdicts_review INTEGER DEFAULT 0,
                verdicts_block INTEGER DEFAULT 0,
                started_at INTEGER NOT NULL,
                completed_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reasoning TEXT NOT NULL,
                evidence TEXT NOT NULL,
                confidence REAL NOT NULL,
                agent TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );

            CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state);
            ",
        )?;
        Ok(())
    }

    pub fn create_session(&self, mode: &str, target: &str) -> Result<Session, StoreError> {
        let session = Session {
            id: Uuid::new_v4().to_string(),
            mode: mode.to_string(),
            target: target.to_string(),
            state: "created".to_string(),
            packages_total: 0,
            packages_scanned: 0,
            verdicts_allow: 0,
            verdicts_review: 0,
            verdicts_block: 0,
            started_at: chrono::Utc::now().timestamp_millis(),
            completed_at: None,
        };

        self.conn.execute(
            "INSERT INTO sessions (id, mode, target, state, packages_total, packages_scanned, verdicts_allow, verdicts_review, verdicts_block, started_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                &session.id,
                &session.mode,
                &session.target,
                &session.state,
                session.packages_total,
                session.packages_scanned,
                session.verdicts_allow,
                session.verdicts_review,
                session.verdicts_block,
                session.started_at,
                session.completed_at,
            ],
        )?;

        Ok(session)
    }

    pub fn get_session(&self, id: &str) -> Result<Session, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, mode, target, state, packages_total, packages_scanned, verdicts_allow, verdicts_review, verdicts_block, started_at, completed_at
             FROM sessions WHERE id = ?1",
        )?;

        let session = stmt.query_row([id], |row| {
            Ok(Session {
                id: row.get(0)?,
                mode: row.get(1)?,
                target: row.get(2)?,
                state: row.get(3)?,
                packages_total: row.get(4)?,
                packages_scanned: row.get(5)?,
                verdicts_allow: row.get(6)?,
                verdicts_review: row.get(7)?,
                verdicts_block: row.get(8)?,
                started_at: row.get(9)?,
                completed_at: row.get(10)?,
            })
        })?;

        Ok(session)
    }

    pub fn update_session_state(&self, id: &str, state: &str) -> Result<(), StoreError> {
        let rows = self.conn.execute(
            "UPDATE sessions SET state = ?1 WHERE id = ?2",
            params![state, id],
        )?;
        if rows == 0 {
            return Err(StoreError::NotFound(id.to_string()));
        }
        Ok(())
    }

    pub fn complete_session(&self, id: &str) -> Result<(), StoreError> {
        let rows = self.conn.execute(
            "UPDATE sessions SET state = 'sealed', completed_at = ?1 WHERE id = ?2",
            params![chrono::Utc::now().timestamp_millis(), id],
        )?;
        if rows == 0 {
            return Err(StoreError::NotFound(id.to_string()));
        }
        Ok(())
    }

    pub fn add_finding(&self, finding: &Finding) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO findings (id, session_id, package, version, verdict, reasoning, evidence, confidence, agent, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                &finding.id,
                &finding.session_id,
                &finding.package,
                &finding.version,
                &finding.verdict,
                &finding.reasoning,
                serde_json::to_string(&finding.evidence).unwrap_or_default(),
                finding.confidence,
                &finding.agent,
                finding.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_findings(&self, session_id: &str) -> Result<Vec<Finding>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, package, version, verdict, reasoning, evidence, confidence, agent, created_at
             FROM findings WHERE session_id = ?1 ORDER BY created_at ASC",
        )?;

        let findings = stmt
            .query_map([session_id], |row| {
                let evidence_str: String = row.get(6)?;
                let evidence: Vec<String> = serde_json::from_str(&evidence_str).unwrap_or_default();

                Ok(Finding {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    package: row.get(2)?,
                    version: row.get(3)?,
                    verdict: row.get(4)?,
                    reasoning: row.get(5)?,
                    evidence,
                    confidence: row.get(7)?,
                    agent: row.get(8)?,
                    created_at: row.get(9)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(findings)
    }

    pub fn list_sessions(&self) -> Result<Vec<Session>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, mode, target, state, packages_total, packages_scanned, verdicts_allow, verdicts_review, verdicts_block, started_at, completed_at
             FROM sessions ORDER BY started_at DESC",
        )?;

        let sessions = stmt
            .query_map([], |row| {
                Ok(Session {
                    id: row.get(0)?,
                    mode: row.get(1)?,
                    target: row.get(2)?,
                    state: row.get(3)?,
                    packages_total: row.get(4)?,
                    packages_scanned: row.get(5)?,
                    verdicts_allow: row.get(6)?,
                    verdicts_review: row.get(7)?,
                    verdicts_block: row.get(8)?,
                    started_at: row.get(9)?,
                    completed_at: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(sessions)
    }
}

use rusqlite::Connection;
use thiserror::Error;

/// SessionStore 错误
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("session not found: {0}")]
    NotFound(String),
}

pub struct SessionStore {
    conn: Connection,
}

impl SessionStore {
    pub fn new(path: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Ok(Self { conn })
    }

    // TODO: 实现会话 CRUD
}

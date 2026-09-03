use serde::Serialize;
use thiserror::Error;

/// 输出错误
#[derive(Debug, Error)]
pub enum OutputError {
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, OutputError>;

/// JSON 输出格式化
pub fn format_json<T: Serialize>(data: &T, pretty: bool) -> Result<String> {
    if pretty {
        Ok(serde_json::to_string_pretty(data)?)
    } else {
        Ok(serde_json::to_string(data)?)
    }
}

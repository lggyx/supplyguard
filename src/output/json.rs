use serde::Serialize;

/// JSON 输出格式化
pub fn format_json<T: Serialize>(data: &T, pretty: bool) -> anyhow::Result<String> {
    if pretty {
        Ok(serde_json::to_string_pretty(data)?)
    } else {
        Ok(serde_json::to_string(data)?)
    }
}

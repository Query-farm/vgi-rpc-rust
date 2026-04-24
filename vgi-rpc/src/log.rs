//! Client-directed log messages carried in batch custom_metadata.

use serde_json::json;

/// Log severity level. Matches the Python `vgi_rpc.log.Level` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Exception,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Exception => "EXCEPTION",
        }
    }
}

/// A log message emitted by a server method, delivered to the client
/// via an out-of-band zero-row batch.
#[derive(Debug, Clone)]
pub struct LogMessage {
    pub level: LogLevel,
    pub message: String,
    pub extras: Vec<(String, String)>,
}

impl LogMessage {
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
            extras: Vec::new(),
        }
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extras.push((key.into(), value.into()));
        self
    }

    /// JSON encoding of extras as a flat object (string values).
    pub fn extras_json(&self) -> String {
        let mut map = serde_json::Map::new();
        for (k, v) in &self.extras {
            map.insert(k.clone(), json!(v));
        }
        serde_json::Value::Object(map).to_string()
    }
}

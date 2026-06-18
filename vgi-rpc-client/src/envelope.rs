//! Response-envelope classification: split a `(batch, metadata)` frame into
//! a data batch, an out-of-band log, or an exception. Reimplements Python's
//! `_dispatch_log_or_error` using the public wire constants (the server's own
//! parser is crate-private to `vgi-rpc`).

use arrow_array::RecordBatch;
use serde_json::Value;

use vgi_rpc::errors::RpcError;
use vgi_rpc::log::{LogLevel, LogMessage};
use vgi_rpc::metadata::{LOG_EXTRA_KEY, LOG_LEVEL_KEY, LOG_MESSAGE_KEY, REQUEST_ID_KEY};
use vgi_rpc::wire::{md_get, Metadata};

/// What a received frame represents.
pub enum BatchKind {
    /// A user-visible data batch.
    Data,
    /// An out-of-band log message (zero-row, non-EXCEPTION level).
    Log(LogMessage),
    /// An error envelope (zero-row, EXCEPTION level).
    Exception(RpcError),
}

/// Classify a received `(batch, metadata)` frame.
///
/// A frame is data unless it is a **zero-row** batch carrying a
/// `vgi_rpc.log_level` key — then it is a log (or, at `EXCEPTION` level, an
/// error envelope).
pub fn classify(batch: &RecordBatch, md: &Metadata) -> BatchKind {
    if batch.num_rows() != 0 {
        return BatchKind::Data;
    }
    let Some(level_str) = md_get(md, LOG_LEVEL_KEY) else {
        return BatchKind::Data;
    };
    let message = md_get(md, LOG_MESSAGE_KEY).unwrap_or("").to_string();
    let request_id = md_get(md, REQUEST_ID_KEY).unwrap_or("").to_string();
    let extra_json = md_get(md, LOG_EXTRA_KEY);

    if level_str == "EXCEPTION" {
        let (etype, traceback) = parse_exception_extra(extra_json);
        let mut err = RpcError::new(etype, message);
        err.traceback = traceback;
        err.request_id = request_id;
        return BatchKind::Exception(err);
    }

    let mut msg = LogMessage::new(parse_level(level_str), message);
    if let Some(j) = extra_json {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(j) {
            for (k, v) in map {
                let vs = match v {
                    Value::String(s) => s,
                    other => other.to_string(),
                };
                msg = msg.with_extra(k, vs);
            }
        }
    }
    BatchKind::Log(msg)
}

fn parse_level(s: &str) -> LogLevel {
    match s {
        "TRACE" => LogLevel::Trace,
        "DEBUG" => LogLevel::Debug,
        "INFO" => LogLevel::Info,
        "WARN" => LogLevel::Warn,
        "ERROR" => LogLevel::Error,
        "EXCEPTION" => LogLevel::Exception,
        _ => LogLevel::Info,
    }
}

/// Pull `exception_type` and `traceback` out of the `vgi_rpc.log_extra` JSON.
fn parse_exception_extra(extra_json: Option<&str>) -> (String, String) {
    let mut etype = "Exception".to_string();
    let mut traceback = String::new();
    if let Some(j) = extra_json {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(j) {
            if let Some(Value::String(t)) = map.get("exception_type") {
                etype = t.clone();
            }
            if let Some(Value::String(tb)) = map.get("traceback") {
                traceback = tb.clone();
            }
        }
    }
    (etype, traceback)
}

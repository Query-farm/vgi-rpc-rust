//! Response-envelope classification: split a `(batch, metadata)` frame into
//! a data batch, an out-of-band log, or an exception. Reimplements Python's
//! `_dispatch_log_or_error` using the public wire constants (the server's own
//! parser is crate-private to `vgi-rpc`).

use arrow_array::RecordBatch;
use serde_json::Value;

use vgi_rpc::errors::RpcError;
use vgi_rpc::log::{LogLevel, LogMessage};
use vgi_rpc::metadata::{
    ERROR_CODE_KEY, ERROR_DETAILS_KEY, ERROR_KIND_KEY, LOCATION_KEY, LOG_EXTRA_KEY, LOG_LEVEL_KEY,
    LOG_MESSAGE_KEY, REQUEST_ID_KEY,
};
use vgi_rpc::wire::{md_get, Metadata};

/// What a received frame represents.
pub enum BatchKind {
    /// A user-visible data batch.
    Data,
    /// An external-location pointer standing in for a batch (or, on a stream,
    /// for a whole output cycle) that lives in storage. Zero-row by
    /// construction, which is why it is tested for *first*: a reader that
    /// classified it as a log would skip it, and the payload would be missing
    /// rather than malformed.
    Pointer,
    /// An out-of-band log message (zero-row, non-EXCEPTION level).
    Log(LogMessage),
    /// An error envelope (zero-row, EXCEPTION level).
    Exception(RpcError),
}

/// Classify a received `(batch, metadata)` frame.
///
/// `vgi_rpc.location` is tested **before** anything else, including the
/// zero-row shortcut. A pointer batch is zero-row by construction, so a
/// classifier that reached the log test first would report the frame as a log
/// and drop it — the failure mode WIRE_PROTOCOL.md §1.5 describes for stream
/// headers, where the header then "does not fail to parse, it fails to exist".
///
/// Otherwise a frame is data unless it is a **zero-row** batch carrying a
/// `vgi_rpc.log_level` key — then it is a log (or, at `EXCEPTION` level, an
/// error envelope).
pub fn classify(batch: &RecordBatch, md: &Metadata) -> BatchKind {
    if md_get(md, LOCATION_KEY).is_some() {
        return BatchKind::Pointer;
    }
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
        return BatchKind::Exception(decode_exception(md, message, request_id, extra_json));
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

/// Build the client-side [`RpcError`] for an EXCEPTION envelope.
///
/// The single decode point every path funnels through -- unary, stream
/// init, stream exchange, and an externalized error batch -- so the error
/// model (WIRE_PROTOCOL.md §8) cannot be dropped on one of them. Each of
/// `error_code` / `error_kind` / `error_details` is read from its top-level
/// key first and from the `log_extra` mirror when that key is absent. The code
/// is kept verbatim (`""` when the server sent none -- a different answer
/// from `"UNKNOWN"`), and the details keep every element, unknown types
/// included; only the typed accessors filter.
fn decode_exception(
    md: &Metadata,
    message: String,
    request_id: String,
    extra_json: Option<&str>,
) -> RpcError {
    let (etype, traceback) = parse_exception_extra(extra_json);
    let extra: Option<serde_json::Map<String, Value>> = extra_json
        .and_then(|j| serde_json::from_str::<Value>(j).ok())
        .and_then(|v| match v {
            Value::Object(m) => Some(m),
            _ => None,
        });
    let mirror_str = |key: &str| -> String {
        extra
            .as_ref()
            .and_then(|m| m.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let code = match md_get(md, ERROR_CODE_KEY) {
        Some(code) => code.to_string(),
        None => mirror_str("error_code"),
    };
    let kind = match md_get(md, ERROR_KIND_KEY) {
        Some(kind) => kind.to_string(),
        None => mirror_str("error_kind"),
    };
    let details = match md_get(md, ERROR_DETAILS_KEY) {
        Some(raw) => vgi_rpc::error_model::decode_error_details(raw),
        None => match extra.as_ref().and_then(|m| m.get("error_details")) {
            Some(Value::Array(items)) => items.iter().filter(|v| v.is_object()).cloned().collect(),
            _ => Vec::new(),
        },
    };
    let mut err = RpcError::new(etype, message);
    err.traceback = traceback.into_boxed_str();
    err.request_id = request_id.into_boxed_str();
    if !kind.is_empty() {
        err = err.with_error_kind(kind);
    }
    err.set_wire_status(&code, details);
    err
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

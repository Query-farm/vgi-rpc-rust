//! Conformance client-driver: a thin, generic JSONL bridge that lets the
//! Python conformance suite drive the Rust `vgi-rpc-client`.
//!
//! The driver speaks newline-delimited JSON on stdin/stdout. The Python shim
//! reuses the canonical `vgi_rpc` value encoders/decoders, so the bytes that
//! cross this boundary are **Arrow IPC stream bytes** (base64) plus a method
//! name — never typed values. The Rust client does all real wire framing,
//! transport I/O, stream lockstep / HTTP token round-trips, and log/error
//! envelope parsing; the driver just relays.
//!
//! Protocol (one JSON object per line, request then response):
//!   {"op":"connect","transport":"stdio|unix|tcp|http","target":<argv|path|host:port|url>}
//!   {"op":"unary","request_b64":...}            -> {ok,result_b64,logs,error}
//!   {"op":"describe"}                            -> {ok,result_b64}
//!   {"op":"stream_open","request_b64":...,"is_exchange":bool,"has_header":bool}
//!        -> {ok,header_b64,logs}  then a sub-loop of:
//!   {"op":"tick"}                                -> {ok,done,batch_b64,logs,error}
//!   {"op":"exchange","input_b64":...}            -> {ok,batch_b64,logs,error}
//!   {"op":"cancel"} / {"op":"close"}             -> {ok}

use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};

use arrow_array::RecordBatch;
use base64::Engine;
use serde_json::{json, Value};

use vgi_rpc::log::LogMessage;
use vgi_rpc::wire::{empty_batch, md_get, write_one_batch, Metadata, StreamReader};
use vgi_rpc_client::{HttpClient, RpcClient};

type LogBuf = Arc<Mutex<Vec<LogMessage>>>;

// Holds exactly one client for the driver's lifetime; the size delta between
// the byte-stream and HTTP variants doesn't matter here.
#[allow(clippy::large_enum_variant)]
enum Conn {
    ByteStream(RpcClient),
    Http(HttpClient),
}

/// Uniform stream interface over the byte-stream and HTTP session types.
trait DriverSession {
    fn tick(&mut self) -> vgi_rpc::errors::Result<Option<(RecordBatch, Metadata)>>;
    fn exchange(
        &mut self,
        input: &RecordBatch,
        md: Option<&Metadata>,
    ) -> vgi_rpc::errors::Result<Option<(RecordBatch, Metadata)>>;
    fn cancel(&mut self) -> vgi_rpc::errors::Result<()>;
    fn header(&self) -> Option<&(RecordBatch, Metadata)>;
}

impl DriverSession for vgi_rpc_client::StreamSession<'_> {
    fn tick(&mut self) -> vgi_rpc::errors::Result<Option<(RecordBatch, Metadata)>> {
        vgi_rpc_client::StreamSession::tick(self)
    }
    fn exchange(
        &mut self,
        input: &RecordBatch,
        md: Option<&Metadata>,
    ) -> vgi_rpc::errors::Result<Option<(RecordBatch, Metadata)>> {
        vgi_rpc_client::StreamSession::exchange(self, input, md)
    }
    fn cancel(&mut self) -> vgi_rpc::errors::Result<()> {
        vgi_rpc_client::StreamSession::cancel(self)
    }
    fn header(&self) -> Option<&(RecordBatch, Metadata)> {
        vgi_rpc_client::StreamSession::header(self)
    }
}

impl DriverSession for vgi_rpc_client::HttpStreamSession<'_> {
    fn tick(&mut self) -> vgi_rpc::errors::Result<Option<(RecordBatch, Metadata)>> {
        vgi_rpc_client::HttpStreamSession::tick(self)
    }
    fn exchange(
        &mut self,
        input: &RecordBatch,
        md: Option<&Metadata>,
    ) -> vgi_rpc::errors::Result<Option<(RecordBatch, Metadata)>> {
        vgi_rpc_client::HttpStreamSession::exchange(self, input, md)
    }
    fn cancel(&mut self) -> vgi_rpc::errors::Result<()> {
        vgi_rpc_client::HttpStreamSession::cancel(self)
    }
    fn header(&self) -> Option<&(RecordBatch, Metadata)> {
        vgi_rpc_client::HttpStreamSession::header(self)
    }
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode: {e}"))
}

/// Parse a request/input IPC stream into its single (batch, metadata).
fn read_one(bytes: &[u8]) -> Result<(RecordBatch, Metadata), String> {
    let mut reader = StreamReader::new(bytes).map_err(|e| e.to_string())?;
    match reader.read_next().map_err(|e| e.to_string())? {
        Some(pair) => Ok(pair),
        None => Err("empty IPC stream (no batch)".into()),
    }
}

fn batch_b64(batch: &RecordBatch, md: &Metadata) -> Result<String, String> {
    let bytes = write_one_batch(batch, Some(md)).map_err(|e| e.to_string())?;
    Ok(b64_encode(&bytes))
}

fn log_to_json(m: &LogMessage) -> Value {
    let extra: serde_json::Map<String, Value> = m
        .extras
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    json!({"level": m.level.as_str(), "message": m.message, "extra": Value::Object(extra)})
}

fn drain_logs(buf: &LogBuf) -> Vec<Value> {
    let mut g = buf.lock().unwrap();
    let out = g.iter().map(log_to_json).collect();
    g.clear();
    out
}

fn error_to_json(e: &vgi_rpc::errors::RpcError) -> Value {
    json!({
        "error_type": e.error_type,
        "error_message": e.message,
        "traceback": e.traceback,
    })
}

fn write_response(out: &mut impl Write, v: &Value) {
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

fn make_log_sink(buf: &LogBuf) -> vgi_rpc_client::OnLog {
    let b = buf.clone();
    Box::new(move |m: LogMessage| {
        b.lock().unwrap().push(m);
    })
}

fn main() {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let log_buf: LogBuf = Arc::new(Mutex::new(Vec::new()));
    let mut conn: Option<Conn> = None;

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(_) => break,
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                write_response(
                    &mut out,
                    &json!({"ok": false, "error": format!("bad json: {e}")}),
                );
                continue;
            }
        };
        let op = req.get("op").and_then(Value::as_str).unwrap_or("");

        match op {
            "connect" => match do_connect(&req, &log_buf) {
                Ok(c) => {
                    conn = Some(c);
                    write_response(&mut out, &json!({"ok": true}));
                }
                Err(e) => write_response(&mut out, &json!({"ok": false, "error": e})),
            },
            "unary" | "describe" => {
                let Some(c) = conn.as_mut() else {
                    write_response(&mut out, &json!({"ok": false, "error": "not connected"}));
                    continue;
                };
                let resp = handle_unary(c, op, &req, &log_buf);
                write_response(&mut out, &resp);
            }
            "stream_open" => {
                let Some(c) = conn.as_mut() else {
                    write_response(&mut out, &json!({"ok": false, "error": "not connected"}));
                    continue;
                };
                run_stream(c, &req, &log_buf, &mut reader, &mut out);
            }
            "capabilities"
            | "request_upload_urls"
            | "session_begin"
            | "session_token"
            | "session_echo_headers"
            | "session_detach"
            | "session_end" => {
                let resp = match conn.as_mut() {
                    Some(Conn::Http(c)) => handle_http_admin(c, op, &req),
                    Some(Conn::ByteStream(_)) => {
                        json!({"ok": false, "error": "op requires http transport"})
                    }
                    None => json!({"ok": false, "error": "not connected"}),
                };
                write_response(&mut out, &resp);
            }
            "shutdown" => {
                write_response(&mut out, &json!({"ok": true}));
                break;
            }
            other => {
                write_response(
                    &mut out,
                    &json!({"ok": false, "error": format!("unknown op: {other}")}),
                );
            }
        }
    }
}

fn do_connect(req: &Value, log_buf: &LogBuf) -> Result<Conn, String> {
    let transport = req.get("transport").and_then(Value::as_str).unwrap_or("");
    let target = req.get("target").cloned().unwrap_or(Value::Null);
    let relax = req
        .get("relax_nullability")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match transport {
        "stdio" => {
            let argv: Vec<String> = target
                .as_array()
                .ok_or("stdio target must be an argv array")?
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect();
            let client = RpcClient::connect(&argv)
                .map_err(|e| e.to_string())?
                .relax_nullability(relax)
                .on_log(make_log_sink(log_buf));
            Ok(Conn::ByteStream(client))
        }
        "shm" => {
            let argv: Vec<String> = target
                .as_array()
                .ok_or("shm target must be an argv array")?
                .iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect();
            let size = req
                .get("shm_size")
                .and_then(Value::as_u64)
                .unwrap_or(4 * 1024 * 1024) as usize;
            let client = RpcClient::shm_connect(&argv, size)
                .map_err(|e| e.to_string())?
                .relax_nullability(relax)
                .on_log(make_log_sink(log_buf));
            Ok(Conn::ByteStream(client))
        }
        "unix" => {
            let path = target.as_str().ok_or("unix target must be a path string")?;
            #[cfg(unix)]
            {
                let client = RpcClient::unix_connect(path)
                    .map_err(|e| e.to_string())?
                    .relax_nullability(relax)
                    .on_log(make_log_sink(log_buf));
                Ok(Conn::ByteStream(client))
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                Err("unix transport not available on this platform".into())
            }
        }
        "tcp" => {
            // Raw TCP, network analog of unix: `[HOST:]PORT` (host defaults to
            // loopback). No auth/TLS — trusted networks only.
            let address = target
                .as_str()
                .ok_or("tcp target must be a host:port string")?;
            let (host, port) = match address.rsplit_once(':') {
                Some((h, p)) => {
                    let host = if h.is_empty() { "127.0.0.1" } else { h };
                    (
                        host.to_string(),
                        p.parse::<u16>().map_err(|e| e.to_string())?,
                    )
                }
                None => (
                    "127.0.0.1".to_string(),
                    address.parse::<u16>().map_err(|e| e.to_string())?,
                ),
            };
            let client = RpcClient::tcp_connect(&host, port)
                .map_err(|e| e.to_string())?
                .relax_nullability(relax)
                .on_log(make_log_sink(log_buf));
            Ok(Conn::ByteStream(client))
        }
        "http" => {
            let url = target.as_str().ok_or("http target must be a url string")?;
            let mut builder = HttpClient::connect(url)
                .relax_nullability(relax)
                .on_log(make_log_sink(log_buf));
            // compression_level: absent => default; null => disabled; int => level.
            match req.get("compression_level") {
                None => {}
                Some(Value::Null) => builder = builder.compression_level(None),
                Some(v) => {
                    builder = builder.compression_level(v.as_i64().map(|n| n as i32));
                }
            }
            if req
                .get("external")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                builder = builder.external_resolution_any();
            }
            let client = builder.build().map_err(|e| e.to_string())?;
            Ok(Conn::Http(client))
        }
        other => Err(format!("unknown transport: {other}")),
    }
}

/// HTTP-only admin ops: capabilities, upload URLs, and sticky-session control.
fn handle_http_admin(c: &mut HttpClient, op: &str, req: &Value) -> Value {
    match op {
        "capabilities" => match c.capabilities() {
            Ok(caps) => json!({"ok": true, "caps": {
                "sticky_enabled": caps.sticky_enabled,
                "sticky_default_ttl": caps.sticky_default_ttl,
                "sticky_echo_headers": caps.sticky_echo_headers,
                "upload_url_support": caps.upload_url_support,
                "max_request_bytes": caps.max_request_bytes,
                "max_response_bytes": caps.max_response_bytes,
                "max_externalized_response_bytes": caps.max_externalized_response_bytes,
                "externalization_enabled": caps.externalization_enabled,
                "max_upload_bytes": caps.max_upload_bytes,
                "supported_encodings": caps.supported_encodings,
            }}),
            Err(e) => json!({"ok": false, "error": e.to_string()}),
        },
        "request_upload_urls" => {
            let count = req.get("count").and_then(Value::as_u64).unwrap_or(1) as usize;
            match c.request_upload_urls(count) {
                Ok(urls) => {
                    let list: Vec<Value> = urls
                        .into_iter()
                        .map(|u| json!({"upload_url": u.upload_url, "download_url": u.download_url, "expires_at": u.expires_at}))
                        .collect();
                    json!({"ok": true, "urls": list})
                }
                Err(e) => json!({"ok": false, "error": e.to_string()}),
            }
        }
        "session_begin" => {
            let token = req
                .get("token")
                .and_then(Value::as_str)
                .map(|s| s.to_string());
            c.begin_session(token);
            json!({"ok": true})
        }
        "session_token" => json!({"ok": true, "token": c.current_session_token()}),
        "session_echo_headers" => {
            let map: serde_json::Map<String, Value> = c
                .current_echo_headers()
                .into_iter()
                .map(|(k, v)| (k, Value::String(v)))
                .collect();
            json!({"ok": true, "headers": Value::Object(map)})
        }
        "session_detach" => json!({"ok": true, "token": c.detach_session()}),
        "session_end" => {
            c.end_session();
            json!({"ok": true})
        }
        other => json!({"ok": false, "error": format!("unknown admin op: {other}")}),
    }
}

fn handle_unary(conn: &mut Conn, op: &str, req: &Value, log_buf: &LogBuf) -> Value {
    // Build (method, batch, md) for the call.
    let (method, batch, md): (String, RecordBatch, Metadata) = if op == "describe" {
        let b = match empty_batch(&arrow_schema::Schema::empty()) {
            Ok(b) => b,
            Err(e) => return json!({"ok": false, "error": e.to_string()}),
        };
        (
            vgi_rpc::introspect::DESCRIBE_METHOD_NAME.to_string(),
            b,
            Metadata::new(),
        )
    } else {
        let b64 = req.get("request_b64").and_then(Value::as_str).unwrap_or("");
        let bytes = match b64_decode(b64) {
            Ok(b) => b,
            Err(e) => return json!({"ok": false, "error": e}),
        };
        let (batch, md) = match read_one(&bytes) {
            Ok(x) => x,
            Err(e) => return json!({"ok": false, "error": e}),
        };
        let method = md_get(&md, vgi_rpc::metadata::RPC_METHOD_KEY)
            .unwrap_or(vgi_rpc::introspect::DESCRIBE_METHOD_NAME)
            .to_string();
        (method, batch, md)
    };

    let extra = if md.is_empty() { None } else { Some(&md) };
    let result = match conn {
        Conn::ByteStream(c) => c.call_unary(&method, &batch, extra),
        Conn::Http(c) => c.call_unary(&method, &batch, extra),
    };
    let logs = drain_logs(log_buf);
    match result {
        Ok((rb, rmd)) => match batch_b64(&rb, &rmd) {
            Ok(b64) => json!({"ok": true, "result_b64": b64, "logs": logs, "error": Value::Null}),
            Err(e) => json!({"ok": false, "error": e}),
        },
        Err(e) => {
            json!({"ok": true, "result_b64": Value::Null, "logs": logs, "error": error_to_json(&e)})
        }
    }
}

fn run_stream(
    conn: &mut Conn,
    req: &Value,
    log_buf: &LogBuf,
    reader: &mut impl BufRead,
    out: &mut impl Write,
) {
    let b64 = req.get("request_b64").and_then(Value::as_str).unwrap_or("");
    let bytes = match b64_decode(b64) {
        Ok(b) => b,
        Err(e) => return write_response(out, &json!({"ok": false, "error": e})),
    };
    let (batch, md) = match read_one(&bytes) {
        Ok(x) => x,
        Err(e) => return write_response(out, &json!({"ok": false, "error": e})),
    };
    let method = md_get(&md, vgi_rpc::metadata::RPC_METHOD_KEY)
        .unwrap_or("")
        .to_string();
    let is_exchange = req
        .get("is_exchange")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let has_header = req
        .get("has_header")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let extra = if md.is_empty() { None } else { Some(&md) };

    match conn {
        Conn::ByteStream(c) => {
            let session = if is_exchange {
                c.open_exchange(&method, &batch, extra, has_header)
            } else {
                c.open_producer(&method, &batch, extra, has_header)
            };
            match session {
                Ok(mut s) => stream_sub_loop(&mut s, log_buf, reader, out),
                Err(e) => write_response(out, &json!({"ok": false, "error": e.to_string()})),
            }
        }
        Conn::Http(c) => {
            let session = if is_exchange {
                c.open_exchange(&method, &batch, extra, has_header)
            } else {
                c.open_producer(&method, &batch, extra, has_header)
            };
            match session {
                Ok(mut s) => stream_sub_loop(&mut s, log_buf, reader, out),
                Err(e) => write_response(out, &json!({"ok": false, "error": e.to_string()})),
            }
        }
    }
}

fn stream_sub_loop(
    session: &mut dyn DriverSession,
    log_buf: &LogBuf,
    reader: &mut impl BufRead,
    out: &mut impl Write,
) {
    // Open response: header (if any) + any init logs.
    let header_b64 = match session.header() {
        Some((b, m)) => match batch_b64(b, m) {
            Ok(s) => Value::String(s),
            Err(e) => return write_response(out, &json!({"ok": false, "error": e})),
        },
        None => Value::Null,
    };
    let logs = drain_logs(log_buf);
    write_response(
        out,
        &json!({"ok": true, "header_b64": header_b64, "logs": logs}),
    );

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {}
            Err(_) => return,
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                write_response(
                    out,
                    &json!({"ok": false, "error": format!("bad json: {e}")}),
                );
                continue;
            }
        };
        let op = req.get("op").and_then(Value::as_str).unwrap_or("");
        match op {
            "tick" => {
                let r = session.tick();
                let terminal = !matches!(r, Ok(Some(_)));
                let logs = drain_logs(log_buf);
                write_response(out, &stream_item_response(r, logs));
                if terminal {
                    return; // stream ended (EOS or error); release the client
                }
            }
            "exchange" => {
                let b64 = req.get("input_b64").and_then(Value::as_str).unwrap_or("");
                let (resp, terminal) = match b64_decode(b64).and_then(|bytes| read_one(&bytes)) {
                    Ok((ib, imd)) => {
                        let imd_ref = if imd.is_empty() { None } else { Some(&imd) };
                        let r = session.exchange(&ib, imd_ref);
                        let terminal = !matches!(r, Ok(Some(_)));
                        let logs = drain_logs(log_buf);
                        (stream_item_response(r, logs), terminal)
                    }
                    Err(e) => (json!({"ok": false, "error": e}), true),
                };
                write_response(out, &resp);
                if terminal {
                    return;
                }
            }
            "cancel" => {
                let _ = session.cancel();
                let logs = drain_logs(log_buf);
                write_response(out, &json!({"ok": true, "logs": logs}));
                return; // cancel terminates the stream
            }
            "close" => {
                write_response(out, &json!({"ok": true}));
                return;
            }
            other => {
                write_response(
                    out,
                    &json!({"ok": false, "error": format!("unknown stream op: {other}")}),
                );
            }
        }
    }
}

fn stream_item_response(
    r: vgi_rpc::errors::Result<Option<(RecordBatch, Metadata)>>,
    logs: Vec<Value>,
) -> Value {
    match r {
        Ok(Some((b, m))) => match batch_b64(&b, &m) {
            Ok(b64) => {
                json!({"ok": true, "done": false, "batch_b64": b64, "logs": logs, "error": Value::Null})
            }
            Err(e) => json!({"ok": false, "error": e}),
        },
        Ok(None) => {
            json!({"ok": true, "done": true, "batch_b64": Value::Null, "logs": logs, "error": Value::Null})
        }
        Err(e) => {
            json!({"ok": true, "done": true, "batch_b64": Value::Null, "logs": logs, "error": error_to_json(&e)})
        }
    }
}

//! HTTP transport. Implements the vgi-rpc protocol over HTTP:
//!   `POST /{method}`            unary
//!   `POST /{method}/init`       stream init (producer or exchange)
//!   `POST /{method}/exchange`   stream continuation
//!
//! Stream state lives in an in-memory session map, keyed by an opaque
//! HMAC-signed token the client echoes back on each request. Short-lived
//! conformance tests don't need cross-process state serialization.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arrow_array::RecordBatch;
use arrow_schema::{Schema, SchemaRef};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use crate::errors::{Result, RpcError};
use crate::log::LogMessage;
use crate::metadata::{
    CANCEL_KEY, LOG_EXTRA_KEY, LOG_LEVEL_KEY, LOG_MESSAGE_KEY, REQUEST_ID_KEY, REQUEST_VERSION,
    REQUEST_VERSION_KEY, RPC_METHOD_KEY, SERVER_ID_KEY, STATE_KEY,
};
use crate::server::{CallContext, MethodType, Request, RpcServer};
use crate::stream::{empty_schema, Emitted, OutputCollector, StreamResult, StreamStateKind};
use crate::wire::{empty_batch, md_get, Metadata, ReadBatch, StreamReader, StreamWriter};

pub const ARROW_CONTENT_TYPE: &str = "application/vnd.apache.arrow.stream";

type HmacSha256 = Hmac<Sha256>;

struct Session {
    output_schema: SchemaRef,
    input_schema: Option<SchemaRef>,
    state: StreamStateKind,
    method: String,
}

pub struct HttpState {
    server: Arc<RpcServer>,
    sessions: Mutex<HashMap<String, Session>>,
    signing_key: [u8; 32],
    producer_batch_limit: usize,
}

impl HttpState {
    pub fn new(server: Arc<RpcServer>) -> Arc<Self> {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Arc::new(Self {
            server,
            sessions: Mutex::new(HashMap::new()),
            signing_key: key,
            producer_batch_limit: 1,
        })
    }

    fn sign_token(&self, session_id: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.signing_key).expect("hmac key");
        mac.update(session_id.as_bytes());
        let sig = mac.finalize().into_bytes();
        let mut raw = Vec::with_capacity(session_id.len() + 1 + sig.len());
        raw.extend_from_slice(session_id.as_bytes());
        raw.push(b'|');
        raw.extend_from_slice(&sig);
        base64::engine::general_purpose::STANDARD.encode(raw)
    }

    fn verify_token(&self, token: &str) -> Result<String> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(token.as_bytes())
            .map_err(|_| RpcError::runtime_error("Malformed state token"))?;
        let pipe = raw
            .iter()
            .position(|&b| b == b'|')
            .ok_or_else(|| RpcError::runtime_error("Malformed state token"))?;
        let session_id = std::str::from_utf8(&raw[..pipe])
            .map_err(|_| RpcError::runtime_error("Malformed state token"))?
            .to_string();
        let provided_sig = &raw[pipe + 1..];
        let mut mac = HmacSha256::new_from_slice(&self.signing_key).expect("hmac key");
        mac.update(session_id.as_bytes());
        mac.verify_slice(provided_sig)
            .map_err(|_| RpcError::runtime_error("State token signature verification failed"))?;
        Ok(session_id)
    }
}

pub fn build_router(state: Arc<HttpState>) -> Router {
    Router::new()
        .route("/:method", post(handle_unary))
        .route("/:method/init", post(handle_stream_init))
        .route("/:method/exchange", post(handle_stream_exchange))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn arrow_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(ARROW_CONTENT_TYPE),
    );
    (status, headers, body).into_response()
}

fn plain_error(status: StatusCode, msg: String) -> Response {
    (status, msg).into_response()
}

fn has_arrow_ct(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s == ARROW_CONTENT_TYPE)
        .unwrap_or(false)
}

fn maybe_decompress(headers: &HeaderMap, body: &Bytes) -> Result<Vec<u8>> {
    let enc = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if enc.eq_ignore_ascii_case("zstd") {
        zstd::decode_all(body.as_ref())
            .map_err(|e| RpcError::runtime_error(format!("zstd decode: {e}")))
    } else {
        Ok(body.to_vec())
    }
}

fn parse_request_from_body(body: &[u8]) -> Result<Request> {
    let mut r = StreamReader::new(body)?;
    let ReadBatch { batch, metadata } = r
        .read_next()?
        .ok_or_else(|| RpcError::protocol_error("empty IPC stream"))?;
    r.drain()?;
    let method = md_get(&metadata, RPC_METHOD_KEY).unwrap_or("").to_string();
    let version = md_get(&metadata, REQUEST_VERSION_KEY).ok_or_else(|| {
        RpcError::version_error("Missing vgi_rpc.request_version in request metadata")
    })?;
    if version != REQUEST_VERSION {
        return Err(RpcError::version_error(format!(
            "Unsupported request version {version:?}"
        )));
    }
    let request_id = md_get(&metadata, REQUEST_ID_KEY).unwrap_or("").to_string();
    Ok(Request { method, request_id, batch, metadata })
}

fn build_call_ctx(server: &Arc<RpcServer>, req: &Request) -> CallContext {
    CallContext {
        server_id: server.server_id.clone(),
        method: req.method.clone(),
        request_id: req.request_id.clone(),
        transport_metadata: Arc::new(req.metadata.clone()),
        log_sink: Arc::new(Mutex::new(Vec::new())),
    }
}

fn build_log_metadata(msg: &LogMessage, server_id: &str, request_id: &str) -> Metadata {
    let mut md = vec![
        (LOG_LEVEL_KEY.to_string(), msg.level.as_str().to_string()),
        (LOG_MESSAGE_KEY.to_string(), msg.message.clone()),
    ];
    if !msg.extras.is_empty() {
        md.push((LOG_EXTRA_KEY.to_string(), msg.extras_json()));
    }
    if !server_id.is_empty() {
        md.push((SERVER_ID_KEY.to_string(), server_id.to_string()));
    }
    if !request_id.is_empty() {
        md.push((REQUEST_ID_KEY.to_string(), request_id.to_string()));
    }
    md
}

fn build_error_metadata(err: &RpcError, server_id: &str, request_id: &str) -> Metadata {
    let extra = serde_json::json!({
        "exception_type": err.error_type,
        "exception_message": err.message,
        "traceback": err.traceback,
    })
    .to_string();
    let mut md = vec![
        (LOG_LEVEL_KEY.to_string(), "EXCEPTION".to_string()),
        (LOG_MESSAGE_KEY.to_string(), err.message.clone()),
        (LOG_EXTRA_KEY.to_string(), extra),
    ];
    if !server_id.is_empty() {
        md.push((SERVER_ID_KEY.to_string(), server_id.to_string()));
    }
    if !request_id.is_empty() {
        md.push((REQUEST_ID_KEY.to_string(), request_id.to_string()));
    }
    md
}

fn error_stream_bytes(
    schema: &Schema,
    err: &RpcError,
    server_id: &str,
    request_id: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut w = StreamWriter::new(&mut buf, schema).unwrap();
    let md = build_error_metadata(err, server_id, request_id);
    let _ = w.write(&empty_batch(schema).unwrap(), Some(&md));
    let _ = w.finish();
    drop(w);
    buf
}

fn new_session_id() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for byte in b {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// Unary
// ---------------------------------------------------------------------------

async fn handle_unary(
    State(state): State<Arc<HttpState>>,
    Path(method): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !has_arrow_ct(&headers) {
        return plain_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "need arrow content type".into());
    }
    let server = state.server.clone();

    let body = match maybe_decompress(&headers, &body) {
        Ok(b) => b,
        Err(e) => {
            return arrow_response(
                StatusCode::BAD_REQUEST,
                error_stream_bytes(&Schema::empty(), &e, &state.server.server_id, ""),
            );
        }
    };
    let req = match parse_request_from_body(&body) {
        Ok(r) => r,
        Err(e) => {
            return arrow_response(
                StatusCode::BAD_REQUEST,
                error_stream_bytes(&Schema::empty(), &e, &server.server_id, ""),
            );
        }
    };

    // __describe__ introspection — served as a unary call.
    if server.describe_enabled() && method == crate::introspect::DESCRIBE_METHOD_NAME {
        let (batch, md) = match crate::introspect::build_describe(
            server.protocol_name(),
            server.methods(),
            &server.server_id,
        ) {
            Ok(x) => x,
            Err(err) => {
                return arrow_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_stream_bytes(&Schema::empty(), &err, &server.server_id, &req.request_id),
                );
            }
        };
        let mut buf = Vec::new();
        let _ = crate::introspect::write_describe_response(&mut buf, &batch, &md);
        return arrow_response(StatusCode::OK, buf);
    }

    let Some(info) = server.method(&method).filter(|m| m.method_type == MethodType::Unary) else {
        let err = RpcError::new("AttributeError", format!("Unknown method: '{}'", method));
        return arrow_response(
            StatusCode::NOT_FOUND,
            error_stream_bytes(&Schema::empty(), &err, &server.server_id, &req.request_id),
        );
    };

    let ctx = build_call_ctx(&server, &req);
    let result = (info.unary.as_ref().unwrap())(&req, &ctx);
    let logs = ctx.drain_logs();

    let mut buf = Vec::new();
    {
        let mut sw = StreamWriter::new(&mut buf, &info.result_schema).unwrap();
        for log in &logs {
            let md = build_log_metadata(log, &server.server_id, &req.request_id);
            let _ = sw.write(&empty_batch(&info.result_schema).unwrap(), Some(&md));
        }
        match result {
            Ok(batch_opt) => {
                let out_batch = batch_opt
                    .unwrap_or_else(|| empty_batch(&info.result_schema).unwrap());
                let _ = sw.write(&out_batch, None);
            }
            Err(err) => {
                let md = build_error_metadata(&err, &server.server_id, &req.request_id);
                let _ = sw.write(&empty_batch(&info.result_schema).unwrap(), Some(&md));
            }
        }
        let _ = sw.finish();
    }
    arrow_response(StatusCode::OK, buf)
}

// ---------------------------------------------------------------------------
// Stream init
// ---------------------------------------------------------------------------

async fn handle_stream_init(
    State(state): State<Arc<HttpState>>,
    Path(method): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !has_arrow_ct(&headers) {
        return plain_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "need arrow content type".into());
    }
    let server = state.server.clone();
    let body = match maybe_decompress(&headers, &body) {
        Ok(b) => b,
        Err(e) => {
            return arrow_response(
                StatusCode::BAD_REQUEST,
                error_stream_bytes(&Schema::empty(), &e, &state.server.server_id, ""),
            );
        }
    };
    let req = match parse_request_from_body(&body) {
        Ok(r) => r,
        Err(e) => {
            return arrow_response(
                StatusCode::BAD_REQUEST,
                error_stream_bytes(&Schema::empty(), &e, &server.server_id, ""),
            );
        }
    };

    let Some(info) = server.method(&method).filter(|m| m.method_type != MethodType::Unary) else {
        let err = RpcError::new(
            "AttributeError",
            format!("Unknown stream method: '{}'", method),
        );
        return arrow_response(
            StatusCode::NOT_FOUND,
            error_stream_bytes(&Schema::empty(), &err, &server.server_id, &req.request_id),
        );
    };

    let ctx = build_call_ctx(&server, &req);
    let init_result = (info.stream.as_ref().unwrap())(&req, &ctx);
    let init_logs = ctx.drain_logs();

    let sr = match init_result {
        Ok(s) => s,
        Err(err) => {
            return arrow_response(
                StatusCode::OK,
                error_stream_bytes(&empty_schema(), &err, &server.server_id, &req.request_id),
            );
        }
    };

    let StreamResult {
        output_schema,
        input_schema,
        state: mut ss,
        header,
        header_metadata,
    } = sr;

    let mut body_buf = Vec::new();

    // Write header stream (if any) into body_buf.
    if let Some(header_batch) = header.as_ref() {
        let hdr_schema = header_batch.schema();
        let mut hw = StreamWriter::new(&mut body_buf, hdr_schema.as_ref()).unwrap();
        for log in &init_logs {
            let md = build_log_metadata(log, &server.server_id, &req.request_id);
            let _ = hw.write(&empty_batch(hdr_schema.as_ref()).unwrap(), Some(&md));
        }
        let _ = hw.write(header_batch, header_metadata.as_ref());
        let _ = hw.finish();
    }

    let is_producer = matches!(ss, StreamStateKind::Producer(_));
    let session_id = new_session_id();
    let token = state.sign_token(&session_id);

    let mut finished = false;
    {
        let mut sw = StreamWriter::new(&mut body_buf, output_schema.as_ref()).unwrap();
        if header.is_none() {
            for log in &init_logs {
                let md = build_log_metadata(log, &server.server_id, &req.request_id);
                let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
            }
        }
        let _ = header_metadata;
        if is_producer {
            finished = run_producer(
                &mut sw,
                &mut ss,
                &output_schema,
                &server,
                &req,
                state.producer_batch_limit,
            );
        }
        if !finished {
            let md = vec![(STATE_KEY.to_string(), token.clone())];
            let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
        }
        let _ = sw.finish();
    }

    if !finished {
        let session = Session {
            output_schema,
            input_schema,
            state: ss,
            method: method.clone(),
        };
        state.sessions.lock().unwrap().insert(session_id, session);
    }

    arrow_response(StatusCode::OK, body_buf)
}

fn run_producer<W: std::io::Write>(
    sw: &mut StreamWriter<W>,
    ss: &mut StreamStateKind,
    output_schema: &SchemaRef,
    server: &Arc<RpcServer>,
    req: &Request,
    limit: usize,
) -> bool {
    let ctx = build_call_ctx(server, req);
    let producer = match ss {
        StreamStateKind::Producer(p) => p,
        StreamStateKind::Exchange(_) => unreachable!(),
    };
    let mut batches_written = 0usize;
    while limit == 0 || batches_written < limit {
        let mut out = OutputCollector::new(output_schema.clone(), true);
        let result = producer.produce(&mut out, &ctx);
        for log in ctx.drain_logs() {
            let md = build_log_metadata(&log, &server.server_id, &req.request_id);
            let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
        }
        if let Err(err) = result {
            let md = build_error_metadata(&err, &server.server_id, &req.request_id);
            let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
            return true;
        }
        let finished = out.finished();
        let mut emitted_data = false;
        for item in out.items.drain(..) {
            match item {
                Emitted::Log(log) => {
                    let md = build_log_metadata(&log, &server.server_id, &req.request_id);
                    let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                }
                Emitted::Batch { batch, metadata } => {
                    let _ = sw.write(&batch, metadata.as_ref());
                    emitted_data = true;
                }
            }
        }
        if emitted_data {
            batches_written += 1;
        }
        if finished {
            return true;
        }
        if !emitted_data {
            // Guard against degenerate producers that neither emit nor finish.
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Stream exchange / producer continuation / cancel
// ---------------------------------------------------------------------------

async fn handle_stream_exchange(
    State(state): State<Arc<HttpState>>,
    Path(_method): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !has_arrow_ct(&headers) {
        return plain_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "need arrow content type".into());
    }

    let server = state.server.clone();
    let body = match maybe_decompress(&headers, &body) {
        Ok(b) => b,
        Err(e) => {
            return arrow_response(
                StatusCode::BAD_REQUEST,
                error_stream_bytes(&Schema::empty(), &e, &server.server_id, ""),
            );
        }
    };
    // Parse input batch (may be empty-schema for cancel / producer continuation).
    let (batch, metadata) = match read_input_batch(&body) {
        Ok(x) => x,
        Err(e) => {
            return arrow_response(
                StatusCode::BAD_REQUEST,
                error_stream_bytes(&Schema::empty(), &e, &server.server_id, ""),
            );
        }
    };

    let Some(token) = md_get(&metadata, STATE_KEY).map(str::to_owned) else {
        let err = RpcError::runtime_error("Missing state token in exchange request");
        return arrow_response(
            StatusCode::BAD_REQUEST,
            error_stream_bytes(&Schema::empty(), &err, &server.server_id, ""),
        );
    };
    let cancelled = md_get(&metadata, CANCEL_KEY).is_some();

    let session_id = match state.verify_token(&token) {
        Ok(sid) => sid,
        Err(err) => {
            return arrow_response(
                StatusCode::BAD_REQUEST,
                error_stream_bytes(&Schema::empty(), &err, &server.server_id, ""),
            );
        }
    };

    let Some(mut session) = state.sessions.lock().unwrap().remove(&session_id) else {
        let err = RpcError::runtime_error("State token expired or unknown");
        return arrow_response(
            StatusCode::BAD_REQUEST,
            error_stream_bytes(&Schema::empty(), &err, &server.server_id, ""),
        );
    };

    let req = Request {
        method: session.method.clone(),
        request_id: md_get(&metadata, REQUEST_ID_KEY).unwrap_or("").to_string(),
        batch: empty_batch(&Schema::empty()).unwrap(),
        metadata: metadata.clone(),
    };
    let ctx = build_call_ctx(&server, &req);

    let mut body_buf = Vec::new();

    if cancelled {
        match &mut session.state {
            StreamStateKind::Producer(p) => p.on_cancel(&ctx),
            StreamStateKind::Exchange(e) => e.on_cancel(&ctx),
        }
        {
            let mut sw = StreamWriter::new(&mut body_buf, session.output_schema.as_ref()).unwrap();
            let _ = sw.finish();
        }
        return arrow_response(StatusCode::OK, body_buf);
    }

    let output_schema = session.output_schema.clone();
    let input_schema = session.input_schema.clone();

    if matches!(session.state, StreamStateKind::Producer(_)) {
        // Producer continuation.
        let mut finished;
        {
            let mut sw = StreamWriter::new(&mut body_buf, output_schema.as_ref()).unwrap();
            finished = run_producer(
                &mut sw,
                &mut session.state,
                &output_schema,
                &server,
                &req,
                state.producer_batch_limit,
            );
            if !finished {
                let new_token = state.sign_token(&session_id);
                let md = vec![(STATE_KEY.to_string(), new_token)];
                let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
            }
            let _ = sw.finish();
        }
        if !finished {
            state.sessions.lock().unwrap().insert(session_id, session);
        }
        let _ = finished;
        return arrow_response(StatusCode::OK, body_buf);
    }

    // Exchange continuation.
    let casted = match &input_schema {
        Some(exp) if batch.schema() != *exp => {
            match crate::server::cast_batch_public(&batch, exp) {
                Ok(b) => b,
                Err(e) => {
                    let mut sw =
                        StreamWriter::new(&mut body_buf, output_schema.as_ref()).unwrap();
                    let md = build_error_metadata(&e, &server.server_id, &req.request_id);
                    let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                    let _ = sw.finish();
                    drop(sw);
                    // Session consumed (exchange errored).
                    return arrow_response(StatusCode::OK, body_buf);
                }
            }
        }
        _ => batch,
    };

    let mut out = OutputCollector::new(output_schema.clone(), false);
    let res = match &mut session.state {
        StreamStateKind::Exchange(e) => e.exchange(&casted, &mut out, &ctx),
        _ => unreachable!(),
    };

    let new_token = state.sign_token(&session_id);
    let mut keep_session = true;
    {
        let mut sw = StreamWriter::new(&mut body_buf, output_schema.as_ref()).unwrap();
        for log in ctx.drain_logs() {
            let md = build_log_metadata(&log, &server.server_id, &req.request_id);
            let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
        }
        if let Err(err) = res {
            let md = build_error_metadata(&err, &server.server_id, &req.request_id);
            let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
            keep_session = false;
        } else {
            let mut wrote_data = false;
            for item in out.items.drain(..) {
                match item {
                    Emitted::Log(log) => {
                        let md = build_log_metadata(&log, &server.server_id, &req.request_id);
                        let _ =
                            sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
                    }
                    Emitted::Batch { batch, metadata } => {
                        let mut md = metadata.unwrap_or_default();
                        md.push((STATE_KEY.to_string(), new_token.clone()));
                        let _ = sw.write(&batch, Some(&md));
                        wrote_data = true;
                    }
                }
            }
            if !wrote_data {
                let md = vec![(STATE_KEY.to_string(), new_token.clone())];
                let _ = sw.write(&empty_batch(output_schema.as_ref()).unwrap(), Some(&md));
            }
        }
        let _ = sw.finish();
    }

    if keep_session {
        state.sessions.lock().unwrap().insert(session_id, session);
    }
    arrow_response(StatusCode::OK, body_buf)
}

fn read_input_batch(body: &[u8]) -> Result<(RecordBatch, Metadata)> {
    let mut r = StreamReader::new(body)?;
    let ReadBatch { batch, metadata } = r
        .read_next()?
        .ok_or_else(|| RpcError::runtime_error("no batch in exchange request"))?;
    r.drain()?;
    Ok((batch, metadata))
}

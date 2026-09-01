//! Stable JavaScript-facing browser API.
//!
//! The Rust types in this module deliberately expose byte streams rather than
//! Arrow objects.  The DuckDB-WASM adapter already owns VGI framing, Arrow IPC,
//! cancellation, and its SharedArrayBuffer rings; this layer only supplies an
//! authenticated Iroh byte transport shared by `vgi-rpc/arrow-mux/1` and
//! `iroh-http/2`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::str::FromStr;

use futures_util::future::{FutureExt, LocalBoxFuture, Shared};
use http_body_util::BodyExt;
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey};
use js_sys::{Array, Reflect, Uint8Array};
use tokio::sync::{watch, Mutex};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::{IrohHttpEndpoint, IrohHttpError, RequestBody, IROH_HTTP_ALPN};

const VGI_MUX_ALPN: &[u8] = b"vgi-rpc/arrow-mux/1";
const CLOSE_CODE: u32 = 0;

fn js_error(context: &str, error: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&format!("{context}: {error}")).into()
}

fn httpi_error(error: JsValue, stage: &str, category: &str, dispatch: &str) -> JsValue {
    let _ = Reflect::set(&error, &"vgiStage".into(), &stage.into());
    let _ = Reflect::set(&error, &"vgiCategory".into(), &category.into());
    let _ = Reflect::set(&error, &"vgiDispatchCertainty".into(), &dispatch.into());
    error
}

fn parse_endpoint_id(value: &str) -> Result<EndpointId, JsValue> {
    EndpointId::from_str(value).map_err(|error| js_error("invalid Iroh endpoint ID", error))
}

fn option_property(options: &Option<JsValue>, name: &str) -> Result<Option<JsValue>, JsValue> {
    let Some(options) = options else {
        return Ok(None);
    };
    let value = Reflect::get(options, &JsValue::from_str(name))?;
    if value.is_undefined() || value.is_null() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Protocol {
    VgiMux,
    Http,
}

impl Protocol {
    fn alpn(self) -> &'static [u8] {
        match self {
            Self::VgiMux => VGI_MUX_ALPN,
            Self::Http => IROH_HTTP_ALPN,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ConnectionKey {
    remote: EndpointId,
    protocol: Protocol,
}

type SharedConnection = Shared<LocalBoxFuture<'static, Result<Connection, String>>>;

/// One browser Iroh identity and its protocol-specific connection pools.
///
/// Construct this with [`create_iroh_node`].  One instance should be shared by
/// an entire DuckDB engine so HTTP and raw VGI calls present the same endpoint
/// identity to workers.
#[wasm_bindgen]
pub struct BrowserIrohNode {
    endpoint: Endpoint,
    connections: Rc<RefCell<HashMap<ConnectionKey, SharedConnection>>>,
}

impl BrowserIrohNode {
    async fn connection(
        &self,
        remote: EndpointId,
        protocol: Protocol,
    ) -> Result<Connection, JsValue> {
        let key = ConnectionKey { remote, protocol };
        loop {
            let existing = self.connections.borrow().get(&key).cloned();
            let connection = match existing {
                Some(connecting) => connecting.await,
                None => {
                    let endpoint = self.endpoint.clone();
                    let connecting = async move {
                        endpoint
                            .connect(EndpointAddr::from(remote), protocol.alpn())
                            .await
                            .map_err(|error| error.to_string())
                    }
                    .boxed_local()
                    .shared();
                    self.connections
                        .borrow_mut()
                        .insert(key, connecting.clone());
                    connecting.await
                }
            };
            match connection {
                Ok(connection) if connection.close_reason().is_none() => return Ok(connection),
                Ok(_) => {
                    self.connections.borrow_mut().remove(&key);
                }
                Err(error) => {
                    self.connections.borrow_mut().remove(&key);
                    return Err(js_error("Iroh connect failed", error));
                }
            }
        }
    }
}

#[wasm_bindgen]
impl BrowserIrohNode {
    /// Lowercase 64-hex public endpoint key used by VGI's identity contract.
    #[wasm_bindgen(getter, js_name = endpointId)]
    pub fn endpoint_id(&self) -> String {
        self.endpoint.id().to_string()
    }

    /// Open one independent VGI byte stream on the pooled mux connection.
    #[wasm_bindgen(js_name = openVgiStream)]
    pub async fn open_vgi_stream(&self, remote: String) -> Result<BrowserVgiStream, JsValue> {
        let remote = parse_endpoint_id(&remote)?;
        let connection = self.connection(remote, Protocol::VgiMux).await?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|error| js_error("opening VGI stream failed", error))?;
        Ok(BrowserVgiStream {
            send: Rc::new(Mutex::new(Some(send))),
            recv: Rc::new(Mutex::new(Some(recv))),
            send_cancel: watch::channel(false).0,
            recv_cancel: watch::channel(false).0,
            #[cfg(feature = "browser-smoke")]
            smoke: false,
        })
    }

    /// Send one HTTP/1.1 request over a pooled `iroh-http/2` connection.
    ///
    /// `headers` is an array of `[name, value]` pairs so ordering and duplicate
    /// fields are preserved.  The response body remains streaming through
    /// [`BrowserHttpResponse::read`].
    #[wasm_bindgen(js_name = fetchHttpi)]
    pub async fn fetch_httpi(
        &self,
        remote: String,
        method: String,
        path: String,
        headers: Array,
        body: Uint8Array,
    ) -> Result<BrowserHttpResponse, JsValue> {
        let remote = parse_endpoint_id(&remote)
            .map_err(|error| httpi_error(error, "parse", "invalid_request", "not_dispatched"))?;
        let connection = self
            .connection(remote, Protocol::Http)
            .await
            .map_err(|error| httpi_error(error, "connect", "unavailable", "not_dispatched"))?;
        let mut builder = hyper::Request::builder()
            .method(method.as_str())
            .uri(path.as_str());
        for item in headers.iter() {
            let pair = Array::from(&item);
            if pair.length() != 2 {
                return Err(
                    js_sys::TypeError::new("each header must be a [name, value] pair").into(),
                );
            }
            let name = pair
                .get(0)
                .as_string()
                .ok_or_else(|| js_sys::TypeError::new("header name must be a string"))?;
            let value = pair
                .get(1)
                .as_string()
                .ok_or_else(|| js_sys::TypeError::new("header value must be a string"))?;
            builder = builder.header(name, value);
        }
        let request = builder
            .body(RequestBody::from(bytes::Bytes::from(body.to_vec())))
            .map_err(|error| {
                httpi_error(
                    js_error("invalid HTTP request", error),
                    "request",
                    "invalid_request",
                    "not_dispatched",
                )
            })?;
        let response = IrohHttpEndpoint::new(self.endpoint.clone())
            .request_on_connection(&connection, request)
            .await
            .map_err(|error| match error {
                setup @ (IrohHttpError::OpenStream(_) | IrohHttpError::Handshake(_)) => {
                    httpi_error(
                        js_error("Iroh HTTP request setup failed", setup),
                        "connect",
                        "unavailable",
                        "not_dispatched",
                    )
                }
                request @ IrohHttpError::Request(_) => httpi_error(
                    js_error("Iroh HTTP request failed", request),
                    "request",
                    "transport",
                    "ambiguous",
                ),
                connect @ IrohHttpError::Connect(_) => httpi_error(
                    js_error("Iroh HTTP connect failed", connect),
                    "connect",
                    "unavailable",
                    "not_dispatched",
                ),
            })?;
        let status = response.status().as_u16();
        let mut response_headers = Vec::with_capacity(response.headers().len());
        for (name, value) in response.headers() {
            let value = value.to_str().map_err(|error| {
                httpi_error(
                    js_error("HTTP response header is not text", error),
                    "response_head",
                    "protocol",
                    "dispatched",
                )
            })?;
            response_headers.push((name.as_str().to_owned(), value.to_owned()));
        }
        Ok(BrowserHttpResponse {
            status,
            headers: response_headers,
            body: Rc::new(Mutex::new(Some(response.into_body()))),
            cancel: watch::channel(false).0,
            #[cfg(feature = "browser-smoke")]
            smoke: false,
        })
    }

    /// Close all pooled connections and release the browser endpoint.
    pub async fn close(&self) {
        self.connections.borrow_mut().clear();
        self.endpoint.close().await;
    }
}

/// Create a relay-capable browser endpoint.
///
/// `options.secretKey` accepts Iroh's 64-hex or z-base-32 secret-key encoding.
/// When omitted, a fresh ephemeral identity is generated.  Persist the secret
/// only when stable browser identity is an explicit application requirement.
/// `options.relayUrls`, when supplied, replaces the n0 relay set.
#[wasm_bindgen(js_name = createIrohNode)]
pub async fn create_iroh_node(options: Option<JsValue>) -> Result<BrowserIrohNode, JsValue> {
    let mut builder = Endpoint::builder(presets::N0);
    if let Some(secret_key) = option_property(&options, "secretKey")? {
        let secret_key = secret_key
            .as_string()
            .ok_or_else(|| js_sys::TypeError::new("secretKey must be a string"))?;
        let secret_key = SecretKey::from_str(&secret_key)
            .map_err(|error| js_error("invalid Iroh secret key", error))?;
        builder = builder.secret_key(secret_key);
    }
    if let Some(relay_urls) = option_property(&options, "relayUrls")? {
        if !Array::is_array(&relay_urls) {
            return Err(js_sys::TypeError::new("relayUrls must be an array of URLs").into());
        }
        let mut parsed = Vec::<RelayUrl>::new();
        for relay_url in Array::from(&relay_urls).iter() {
            let relay_url = relay_url
                .as_string()
                .ok_or_else(|| js_sys::TypeError::new("relayUrls entries must be strings"))?;
            parsed.push(
                RelayUrl::from_str(&relay_url)
                    .map_err(|error| js_error("invalid Iroh relay URL", error))?,
            );
        }
        if parsed.is_empty() {
            return Err(js_sys::TypeError::new("relayUrls cannot be empty").into());
        }
        builder = builder.relay_mode(RelayMode::custom(parsed));
    }
    let endpoint = builder
        .bind()
        .await
        .map_err(|error| js_error("binding browser Iroh endpoint failed", error))?;
    Ok(BrowserIrohNode {
        endpoint,
        connections: Rc::new(RefCell::new(HashMap::new())),
    })
}

/// Raw bidirectional VGI stream.  The accompanying TypeScript wrapper exposes
/// these methods as WHATWG `ReadableStream` and `WritableStream` objects.
#[wasm_bindgen]
pub struct BrowserVgiStream {
    send: Rc<Mutex<Option<SendStream>>>,
    recv: Rc<Mutex<Option<RecvStream>>>,
    send_cancel: watch::Sender<bool>,
    recv_cancel: watch::Sender<bool>,
    #[cfg(feature = "browser-smoke")]
    smoke: bool,
}

async fn cancelled(mut receiver: watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    while receiver.changed().await.is_ok() {
        if *receiver.borrow() {
            return;
        }
    }
}

fn reset_send(send: Rc<Mutex<Option<SendStream>>>) {
    spawn_local(async move {
        if let Some(mut send) = send.lock().await.take() {
            let _ = send.reset(CLOSE_CODE.into());
        }
    });
}

fn stop_recv(recv: Rc<Mutex<Option<RecvStream>>>) {
    spawn_local(async move {
        if let Some(mut recv) = recv.lock().await.take() {
            let _ = recv.stop(CLOSE_CODE.into());
        }
    });
}

#[wasm_bindgen]
impl BrowserVgiStream {
    /// Write the complete chunk, respecting QUIC backpressure.
    pub async fn write(&self, chunk: Uint8Array) -> Result<(), JsValue> {
        #[cfg(feature = "browser-smoke")]
        if self.smoke {
            if *self.send_cancel.borrow() {
                return Err(js_sys::Error::new("VGI stream write aborted").into());
            }
            let _ = chunk;
            return Ok(());
        }
        let chunk = chunk.to_vec();
        let mut send = self.send.lock().await;
        let send = send
            .as_mut()
            .ok_or_else(|| js_sys::Error::new("VGI stream write side is closed"))?;
        tokio::select! {
            result = send.write_all(&chunk) => {
                result.map_err(|error| js_error("VGI stream write failed", error))
            }
            () = cancelled(self.send_cancel.subscribe()) => {
                Err(js_sys::Error::new("VGI stream write aborted").into())
            }
        }
    }

    /// Read up to `max_bytes`; returns `undefined` after a clean peer FIN.
    pub async fn read(&self, max_bytes: usize) -> Result<Option<Uint8Array>, JsValue> {
        if max_bytes == 0 {
            return Err(js_sys::RangeError::new("maxBytes must be positive").into());
        }
        #[cfg(feature = "browser-smoke")]
        if self.smoke {
            cancelled(self.recv_cancel.subscribe()).await;
            return Err(js_sys::Error::new("VGI stream read aborted").into());
        }
        let mut recv = self.recv.lock().await;
        let stream = recv
            .as_mut()
            .ok_or_else(|| js_sys::Error::new("VGI stream read side is closed"))?;
        let mut buffer = vec![0; max_bytes.min(1024 * 1024)];
        let read = tokio::select! {
            result = stream.read(&mut buffer) => {
                result.map_err(|error| js_error("VGI stream read failed", error))?
            }
            () = cancelled(self.recv_cancel.subscribe()) => {
                return Err(js_sys::Error::new("VGI stream read aborted").into());
            }
        };
        match read {
            Some(read) => {
                buffer.truncate(read);
                Ok(Some(Uint8Array::from(buffer.as_slice())))
            }
            None => {
                *recv = None;
                Ok(None)
            }
        }
    }

    /// Finish the request direction while retaining the response direction.
    #[wasm_bindgen(js_name = closeWrite)]
    pub async fn close_write(&self) -> Result<(), JsValue> {
        #[cfg(feature = "browser-smoke")]
        if self.smoke {
            return Ok(());
        }
        let mut guard = self.send.lock().await;
        let Some(mut send) = guard.take() else {
            return Ok(());
        };
        send.finish()
            .map_err(|error| js_error("finishing VGI stream failed", error))
    }

    /// Reset both stream directions.  This never closes sibling mux streams.
    pub fn abort(&self) {
        self.send_cancel.send_replace(true);
        self.recv_cancel.send_replace(true);
        reset_send(Rc::clone(&self.send));
        stop_recv(Rc::clone(&self.recv));
    }
}

/// Streaming HTTP response preserving ordered duplicate headers.
#[wasm_bindgen]
pub struct BrowserHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Rc<Mutex<Option<hyper::body::Incoming>>>,
    cancel: watch::Sender<bool>,
    #[cfg(feature = "browser-smoke")]
    smoke: bool,
}

#[wasm_bindgen]
impl BrowserHttpResponse {
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> u16 {
        self.status
    }

    #[wasm_bindgen(getter)]
    pub fn headers(&self) -> Array {
        let headers = Array::new();
        for (name, value) in &self.headers {
            let pair = Array::new();
            pair.push(&JsValue::from_str(name));
            pair.push(&JsValue::from_str(value));
            headers.push(&pair);
        }
        headers
    }

    /// Read the next raw HTTP body data frame; trailers are currently skipped.
    /// No browser content decoding is performed.
    pub async fn read(&self) -> Result<Option<Uint8Array>, JsValue> {
        #[cfg(feature = "browser-smoke")]
        if self.smoke {
            cancelled(self.cancel.subscribe()).await;
            return Err(js_sys::Error::new("HTTP response body cancelled").into());
        }
        let mut guard = self.body.lock().await;
        let Some(body) = guard.as_mut() else {
            return Ok(None);
        };
        loop {
            let frame = tokio::select! {
                frame = body.frame() => frame,
                () = cancelled(self.cancel.subscribe()) => {
                    return Err(js_sys::Error::new("HTTP response body cancelled").into());
                }
            };
            let Some(frame) = frame else {
                *guard = None;
                return Ok(None);
            };
            let frame =
                frame.map_err(|error| js_error("reading HTTP response body failed", error))?;
            if let Ok(data) = frame.into_data() {
                return Ok(Some(Uint8Array::from(data.as_ref())));
            }
        }
    }

    pub fn cancel(&self) {
        self.cancel.send_replace(true);
        let body = Rc::clone(&self.body);
        spawn_local(async move {
            body.lock().await.take();
        });
    }
}

/// Test-only factory used by the generated-bindings browser smoke.  It returns
/// the real exported class with deterministic pending I/O, so the test detects
/// wasm-bindgen's dynamic borrow behavior rather than exercising a mock.
#[cfg(feature = "browser-smoke")]
#[wasm_bindgen(js_name = __vgiBorrowSmoke)]
pub fn vgi_borrow_smoke() -> BrowserVgiStream {
    BrowserVgiStream {
        send: Rc::new(Mutex::new(None)),
        recv: Rc::new(Mutex::new(None)),
        send_cancel: watch::channel(false).0,
        recv_cancel: watch::channel(false).0,
        smoke: true,
    }
}

/// Test-only pending HTTP body for verifying cancel-during-read through the
/// actual wasm-bindgen JavaScript glue.
#[cfg(feature = "browser-smoke")]
#[wasm_bindgen(js_name = __httpBorrowSmoke)]
pub fn http_borrow_smoke() -> BrowserHttpResponse {
    BrowserHttpResponse {
        status: 200,
        headers: Vec::new(),
        body: Rc::new(Mutex::new(None)),
        cancel: watch::channel(false).0,
        smoke: true,
    }
}

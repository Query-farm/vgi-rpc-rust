//! Integration tests: CORS, health endpoint, landing/describe pages,
//! URL prefix mounting, and zstd response compression.

use std::sync::Arc;

use arrow_array::{RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use vgi_rpc::http::{HttpState, ARROW_CONTENT_TYPE};
use vgi_rpc::metadata::{REQUEST_VERSION, REQUEST_VERSION_KEY};
use vgi_rpc::wire::{Metadata, StreamWriter};
use vgi_rpc::{MethodInfo, RpcServer};

/// Encode a valid unary HTTP request body: one IPC stream carrying `batch`
/// with the request-version metadata (the method is derived from the URL).
fn encode_unary_body(schema: &Schema, batch: &RecordBatch) -> Vec<u8> {
    let mut md = Metadata::new();
    md.insert(REQUEST_VERSION_KEY.into(), REQUEST_VERSION.into());
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, schema).unwrap();
        w.write(batch, Some(&md)).unwrap();
        w.finish().unwrap();
    }
    buf
}

/// Build a test `HttpState`. `compression: None` means *disabled*, not
/// "unset" — response compression is on by default now, and these tests
/// predate that, so `None` keeps its original "no compression" meaning.
/// See `default_server_compresses_and_advertises_zstd` for the default.
fn state_with(
    cors: Option<&str>,
    prefix: Option<&str>,
    compression: Option<i32>,
) -> Arc<HttpState> {
    let mut b = stock_builder();
    if let Some(o) = cors {
        b = b.cors_origins(o);
    }
    if let Some(p) = prefix {
        b = b.prefix(p);
    }
    match compression {
        Some(l) => b.response_compression_level(l),
        None => b.disable_response_compression(),
    }
    .build()
}

/// The same two-method test server, wrapped in a builder with **nothing**
/// configured — so it exercises the shipped defaults, response compression
/// included.
fn stock_builder() -> vgi_rpc::http::HttpStateBuilder {
    let mut srv = RpcServer::builder()
        .server_id("it")
        .protocol_name("Test")
        .enable_describe(true)
        .build();
    srv.register(
        MethodInfo::unary(
            "echo_string",
            arrow_schema::Schema::new(vec![arrow_schema::Field::new(
                "value",
                arrow_schema::DataType::Utf8,
                false,
            )])
            .into(),
            arrow_schema::Schema::new(vec![arrow_schema::Field::new(
                "result",
                arrow_schema::DataType::Utf8,
                false,
            )])
            .into(),
            |_req, _| Ok(None),
        )
        .doc("stub echo")
        .param_type("value", "str"),
    );
    // A method that returns a large, highly compressible body — used to
    // exercise the response-compression path above the size threshold.
    srv.register(MethodInfo::unary(
        "big",
        Schema::new(vec![Field::new("value", DataType::Utf8, false)]).into(),
        Schema::new(vec![Field::new("result", DataType::Utf8, false)]).into(),
        |_req, _| {
            let big = "abcdefgh".repeat(2048); // 16 KiB, compresses well
            let schema = Arc::new(Schema::new(vec![Field::new(
                "result",
                DataType::Utf8,
                false,
            )]));
            let arr = StringArray::from(vec![big]);
            Ok(Some(
                RecordBatch::try_new(schema, vec![Arc::new(arr)]).unwrap(),
            ))
        },
    ));
    HttpState::builder().server(Arc::new(srv))
}

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let state = state_with(None, None, None);
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// `/health` is the mandatory capability-discovery endpoint, and the C++ client
/// probes it with `HEAD`. It must not 405 (which carries no Content-Length and
/// would silently degrade discovery to defaults), and must expose the same
/// capability headers as GET so discovery is verb-independent.
#[tokio::test]
async fn health_head_returns_200_with_capabilities() {
    let caps = |resp: &axum::response::Response| -> Vec<(String, String)> {
        let mut v: Vec<_> = resp
            .headers()
            .iter()
            .filter(|(k, _)| k.as_str().starts_with("vgi-"))
            .map(|(k, val)| (k.as_str().to_string(), val.to_str().unwrap().to_string()))
            .collect();
        v.sort();
        v
    };
    let request = |method: &str| {
        Request::builder()
            .method(method)
            .uri("/health")
            .body(Body::empty())
            .unwrap()
    };

    let get_resp = vgi_rpc::http::build_router(state_with(None, None, None))
        .oneshot(request("GET"))
        .await
        .unwrap();
    let head_resp = vgi_rpc::http::build_router(state_with(None, None, None))
        .oneshot(request("HEAD"))
        .await
        .unwrap();

    assert_eq!(head_resp.status(), StatusCode::OK);
    assert!(head_resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap()
        .contains("application/json"));
    assert_eq!(caps(&head_resp), caps(&get_resp));
    assert!(
        !caps(&get_resp).is_empty(),
        "GET should expose capabilities"
    );

    let get_body = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let head_len = head_resp
        .headers()
        .get(header::CONTENT_LENGTH)
        .map(|v| v.to_str().unwrap().to_string());
    let head_body = axum::body::to_bytes(head_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(head_body.is_empty(), "HEAD carries no body");
    assert_eq!(
        head_len.as_deref(),
        Some(get_body.len().to_string().as_str())
    );
}

/// The `__upload_url__` wire contract is public, so an intermediary that
/// terminates or serves the flow needn't copy the method name or schemas.
#[test]
fn upload_url_contract_is_exported() {
    assert_eq!(vgi_rpc::UPLOAD_URL_METHOD, "__upload_url__");
    assert_eq!(vgi_rpc::MAX_UPLOAD_URL_COUNT, 100);
    let params = vgi_rpc::upload_url_params_schema();
    assert_eq!(
        params
            .fields()
            .iter()
            .map(|f| f.name().as_str())
            .collect::<Vec<_>>(),
        ["count"]
    );
    let response = vgi_rpc::upload_url_response_schema();
    assert_eq!(
        response
            .fields()
            .iter()
            .map(|f| f.name().as_str())
            .collect::<Vec<_>>(),
        ["upload_url", "download_url", "expires_at"]
    );
}

#[tokio::test]
async fn preflight_includes_cors_headers() {
    let state = state_with(Some("https://app.example.com"), None, None);
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/echo_string")
                .header(header::ORIGIN, "https://app.example.com")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let allow = resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .unwrap();
    assert_eq!(allow, "https://app.example.com");
    assert!(resp.headers().contains_key(header::ACCESS_CONTROL_MAX_AGE));
}

#[tokio::test]
async fn prefix_mounts_routes_under_path() {
    let state = state_with(None, Some("/v1"), None);
    let app = vgi_rpc::http::build_router(state);
    // /health is always at the absolute root regardless of API prefix —
    // load balancers and orchestrators should never have to know which
    // prefix the API is under, and the conformance suite enforces this.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // The prefixed path does NOT serve /health (the route lives at root).
    // The prefix path may match the API router pattern `:method` and
    // return 405 (Method Not Allowed for GET) rather than 404 — either
    // is correct as long as it isn't 200.
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() != StatusCode::OK,
        "/v1/health must NOT be the health endpoint when prefix=/v1"
    );
}

#[tokio::test]
async fn describe_html_page_served() {
    let state = state_with(None, None, None);
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/describe")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
    assert!(ct.to_str().unwrap().starts_with("text/html"));
}

#[tokio::test]
async fn small_response_below_threshold_is_not_compressed() {
    let state = state_with(None, None, Some(3));
    let app = vgi_rpc::http::build_router(state);
    // Send a request missing a body to force a small Arrow error stream. It is
    // well under the 1 KiB compression threshold, so even though the client
    // offered `Accept-Encoding: zstd` the reply is shipped uncompressed —
    // `Accept-Encoding` is a client capability, not a demand.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/echo_string")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .header(header::ACCEPT_ENCODING, "zstd")
                .body(Body::from(vec![]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let ce = resp.headers().get(header::CONTENT_ENCODING).cloned();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    // Verify the premise (small body) and the behaviour (no compression).
    assert!(
        body.len() < 1024,
        "error body unexpectedly large ({} bytes)",
        body.len()
    );
    assert!(
        ce.is_none(),
        "sub-threshold bodies must not be zstd-compressed, got {ce:?}"
    );
}

#[tokio::test]
async fn large_response_above_threshold_is_zstd_compressed() {
    let state = state_with(None, None, Some(3));
    let app = vgi_rpc::http::build_router(state);
    let params_schema = Schema::new(vec![Field::new("value", DataType::Utf8, false)]);
    let batch = RecordBatch::try_new(
        Arc::new(params_schema.clone()),
        vec![Arc::new(StringArray::from(vec!["x"]))],
    )
    .unwrap();
    let body = encode_unary_body(&params_schema, &batch);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/big")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .header(header::ACCEPT_ENCODING, "zstd")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ce = resp.headers().get(header::CONTENT_ENCODING);
    assert_eq!(
        ce.and_then(|v| v.to_str().ok()),
        Some("zstd"),
        "large compressible bodies must be zstd-compressed"
    );
}

/// Drive `POST /big` (a 16 KiB compressible Arrow body) with the given
/// request headers against a zstd-level-3 server, returning the response
/// headers.
async fn big_response_headers(headers: &[(&str, &str)]) -> header::HeaderMap {
    big_response_headers_on(state_with(None, None, Some(3)), headers).await
}

/// As `big_response_headers`, but against a caller-supplied state.
async fn big_response_headers_on(
    state: Arc<HttpState>,
    headers: &[(&str, &str)],
) -> header::HeaderMap {
    let app = vgi_rpc::http::build_router(state);
    let params_schema = Schema::new(vec![Field::new("value", DataType::Utf8, false)]);
    let batch = RecordBatch::try_new(
        Arc::new(params_schema.clone()),
        vec![Arc::new(StringArray::from(vec!["x"]))],
    )
    .unwrap();
    let body = encode_unary_body(&params_schema, &batch);
    let mut builder = Request::builder()
        .method("POST")
        .uri("/big")
        .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let resp = app
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    resp.headers().clone()
}

/// The browser/WASM case: `fetch()` cannot set `Accept-Encoding` (forbidden
/// header name), so the client states its preference only in
/// `X-VGI-Accept-Encoding`. The server must honour it and answer on the
/// matching custom response header — a standard `Content-Encoding` would be
/// auto-decoded or mangled by the very fetch layer that forced the custom
/// request header.
#[tokio::test]
async fn custom_accept_encoding_alone_compresses_and_stamps_custom_header() {
    let h = big_response_headers(&[("x-vgi-accept-encoding", "zstd, gzip")]).await;
    assert_eq!(
        h.get("x-vgi-content-encoding")
            .and_then(|v| v.to_str().ok()),
        Some("zstd"),
        "custom-header-only clients must still get a compressed response"
    );
    assert!(
        h.get(header::CONTENT_ENCODING).is_none(),
        "must not claim a standard Content-Encoding for a custom-header client"
    );
}

/// The cpp-httplib case: the DuckDB engine's HTTP client injects
/// `Accept-Encoding: deflate, gzip, br, zstd` (gzip before zstd) while VGI
/// states zstd first in its own header. zstd must win — and because it is
/// present in both lists, it rides the standard `Content-Encoding`.
#[tokio::test]
async fn custom_header_beats_gzip_first_standard_header() {
    let h = big_response_headers(&[
        (header::ACCEPT_ENCODING.as_str(), "deflate, gzip, br, zstd"),
        ("x-vgi-accept-encoding", "zstd, gzip"),
    ])
    .await;
    assert_eq!(
        h.get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("zstd")
    );
    assert!(h.get("x-vgi-content-encoding").is_none());
}

/// A client offering only codings this server cannot produce (gzip is
/// decode-only on the response path) gets an uncompressed body — and no
/// encoding header at all. Same for a client that explicitly asks for
/// `identity`: an identity body is just a body.
#[tokio::test]
async fn unproducible_absent_or_identity_offers_yield_no_encoding_header() {
    for req_headers in [
        &[][..],
        &[("x-vgi-accept-encoding", "gzip")][..],
        &[(header::ACCEPT_ENCODING.as_str(), "gzip, br, deflate")][..],
        // Explicit opt-out, even though zstd is offered right behind it.
        &[("x-vgi-accept-encoding", "identity, zstd")][..],
        &[(header::ACCEPT_ENCODING.as_str(), "identity, zstd")][..],
    ] {
        let h = big_response_headers(req_headers).await;
        assert!(
            h.get(header::CONTENT_ENCODING).is_none() && h.get("x-vgi-content-encoding").is_none(),
            "unexpected encoding header for request headers {req_headers:?}"
        );
    }
}

/// `identity` only wins when the client puts it first — a compressed codec
/// ahead of it still takes the response.
#[tokio::test]
async fn identity_behind_zstd_still_compresses() {
    let h = big_response_headers(&[("x-vgi-accept-encoding", "zstd, identity")]).await;
    assert_eq!(
        h.get("x-vgi-content-encoding")
            .and_then(|v| v.to_str().ok()),
        Some("zstd")
    );
}

/// `VGI-Supported-Encodings` advertises the codecs usable in both directions
/// (decode requests *and* encode responses), in server-preference order and
/// without `identity`. `OPTIONS /health` is the dedicated capability probe.
#[tokio::test]
async fn supported_encodings_advertised_on_options_health() {
    async fn probe(compression: Option<i32>) -> Option<String> {
        let app = vgi_rpc::http::build_router(state_with(None, None, compression));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        resp.headers()
            .get("vgi-supported-encodings")
            .map(|v| v.to_str().unwrap().to_string())
    }
    // zstd is decodable and producible; gzip is decode-only, so it is not in
    // the intersection and is not advertised.
    assert_eq!(probe(Some(3)).await.as_deref(), Some("zstd"));
    // Response compression is off by default: the header must still be
    // present, with an empty value. Absent would mean "legacy server, assume
    // zstd" — the opposite of the truth.
    assert_eq!(probe(None).await.as_deref(), Some(""));
}

/// With compression disabled, a client advertising zstd still gets an
/// uncompressed body and no encoding header — matching the empty
/// `VGI-Supported-Encodings` advertisement.
#[tokio::test]
async fn compression_disabled_server_advertises_and_behaves_consistently() {
    let state = state_with(None, None, None);
    let app = vgi_rpc::http::build_router(state);
    let params_schema = Schema::new(vec![Field::new("value", DataType::Utf8, false)]);
    let batch = RecordBatch::try_new(
        Arc::new(params_schema.clone()),
        vec![Arc::new(StringArray::from(vec!["x"]))],
    )
    .unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/big")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .header(header::ACCEPT_ENCODING, "zstd")
                .header("x-vgi-accept-encoding", "zstd")
                .body(Body::from(encode_unary_body(&params_schema, &batch)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("vgi-supported-encodings")
            .map(|v| v.to_str().unwrap()),
        Some("")
    );
    assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
    assert!(resp.headers().get("x-vgi-content-encoding").is_none());
}

/// A server built with **no** compression configuration compresses, and says
/// so. Response compression used to default to off, which meant a stock Rust
/// server advertised an empty `VGI-Supported-Encodings` and shipped every
/// Arrow body raw. It now defaults to zstd at
/// `DEFAULT_RESPONSE_COMPRESSION_LEVEL`.
#[tokio::test]
async fn default_server_compresses_and_advertises_zstd() {
    let h = big_response_headers_on(stock_builder().build(), &[("accept-encoding", "zstd")]).await;
    assert_eq!(
        h.get("vgi-supported-encodings")
            .and_then(|v| v.to_str().ok()),
        Some("zstd"),
        "a stock server must advertise the codec it can produce"
    );
    assert_eq!(
        h.get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("zstd"),
        "a stock server must actually compress, not just advertise"
    );
}

/// Level 1 is the default, and it is the level that is actually applied —
/// not merely a flag that switches compression on at zstd's own default of 3.
/// Level 1 was measured 4.7x faster than level 3 *and* smaller on an 8.41 MB
/// Arrow payload, so the level is the point, not an incidental.
#[tokio::test]
async fn default_compression_level_is_one() {
    let body_len = |state: Arc<HttpState>| async move {
        let app = vgi_rpc::http::build_router(state);
        let params_schema = Schema::new(vec![Field::new("value", DataType::Utf8, false)]);
        let batch = RecordBatch::try_new(
            Arc::new(params_schema.clone()),
            vec![Arc::new(StringArray::from(vec!["x"]))],
        )
        .unwrap();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/big")
                    .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                    .header(header::ACCEPT_ENCODING, "zstd")
                    .body(Body::from(encode_unary_body(&params_schema, &batch)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .len()
    };
    assert_eq!(
        body_len(stock_builder().build()).await,
        body_len(state_with(None, None, Some(1))).await,
        "the default must be exactly level 1"
    );
}

/// Regression: the compressed-response path used to `return` before
/// `attach_capability_headers` ran, so every compressed Arrow body — i.e.
/// every large response, the ones a client most needs to size correctly —
/// arrived with no `VGI-*` headers at all. Capability discovery is stamped on
/// *every* response in the other SDKs; it must be here too.
#[tokio::test]
async fn compressed_response_still_carries_capability_headers() {
    let state = stock_builder()
        .max_request_bytes(1024 * 1024)
        .max_response_bytes(2 * 1024 * 1024)
        .build();
    let h = big_response_headers_on(state, &[("accept-encoding", "zstd")]).await;
    // Premise: this response really was compressed.
    assert_eq!(
        h.get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("zstd"),
        "test is vacuous unless the body was compressed"
    );
    for name in [
        "vgi-supported-encodings",
        "vgi-max-request-bytes",
        "vgi-max-response-bytes",
        "vgi-externalization-enabled",
        "vgi-sticky-enabled",
    ] {
        assert!(
            h.contains_key(name),
            "compressed response is missing capability header {name}; got {:?}",
            h.keys().map(|k| k.as_str()).collect::<Vec<_>>()
        );
    }
}

/// A browser can only read a response header that CORS exposes. Rust used to
/// expose none of the `VGI-*` capability headers, so a `fetch()` client could
/// not discover a single server capability — including
/// `VGI-Supported-Encodings`, whose entire purpose is client-side discovery.
#[tokio::test]
async fn cors_exposes_every_vgi_capability_header() {
    let state = stock_builder()
        .cors_origins("https://app.example.com")
        .max_request_bytes(1024 * 1024)
        .max_upload_bytes(4096)
        .enable_sticky(true)
        .build();
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let headers = resp.headers().clone();
    let exposed: Vec<String> = headers
        .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    // Every capability header actually emitted must be readable.
    for (name, _) in headers.iter() {
        if name.as_str().starts_with("vgi-") {
            assert!(
                exposed.contains(&name.as_str().to_string()),
                "capability header {name} is emitted but not CORS-exposed; \
                 exposed = {exposed:?}"
            );
        }
    }
    // Plus the non-capability headers a browser client has to read.
    for name in [
        "content-encoding",
        "x-vgi-content-encoding",
        "x-vgi-rpc-error",
        "www-authenticate",
        // Sticky-session headers are stamped per-response, not part of the
        // capability map, so they are named explicitly by the builder.
        "vgi-session",
        "vgi-session-close",
    ] {
        assert!(
            exposed.contains(&name.to_string()),
            "{name} must be CORS-exposed; exposed = {exposed:?}"
        );
    }
}

/// Minimal `HttpState` with a one-method server, configured by `f`.
fn state_configured(
    f: impl FnOnce(vgi_rpc::http::HttpStateBuilder) -> vgi_rpc::http::HttpStateBuilder,
) -> Arc<HttpState> {
    let mut srv = RpcServer::builder().server_id("it").build();
    srv.register(MethodInfo::unary(
        "echo_string",
        arrow_schema::Schema::new(vec![arrow_schema::Field::new(
            "value",
            arrow_schema::DataType::Utf8,
            false,
        )])
        .into(),
        arrow_schema::Schema::new(vec![arrow_schema::Field::new(
            "result",
            arrow_schema::DataType::Utf8,
            false,
        )])
        .into(),
        |_req, _| Ok(None),
    ));
    f(HttpState::builder().server(Arc::new(srv))).build()
}

#[tokio::test]
async fn oversize_request_body_is_rejected_by_body_limit() {
    // The body-limit layer enforces `max_body_size` on the raw bytes,
    // independent of `Content-Length` — a 4 KiB body against a 16-byte
    // limit must be refused before the handler runs.
    let state = state_configured(|b| b.max_body_size(16));
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/echo_string")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(vec![0u8; 4096]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn small_response_under_soft_cap_is_not_rejected() {
    // `max_response_bytes` is a *soft* producer-side cap — a normal
    // response (here, a small Arrow error stream) that happens to be
    // larger than the soft cap must NOT be turned into a 500 by the
    // post-processing middleware. The middleware's hard ceiling is
    // separate and far higher; see `response_buffer_ceiling`.
    let state = state_configured(|b| b.max_response_bytes(8));
    let app = vgi_rpc::http::build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/echo_string")
                .header(header::CONTENT_TYPE, ARROW_CONTENT_TYPE)
                .body(Body::from(vec![]))
                .unwrap(),
        )
        .await
        .unwrap();
    // Empty body → request parse error → 400 (NOT a 500 from the
    // middleware buffer cap).
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

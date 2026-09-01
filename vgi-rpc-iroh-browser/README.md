# vgi-rpc-iroh-browser

Browser-capable client transport for both VGI Iroh protocols:

- `vgi-rpc/arrow-mux/1`: one pooled authenticated connection with one QUIC
  bidirectional stream per logical VGI transport.
- `iroh-http/2`: HTTP/1.1 request framing on independent QUIC streams.

The wasm-bindgen surface exports `createIrohNode`, `BrowserIrohNode`,
`BrowserVgiStream`, and `BrowserHttpResponse`. `js/index.ts` wraps the raw byte
methods as WHATWG streams and provides an optional application-owned target
resolver/authorizer. A literal lowercase 64-hex EndpointId requires no resolver.
The node factory accepts an optional persisted secret key and custom relay URL
set; default construction uses n0's browser-compatible relay/address lookup.

`js/adapter-worker.ts` is the complete adapter Worker pump expected by
Haybarn's `irohAdapterWorker` option. It registers multiple ABI-v1 SAB regions
for both `iroh://` and `httpi://` targets. Raw claims open one mux stream;
HTTP claims decode a bounded binary envelope and call `fetchHttpi`, preserving
ordered duplicate headers and streaming request/response chunks through the
rings. Terminal HTTP evidence records stage, stable category, and dispatch
certainty. Ambiguous POST failures are never replayed, and releasing a claim
cancels its response stream.

One node should be shared by the whole DuckDB engine so raw and HTTP requests
present the same cryptographic endpoint identity. HTTP response bodies are raw
representation bytes; VGI retains responsibility for content decoding, OAuth,
Secure cookies, HTTP status/redirect policy, continuation and external-location
handling, Arrow framing, deadlines, and retry policy. External payload URLs
remain ordinary HTTPS locations rather than nested `httpi://` requests.

Experimental client-only `iroh-http/2` transport seam for browser builds.

The crate wraps an application-owned `iroh::Endpoint`, preserving one Iroh
identity across protocols. It opens a bidirectional stream with the
`iroh-http/2` ALPN and delegates HTTP/1.1 framing to Hyper. Request bodies are
currently materialized `Bytes`; response bodies remain streaming.

This crate remains transport plumbing: VGI owns Arrow serialization and the HTTP
state machine, while this package owns authenticated Iroh execution and the
browser SAB adapter boundary.

Build the browser target with an LLVM clang that includes the WebAssembly
backend. Apple clang does not include it:

```sh
CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang \
AR_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/llvm-ar \
cargo check -p vgi-rpc-iroh-browser --target wasm32-unknown-unknown
```

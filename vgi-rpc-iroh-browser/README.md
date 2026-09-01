# vgi-rpc-iroh-browser

Experimental client-only `iroh-http/2` transport seam for browser builds.

The crate wraps an application-owned `iroh::Endpoint`, preserving one Iroh
identity across protocols. It opens a bidirectional stream with the
`iroh-http/2` ALPN and delegates HTTP/1.1 framing to Hyper. Request bodies are
currently materialized `Bytes`; response bodies remain streaming.

This is transport plumbing, not yet a complete VGI client. VGI Arrow request
serialization, response decoding, retries, cancellation, pooling, and browser
JavaScript bindings remain separate work.

Build the browser target with an LLVM clang that includes the WebAssembly
backend. Apple clang does not include it:

```sh
CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang \
AR_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/llvm-ar \
cargo check -p vgi-rpc-iroh-browser --target wasm32-unknown-unknown
```


//! Proc-macros for `vgi-rpc`.
//!
//! Re-exported from `vgi-rpc` (behind the default-on `macros` feature)
//! so users only depend on `vgi-rpc` directly:
//!
//! ```ignore
//! use vgi_rpc::{service, unary, producer, exchange, VgiArrow, StreamState};
//! ```

mod derive_arrow;
mod derive_stream_state;
mod service;

use proc_macro::TokenStream;

/// Derive `VgiArrow` for a struct, generating a `Struct<fields>` Arrow
/// data type plus per-field read / build_singleton wiring.
///
/// Field types must themselves implement `VgiArrow`. Nullable fields
/// use `Option<T>`. Override the describe-format type name with
/// `#[vgi_arrow(name = "...")]`.
///
/// ```ignore
/// use vgi_rpc::VgiArrow;
///
/// #[derive(VgiArrow)]
/// #[vgi_arrow(name = "Point")]
/// struct Point { x: f64, y: f64 }
///
/// #[derive(VgiArrow)]
/// struct BoundingBox {
///     top_left: Point,
///     bottom_right: Point,
///     label: String,
/// }
/// ```
#[proc_macro_derive(VgiArrow, attributes(vgi_arrow))]
pub fn derive_vgi_arrow(input: TokenStream) -> TokenStream {
    derive_arrow::derive(input)
}

/// Derive `StreamStateCodec` (bincode-backed) and supply the
/// `encode_state` forwarder for `ProducerState` / `ExchangeState`.
///
/// Adds an inherent `__vgi_encode_state(&self)` helper that the trait
/// impl can call from `encode_state` in one line. Phase 4 of the macro
/// pass will land this; this stub keeps the public symbol stable.
#[proc_macro_derive(StreamState, attributes(stream_state))]
pub fn derive_stream_state(input: TokenStream) -> TokenStream {
    derive_stream_state::derive(input)
}

/// Service-level attribute applied to an `impl Block`. Scans methods
/// tagged with `#[unary]`, `#[producer(...)]`, or `#[exchange(...)]`
/// and generates a `register_with(server, instance)` impl.
///
/// Phase 3+ of the macro pass will land this; this stub returns the
/// input unchanged so the public symbol is reserved.
#[proc_macro_attribute]
pub fn service(args: TokenStream, item: TokenStream) -> TokenStream {
    service::expand(args, item)
}

/// No-op attribute consumed by `#[service]`. Standalone use is a
/// compile error in V1.
#[proc_macro_attribute]
pub fn unary(_args: TokenStream, item: TokenStream) -> TokenStream {
    service::passthrough(item)
}

/// No-op attribute consumed by `#[service]`. Standalone use is a
/// compile error in V1.
#[proc_macro_attribute]
pub fn producer(_args: TokenStream, item: TokenStream) -> TokenStream {
    service::passthrough(item)
}

/// No-op attribute consumed by `#[service]`. Standalone use is a
/// compile error in V1.
#[proc_macro_attribute]
pub fn exchange(_args: TokenStream, item: TokenStream) -> TokenStream {
    service::passthrough(item)
}

/// No-op attribute consumed by `#[service]` for per-parameter metadata.
#[proc_macro_attribute]
pub fn param(_args: TokenStream, item: TokenStream) -> TokenStream {
    service::passthrough(item)
}

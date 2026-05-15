//! Serialization codec for streaming state.
//!
//! The HTTP transport is stateless: every continuation request carries
//! the serialized [`ProducerState`](crate::ProducerState) /
//! [`ExchangeState`](crate::ExchangeState) back to the server inside an
//! HMAC-signed token, so any worker behind a load balancer can resume
//! any stream. This module defines the trait for per-state-type
//! encode/decode + a bincode-backed helper for the common case.
//!
//! Pipe and unix transports hold state in memory and skip the codec
//! entirely.

use serde::{de::DeserializeOwned, Serialize};

use crate::errors::{Result, RpcError};

/// Round-trip a streaming-state value through a byte representation.
///
/// Implementations choose their own format (bincode, Arrow IPC, etc.);
/// the bytes are opaque to the HTTP transport which only signs and
/// carries them.
pub trait StreamStateCodec: Sized {
    fn encode(&self) -> Result<Vec<u8>>;
    fn decode(bytes: &[u8]) -> Result<Self>;
}

/// Encode a `serde::Serialize` value with bincode.
///
/// **Internal:** used by `#[derive(StreamState)]` expansion. Most
/// users should implement [`StreamStateCodec`] manually or via the
/// derive macro rather than calling this directly.
#[doc(hidden)]
pub fn bincode_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serialize(value).map_err(|e| RpcError::runtime_error(format!("bincode encode: {e}")))
}

/// Hard ceiling on the number of bytes `bincode_decode` will allocate
/// from a length-prefixed field. Streaming-state values are small
/// (counters, cursors, small buffers); 16 MiB is generous headroom.
/// The HTTP transport already seals these bytes in an AEAD token, so
/// they are integrity-protected — this is defence-in-depth against a
/// crafted length prefix should the codec ever be fed untrusted bytes.
const MAX_STATE_DECODE_BYTES: u64 = 16 * 1024 * 1024;

/// Decode bytes produced by [`bincode_encode`].
///
/// **Internal:** used by `#[derive(StreamState)]` expansion.
#[doc(hidden)]
pub fn bincode_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    use bincode::Options;
    // `DefaultOptions` matches the byte layout of `bincode::serialize`
    // (used by `bincode_encode`); `.with_limit` bounds allocation
    // without changing the wire format.
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_STATE_DECODE_BYTES)
        .deserialize(bytes)
        .map_err(|e| RpcError::runtime_error(format!("bincode decode: {e}")))
}

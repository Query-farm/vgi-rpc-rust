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
/// Suitable as the body of a manual `StreamStateCodec` impl for state
/// types that are plain serde structs (the common case).
pub fn bincode_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serialize(value).map_err(|e| RpcError::runtime_error(format!("bincode encode: {e}")))
}

/// Decode bytes produced by [`bincode_encode`].
pub fn bincode_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes).map_err(|e| RpcError::runtime_error(format!("bincode decode: {e}")))
}

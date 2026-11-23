//! The standard token codec: compress, then seal (`STATE_REF_V1.md` §7).
//!
//! Every sealed token payload this crate mints -- the HTTP cursor and call
//! tokens, and the inline and stored [`StateRef`](crate::state_ref::StateRef)
//! payloads -- is one codec byte followed by the body:
//!
//! ```text
//! sealed_payload := codec (1 byte) || body
//! codec 0x00 = raw, 0x01 = zstd (level 3)
//! ```
//!
//! Compression happens *before* sealing because once sealed a token is
//! ciphertext and no outer codec can find its redundancy. The writer
//! compresses only when that makes the payload smaller, so a small token never
//! grows beyond its plaintext plus the tag byte.
//!
//! This port writes `0x00` and `0x01` only, so (as the spec allows) it reads
//! only those two: the reserved DEFLATE tag `0x02`, and every other value, is
//! refused like any malformed token.

use std::io::Read;

/// Codec tag: the body is the raw plaintext.
pub const CODEC_RAW: u8 = 0x00;
/// Codec tag: the body is one zstd frame.
pub const CODEC_ZSTD: u8 = 0x01;

/// zstd level the writer uses. At token sizes it measures the same speed as
/// level 1 and slightly smaller; the levels that compress materially better
/// cost many times the CPU for a few hundred bytes.
pub const ZSTD_LEVEL: i32 = 3;

/// Bound on a decompressed token (cursor or call token).
pub const MAX_TOKEN_PLAINTEXT_BYTES: usize = 64 << 20;

/// Why a payload would not unpack. Callers map it to their own uniform error
/// (a malformed token, an `invalid_state_ref`), never echoing the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// The payload is empty: no codec byte.
    Empty,
    /// The codec byte is not one this port implements.
    UnknownCodec(u8),
    /// The body does not decompress.
    Corrupt,
    /// The body decompresses to more than the caller's bound.
    TooLarge,
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::Empty => f.write_str("empty payload"),
            CodecError::UnknownCodec(tag) => write!(f, "unknown codec 0x{tag:02x}"),
            CodecError::Corrupt => f.write_str("body does not decompress"),
            CodecError::TooLarge => f.write_str("decompressed body exceeds the bound"),
        }
    }
}

impl std::error::Error for CodecError {}

/// Tag and (when it pays) compress `plaintext`.
pub fn pack(plaintext: &[u8]) -> Vec<u8> {
    if let Ok(packed) = zstd::bulk::compress(plaintext, ZSTD_LEVEL) {
        if packed.len() < plaintext.len() {
            let mut out = Vec::with_capacity(1 + packed.len());
            out.push(CODEC_ZSTD);
            out.extend_from_slice(&packed);
            return out;
        }
    }
    let mut out = Vec::with_capacity(1 + plaintext.len());
    out.push(CODEC_RAW);
    out.extend_from_slice(plaintext);
    out
}

/// Reverse [`pack`], refusing a body that decompresses past `max_bytes`.
///
/// The decode streams into a buffer that grows with the output, so a large
/// bound (a stored `StateRef` may be as large as `max_fetch_bytes`) costs
/// nothing up front, and a frame lying about its size is cut off at the bound.
pub fn unpack(payload: &[u8], max_bytes: usize) -> Result<Vec<u8>, CodecError> {
    let (tag, body) = payload.split_first().ok_or(CodecError::Empty)?;
    match *tag {
        CODEC_RAW => {
            if body.len() > max_bytes {
                return Err(CodecError::TooLarge);
            }
            Ok(body.to_vec())
        }
        CODEC_ZSTD => {
            let decoder =
                zstd::stream::read::Decoder::new(body).map_err(|_| CodecError::Corrupt)?;
            let mut out = Vec::new();
            decoder
                .take(max_bytes as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|_| CodecError::Corrupt)?;
            if out.len() > max_bytes {
                return Err(CodecError::TooLarge);
            }
            Ok(out)
        }
        other => Err(CodecError::UnknownCodec(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redundant_payload_compresses_and_round_trips() {
        let plain = b"vgi-rpc token codec ".repeat(200);
        let packed = pack(&plain);
        assert_eq!(packed[0], CODEC_ZSTD);
        assert!(packed.len() < plain.len());
        assert_eq!(unpack(&packed, 1 << 20).unwrap(), plain);
    }

    #[test]
    fn tiny_payload_stays_raw() {
        let packed = pack(b"abc");
        assert_eq!(packed, b"\x00abc");
        assert_eq!(unpack(&packed, 16).unwrap(), b"abc");
    }

    #[test]
    fn unknown_codec_and_corrupt_body_are_refused() {
        assert_eq!(unpack(b"", 16), Err(CodecError::Empty));
        assert_eq!(unpack(b"\x02abc", 16), Err(CodecError::UnknownCodec(2)));
        assert_eq!(unpack(b"\x7fabc", 16), Err(CodecError::UnknownCodec(0x7f)));
        assert_eq!(unpack(b"\x01not zstd", 16), Err(CodecError::Corrupt));
    }

    #[test]
    fn bound_is_enforced_for_both_codecs() {
        let plain = vec![0u8; 4096];
        assert_eq!(unpack(&pack(&plain), 4095), Err(CodecError::TooLarge));
        assert_eq!(unpack(&pack(&plain), 4096).unwrap(), plain);
        let mut raw = vec![CODEC_RAW];
        raw.extend_from_slice(&[1u8; 10]);
        assert_eq!(unpack(&raw, 9), Err(CodecError::TooLarge));
    }
}

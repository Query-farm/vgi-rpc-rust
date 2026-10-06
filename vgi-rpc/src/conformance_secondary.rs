//! `conformance.Secondary.v1` -- the second application protocol every
//! conformance worker, and every VGI SDK fixture worker, hosts.
//!
//! Normative in vgi-rpc-python's
//! `tools/cross-port/specs/MULTI_PROTOCOL_HOSTING.md` §2. It lives in the
//! library rather than in a test binary so that an SDK built on this crate
//! hosts the *same* fixture through its own hook instead of re-deriving it --
//! which is how fixture copies drift.
//!
//! It makes three things observable that a single-protocol worker hides:
//!
//! - **Routing by pair.** `echo_string` repeats the name and signature of
//!   `ConformanceService.echo_string`, and prefixes its reply, so a server
//!   keying dispatch on the bare method name answers with a wrong value.
//! - **A per-binding version gate.** It declares no `protocol_version`, so a
//!   server gating every call against the primary's version refuses it.
//! - **The error model.** `fail` raises whatever code and kind it is asked to,
//!   with a fixed detail list; `fail_oversized` raises details over the cap,
//!   built so dropping only the large element is detectable.

use std::sync::Arc;

use arrow_array::{Array, Float64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use serde_json::json;

use crate::error_model::{Code, ErrorDetail, FieldViolation};
use crate::errors::{Result, RpcError};
use crate::server::{HostedProtocol, MethodInfo, Request};
use crate::stream::empty_schema;

/// The fixture protocol's wire name.
pub const SECONDARY_PROTOCOL_NAME: &str = "conformance.Secondary.v1";
/// Its pinned canonical hash.
pub const SECONDARY_PROTOCOL_HASH: &str =
    "58557cf1611546ad22d1c379bc3ce1b04166082f78375e9fc959f0086347eab6";
/// What `echo_string` prefixes its reply with.
pub const SECONDARY_ECHO_PREFIX: &str = "secondary:";
/// The protocol-defined detail type no client knows.
pub const PROBE_DETAIL_TYPE: &str = "conformance.Secondary.v1.Probe";
/// Kind raised by `fail` for a code outside the sixteen.
pub const INVALID_CODE_KIND: &str = "invalid_code";
/// Kind raised by `fail_oversized`.
pub const OVERSIZED_KIND: &str = "details_oversized";
/// Bytes of `"x"` padding in `fail_oversized`'s `ErrorInfo`.
pub const OVERSIZED_PADDING_BYTES: usize = 5000;

fn utf8(name: &str) -> Field {
    Field::new(name, DataType::Utf8, false)
}

fn echo_params() -> SchemaRef {
    Arc::new(Schema::new(vec![utf8("value")]))
}

fn echo_result() -> SchemaRef {
    Arc::new(Schema::new(vec![utf8("result")]))
}

fn fail_params() -> SchemaRef {
    Arc::new(Schema::new(vec![
        utf8("code"),
        utf8("kind"),
        Field::new("retry_delay_seconds", DataType::Float64, false),
    ]))
}

fn string_arg(req: &Request, name: &str) -> Result<String> {
    req.column(name)
        .and_then(|c| c.as_any().downcast_ref::<StringArray>())
        .filter(|c| !c.is_empty())
        .map(|c| c.value(0).to_string())
        .ok_or_else(|| RpcError::type_error(format!("missing utf8 argument {name:?}")))
}

fn float_arg(req: &Request, name: &str) -> Result<f64> {
    req.column(name)
        .and_then(|c| c.as_any().downcast_ref::<Float64Array>())
        .filter(|c| !c.is_empty())
        .map(|c| c.value(0))
        .ok_or_else(|| RpcError::type_error(format!("missing float64 argument {name:?}")))
}

/// The error `fail(code, kind, retry_delay_seconds)` raises.
pub fn fail_error(code: &str, kind: &str, retry_delay_seconds: f64) -> RpcError {
    let Some(code) = Code::from_name(code) else {
        return RpcError::value_error(format!("{code:?} is not a canonical error code"))
            .with_status(Code::InvalidArgument, INVALID_CODE_KIND)
            .with_details([ErrorDetail::BadRequest {
                field_violations: vec![FieldViolation {
                    field: "code".into(),
                    description: "must be a canonical code name".into(),
                }],
            }]);
    };
    let mut err = RpcError::new(
        "StatusError",
        format!("conformance: fail({code}, {kind:?}, {retry_delay_seconds})"),
    )
    .with_code(code)
    .with_details([ErrorDetail::error_info([(
        "fixture",
        SECONDARY_PROTOCOL_NAME,
    )])]);
    if !kind.is_empty() {
        err = err.with_error_kind(kind);
    }
    if retry_delay_seconds > 0.0 {
        err = err.with_details([ErrorDetail::retry_info(retry_delay_seconds)]);
    }
    err.with_raw_details([json!({
        "@type": PROBE_DETAIL_TYPE,
        "note": "clients ignore detail types they do not know",
    })])
}

/// The error `fail_oversized()` raises: over the 4 KiB cap, with the small
/// `RetryInfo` first so a server keeping "the elements that fit" is caught.
pub fn oversized_error() -> RpcError {
    RpcError::new(
        "StatusError",
        "conformance: error details over the 4 KiB cap",
    )
    .with_status(Code::ResourceExhausted, OVERSIZED_KIND)
    .with_details([
        ErrorDetail::retry_info(1.0),
        ErrorDetail::error_info([("padding", "x".repeat(OVERSIZED_PADDING_BYTES))]),
    ])
}

/// Build `conformance.Secondary.v1`, ready for
/// [`RpcServerBuilder::add_protocol`](crate::server::RpcServerBuilder::add_protocol).
pub fn conformance_secondary_protocol() -> HostedProtocol {
    HostedProtocol::new(SECONDARY_PROTOCOL_NAME)
        .with_method(MethodInfo::unary(
            "echo_string",
            echo_params(),
            echo_result(),
            |req, _ctx| {
                let value = string_arg(req, "value")?;
                let out = StringArray::from(vec![format!("{SECONDARY_ECHO_PREFIX}{value}")]);
                Ok(Some(RecordBatch::try_new(
                    echo_result(),
                    vec![Arc::new(out)],
                )?))
            },
        ))
        .with_method(MethodInfo::unary(
            "fail",
            fail_params(),
            empty_schema(),
            |req, _ctx| {
                Err(fail_error(
                    &string_arg(req, "code")?,
                    &string_arg(req, "kind")?,
                    float_arg(req, "retry_delay_seconds")?,
                ))
            },
        ))
        .with_method(MethodInfo::unary(
            "fail_oversized",
            empty_schema(),
            empty_schema(),
            |_req, _ctx| Err(oversized_error()),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_matches_the_pin() {
        assert_eq!(
            conformance_secondary_protocol().protocol_hash(),
            SECONDARY_PROTOCOL_HASH
        );
    }

    /// V1's array, byte for byte.
    #[test]
    fn fail_details_match_the_vector() {
        let err = fail_error("UNAVAILABLE", "backend_down", 7.0);
        assert_eq!(
            crate::error_model::encode_error_details(&err.wire_details()).unwrap(),
            r#"[{"@type":"vgi_rpc.ErrorInfo","metadata":{"fixture":"conformance.Secondary.v1"}},{"@type":"vgi_rpc.RetryInfo","retry_delay_seconds":7},{"@type":"conformance.Secondary.v1.Probe","note":"clients ignore detail types they do not know"}]"#
        );
        assert!(
            crate::error_model::encode_error_details(&oversized_error().wire_details()).is_none()
        );
    }
}

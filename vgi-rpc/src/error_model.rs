//! The error model: a canonical code, an open reason, and typed details.
//!
//! Every EXCEPTION batch carries three layers, adopted from gRPC's
//! `google.rpc.Status` (WIRE_PROTOCOL.md §8):
//!
//! | Layer   | Wire key                 | Set |
//! |---------|--------------------------|-----|
//! | Code    | `vgi_rpc.error_code`     | **Closed**: gRPC's sixteen codes minus `OK`, sent as the code's *name* |
//! | Reason  | `vgi_rpc.error_kind`     | Open, unique within the protocol that raised it |
//! | Details | `vgi_rpc.error_details`  | A JSON array of typed objects from a fixed catalog |
//!
//! The code is what generic handling keys on -- retry or not, how to show it.
//! The kind is what a client branches on. The details carry machine-readable
//! specifics: how long to wait, which field was wrong, which resource.
//!
//! Servers attach the model to an [`RpcError`](crate::errors::RpcError) with
//! [`RpcError::with_code`](crate::errors::RpcError::with_code),
//! [`RpcError::with_status`](crate::errors::RpcError::with_status) and
//! [`RpcError::with_details`](crate::errors::RpcError::with_details). Clients
//! read the same type back: [`RpcError::error_code`](crate::errors::RpcError::error_code),
//! [`RpcError::error_kind`](crate::errors::RpcError::error_kind),
//! [`RpcError::error_details`](crate::errors::RpcError::error_details), the
//! typed accessors and [`RpcError::is_retryable`](crate::errors::RpcError::is_retryable).
//!
//! The details array is capped at [`MAX_ERROR_DETAILS_BYTES`] and dropped
//! **whole** when over -- never trimmed, because a client cannot tell a
//! partial list from a complete one.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

/// Cap on the serialized `vgi_rpc.error_details` value, in UTF-8 bytes. A
/// server whose array would exceed it omits the array entirely.
pub const MAX_ERROR_DETAILS_BYTES: usize = 4096;

/// The `@type` prefix reserved for the catalog.
const RESERVED_DETAIL_PREFIX: &str = "vgi_rpc.";

/// The closed set of canonical error codes: gRPC's sixteen, minus `OK`.
///
/// The wire value is the code's *name* -- `"UNAVAILABLE"`, never `14` -- so a
/// log line, a proxy rule and a client switch all read the same string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
    Cancelled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    Internal,
    Unavailable,
    DataLoss,
    Unauthenticated,
}

impl Code {
    /// Every code, in gRPC's numeric order.
    pub const ALL: [Code; 16] = [
        Code::Cancelled,
        Code::Unknown,
        Code::InvalidArgument,
        Code::DeadlineExceeded,
        Code::NotFound,
        Code::AlreadyExists,
        Code::PermissionDenied,
        Code::ResourceExhausted,
        Code::FailedPrecondition,
        Code::Aborted,
        Code::OutOfRange,
        Code::Unimplemented,
        Code::Internal,
        Code::Unavailable,
        Code::DataLoss,
        Code::Unauthenticated,
    ];

    /// The wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Code::Cancelled => "CANCELLED",
            Code::Unknown => "UNKNOWN",
            Code::InvalidArgument => "INVALID_ARGUMENT",
            Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Code::NotFound => "NOT_FOUND",
            Code::AlreadyExists => "ALREADY_EXISTS",
            Code::PermissionDenied => "PERMISSION_DENIED",
            Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Code::FailedPrecondition => "FAILED_PRECONDITION",
            Code::Aborted => "ABORTED",
            Code::OutOfRange => "OUT_OF_RANGE",
            Code::Unimplemented => "UNIMPLEMENTED",
            Code::Internal => "INTERNAL",
            Code::Unavailable => "UNAVAILABLE",
            Code::DataLoss => "DATA_LOSS",
            Code::Unauthenticated => "UNAUTHENTICATED",
        }
    }

    /// Exact lookup of a wire name; `None` for anything outside the set.
    pub fn from_name(name: &str) -> Option<Code> {
        Code::ALL.iter().copied().find(|c| c.as_str() == name)
    }

    /// Read a wire value, mapping anything unrecognised (or absent) to
    /// [`Code::Unknown`], as WIRE_PROTOCOL.md §8 requires of a client.
    pub fn parse(name: &str) -> Code {
        Code::from_name(name).unwrap_or(Code::Unknown)
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One wrong input ([`ErrorDetail::BadRequest`]).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FieldViolation {
    pub field: String,
    pub description: String,
}

/// One unmet precondition ([`ErrorDetail::PreconditionFailure`]).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PreconditionViolation {
    pub r#type: String,
    pub subject: String,
    pub description: String,
}

/// One exhausted limit ([`ErrorDetail::QuotaFailure`]).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct QuotaViolation {
    pub subject: String,
    pub description: String,
}

/// One documentation pointer ([`ErrorDetail::Help`]).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HelpLink {
    pub description: String,
    pub url: String,
}

/// A member of the fixed detail catalog.
///
/// Protocol-defined types (under the protocol's own name) travel as raw JSON
/// objects through [`RpcError::with_raw_details`](crate::errors::RpcError::with_raw_details);
/// a client that does not know them keeps them in the raw array and the typed
/// accessors skip them.
#[derive(Clone, Debug, PartialEq)]
pub enum ErrorDetail {
    /// `vgi_rpc.ErrorInfo` -- string-to-string context for the reason.
    ErrorInfo { metadata: BTreeMap<String, String> },
    /// `vgi_rpc.RetryInfo` -- how long to wait before retrying.
    RetryInfo { retry_delay_seconds: f64 },
    /// `vgi_rpc.BadRequest` -- which inputs were wrong.
    BadRequest {
        field_violations: Vec<FieldViolation>,
    },
    /// `vgi_rpc.PreconditionFailure` -- what state must change first.
    PreconditionFailure {
        violations: Vec<PreconditionViolation>,
    },
    /// `vgi_rpc.QuotaFailure` -- which limit was hit.
    QuotaFailure { violations: Vec<QuotaViolation> },
    /// `vgi_rpc.ResourceInfo` -- which object the error concerns.
    ResourceInfo {
        resource_type: String,
        resource_name: String,
        owner: String,
        description: String,
    },
    /// `vgi_rpc.Help` -- where to read more.
    Help { links: Vec<HelpLink> },
    /// `vgi_rpc.LocalizedMessage` -- text safe to show an end user.
    LocalizedMessage { locale: String, message: String },
}

/// `@type` of [`ErrorDetail::ErrorInfo`].
pub const ERROR_INFO_TYPE: &str = "vgi_rpc.ErrorInfo";
/// `@type` of [`ErrorDetail::RetryInfo`].
pub const RETRY_INFO_TYPE: &str = "vgi_rpc.RetryInfo";
/// `@type` of [`ErrorDetail::BadRequest`].
pub const BAD_REQUEST_TYPE: &str = "vgi_rpc.BadRequest";
/// `@type` of [`ErrorDetail::PreconditionFailure`].
pub const PRECONDITION_FAILURE_TYPE: &str = "vgi_rpc.PreconditionFailure";
/// `@type` of [`ErrorDetail::QuotaFailure`].
pub const QUOTA_FAILURE_TYPE: &str = "vgi_rpc.QuotaFailure";
/// `@type` of [`ErrorDetail::ResourceInfo`].
pub const RESOURCE_INFO_TYPE: &str = "vgi_rpc.ResourceInfo";
/// `@type` of [`ErrorDetail::Help`].
pub const HELP_TYPE: &str = "vgi_rpc.Help";
/// `@type` of [`ErrorDetail::LocalizedMessage`].
pub const LOCALIZED_MESSAGE_TYPE: &str = "vgi_rpc.LocalizedMessage";

/// Every catalog `@type`.
pub const CATALOG_TYPES: [&str; 8] = [
    ERROR_INFO_TYPE,
    RETRY_INFO_TYPE,
    BAD_REQUEST_TYPE,
    PRECONDITION_FAILURE_TYPE,
    QUOTA_FAILURE_TYPE,
    RESOURCE_INFO_TYPE,
    HELP_TYPE,
    LOCALIZED_MESSAGE_TYPE,
];

/// A whole number of seconds travels as an integer so the common case reads
/// the same in every language's encoder (`7`, not `7.0`).
fn delay_json(delay: f64) -> Value {
    if delay.is_finite() && delay.fract() == 0.0 && delay.abs() < 9.0e15 {
        json!(delay as i64)
    } else {
        json!(delay)
    }
}

impl ErrorDetail {
    /// A `RetryInfo` detail.
    pub fn retry_info(retry_delay_seconds: f64) -> Self {
        ErrorDetail::RetryInfo {
            retry_delay_seconds,
        }
    }

    /// An `ErrorInfo` detail.
    pub fn error_info<K: Into<String>, V: Into<String>>(
        metadata: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        ErrorDetail::ErrorInfo {
            metadata: metadata
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    /// The `@type` naming this detail on the wire.
    pub fn type_name(&self) -> &'static str {
        match self {
            ErrorDetail::ErrorInfo { .. } => ERROR_INFO_TYPE,
            ErrorDetail::RetryInfo { .. } => RETRY_INFO_TYPE,
            ErrorDetail::BadRequest { .. } => BAD_REQUEST_TYPE,
            ErrorDetail::PreconditionFailure { .. } => PRECONDITION_FAILURE_TYPE,
            ErrorDetail::QuotaFailure { .. } => QUOTA_FAILURE_TYPE,
            ErrorDetail::ResourceInfo { .. } => RESOURCE_INFO_TYPE,
            ErrorDetail::Help { .. } => HELP_TYPE,
            ErrorDetail::LocalizedMessage { .. } => LOCALIZED_MESSAGE_TYPE,
        }
    }

    /// The JSON object form, `@type` included.
    pub fn to_json(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("@type".into(), json!(self.type_name()));
        match self {
            ErrorDetail::ErrorInfo { metadata } => {
                obj.insert("metadata".into(), json!(metadata));
            }
            ErrorDetail::RetryInfo {
                retry_delay_seconds,
            } => {
                obj.insert(
                    "retry_delay_seconds".into(),
                    delay_json(*retry_delay_seconds),
                );
            }
            ErrorDetail::BadRequest { field_violations } => {
                obj.insert(
                    "field_violations".into(),
                    Value::Array(
                        field_violations
                            .iter()
                            .map(|v| json!({"field": v.field, "description": v.description}))
                            .collect(),
                    ),
                );
            }
            ErrorDetail::PreconditionFailure { violations } => {
                obj.insert(
                    "violations".into(),
                    Value::Array(
                        violations
                            .iter()
                            .map(|v| {
                                json!({"type": v.r#type, "subject": v.subject, "description": v.description})
                            })
                            .collect(),
                    ),
                );
            }
            ErrorDetail::QuotaFailure { violations } => {
                obj.insert(
                    "violations".into(),
                    Value::Array(
                        violations
                            .iter()
                            .map(|v| json!({"subject": v.subject, "description": v.description}))
                            .collect(),
                    ),
                );
            }
            ErrorDetail::ResourceInfo {
                resource_type,
                resource_name,
                owner,
                description,
            } => {
                obj.insert("resource_type".into(), json!(resource_type));
                obj.insert("resource_name".into(), json!(resource_name));
                obj.insert("owner".into(), json!(owner));
                obj.insert("description".into(), json!(description));
            }
            ErrorDetail::Help { links } => {
                obj.insert(
                    "links".into(),
                    Value::Array(
                        links
                            .iter()
                            .map(|v| json!({"description": v.description, "url": v.url}))
                            .collect(),
                    ),
                );
            }
            ErrorDetail::LocalizedMessage { locale, message } => {
                obj.insert("locale".into(), json!(locale));
                obj.insert("message".into(), json!(message));
            }
        }
        Value::Object(obj)
    }

    /// Decode one detail object, or `None` when it is unknown or malformed.
    ///
    /// Clients ignore detail types they do not know, and a malformed known
    /// type is treated as absent rather than failing the error it rides on:
    /// the error is the news, the detail is commentary.
    pub fn from_json(value: &Value) -> Option<Self> {
        let obj = value.as_object()?;
        let ty = obj.get("@type")?.as_str()?;
        match ty {
            ERROR_INFO_TYPE => {
                let mut metadata = BTreeMap::new();
                match obj.get("metadata") {
                    None => {}
                    Some(Value::Object(m)) => {
                        for (k, v) in m {
                            metadata.insert(k.clone(), v.as_str()?.to_string());
                        }
                    }
                    Some(_) => return None,
                }
                Some(ErrorDetail::ErrorInfo { metadata })
            }
            RETRY_INFO_TYPE => {
                let delay = obj.get("retry_delay_seconds")?;
                if delay.is_boolean() {
                    return None;
                }
                let d = delay.as_f64()?;
                if !d.is_finite() || d < 0.0 {
                    return None;
                }
                Some(ErrorDetail::RetryInfo {
                    retry_delay_seconds: d,
                })
            }
            BAD_REQUEST_TYPE => Some(ErrorDetail::BadRequest {
                field_violations: objects(obj, "field_violations")?
                    .into_iter()
                    .map(|v| {
                        Some(FieldViolation {
                            field: string(v, "field")?,
                            description: string(v, "description")?,
                        })
                    })
                    .collect::<Option<_>>()?,
            }),
            PRECONDITION_FAILURE_TYPE => Some(ErrorDetail::PreconditionFailure {
                violations: objects(obj, "violations")?
                    .into_iter()
                    .map(|v| {
                        Some(PreconditionViolation {
                            r#type: string(v, "type")?,
                            subject: string(v, "subject")?,
                            description: string(v, "description")?,
                        })
                    })
                    .collect::<Option<_>>()?,
            }),
            QUOTA_FAILURE_TYPE => Some(ErrorDetail::QuotaFailure {
                violations: objects(obj, "violations")?
                    .into_iter()
                    .map(|v| {
                        Some(QuotaViolation {
                            subject: string(v, "subject")?,
                            description: string(v, "description")?,
                        })
                    })
                    .collect::<Option<_>>()?,
            }),
            RESOURCE_INFO_TYPE => Some(ErrorDetail::ResourceInfo {
                resource_type: string(obj, "resource_type")?,
                resource_name: string(obj, "resource_name")?,
                owner: string(obj, "owner")?,
                description: string(obj, "description")?,
            }),
            HELP_TYPE => Some(ErrorDetail::Help {
                links: objects(obj, "links")?
                    .into_iter()
                    .map(|v| {
                        Some(HelpLink {
                            description: string(v, "description")?,
                            url: string(v, "url")?,
                        })
                    })
                    .collect::<Option<_>>()?,
            }),
            LOCALIZED_MESSAGE_TYPE => Some(ErrorDetail::LocalizedMessage {
                locale: string(obj, "locale")?,
                message: string(obj, "message")?,
            }),
            _ => None,
        }
    }
}

/// A string field; absent reads as `""`, a non-string is malformed.
fn string(obj: &Map<String, Value>, key: &str) -> Option<String> {
    match obj.get(key) {
        None => Some(String::new()),
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => None,
    }
}

/// An array-of-objects field; absent reads as `[]`.
fn objects<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<Vec<&'a Map<String, Value>>> {
    match obj.get(key) {
        None => Some(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(Value::as_object).collect(),
        Some(_) => None,
    }
}

/// Apply the catalog rules: every element an object naming a qualified
/// `@type`, no type twice, nothing invented under the reserved prefix.
pub fn validate_error_details(details: &[Value]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for detail in details {
        let Some(obj) = detail.as_object() else {
            return Err("every error detail must be a JSON object".into());
        };
        let Some(ty) = obj
            .get("@type")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
        else {
            return Err("every error detail must name its type in '@type'".into());
        };
        if !seen.insert(ty) {
            return Err(format!("error detail type {ty:?} appears more than once"));
        }
        if ty.starts_with(RESERVED_DETAIL_PREFIX) && !CATALOG_TYPES.contains(&ty) {
            return Err(format!(
                "{ty:?} claims the reserved 'vgi_rpc.' prefix but is not in the catalog"
            ));
        }
        if !ty.contains('.') {
            return Err(format!(
                "{ty:?} is not qualified; protocol-defined types live under the protocol's name"
            ));
        }
    }
    Ok(())
}

/// Serialize a detail list for `vgi_rpc.error_details`, enforcing the rules.
///
/// Returns `None` -- meaning *omit the key, and the `log_extra` mirror* --
/// for an empty list, a list breaking a catalog rule, and one whose
/// serialized form exceeds [`MAX_ERROR_DETAILS_BYTES`]. The array is dropped
/// whole, never trimmed.
pub fn encode_error_details(details: &[Value]) -> Option<String> {
    if details.is_empty() || validate_error_details(details).is_err() {
        return None;
    }
    let text = serde_json::to_string(details).ok()?;
    if text.len() > MAX_ERROR_DETAILS_BYTES {
        return None;
    }
    Some(text)
}

/// Decode a `vgi_rpc.error_details` value into its JSON objects.
///
/// Tolerant by design: anything that is not a JSON array decodes as empty,
/// and non-object elements are skipped. Unknown `@type` values are kept --
/// filtering to the catalog is what the typed accessors do.
pub fn decode_error_details(raw: &str) -> Vec<Value> {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Array(items)) => items.into_iter().filter(Value::is_object).collect(),
        _ => Vec::new(),
    }
}

/// Whether the rule in WIRE_PROTOCOL.md §8 calls an error retryable.
///
/// `UNAVAILABLE` is retryable; `RESOURCE_EXHAUSTED` only when it carries
/// `RetryInfo`. Everything else is final -- `ABORTED` included, which means
/// "retry the whole operation at a higher level". A classification, not a
/// policy: nothing in this crate retries an RPC error automatically.
pub fn is_retryable(code: &str, details: &[Value]) -> bool {
    match Code::from_name(code) {
        Some(Code::Unavailable) => true,
        Some(Code::ResourceExhausted) => details.iter().any(|d| {
            matches!(
                ErrorDetail::from_json(d),
                Some(ErrorDetail::RetryInfo { .. })
            )
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_by_name() {
        for code in Code::ALL {
            assert_eq!(Code::from_name(code.as_str()), Some(code));
        }
        assert_eq!(Code::from_name("OK"), None);
        assert_eq!(Code::parse("OK"), Code::Unknown);
        assert_eq!(Code::parse(""), Code::Unknown);
    }

    #[test]
    fn whole_delays_are_integers() {
        assert_eq!(
            ErrorDetail::retry_info(7.0).to_json().to_string(),
            r#"{"@type":"vgi_rpc.RetryInfo","retry_delay_seconds":7}"#
        );
        assert_eq!(
            ErrorDetail::retry_info(0.5).to_json()["retry_delay_seconds"],
            json!(0.5)
        );
    }

    /// V5: `51 + N` bytes compactly; 4045 is exactly the cap, 4046 is over.
    #[test]
    fn cap_boundary_is_measured_in_bytes() {
        let at = |n: usize| {
            vec![json!({"@type": "vgi_rpc.ErrorInfo", "metadata": {"p": "x".repeat(n)}})]
        };
        assert_eq!(serde_json::to_string(&at(0)).unwrap().len(), 51);
        assert!(encode_error_details(&at(4045)).is_some());
        assert!(encode_error_details(&at(4046)).is_none());
        let wide = vec![
            json!({"@type": "vgi_rpc.LocalizedMessage", "locale": "fr", "message": "é".repeat(2048)}),
        ];
        assert!(encode_error_details(&wide).is_none());
    }

    /// V6: rule violations drop the array at emission.
    #[test]
    fn rule_violations_are_dropped() {
        let retry = ErrorDetail::retry_info(1.0).to_json();
        for bad in [
            vec![retry.clone(), retry.clone()],
            vec![json!({"@type": "vgi_rpc.Made.Up"})],
            vec![json!({"@type": "Unqualified"})],
            vec![json!({"no": "type"})],
        ] {
            assert!(encode_error_details(&bad).is_none(), "{bad:?}");
        }
        assert!(encode_error_details(&[json!({"@type": "my.proto.v1.Thing"})]).is_some());
    }

    /// V7: tolerant decoding.
    #[test]
    fn malformed_details_are_skipped_not_fatal() {
        assert!(decode_error_details("{}").is_empty());
        assert!(decode_error_details("not json").is_empty());
        let raw = r#"[1, {"@type":"vgi_rpc.RetryInfo","retry_delay_seconds":"soon"},
            {"@type":"vgi_rpc.RetryInfo","retry_delay_seconds":-1},
            {"@type":"vgi_rpc.ErrorInfo","metadata":{"a":1}}, {"@type":"x.Y"}]"#;
        let decoded = decode_error_details(raw);
        assert_eq!(decoded.len(), 4);
        assert!(decoded.iter().all(|d| ErrorDetail::from_json(d).is_none()));
    }

    /// V3.
    #[test]
    fn retryability_follows_the_code() {
        let retry = vec![ErrorDetail::retry_info(1.0).to_json()];
        assert!(is_retryable("UNAVAILABLE", &[]));
        assert!(is_retryable("RESOURCE_EXHAUSTED", &retry));
        assert!(!is_retryable("RESOURCE_EXHAUSTED", &[]));
        assert!(!is_retryable("ABORTED", &retry));
        assert!(!is_retryable("INTERNAL", &retry));
        assert!(!is_retryable("", &[]));
        assert!(!is_retryable("BOGUS", &retry));
    }

    #[test]
    fn every_catalog_type_round_trips() {
        let details = vec![
            ErrorDetail::error_info([("a", "b")]),
            ErrorDetail::retry_info(2.5),
            ErrorDetail::BadRequest {
                field_violations: vec![FieldViolation {
                    field: "f".into(),
                    description: "d".into(),
                }],
            },
            ErrorDetail::PreconditionFailure {
                violations: vec![PreconditionViolation {
                    r#type: "t".into(),
                    subject: "s".into(),
                    description: "d".into(),
                }],
            },
            ErrorDetail::QuotaFailure {
                violations: vec![QuotaViolation {
                    subject: "s".into(),
                    description: "d".into(),
                }],
            },
            ErrorDetail::ResourceInfo {
                resource_type: "r".into(),
                resource_name: "n".into(),
                owner: "o".into(),
                description: "d".into(),
            },
            ErrorDetail::Help {
                links: vec![HelpLink {
                    description: "d".into(),
                    url: "u".into(),
                }],
            },
            ErrorDetail::LocalizedMessage {
                locale: "en".into(),
                message: "m".into(),
            },
        ];
        for d in details {
            assert_eq!(ErrorDetail::from_json(&d.to_json()), Some(d));
        }
    }
}

//! The protocol hash: a fingerprint of a protocol's wire surface.
//!
//! A client and a worker agree on a protocol or they do not, and the hash is
//! how either side says which one it has without shipping the whole
//! description. For that to be worth anything the same protocol must hash the
//! same in every port, which the previous definition could not promise: it
//! hashed serialized Arrow IPC bytes, and each language's Arrow implementation
//! may legitimately emit different bytes for the same logical schema. The docs
//! said so, which made the field advisory -- comparable only against itself.
//!
//! So the preimage is canonical JSON of what Arrow *decodes to*:
//!
//! ```text
//! sha256("vgi_rpc.protocol_hash.v1|" + canonical_json(description))
//! ```
//!
//! Profile: RFC 8785 (JCS), chosen for its published test vectors. The
//! structure is deliberately restricted to objects, arrays, strings and
//! booleans; every number is folded into a type token (`decimal128(38,9)`), so
//! JCS's hardest rule -- number canonicalisation, and the likeliest place for
//! six ports to diverge -- never applies. Keep it that way.
//!
//! Not in the preimage: server identity, docstrings, parameter defaults,
//! language-specific type names, the framework's own request/describe versions,
//! and whether a stream is an exchange. That last is an *implementation*
//! property, not visible on the protocol definition, so one port can determine
//! it and another cannot -- and a field one port knows and another does not
//! cannot be part of a cross-language contract. It still reaches clients as
//! `stream_kind` on the description, where "unknown" is a sayable answer; a
//! hash has no such option.

use arrow_schema::Schema;
use sha2::{Digest, Sha256};

use crate::type_tokens::{schema_tokens, FieldToken, UnsupportedArrowType};

/// Domain separator. Moves only when the hash definition moves, never when a
/// protocol changes -- that is what the hash itself is for.
pub const HASH_DOMAIN: &str = "vgi_rpc.protocol_hash.v1|";

/// One method's input to [`compute_protocol_hash`].
///
/// Takes decoded schemas rather than serialized IPC: the hash is over
/// structure, and accepting bytes would invite a caller to pass whatever its
/// encoder produced.
#[derive(Debug, Clone)]
pub struct HashMethod<'a> {
    pub name: &'a str,
    /// `"unary"` or `"stream"`.
    pub method_type: &'a str,
    pub has_return: bool,
    pub has_header: bool,
    pub params_schema: Option<&'a Schema>,
    /// `None` when `has_return` is false.
    pub result_schema: Option<&'a Schema>,
    /// `None` when `has_header` is false.
    pub header_schema: Option<&'a Schema>,
}

#[derive(serde::Serialize)]
// Fields are declared in *sorted key order*, because serde_json emits them in
// declaration order and canonical JSON requires sorted keys. Adding a field in
// the wrong position here silently changes the digest for every protocol, which
// is exactly the class of bug the canonical form exists to prevent -- so the
// order is load bearing, not cosmetic.
struct MethodEntry {
    has_header: bool,
    has_return: bool,
    // Absent and empty are different: a method returning nothing is not a
    // method returning an empty struct, and they must not hash alike.
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<Vec<FieldToken>>,
    name: String,
    params: Vec<FieldToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Vec<FieldToken>>,
    #[serde(rename = "type")]
    method_type: String,
}

/// Build the canonical preimage for one protocol.
///
/// Exposed because a hash mismatch between ports is otherwise one bit of
/// information. With the preimage in hand a failing port diffs two JSON
/// documents and sees which method, field or type token it spells differently.
pub fn canonical_description(
    protocol_name: &str,
    methods: &[HashMethod<'_>],
) -> Result<String, UnsupportedArrowType> {
    // Sorted so two ports iterating differently-ordered maps still agree.
    let mut sorted: Vec<&HashMethod<'_>> = methods.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(b.name));

    let mut entries = Vec::with_capacity(sorted.len());
    for m in sorted {
        entries.push(MethodEntry {
            has_header: m.has_header,
            has_return: m.has_return,
            header: if m.has_header {
                Some(schema_tokens(m.header_schema)?)
            } else {
                None
            },
            name: m.name.to_string(),
            params: schema_tokens(m.params_schema)?,
            result: if m.has_return {
                Some(schema_tokens(m.result_schema)?)
            } else {
                None
            },
            method_type: m.method_type.to_string(),
        });
    }

    // serde_json emits struct fields in declaration order, so the entries above
    // are declared in the sorted key order canonical JSON requires -- and the
    // top level is assembled by hand for the same reason. Both are ASCII, so
    // byte order and UTF-16 code-unit order agree.
    let methods_json = serde_json::to_string(&entries)
        .expect("method entries are plain data and always serialize");
    let protocol_json = serde_json::to_string(protocol_name)
        .expect("a protocol name is a string and always serializes");
    Ok(format!(
        "{{\"methods\":{methods_json},\"protocol\":{protocol_json}}}"
    ))
}

/// Return the SHA-256 hex digest of a protocol's canonical description.
///
/// Identical in every port for the same protocol -- which is a property
/// conformance can assert, and could not before.
pub fn compute_protocol_hash(
    protocol_name: &str,
    methods: &[HashMethod<'_>],
) -> Result<String, UnsupportedArrowType> {
    let preimage = canonical_description(protocol_name, methods)?;
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN.as_bytes());
    hasher.update(preimage.as_bytes());
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arrow_schema::{DataType, Field, Schema};

    use super::*;

    fn utf8_schema(name: &str) -> Schema {
        Schema::new(vec![Field::new(name, DataType::Utf8, false)])
    }

    /// The cross-port contract. This digest is produced by the Python reference
    /// (`vgi_rpc/rpc/_protocol_hash.py`); a mismatch means this port and that
    /// one would disagree about whether they speak the same protocol.
    ///
    /// A failure is a JSON diff, not a guess: [`canonical_description`] returns
    /// the exact preimage, so print it and compare.
    #[test]
    fn matches_the_python_reference_digest() {
        let params = utf8_schema("value");
        let result = utf8_schema("result");
        let methods = vec![HashMethod {
            name: "echo",
            method_type: "unary",
            has_return: true,
            has_header: false,
            params_schema: Some(&params),
            result_schema: Some(&result),
            header_schema: None,
        }];
        assert_eq!(
            compute_protocol_hash("demo.Hash.v1", &methods).unwrap(),
            "a4b8ae57bf777c906081ff3610d435836b77dbc1f17a381c6a2febf1a2adb115",
        );
    }

    /// Absent and empty are different and must not hash alike.
    #[test]
    fn omits_result_for_a_method_returning_nothing() {
        let params = utf8_schema("v");
        let methods = vec![HashMethod {
            name: "fire",
            method_type: "unary",
            has_return: false,
            has_header: false,
            params_schema: Some(&params),
            result_schema: None,
            header_schema: None,
        }];
        assert_eq!(
            canonical_description("demo.Void.v1", &methods).unwrap(),
            r#"{"methods":[{"has_header":false,"has_return":false,"name":"fire","params":[{"name":"v","nullable":false,"type":"utf8"}],"type":"unary"}],"protocol":"demo.Void.v1"}"#,
        );
    }

    /// A port iterating a hash map must still produce this order.
    #[test]
    fn sorts_methods_by_name() {
        let empty = Schema::empty();
        let mk = |name: &'static str| HashMethod {
            name,
            method_type: "unary",
            has_return: false,
            has_header: false,
            params_schema: Some(&empty),
            result_schema: None,
            header_schema: None,
        };
        assert_eq!(
            compute_protocol_hash("p", &[mk("a"), mk("b")]).unwrap(),
            compute_protocol_hash("p", &[mk("b"), mk("a")]).unwrap(),
        );
    }

    /// Arrow ignores a list child's *name*, so the token must too -- otherwise
    /// two ports that default differently hash the same protocol differently.
    #[test]
    fn list_child_name_is_normalised_but_nullability_is_kept() {
        use crate::type_tokens::type_token;
        let named = DataType::List(Arc::new(Field::new("element", DataType::Int64, true)));
        assert_eq!(type_token(&named).unwrap(), "list<item?:int64>");
        let non_null = DataType::List(Arc::new(Field::new("item", DataType::Int64, false)));
        assert_eq!(type_token(&non_null).unwrap(), "list<item:int64>");
    }
}

//! Canonical text tokens for Arrow types, for the protocol hash preimage.
//!
//! The protocol hash is taken over what Arrow *decodes to*, not over what an
//! encoder emits: each language's Arrow implementation may legitimately produce
//! different bytes for the same logical schema, so a hash over serialized IPC is
//! not a cross-language contract. The preimage is canonical JSON (RFC 8785) of
//! the decoded description, and these tokens are how a type appears inside it.
//!
//! JSON solves framing, escaping and key ordering. It does not solve spelling --
//! two ports can agree on every JCS rule and still disagree on whether a
//! microsecond timestamp is `timestamp[us]` or `timestamp(us)`, which is a
//! silent hash divergence. So the vocabulary is enumerated exhaustively and
//! [`type_token`] is total: an unrecognised type is an error rather than a
//! fallback to `DataType`'s `Display`, whose output is an arrow-rs
//! implementation detail that differs from every other port.
//!
//! # Grammar
//!
//! A token is lowercase ASCII. Parameters go in parentheses, children in angle
//! brackets. A child is `name:token` when non-nullable and `name?:token` when
//! nullable -- child nullability is part of the type in Arrow, and two schemas
//! differing only there are different schemas. Numeric parameters are folded
//! into the token (`decimal128(38,9)`) so the preimage contains no JSON numbers
//! and RFC 8785's hardest rule, number canonicalisation, never applies. Keep it
//! that way.
//!
//! # What is normalised
//!
//! Arrow's own type equality ignores the *name* of a list's child field and of
//! a map's key/value fields -- arrow-rs names the list child `item`, some
//! Parquet producers name it `element`. Those names are normalised, because
//! keeping them would give two ports different hashes for a protocol Arrow
//! itself calls identical. Everything Arrow does treat as part of the type is
//! kept: child nullability, struct field names, union child names and type
//! codes, dictionary index/value types and orderedness, and map `keys_sorted`.

use arrow_schema::{DataType, Field, Fields, IntervalUnit, Schema, TimeUnit, UnionMode};

/// An Arrow type with no canonical token.
///
/// An error rather than a fallback to `Display`: a port that silently spelled
/// an unknown type its own way would produce a protocol hash that disagrees
/// with every other port, and the disagreement would surface as an unexplained
/// mismatch at a client rather than as an error here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedArrowType(pub String);

impl std::fmt::Display for UnsupportedArrowType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Arrow type {} has no canonical token. Add one to type_tokens.rs and to \
             every other port at the same time: a one-sided addition changes only \
             this port's protocol hash.",
            self.0
        )
    }
}

impl std::error::Error for UnsupportedArrowType {}

type TokenResult = Result<String, UnsupportedArrowType>;

/// Arrow's own spelling of a time unit.
fn unit_token(unit: &TimeUnit) -> &'static str {
    match unit {
        TimeUnit::Second => "s",
        TimeUnit::Millisecond => "ms",
        TimeUnit::Microsecond => "us",
        TimeUnit::Nanosecond => "ns",
    }
}

/// Spell a child whose name Arrow does not consider part of the type.
///
/// A list's child is named `item` by arrow-rs, `element` by some Parquet
/// producers, and whatever the caller passed by anyone constructing the type by
/// hand -- and Arrow's own type equality ignores all of it. Normalising to a
/// fixed name is what keeps two ports that default differently from hashing the
/// same protocol differently. Nullability *is* part of the type, so it is kept.
fn anon_child(field: &Field, name: &str) -> TokenResult {
    Ok(format!(
        "{name}{}:{}",
        if field.is_nullable() { "?" } else { "" },
        type_token(field.data_type())?
    ))
}

/// Spell a child field whose name is part of the type.
fn child(field: &Field) -> TokenResult {
    anon_child(field, field.name())
}

fn children_tokens(fields: &Fields) -> TokenResult {
    let mut parts = Vec::with_capacity(fields.len());
    for f in fields {
        parts.push(child(f)?);
    }
    Ok(parts.join(","))
}

/// Return the canonical token for `dt`.
pub fn type_token(dt: &DataType) -> TokenResult {
    Ok(match dt {
        DataType::Null => "null".into(),
        DataType::Boolean => "bool".into(),
        DataType::Int8 => "int8".into(),
        DataType::Int16 => "int16".into(),
        DataType::Int32 => "int32".into(),
        DataType::Int64 => "int64".into(),
        DataType::UInt8 => "uint8".into(),
        DataType::UInt16 => "uint16".into(),
        DataType::UInt32 => "uint32".into(),
        DataType::UInt64 => "uint64".into(),
        DataType::Float16 => "float16".into(),
        DataType::Float32 => "float32".into(),
        DataType::Float64 => "float64".into(),
        DataType::Utf8 => "utf8".into(),
        DataType::LargeUtf8 => "large_utf8".into(),
        DataType::Utf8View => "utf8_view".into(),
        DataType::Binary => "binary".into(),
        DataType::LargeBinary => "large_binary".into(),
        DataType::BinaryView => "binary_view".into(),
        DataType::FixedSizeBinary(width) => format!("fixed_size_binary({width})"),
        DataType::Date32 => "date32".into(),
        DataType::Date64 => "date64".into(),
        DataType::Time32(unit) => format!("time32({})", unit_token(unit)),
        DataType::Time64(unit) => format!("time64({})", unit_token(unit)),
        // The zone is carried verbatim: "UTC" and "+00:00" are distinct Arrow
        // types and must not collapse to one token.
        DataType::Timestamp(unit, tz) => match tz {
            Some(tz) => format!("timestamp({},tz={tz})", unit_token(unit)),
            None => format!("timestamp({})", unit_token(unit)),
        },
        DataType::Duration(unit) => format!("duration({})", unit_token(unit)),
        DataType::Interval(IntervalUnit::YearMonth) => "interval_months".into(),
        DataType::Interval(IntervalUnit::DayTime) => "interval_day_time".into(),
        DataType::Interval(IntervalUnit::MonthDayNano) => "interval_month_day_nano".into(),
        // arrow-rs exposes 32- and 64-bit decimals that the other ports' Arrow
        // bindings do not yet surface. Spelled the same way, so a port whose
        // Arrow later gains them agrees without a hash rotation -- and until
        // then a protocol using one simply cannot be expressed in those ports,
        // which is a build error there rather than a silent hash divergence.
        DataType::Decimal32(p, s) => format!("decimal32({p},{s})"),
        DataType::Decimal64(p, s) => format!("decimal64({p},{s})"),
        DataType::Decimal128(p, s) => format!("decimal128({p},{s})"),
        DataType::Decimal256(p, s) => format!("decimal256({p},{s})"),
        DataType::List(f) => format!("list<{}>", anon_child(f, "item")?),
        DataType::LargeList(f) => format!("large_list<{}>", anon_child(f, "item")?),
        DataType::ListView(f) => format!("list_view<{}>", anon_child(f, "item")?),
        DataType::LargeListView(f) => format!("large_list_view<{}>", anon_child(f, "item")?),
        DataType::FixedSizeList(f, n) => {
            format!("fixed_size_list({n})<{}>", anon_child(f, "item")?)
        }
        DataType::Struct(fields) => format!("struct<{}>", children_tokens(fields)?),
        DataType::Map(entries, keys_sorted) => {
            // A map's child is a struct of the key and value fields.
            let DataType::Struct(kv) = entries.data_type() else {
                return Err(UnsupportedArrowType(format!("{dt:?}")));
            };
            if kv.len() != 2 {
                return Err(UnsupportedArrowType(format!("{dt:?}")));
            }
            let token = format!(
                "map<{},{}>",
                anon_child(&kv[0], "key")?,
                anon_child(&kv[1], "value")?
            );
            // keys_sorted is part of the type in Arrow, so it is part of the token.
            if *keys_sorted {
                format!("{token},keys_sorted")
            } else {
                token
            }
        }
        DataType::Dictionary(index, value) => {
            // arrow-rs carries no `ordered` flag on DataType::Dictionary, so
            // there is nothing to append -- unlike the other ports, which do.
            // An ordered dictionary reaching here from another port would decode
            // as unordered, so the hash would differ, which is the correct and
            // visible outcome rather than a silent equality.
            format!(
                "dictionary<index:{},value:{}>",
                type_token(index)?,
                type_token(value)?
            )
        }
        DataType::RunEndEncoded(run_ends, values) => format!(
            "run_end_encoded<run_ends:{},values:{}>",
            type_token(run_ends.data_type())?,
            type_token(values.data_type())?
        ),
        DataType::Union(fields, mode) => {
            // Type codes need not be 0..n-1, so they are spelled rather than
            // implied by position.
            let kind = match mode {
                UnionMode::Sparse => "sparse_union",
                UnionMode::Dense => "dense_union",
            };
            let mut parts = Vec::with_capacity(fields.len());
            for (code, f) in fields.iter() {
                parts.push(format!("{code}={}", child(f)?));
            }
            format!("{kind}<{}>", parts.join(","))
        }
    })
}

/// One top-level schema field as it appears in the hash preimage.
///
/// Strings and booleans only, so the preimage carries no JSON numbers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FieldToken {
    pub name: String,
    pub nullable: bool,
    #[serde(rename = "type")]
    pub type_token: String,
}

/// Describe a schema's fields in declaration order, which is significant.
pub fn schema_tokens(schema: Option<&Schema>) -> Result<Vec<FieldToken>, UnsupportedArrowType> {
    let Some(schema) = schema else {
        return Ok(Vec::new());
    };
    schema
        .fields()
        .iter()
        .map(|f| {
            Ok(FieldToken {
                name: f.name().clone(),
                nullable: f.is_nullable(),
                type_token: type_token(f.data_type())?,
            })
        })
        .collect()
}

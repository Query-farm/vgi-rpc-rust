//! Per-method parameter Arrow schemas — used both for introspection and as
//! reference types when matching `arrow-ipc`'s schema-equality checks.
//!
//! Field nullability matches the pyarrow defaults (list inner / map values
//! are nullable; top-level fields are not unless declared Optional).

use std::sync::Arc;

use arrow_schema::{DataType, Field, Schema, SchemaRef};

use super::types;

fn s(fields: Vec<Field>) -> SchemaRef {
    Arc::new(Schema::new(fields))
}

pub fn empty() -> SchemaRef {
    Arc::new(Schema::empty())
}

// ---- scalar echo ----
pub fn echo_string() -> SchemaRef {
    s(vec![Field::new("value", DataType::Utf8, false)])
}
pub fn echo_bytes() -> SchemaRef {
    s(vec![Field::new("data", DataType::Binary, false)])
}
pub fn echo_int() -> SchemaRef {
    s(vec![Field::new("value", DataType::Int64, false)])
}
pub fn echo_float() -> SchemaRef {
    s(vec![Field::new("value", DataType::Float64, false)])
}
pub fn echo_bool() -> SchemaRef {
    s(vec![Field::new("value", DataType::Boolean, false)])
}

// ---- void ----
pub fn void_noop() -> SchemaRef {
    empty()
}
pub fn void_with_param() -> SchemaRef {
    s(vec![Field::new("value", DataType::Int64, false)])
}

// ---- complex types ----
pub fn echo_enum() -> SchemaRef {
    s(vec![Field::new(
        "status",
        DataType::Dictionary(Box::new(DataType::Int16), Box::new(DataType::Utf8)),
        false,
    )])
}
pub fn echo_list() -> SchemaRef {
    s(vec![Field::new(
        "values",
        DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
        false,
    )])
}
pub fn echo_dict() -> SchemaRef {
    s(vec![Field::new("mapping", map_str_i64_type(), false)])
}
pub fn echo_nested_list() -> SchemaRef {
    s(vec![Field::new(
        "matrix",
        DataType::List(Arc::new(Field::new(
            "item",
            DataType::List(Arc::new(Field::new("item", DataType::Int64, true))),
            true,
        ))),
        false,
    )])
}

// ---- optional ----
pub fn echo_optional_string() -> SchemaRef {
    s(vec![Field::new("value", DataType::Utf8, true)])
}
pub fn echo_optional_int() -> SchemaRef {
    s(vec![Field::new("value", DataType::Int64, true)])
}

// ---- dataclass round-trip (param is serialized as binary IPC bytes) ----
pub fn echo_point() -> SchemaRef {
    s(vec![Field::new("point", DataType::Binary, false)])
}
pub fn echo_all_types() -> SchemaRef {
    s(vec![Field::new("data", DataType::Binary, false)])
}
pub fn echo_bounding_box() -> SchemaRef {
    s(vec![Field::new("box", DataType::Binary, false)])
}
pub fn inspect_point() -> SchemaRef {
    s(vec![Field::new("point", DataType::Binary, false)])
}

// ---- annotated ----
pub fn echo_int32() -> SchemaRef {
    s(vec![Field::new("value", DataType::Int32, false)])
}
pub fn echo_float32() -> SchemaRef {
    s(vec![Field::new("value", DataType::Float32, false)])
}

// ---- multi-param ----
pub fn add_floats() -> SchemaRef {
    s(vec![
        Field::new("a", DataType::Float64, false),
        Field::new("b", DataType::Float64, false),
    ])
}
pub fn concatenate() -> SchemaRef {
    s(vec![
        Field::new("prefix", DataType::Utf8, false),
        Field::new("suffix", DataType::Utf8, false),
        Field::new("separator", DataType::Utf8, false),
    ])
}
pub fn with_defaults() -> SchemaRef {
    s(vec![
        Field::new("required", DataType::Int64, false),
        Field::new("optional_str", DataType::Utf8, false),
        Field::new("optional_int", DataType::Int64, false),
    ])
}

// ---- errors / logging ----
pub fn raise_error() -> SchemaRef {
    s(vec![Field::new("message", DataType::Utf8, false)])
}
pub fn echo_with_value() -> SchemaRef {
    s(vec![Field::new("value", DataType::Utf8, false)])
}

// ---- cancel probe ----
pub fn cancel_probe_counters() -> SchemaRef {
    empty()
}
pub fn reset_cancel_probe() -> SchemaRef {
    empty()
}

// ---- producer streams ----
pub fn count_only() -> SchemaRef {
    s(vec![Field::new("count", DataType::Int64, false)])
}
pub fn produce_empty() -> SchemaRef {
    empty()
}
pub fn produce_single() -> SchemaRef {
    empty()
}
pub fn produce_large_batches() -> SchemaRef {
    s(vec![
        Field::new("rows_per_batch", DataType::Int64, false),
        Field::new("batch_count", DataType::Int64, false),
    ])
}
pub fn produce_error_mid_stream() -> SchemaRef {
    s(vec![Field::new("emit_before_error", DataType::Int64, false)])
}

// ---- exchange streams ----
pub fn factor_only() -> SchemaRef {
    s(vec![Field::new("factor", DataType::Float64, false)])
}
pub fn exchange_accumulate() -> SchemaRef {
    empty()
}
pub fn exchange_with_logs() -> SchemaRef {
    empty()
}
pub fn exchange_error_on_nth() -> SchemaRef {
    s(vec![Field::new("fail_on", DataType::Int64, false)])
}
pub fn exchange_error_on_init() -> SchemaRef {
    empty()
}
pub fn exchange_zero_columns() -> SchemaRef {
    empty()
}
pub fn exchange_cast_compatible() -> SchemaRef {
    empty()
}

// ---- rich header + dynamic ----
pub fn produce_with_rich_header() -> SchemaRef {
    s(vec![
        Field::new("seed", DataType::Int64, false),
        Field::new("count", DataType::Int64, false),
    ])
}
pub fn produce_dynamic_schema() -> SchemaRef {
    s(vec![
        Field::new("seed", DataType::Int64, false),
        Field::new("count", DataType::Int64, false),
        Field::new("include_strings", DataType::Boolean, false),
        Field::new("include_floats", DataType::Boolean, false),
    ])
}
pub fn exchange_with_rich_header() -> SchemaRef {
    s(vec![
        Field::new("seed", DataType::Int64, false),
        Field::new("factor", DataType::Float64, false),
    ])
}

pub fn cancellable() -> SchemaRef {
    empty()
}

// ---- map type helper (matches types::all_types_schema internals) ----
fn map_str_i64_type() -> DataType {
    let entries = Field::new(
        "entries",
        DataType::Struct(
            vec![
                Field::new("keys", DataType::Utf8, false),
                Field::new("values", DataType::Int64, true),
            ]
            .into(),
        ),
        false,
    );
    DataType::Map(Arc::new(entries), false)
}

pub fn conformance_header_schema() -> SchemaRef {
    types::conformance_header_schema()
}

pub fn rich_header_schema() -> SchemaRef {
    types::all_types_schema()
}

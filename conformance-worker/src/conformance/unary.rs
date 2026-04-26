//! Conformance unary methods, defined via `#[vgi_rpc::service]`.
//!
//! All 30 methods that mirror the Python `ConformanceService` unary
//! surface, expressed declaratively. Dataclass-typed params/returns
//! (`Point`, `BoundingBox`, `AllTypes`) round-trip through Arrow
//! `Binary` IPC bytes (matches Python's `ArrowSerializableDataclass`
//! wire convention) — those use `Bytes` + `param_type = "..."` to
//! preserve the `__describe__` type names.

use std::sync::Arc;

use vgi_rpc::{
    service, Bytes, CallContext, Decimal20_4, DictString, FixedBinary, LargeBytes, LargeString,
    LogLevel, LogMessage, Result, RpcError, RpcServer, UtcTimestamp,
};

use super::types;
use super::wide_types::{
    dataclass_deserialize_ipc, dataclass_serialize_ipc, ContainerWideTypes, DeepNested,
    EmbeddedArrow, WideTypes,
};

/// Stateless service handle.
pub struct UnarySvc;

#[service]
impl UnarySvc {
    // --- Scalar echo ---

    /// Echo a string value.
    #[unary]
    fn echo_string(&self, value: String) -> Result<String> {
        Ok(value)
    }

    /// Echo a bytes value.
    #[unary]
    #[param(name = "data")]
    fn echo_bytes(&self, data: Bytes) -> Result<Bytes> {
        Ok(data)
    }

    /// Echo an integer value.
    #[unary]
    fn echo_int(&self, value: i64) -> Result<i64> {
        Ok(value)
    }

    /// Echo a float value.
    #[unary]
    fn echo_float(&self, value: f64) -> Result<f64> {
        Ok(value)
    }

    /// Echo a boolean value.
    #[unary]
    fn echo_bool(&self, value: bool) -> Result<bool> {
        Ok(value)
    }

    // --- Void ---

    /// No-op returning void.
    #[unary]
    fn void_noop(&self) -> Result<()> {
        Ok(())
    }

    /// Accept a parameter, return void.
    #[unary]
    fn void_with_param(&self, value: i64) -> Result<()> {
        let _ = value;
        Ok(())
    }

    // --- Wide Arrow primitives ---

    /// Echo an int8 value.
    #[unary]
    fn echo_int8(&self, value: i8) -> Result<i8> {
        Ok(value)
    }

    /// Echo an int16 value.
    #[unary]
    fn echo_int16(&self, value: i16) -> Result<i16> {
        Ok(value)
    }

    /// Echo a uint8 value.
    #[unary]
    fn echo_uint8(&self, value: u8) -> Result<u8> {
        Ok(value)
    }

    /// Echo a uint16 value.
    #[unary]
    fn echo_uint16(&self, value: u16) -> Result<u16> {
        Ok(value)
    }

    /// Echo a uint32 value.
    #[unary]
    fn echo_uint32(&self, value: u32) -> Result<u32> {
        Ok(value)
    }

    /// Echo a uint64 value.
    #[unary]
    fn echo_uint64(&self, value: u64) -> Result<u64> {
        Ok(value)
    }

    /// Echo a date value.
    #[unary]
    fn echo_date(&self, value: chrono::NaiveDate) -> Result<chrono::NaiveDate> {
        Ok(value)
    }

    /// Echo a naive timestamp.
    #[unary]
    fn echo_timestamp(&self, value: chrono::NaiveDateTime) -> Result<chrono::NaiveDateTime> {
        Ok(value)
    }

    /// Echo a UTC timestamp.
    #[unary]
    fn echo_timestamp_utc(&self, value: UtcTimestamp) -> Result<UtcTimestamp> {
        Ok(value)
    }

    /// Echo a time-of-day value.
    #[unary]
    fn echo_time(&self, value: chrono::NaiveTime) -> Result<chrono::NaiveTime> {
        Ok(value)
    }

    /// Echo a duration.
    #[unary]
    fn echo_duration(&self, value: chrono::Duration) -> Result<chrono::Duration> {
        Ok(value)
    }

    /// Echo a decimal value (precision 20, scale 4 — matches the conformance schema).
    #[unary]
    fn echo_decimal(&self, value: Decimal20_4) -> Result<Decimal20_4> {
        Ok(value)
    }

    /// Echo a large_string value.
    #[unary]
    fn echo_large_string(&self, value: LargeString) -> Result<LargeString> {
        Ok(value)
    }

    /// Echo a large_binary value.
    #[unary]
    fn echo_large_binary(&self, value: LargeBytes) -> Result<LargeBytes> {
        Ok(value)
    }

    /// Echo a fixed_size_binary(8) value.
    #[unary]
    fn echo_fixed_binary(&self, value: FixedBinary<8>) -> Result<FixedBinary<8>> {
        Ok(value)
    }

    /// Echo a dictionary-encoded string.
    #[unary]
    fn echo_dict_encoded_string(&self, value: DictString) -> Result<DictString> {
        Ok(value)
    }

    // --- Complex type echo ---

    /// Echo an enum value.
    ///
    /// The `Status` enum is carried over the wire as `Utf8`; the
    /// describe metadata names it `"Status"` to match Python.
    #[unary]
    #[param(name = "status", arrow_type = "Status")]
    fn echo_enum(&self, status: String) -> Result<String> {
        Ok(status)
    }

    /// Echo a list of strings.
    #[unary]
    #[param(name = "values")]
    fn echo_list(&self, values: Vec<String>) -> Result<Vec<String>> {
        Ok(values)
    }

    /// Echo a dict mapping.
    #[unary]
    #[param(name = "mapping")]
    fn echo_dict(&self, mapping: Vec<(String, i64)>) -> Result<Vec<(String, i64)>> {
        Ok(mapping)
    }

    /// Echo a nested list.
    #[unary]
    #[param(name = "matrix")]
    fn echo_nested_list(&self, matrix: Vec<Vec<i64>>) -> Result<Vec<Vec<i64>>> {
        Ok(matrix)
    }

    // --- Optional ---

    /// Echo an optional string (may be None).
    #[unary]
    fn echo_optional_string(&self, value: Option<String>) -> Result<Option<String>> {
        Ok(value)
    }

    /// Echo an optional int (may be None).
    #[unary]
    fn echo_optional_int(&self, value: Option<i64>) -> Result<Option<i64>> {
        Ok(value)
    }

    // --- Dataclass round-trip (carried as Arrow Binary IPC bytes) ---

    /// Echo a Point dataclass.
    #[unary]
    #[param(name = "point", arrow_type = "Point")]
    fn echo_point(&self, point: Bytes) -> Result<Bytes> {
        let p = types::Point::deserialize_ipc(&point.0)?;
        Ok(Bytes(p.serialize_ipc()?))
    }

    /// Echo an AllTypes dataclass exercising every type mapping.
    #[unary]
    #[param(name = "data", arrow_type = "AllTypes")]
    fn echo_all_types(&self, data: Bytes) -> Result<Bytes> {
        let at = types::AllTypes::deserialize_ipc(&data.0)?;
        Ok(Bytes(at.serialize_ipc()?))
    }

    /// Echo a BoundingBox with nested Points.
    #[unary]
    #[param(name = "box", arrow_type = "BoundingBox")]
    fn echo_bounding_box(&self, r#box: Bytes) -> Result<Bytes> {
        let (tl, br, label) = types::deserialize_bounding_box_ipc(&r#box.0)?;
        Ok(Bytes(types::serialize_bounding_box_ipc(&tl, &br, &label)?))
    }

    /// Echo a WideTypes dataclass exercising every wide-Arrow primitive.
    #[unary]
    #[param(name = "data", arrow_type = "WideTypes")]
    fn echo_wide_types(&self, data: Bytes) -> Result<Bytes> {
        let w: WideTypes = dataclass_deserialize_ipc(&data.0)?;
        Ok(Bytes(dataclass_serialize_ipc(w)?))
    }

    /// Echo a ContainerWideTypes dataclass (wide types inside list/dict/optional).
    #[unary]
    #[param(name = "data", arrow_type = "ContainerWideTypes")]
    fn echo_container_wide_types(&self, data: Bytes) -> Result<Bytes> {
        let c: ContainerWideTypes = dataclass_deserialize_ipc(&data.0)?;
        Ok(Bytes(dataclass_serialize_ipc(c)?))
    }

    /// Echo a DeepNested dataclass (deep container nesting + dict-encoded strings).
    #[unary]
    #[param(name = "data", arrow_type = "DeepNested")]
    fn echo_deep_nested(&self, data: Bytes) -> Result<Bytes> {
        let d: DeepNested = dataclass_deserialize_ipc(&data.0)?;
        Ok(Bytes(dataclass_serialize_ipc(d)?))
    }

    /// Echo an EmbeddedArrow dataclass (RecordBatch + Schema as nested IPC bytes).
    #[unary]
    #[param(name = "data", arrow_type = "EmbeddedArrow")]
    fn echo_embedded_arrow(&self, data: Bytes) -> Result<Bytes> {
        let e: EmbeddedArrow = dataclass_deserialize_ipc(&data.0)?;
        Ok(Bytes(dataclass_serialize_ipc(e)?))
    }

    /// Accept a Point param (`pa.binary()` on wire), return formatted string.
    #[unary]
    #[param(name = "point", arrow_type = "Point")]
    fn inspect_point(&self, point: Bytes) -> Result<String> {
        let p = types::Point::deserialize_ipc(&point.0)?;
        Ok(format!(
            "Point({}, {})",
            format_float(p.x),
            format_float(p.y)
        ))
    }

    // --- Annotated ---

    /// Echo an int32 value.
    ///
    /// Wire schema is `Int32`, but Python writes `pa.int32()` from a
    /// generic `int`, so the describe type is `"int"`.
    #[unary]
    #[param(name = "value", arrow_type = "int")]
    fn echo_int32(&self, value: i32) -> Result<i32> {
        Ok(value)
    }

    /// Echo a float32 value.
    #[unary]
    #[param(name = "value", arrow_type = "float")]
    fn echo_float32(&self, value: f32) -> Result<f32> {
        Ok(value)
    }

    // --- Multi-param & defaults ---

    /// Add two floats.
    #[unary]
    fn add_floats(&self, a: f64, b: f64) -> Result<f64> {
        Ok(a + b)
    }

    /// Concatenate prefix + separator + suffix.
    #[unary]
    #[param(name = "separator", default = "-")]
    fn concatenate(&self, prefix: String, suffix: String, separator: String) -> Result<String> {
        Ok(format!("{prefix}{separator}{suffix}"))
    }

    /// Return a formatted string showing all param values.
    #[unary]
    #[param(name = "optional_str", default = "default")]
    #[param(name = "optional_int", default = 42)]
    fn with_defaults(
        &self,
        required: i64,
        optional_str: String,
        optional_int: i64,
    ) -> Result<String> {
        Ok(format!(
            "required={}, optional_str={}, optional_int={}",
            required, optional_str, optional_int
        ))
    }

    // --- Error propagation ---

    /// Raise a ValueError with the given message.
    #[unary]
    fn raise_value_error(&self, message: String) -> Result<String> {
        Err(RpcError::value_error(message))
    }

    /// Raise a RuntimeError with the given message.
    #[unary]
    fn raise_runtime_error(&self, message: String) -> Result<String> {
        Err(RpcError::runtime_error(message))
    }

    /// Raise a TypeError with the given message.
    #[unary]
    fn raise_type_error(&self, message: String) -> Result<String> {
        Err(RpcError::type_error(message))
    }

    // --- Client-directed logging ---

    /// Echo value, emitting one INFO log.
    #[unary]
    fn echo_with_info_log(&self, ctx: &CallContext, value: String) -> Result<String> {
        ctx.client_log(LogLevel::Info, format!("info: {value}"));
        Ok(value)
    }

    /// Echo value, emitting DEBUG + INFO + WARN logs.
    #[unary]
    fn echo_with_multi_logs(&self, ctx: &CallContext, value: String) -> Result<String> {
        ctx.client_log(LogLevel::Debug, format!("debug: {value}"));
        ctx.client_log(LogLevel::Info, format!("info: {value}"));
        ctx.client_log(LogLevel::Warn, format!("warn: {value}"));
        Ok(value)
    }

    /// Echo value, emitting an INFO log with extra key-value pairs.
    #[unary]
    fn echo_with_log_extras(&self, ctx: &CallContext, value: String) -> Result<String> {
        let msg = LogMessage::new(LogLevel::Info, "echo_with_extras")
            .with_extra("source", "conformance")
            .with_extra("detail", &value);
        ctx.client_log_with(msg);
        Ok(value)
    }

    /// Echo value, emitting one log per non-EXCEPTION level (TRACE..ERROR).
    #[unary]
    fn echo_with_all_log_levels(&self, ctx: &CallContext, value: String) -> Result<String> {
        for (level, label) in [
            (LogLevel::Trace, "trace"),
            (LogLevel::Debug, "debug"),
            (LogLevel::Info, "info"),
            (LogLevel::Warn, "warn"),
            (LogLevel::Error, "error"),
        ] {
            ctx.client_log(level, format!("{label}: {value}"));
        }
        Ok(value)
    }

    // --- Cancel probe ---

    /// Return ``[produce_calls, exchange_calls, on_cancel_calls]`` observed on the server.
    #[unary]
    fn cancel_probe_counters(&self) -> Result<Vec<i64>> {
        let [a, b, c] = super::read_cancel_probe();
        Ok(vec![a, b, c])
    }

    /// Reset all cancel-probe counters to zero on the server.
    #[unary]
    fn reset_cancel_probe(&self) -> Result<()> {
        super::reset_cancel_probe();
        Ok(())
    }
}

pub fn register(srv: &mut RpcServer) {
    UnarySvc::register_with(srv, Arc::new(UnarySvc));
}

fn format_float(f: f64) -> String {
    let s = format!("{f}");
    if !s.contains('.')
        && !s.contains('e')
        && !s.contains('E')
        && !s.contains("inf")
        && !s.contains("NaN")
    {
        format!("{s}.0")
    } else {
        s
    }
}

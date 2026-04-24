//! Register all conformance unary methods with full describe metadata.

use serde_json::json;
use vgi_rpc::{LogLevel, LogMessage, MethodInfo, RpcError, RpcServer};

use super::param_schemas as ps;
use super::params as p;
use super::results as r;
use super::types;

pub fn register(s: &mut RpcServer) {
    // --- Scalar echo ---
    s.register(
        MethodInfo::unary(
            "echo_string",
            ps::echo_string(),
            r::schema_string(),
            |req, _| {
                let v = p::str_col(req, "value")?.to_string();
                Ok(Some(r::unary_string(r::schema_string(), &v)?))
            },
        )
        .doc("Echo a string value.")
        .param_type("value", "str"),
    );
    s.register(
        MethodInfo::unary(
            "echo_bytes",
            ps::echo_bytes(),
            r::schema_bytes(),
            |req, _| {
                let v = p::bytes_col(req, "data")?.to_vec();
                Ok(Some(r::unary_bytes(r::schema_bytes(), &v)?))
            },
        )
        .doc("Echo a bytes value.")
        .param_type("data", "bytes"),
    );
    s.register(
        MethodInfo::unary("echo_int", ps::echo_int(), r::schema_int64(), |req, _| {
            let v = p::i64_col(req, "value")?;
            Ok(Some(r::unary_int64(r::schema_int64(), v)?))
        })
        .doc("Echo an integer value.")
        .param_type("value", "int"),
    );
    s.register(
        MethodInfo::unary(
            "echo_float",
            ps::echo_float(),
            r::schema_float64(),
            |req, _| {
                let v = p::f64_col(req, "value")?;
                Ok(Some(r::unary_float64(r::schema_float64(), v)?))
            },
        )
        .doc("Echo a float value.")
        .param_type("value", "float"),
    );
    s.register(
        MethodInfo::unary("echo_bool", ps::echo_bool(), r::schema_bool(), |req, _| {
            let v = p::bool_col(req, "value")?;
            Ok(Some(r::unary_bool(r::schema_bool(), v)?))
        })
        .doc("Echo a boolean value.")
        .param_type("value", "bool"),
    );

    // --- Void ---
    s.register(
        MethodInfo::unary(
            "void_noop",
            ps::void_noop(),
            r::schema_empty(),
            |_req, _| Ok(None),
        )
        .doc("No-op returning void."),
    );
    s.register(
        MethodInfo::unary(
            "void_with_param",
            ps::void_with_param(),
            r::schema_empty(),
            |_req, _| Ok(None),
        )
        .doc("Accept a parameter, return void.")
        .param_type("value", "int"),
    );

    // --- Complex type echo ---
    s.register(
        MethodInfo::unary(
            "echo_enum",
            ps::echo_enum(),
            r::schema_dict_enum(),
            |req, _| {
                let v = p::enum_str(req, "status")?;
                Ok(Some(r::unary_enum(r::schema_dict_enum(), &v)?))
            },
        )
        .doc("Echo an enum value.")
        .param_type("status", "Status"),
    );
    s.register(
        MethodInfo::unary(
            "echo_list",
            ps::echo_list(),
            r::schema_list_str(),
            |req, _| {
                let v = p::list_str(req, "values")?;
                Ok(Some(r::unary_list_str(r::schema_list_str(), &v)?))
            },
        )
        .doc("Echo a list of strings.")
        .param_type("values", "list[str]"),
    );
    s.register(
        MethodInfo::unary(
            "echo_dict",
            ps::echo_dict(),
            r::schema_map_str_int64(),
            |req, _| {
                let v = p::map_string_int64(req, "mapping")?;
                Ok(Some(r::unary_map_str_int64(r::schema_map_str_int64(), &v)?))
            },
        )
        .doc("Echo a dict mapping.")
        .param_type("mapping", "dict[str, int]"),
    );
    s.register(
        MethodInfo::unary(
            "echo_nested_list",
            ps::echo_nested_list(),
            r::schema_nested_list_i64(),
            |req, _| {
                let v = p::nested_list_i64(req, "matrix")?;
                Ok(Some(r::unary_nested_list_i64(
                    r::schema_nested_list_i64(),
                    &v,
                )?))
            },
        )
        .doc("Echo a nested list.")
        .param_type("matrix", "list[list[int]]"),
    );

    // --- Optional ---
    s.register(
        MethodInfo::unary(
            "echo_optional_string",
            ps::echo_optional_string(),
            r::schema_opt_string(),
            |req, _| {
                let v = p::opt_str(req, "value")?;
                Ok(Some(r::unary_opt_string(
                    r::schema_opt_string(),
                    v.as_deref(),
                )?))
            },
        )
        .doc("Echo an optional string (may be None).")
        .param_type("value", "str | None"),
    );
    s.register(
        MethodInfo::unary(
            "echo_optional_int",
            ps::echo_optional_int(),
            r::schema_opt_int64(),
            |req, _| {
                let v = p::opt_i64(req, "value")?;
                Ok(Some(r::unary_opt_int64(r::schema_opt_int64(), v)?))
            },
        )
        .doc("Echo an optional int (may be None).")
        .param_type("value", "int | None"),
    );

    // --- Dataclass round-trip ---
    s.register(
        MethodInfo::unary(
            "echo_point",
            ps::echo_point(),
            r::schema_binary_dataclass(),
            |req, _| {
                let bytes = p::bytes_col(req, "point")?;
                let point = types::Point::deserialize_ipc(bytes)?;
                let ipc = point.serialize_ipc()?;
                Ok(Some(r::unary_binary_dataclass(
                    r::schema_binary_dataclass(),
                    ipc,
                )?))
            },
        )
        .doc("Echo a Point dataclass.")
        .param_type("point", "Point"),
    );
    s.register(
        MethodInfo::unary(
            "echo_all_types",
            ps::echo_all_types(),
            r::schema_binary_dataclass(),
            |req, _| {
                let bytes = p::bytes_col(req, "data")?;
                let at = types::AllTypes::deserialize_ipc(bytes)?;
                let ipc = at.serialize_ipc()?;
                Ok(Some(r::unary_binary_dataclass(
                    r::schema_binary_dataclass(),
                    ipc,
                )?))
            },
        )
        .doc("Echo an AllTypes dataclass exercising every type mapping.")
        .param_type("data", "AllTypes"),
    );
    s.register(
        MethodInfo::unary(
            "echo_bounding_box",
            ps::echo_bounding_box(),
            r::schema_binary_dataclass(),
            |req, _| {
                let bytes = p::bytes_col(req, "box")?;
                let (tl, br, label) = types::deserialize_bounding_box_ipc(bytes)?;
                let ipc = types::serialize_bounding_box_ipc(&tl, &br, &label)?;
                Ok(Some(r::unary_binary_dataclass(
                    r::schema_binary_dataclass(),
                    ipc,
                )?))
            },
        )
        .doc("Echo a BoundingBox with nested Points.")
        .param_type("box", "BoundingBox"),
    );

    // --- Dataclass as parameter ---
    s.register(
        MethodInfo::unary(
            "inspect_point",
            ps::inspect_point(),
            r::schema_string(),
            |req, _| {
                let bytes = p::bytes_col(req, "point")?;
                let point = types::Point::deserialize_ipc(bytes)?;
                let txt = format!(
                    "Point({}, {})",
                    format_float(point.x),
                    format_float(point.y)
                );
                Ok(Some(r::unary_string(r::schema_string(), &txt)?))
            },
        )
        .doc("Accept a Point param (pa.binary() on wire), return formatted string.")
        .param_type("point", "Point"),
    );

    // --- Annotated ---
    s.register(
        MethodInfo::unary(
            "echo_int32",
            ps::echo_int32(),
            r::schema_int32(),
            |req, _| {
                let v = p::i64_col(req, "value")? as i32;
                Ok(Some(r::unary_int32(r::schema_int32(), v)?))
            },
        )
        .doc("Echo an int32 value.")
        .param_type("value", "int"),
    );
    s.register(
        MethodInfo::unary(
            "echo_float32",
            ps::echo_float32(),
            r::schema_float32(),
            |req, _| {
                let v = p::f64_col(req, "value")? as f32;
                Ok(Some(r::unary_float32(r::schema_float32(), v)?))
            },
        )
        .doc("Echo a float32 value.")
        .param_type("value", "float"),
    );

    // --- Multi-param & defaults ---
    s.register(
        MethodInfo::unary(
            "add_floats",
            ps::add_floats(),
            r::schema_float64(),
            |req, _| {
                let a = p::f64_col(req, "a")?;
                let b = p::f64_col(req, "b")?;
                Ok(Some(r::unary_float64(r::schema_float64(), a + b)?))
            },
        )
        .doc("Add two floats.")
        .param_type("a", "float")
        .param_type("b", "float"),
    );
    s.register(
        MethodInfo::unary(
            "concatenate",
            ps::concatenate(),
            r::schema_string(),
            |req, _| {
                let prefix = p::str_col(req, "prefix")?.to_string();
                let suffix = p::str_col(req, "suffix")?.to_string();
                let sep = p::opt_str(req, "separator")?.unwrap_or_else(|| "-".to_string());
                Ok(Some(r::unary_string(
                    r::schema_string(),
                    &format!("{prefix}{sep}{suffix}"),
                )?))
            },
        )
        .doc("Concatenate prefix + separator + suffix.")
        .param_type("prefix", "str")
        .param_type("suffix", "str")
        .param_type("separator", "str")
        .param_default("separator", json!("-")),
    );
    s.register(
        MethodInfo::unary(
            "with_defaults",
            ps::with_defaults(),
            r::schema_string(),
            |req, _| {
                let required = p::i64_col(req, "required")?;
                let optional_str =
                    p::opt_str(req, "optional_str")?.unwrap_or_else(|| "default".to_string());
                let optional_int = p::opt_i64(req, "optional_int")?.unwrap_or(42);
                Ok(Some(r::unary_string(
                    r::schema_string(),
                    &format!(
                        "required={}, optional_str={}, optional_int={}",
                        required, optional_str, optional_int
                    ),
                )?))
            },
        )
        .doc("Return a formatted string showing all param values.")
        .param_type("required", "int")
        .param_type("optional_str", "str")
        .param_type("optional_int", "int")
        .param_default("optional_str", json!("default"))
        .param_default("optional_int", json!(42)),
    );

    // --- Error propagation ---
    s.register(
        MethodInfo::unary(
            "raise_value_error",
            ps::raise_error(),
            r::schema_string(),
            |req, _| {
                let msg = p::str_col(req, "message")?.to_string();
                Err::<Option<_>, _>(RpcError::value_error(msg))
            },
        )
        .doc("Raise a ValueError with the given message.")
        .param_type("message", "str"),
    );
    s.register(
        MethodInfo::unary(
            "raise_runtime_error",
            ps::raise_error(),
            r::schema_string(),
            |req, _| {
                let msg = p::str_col(req, "message")?.to_string();
                Err::<Option<_>, _>(RpcError::runtime_error(msg))
            },
        )
        .doc("Raise a RuntimeError with the given message.")
        .param_type("message", "str"),
    );
    s.register(
        MethodInfo::unary(
            "raise_type_error",
            ps::raise_error(),
            r::schema_string(),
            |req, _| {
                let msg = p::str_col(req, "message")?.to_string();
                Err::<Option<_>, _>(RpcError::type_error(msg))
            },
        )
        .doc("Raise a TypeError with the given message.")
        .param_type("message", "str"),
    );

    // --- Client-directed logging ---
    s.register(
        MethodInfo::unary(
            "echo_with_info_log",
            ps::echo_with_value(),
            r::schema_string(),
            |req, ctx| {
                let v = p::str_col(req, "value")?.to_string();
                ctx.client_log(LogLevel::Info, format!("info: {v}"));
                Ok(Some(r::unary_string(r::schema_string(), &v)?))
            },
        )
        .doc("Echo value, emitting one INFO log.")
        .param_type("value", "str"),
    );
    s.register(
        MethodInfo::unary(
            "echo_with_multi_logs",
            ps::echo_with_value(),
            r::schema_string(),
            |req, ctx| {
                let v = p::str_col(req, "value")?.to_string();
                ctx.client_log(LogLevel::Debug, format!("debug: {v}"));
                ctx.client_log(LogLevel::Info, format!("info: {v}"));
                ctx.client_log(LogLevel::Warn, format!("warn: {v}"));
                Ok(Some(r::unary_string(r::schema_string(), &v)?))
            },
        )
        .doc("Echo value, emitting DEBUG + INFO + WARN logs.")
        .param_type("value", "str"),
    );
    s.register(
        MethodInfo::unary(
            "echo_with_log_extras",
            ps::echo_with_value(),
            r::schema_string(),
            |req, ctx| {
                let v = p::str_col(req, "value")?.to_string();
                let msg = LogMessage::new(LogLevel::Info, "echo_with_extras")
                    .with_extra("source", "conformance")
                    .with_extra("detail", &v);
                ctx.client_log_with(msg);
                Ok(Some(r::unary_string(r::schema_string(), &v)?))
            },
        )
        .doc("Echo value, emitting an INFO log with extra key-value pairs.")
        .param_type("value", "str"),
    );

    // --- Cancel probe ---
    s.register(
        MethodInfo::unary(
            "cancel_probe_counters",
            ps::cancel_probe_counters(),
            r::schema_list_i64(),
            |_req, _| {
                let [prod, exch, canc] = super::read_cancel_probe();
                Ok(Some(r::unary_list_i64(
                    r::schema_list_i64(),
                    &[prod, exch, canc],
                )?))
            },
        )
        .doc("Return ``[produce_calls, exchange_calls, on_cancel_calls]`` observed on the server."),
    );
    s.register(
        MethodInfo::unary(
            "reset_cancel_probe",
            ps::reset_cancel_probe(),
            r::schema_empty(),
            |_req, _| {
                super::reset_cancel_probe();
                Ok(None)
            },
        )
        .doc("Reset all cancel-probe counters to zero on the server."),
    );
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

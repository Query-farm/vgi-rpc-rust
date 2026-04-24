//! Register all conformance unary methods.

use vgi_rpc::{LogLevel, LogMessage, RpcError, RpcServer};

use super::params as p;
use super::results as r;
use super::types;

pub fn register(s: &mut RpcServer) {
    // --- Scalar echo ---
    s.register_unary("echo_string", r::schema_string(), |req, _| {
        let v = p::str_col(req, "value")?.to_string();
        Ok(Some(r::unary_string(r::schema_string(), &v)?))
    });
    s.register_unary("echo_bytes", r::schema_bytes(), |req, _| {
        let v = p::bytes_col(req, "data")?.to_vec();
        Ok(Some(r::unary_bytes(r::schema_bytes(), &v)?))
    });
    s.register_unary("echo_int", r::schema_int64(), |req, _| {
        let v = p::i64_col(req, "value")?;
        Ok(Some(r::unary_int64(r::schema_int64(), v)?))
    });
    s.register_unary("echo_float", r::schema_float64(), |req, _| {
        let v = p::f64_col(req, "value")?;
        Ok(Some(r::unary_float64(r::schema_float64(), v)?))
    });
    s.register_unary("echo_bool", r::schema_bool(), |req, _| {
        let v = p::bool_col(req, "value")?;
        Ok(Some(r::unary_bool(r::schema_bool(), v)?))
    });

    // --- Void ---
    s.register_unary("void_noop", r::schema_empty(), |_req, _| Ok(None));
    s.register_unary("void_with_param", r::schema_empty(), |_req, _| Ok(None));

    // --- Complex type echo ---
    s.register_unary("echo_enum", r::schema_dict_enum(), |req, _| {
        let v = p::enum_str(req, "status")?;
        Ok(Some(r::unary_enum(r::schema_dict_enum(), &v)?))
    });
    s.register_unary("echo_list", r::schema_list_str(), |req, _| {
        let v = p::list_str(req, "values")?;
        Ok(Some(r::unary_list_str(r::schema_list_str(), &v)?))
    });
    s.register_unary("echo_dict", r::schema_map_str_int64(), |req, _| {
        let v = p::map_string_int64(req, "mapping")?;
        Ok(Some(r::unary_map_str_int64(r::schema_map_str_int64(), &v)?))
    });
    s.register_unary("echo_nested_list", r::schema_nested_list_i64(), |req, _| {
        let v = p::nested_list_i64(req, "matrix")?;
        Ok(Some(r::unary_nested_list_i64(r::schema_nested_list_i64(), &v)?))
    });

    // --- Optional ---
    s.register_unary("echo_optional_string", r::schema_opt_string(), |req, _| {
        let v = p::opt_str(req, "value")?;
        Ok(Some(r::unary_opt_string(
            r::schema_opt_string(),
            v.as_deref(),
        )?))
    });
    s.register_unary("echo_optional_int", r::schema_opt_int64(), |req, _| {
        let v = p::opt_i64(req, "value")?;
        Ok(Some(r::unary_opt_int64(r::schema_opt_int64(), v)?))
    });

    // --- Dataclass round-trip ---
    s.register_unary("echo_point", r::schema_binary_dataclass(), |req, _| {
        let bytes = p::bytes_col(req, "point")?;
        let point = types::Point::deserialize_ipc(bytes)?;
        let ipc = point.serialize_ipc()?;
        Ok(Some(r::unary_binary_dataclass(
            r::schema_binary_dataclass(),
            ipc,
        )?))
    });
    s.register_unary("echo_all_types", r::schema_binary_dataclass(), |req, _| {
        let bytes = p::bytes_col(req, "data")?;
        let at = types::AllTypes::deserialize_ipc(bytes)?;
        let ipc = at.serialize_ipc()?;
        Ok(Some(r::unary_binary_dataclass(
            r::schema_binary_dataclass(),
            ipc,
        )?))
    });
    s.register_unary(
        "echo_bounding_box",
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
    );

    // --- Dataclass as parameter ---
    s.register_unary("inspect_point", r::schema_string(), |req, _| {
        let bytes = p::bytes_col(req, "point")?;
        let point = types::Point::deserialize_ipc(bytes)?;
        let txt = format!(
            "Point({}, {})",
            format_float(point.x),
            format_float(point.y)
        );
        Ok(Some(r::unary_string(r::schema_string(), &txt)?))
    });

    // --- Annotated ---
    s.register_unary("echo_int32", r::schema_int32(), |req, _| {
        let v = p::i64_col(req, "value")? as i32;
        Ok(Some(r::unary_int32(r::schema_int32(), v)?))
    });
    s.register_unary("echo_float32", r::schema_float32(), |req, _| {
        let v = p::f64_col(req, "value")? as f32;
        Ok(Some(r::unary_float32(r::schema_float32(), v)?))
    });

    // --- Multi-param & defaults ---
    s.register_unary("add_floats", r::schema_float64(), |req, _| {
        let a = p::f64_col(req, "a")?;
        let b = p::f64_col(req, "b")?;
        Ok(Some(r::unary_float64(r::schema_float64(), a + b)?))
    });
    s.register_unary("concatenate", r::schema_string(), |req, _| {
        let prefix = p::str_col(req, "prefix")?.to_string();
        let suffix = p::str_col(req, "suffix")?.to_string();
        let sep = p::opt_str(req, "separator")?.unwrap_or_else(|| "-".to_string());
        Ok(Some(r::unary_string(
            r::schema_string(),
            &format!("{prefix}{sep}{suffix}"),
        )?))
    });
    s.register_unary("with_defaults", r::schema_string(), |req, _| {
        let required = p::i64_col(req, "required")?;
        let optional_str = p::opt_str(req, "optional_str")?
            .unwrap_or_else(|| "default".to_string());
        let optional_int = p::opt_i64(req, "optional_int")?.unwrap_or(42);
        Ok(Some(r::unary_string(
            r::schema_string(),
            &format!(
                "required={}, optional_str={}, optional_int={}",
                required, optional_str, optional_int
            ),
        )?))
    });

    // --- Error propagation ---
    s.register_unary("raise_value_error", r::schema_string(), |req, _| {
        let msg = p::str_col(req, "message")?.to_string();
        Err::<Option<_>, _>(RpcError::value_error(msg))
    });
    s.register_unary("raise_runtime_error", r::schema_string(), |req, _| {
        let msg = p::str_col(req, "message")?.to_string();
        Err::<Option<_>, _>(RpcError::runtime_error(msg))
    });
    s.register_unary("raise_type_error", r::schema_string(), |req, _| {
        let msg = p::str_col(req, "message")?.to_string();
        Err::<Option<_>, _>(RpcError::type_error(msg))
    });

    // --- Client-directed logging ---
    s.register_unary("echo_with_info_log", r::schema_string(), |req, ctx| {
        let v = p::str_col(req, "value")?.to_string();
        ctx.client_log(LogLevel::Info, format!("info: {v}"));
        Ok(Some(r::unary_string(r::schema_string(), &v)?))
    });
    s.register_unary("echo_with_multi_logs", r::schema_string(), |req, ctx| {
        let v = p::str_col(req, "value")?.to_string();
        ctx.client_log(LogLevel::Debug, format!("debug: {v}"));
        ctx.client_log(LogLevel::Info, format!("info: {v}"));
        ctx.client_log(LogLevel::Warn, format!("warn: {v}"));
        Ok(Some(r::unary_string(r::schema_string(), &v)?))
    });
    s.register_unary("echo_with_log_extras", r::schema_string(), |req, ctx| {
        let v = p::str_col(req, "value")?.to_string();
        let msg = LogMessage::new(LogLevel::Info, "echo_with_extras")
            .with_extra("source", "conformance")
            .with_extra("detail", &v);
        ctx.client_log_with(msg);
        Ok(Some(r::unary_string(r::schema_string(), &v)?))
    });

    // --- Cancel probe (unary) ---
    s.register_unary(
        "cancel_probe_counters",
        r::schema_list_i64(),
        |_req, _| {
            let [prod, exch, canc] = super::read_cancel_probe();
            Ok(Some(r::unary_list_i64(
                r::schema_list_i64(),
                &[prod, exch, canc],
            )?))
        },
    );
    s.register_unary("reset_cancel_probe", r::schema_empty(), |_req, _| {
        super::reset_cancel_probe();
        Ok(None)
    });
}

fn format_float(f: f64) -> String {
    let s = format!("{f}");
    if !s.contains('.') && !s.contains('e') && !s.contains('E') && !s.contains("inf") && !s.contains("NaN") {
        format!("{s}.0")
    } else {
        s
    }
}


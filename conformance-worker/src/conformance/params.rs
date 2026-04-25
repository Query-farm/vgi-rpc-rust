//! Typed parameter extractors for stream-method handlers. Unary
//! handlers now derive their extractors via `#[vgi_rpc::service]` —
//! only the few helpers that streams still need imperatively live
//! here.

use arrow_array::{Array, BooleanArray, Float32Array, Float64Array, Int32Array, Int64Array};
use vgi_rpc::{Result, RpcError};

use vgi_rpc::server::Request;

pub fn col<'a>(req: &'a Request, name: &str) -> Result<&'a dyn Array> {
    req.column(name)
        .ok_or_else(|| RpcError::type_error(format!("missing param {name}")))
}

fn as_array<'a, A: Array + 'static>(a: &'a dyn Array, field: &str) -> Result<&'a A> {
    a.as_any()
        .downcast_ref::<A>()
        .ok_or_else(|| RpcError::type_error(format!("{field}: unexpected array type")))
}

pub fn i64_col(req: &Request, name: &str) -> Result<i64> {
    let a = col(req, name)?;
    if let Some(arr) = a.as_any().downcast_ref::<Int64Array>() {
        return Ok(arr.value(0));
    }
    if let Some(arr) = a.as_any().downcast_ref::<Int32Array>() {
        return Ok(arr.value(0) as i64);
    }
    Err(RpcError::type_error(format!("expected int for {name}")))
}

pub fn f64_col(req: &Request, name: &str) -> Result<f64> {
    let a = col(req, name)?;
    if let Some(arr) = a.as_any().downcast_ref::<Float64Array>() {
        return Ok(arr.value(0));
    }
    if let Some(arr) = a.as_any().downcast_ref::<Float32Array>() {
        return Ok(arr.value(0) as f64);
    }
    Err(RpcError::type_error(format!("expected float for {name}")))
}

pub fn bool_col(req: &Request, name: &str) -> Result<bool> {
    let a = as_array::<BooleanArray>(col(req, name)?, name)?;
    Ok(a.value(0))
}

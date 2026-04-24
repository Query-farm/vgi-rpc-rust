//! Extract parameter values from a parsed request batch.

use arrow_array::{
    Array, BinaryArray, BooleanArray, Float32Array, Float64Array, Int32Array, Int64Array,
    ListArray, MapArray, StringArray,
};
use vgi_rpc::{Result, RpcError};

use vgi_rpc::server::Request;

pub fn col<'a>(req: &'a Request, name: &str) -> Result<&'a dyn Array> {
    req.column(name)
        .ok_or_else(|| RpcError::type_error(format!("missing param {name}")))
}

pub fn str_col<'a>(req: &'a Request, name: &str) -> Result<&'a str> {
    let a = col(req, name)?
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| RpcError::type_error(format!("expected string for {name}")))?;
    Ok(a.value(0))
}

pub fn opt_str(req: &Request, name: &str) -> Result<Option<String>> {
    let a = col(req, name)?;
    if a.is_null(0) {
        return Ok(None);
    }
    let s = a
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| RpcError::type_error(format!("expected string for {name}")))?;
    Ok(Some(s.value(0).to_string()))
}

pub fn bytes_col<'a>(req: &'a Request, name: &str) -> Result<&'a [u8]> {
    let a = col(req, name)?
        .as_any()
        .downcast_ref::<BinaryArray>()
        .ok_or_else(|| RpcError::type_error(format!("expected binary for {name}")))?;
    Ok(a.value(0))
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

pub fn opt_i64(req: &Request, name: &str) -> Result<Option<i64>> {
    let a = col(req, name)?;
    if a.is_null(0) {
        return Ok(None);
    }
    Ok(Some(i64_col(req, name)?))
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
    let a = col(req, name)?
        .as_any()
        .downcast_ref::<BooleanArray>()
        .ok_or_else(|| RpcError::type_error(format!("expected bool for {name}")))?;
    Ok(a.value(0))
}

/// Extract a list of strings from a ListArray<Utf8> column at row 0.
pub fn list_str(req: &Request, name: &str) -> Result<Vec<String>> {
    let a = col(req, name)?
        .as_any()
        .downcast_ref::<ListArray>()
        .ok_or_else(|| RpcError::type_error(format!("expected list for {name}")))?;
    let values = a.value(0);
    let sv = values
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| RpcError::type_error(format!("expected list<str> for {name}")))?;
    Ok((0..sv.len()).map(|i| sv.value(i).to_string()).collect())
}

/// Extract a list of lists of i64 from a ListArray<ListArray<Int64>> column at row 0.
pub fn nested_list_i64(req: &Request, name: &str) -> Result<Vec<Vec<i64>>> {
    let outer = col(req, name)?
        .as_any()
        .downcast_ref::<ListArray>()
        .ok_or_else(|| RpcError::type_error(format!("expected list for {name}")))?;
    let inner_list = outer.value(0);
    let inner = inner_list
        .as_any()
        .downcast_ref::<ListArray>()
        .ok_or_else(|| RpcError::type_error(format!("expected list<list<int>> for {name}")))?;
    let mut out = Vec::with_capacity(inner.len());
    for i in 0..inner.len() {
        let iv = inner.value(i);
        let ia = iv
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or_else(|| RpcError::type_error(format!("expected list<list<int>> for {name}")))?;
        out.push((0..ia.len()).map(|j| ia.value(j)).collect());
    }
    Ok(out)
}

/// Extract a map<string, int64> column at row 0.
pub fn map_string_int64(req: &Request, name: &str) -> Result<Vec<(String, i64)>> {
    let a = col(req, name)?
        .as_any()
        .downcast_ref::<MapArray>()
        .ok_or_else(|| RpcError::type_error(format!("expected map for {name}")))?;
    let entry = a.value(0);
    let keys = entry
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| RpcError::type_error(format!("expected map<str, int> for {name}")))?;
    let vals = entry
        .column(1)
        .as_any()
        .downcast_ref::<Int64Array>()
        .ok_or_else(|| RpcError::type_error(format!("expected map<str, int> for {name}")))?;
    let mut out = Vec::with_capacity(keys.len());
    for i in 0..keys.len() {
        out.push((keys.value(i).to_string(), vals.value(i)));
    }
    Ok(out)
}

/// Read a string-valued dictionary-encoded enum column.
pub fn enum_str(req: &Request, name: &str) -> Result<String> {
    use arrow_array::DictionaryArray;
    use arrow_array::types::{Int16Type, Int32Type};
    let a = col(req, name)?;
    if let Some(d) = a.as_any().downcast_ref::<DictionaryArray<Int16Type>>() {
        let key = d.keys().value(0);
        let values = d
            .values()
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| RpcError::type_error("dictionary values not utf8".to_string()))?;
        return Ok(values.value(key as usize).to_string());
    }
    if let Some(d) = a.as_any().downcast_ref::<DictionaryArray<Int32Type>>() {
        let key = d.keys().value(0);
        let values = d
            .values()
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| RpcError::type_error("dictionary values not utf8".to_string()))?;
        return Ok(values.value(key as usize).to_string());
    }
    if let Some(s) = a.as_any().downcast_ref::<StringArray>() {
        return Ok(s.value(0).to_string());
    }
    Err(RpcError::type_error(format!(
        "expected enum dictionary for {name}"
    )))
}

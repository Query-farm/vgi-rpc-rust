//! Helpers that wrap a single scalar return value as a 1-row result batch.

use std::sync::Arc;

use arrow_array::{
    builder::{BinaryBuilder, Int64Builder, ListBuilder, MapBuilder, MapFieldNames, StringBuilder},
    ArrayRef, BinaryArray, BooleanArray, Float32Array, Float64Array, Int32Array, Int64Array,
    RecordBatch, StringArray,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use vgi_rpc::Result;

pub fn schema_result(data_type: DataType, nullable: bool) -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new("result", data_type, nullable)]))
}

pub fn schema_string() -> SchemaRef {
    schema_result(DataType::Utf8, false)
}
pub fn schema_opt_string() -> SchemaRef {
    schema_result(DataType::Utf8, true)
}
pub fn schema_bytes() -> SchemaRef {
    schema_result(DataType::Binary, false)
}
pub fn schema_int64() -> SchemaRef {
    schema_result(DataType::Int64, false)
}
pub fn schema_opt_int64() -> SchemaRef {
    schema_result(DataType::Int64, true)
}
pub fn schema_int32() -> SchemaRef {
    schema_result(DataType::Int32, false)
}
pub fn schema_float64() -> SchemaRef {
    schema_result(DataType::Float64, false)
}
pub fn schema_float32() -> SchemaRef {
    schema_result(DataType::Float32, false)
}
pub fn schema_bool() -> SchemaRef {
    schema_result(DataType::Boolean, false)
}
pub fn schema_list_i64() -> SchemaRef {
    schema_result(
        DataType::List(Arc::new(Field::new("item", DataType::Int64, true))),
        false,
    )
}

pub fn schema_list_str() -> SchemaRef {
    schema_result(
        DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
        false,
    )
}

pub fn schema_nested_list_i64() -> SchemaRef {
    schema_result(
        DataType::List(Arc::new(Field::new(
            "item",
            DataType::List(Arc::new(Field::new("item", DataType::Int64, true))),
            true,
        ))),
        false,
    )
}

pub fn schema_map_str_int64() -> SchemaRef {
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
    schema_result(DataType::Map(Arc::new(entries), false), false)
}

pub fn schema_dict_enum() -> SchemaRef {
    schema_result(
        DataType::Dictionary(Box::new(DataType::Int16), Box::new(DataType::Utf8)),
        false,
    )
}

pub fn schema_binary_dataclass() -> SchemaRef {
    // Serialized ArrowSerializableDataclass: Binary of IPC stream bytes.
    schema_result(DataType::Binary, false)
}

pub fn schema_empty() -> SchemaRef {
    Arc::new(Schema::empty())
}

// --- single-row batch builders -------------------------------------------

pub fn unary_string(schema: SchemaRef, val: &str) -> Result<RecordBatch> {
    let arr: ArrayRef = Arc::new(StringArray::from(vec![val.to_string()]));
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}
pub fn unary_opt_string(schema: SchemaRef, val: Option<&str>) -> Result<RecordBatch> {
    let arr: ArrayRef = Arc::new(StringArray::from(vec![val.map(|s| s.to_string())]));
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}
pub fn unary_bytes(schema: SchemaRef, val: &[u8]) -> Result<RecordBatch> {
    let arr: ArrayRef = Arc::new(BinaryArray::from_vec(vec![val]));
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}
pub fn unary_int64(schema: SchemaRef, val: i64) -> Result<RecordBatch> {
    let arr: ArrayRef = Arc::new(Int64Array::from(vec![val]));
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}
pub fn unary_opt_int64(schema: SchemaRef, val: Option<i64>) -> Result<RecordBatch> {
    let arr: ArrayRef = Arc::new(Int64Array::from(vec![val]));
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}
pub fn unary_int32(schema: SchemaRef, val: i32) -> Result<RecordBatch> {
    let arr: ArrayRef = Arc::new(Int32Array::from(vec![val]));
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}
pub fn unary_float64(schema: SchemaRef, val: f64) -> Result<RecordBatch> {
    let arr: ArrayRef = Arc::new(Float64Array::from(vec![val]));
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}
pub fn unary_float32(schema: SchemaRef, val: f32) -> Result<RecordBatch> {
    let arr: ArrayRef = Arc::new(Float32Array::from(vec![val]));
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}
pub fn unary_bool(schema: SchemaRef, val: bool) -> Result<RecordBatch> {
    let arr: ArrayRef = Arc::new(BooleanArray::from(vec![val]));
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}

pub fn unary_list_i64(schema: SchemaRef, vals: &[i64]) -> Result<RecordBatch> {
    let mut b = ListBuilder::new(Int64Builder::new());
    for v in vals {
        b.values().append_value(*v);
    }
    b.append(true);
    let arr: ArrayRef = Arc::new(b.finish());
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}

pub fn unary_list_str(schema: SchemaRef, vals: &[String]) -> Result<RecordBatch> {
    let mut b = ListBuilder::new(StringBuilder::new());
    for v in vals {
        b.values().append_value(v);
    }
    b.append(true);
    let arr: ArrayRef = Arc::new(b.finish());
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}

pub fn unary_nested_list_i64(schema: SchemaRef, vals: &[Vec<i64>]) -> Result<RecordBatch> {
    let mut b = ListBuilder::new(ListBuilder::new(Int64Builder::new()));
    for inner in vals {
        {
            let inner_b = b.values();
            for v in inner {
                inner_b.values().append_value(*v);
            }
            inner_b.append(true);
        }
    }
    b.append(true);
    let arr: ArrayRef = Arc::new(b.finish());
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}

pub fn unary_map_str_int64(schema: SchemaRef, entries: &[(String, i64)]) -> Result<RecordBatch> {
    let field_names = MapFieldNames {
        entry: "entries".into(),
        key: "keys".into(),
        value: "values".into(),
    };
    let mut b = MapBuilder::new(Some(field_names), StringBuilder::new(), Int64Builder::new());
    for (k, v) in entries {
        b.keys().append_value(k);
        b.values().append_value(*v);
    }
    b.append(true)?;
    let arr: ArrayRef = Arc::new(b.finish());
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}

pub fn unary_enum(schema: SchemaRef, val: &str) -> Result<RecordBatch> {
    use arrow_array::builder::StringDictionaryBuilder;
    use arrow_array::types::Int16Type;
    let mut b = StringDictionaryBuilder::<Int16Type>::new();
    b.append_value(val);
    let arr: ArrayRef = Arc::new(b.finish());
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}

pub fn unary_binary_dataclass(schema: SchemaRef, ipc: Vec<u8>) -> Result<RecordBatch> {
    let mut b = BinaryBuilder::new();
    b.append_value(ipc);
    let arr: ArrayRef = Arc::new(b.finish());
    Ok(RecordBatch::try_new(schema, vec![arr])?)
}

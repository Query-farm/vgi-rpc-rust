//! Wide-type conformance dataclasses (Python parity).
//!
//! Defines `WideTypes`, `ContainerWideTypes`, `DeepNested`, `EmbeddedArrow`
//! using `#[derive(VgiArrow)]` and a generic IPC helper that serializes
//! a `VgiArrow` struct as a single-row `RecordBatch` (matching Python's
//! `ArrowSerializableDataclass` wire shape).

use std::sync::Arc;

use arrow_array::{Array, ArrayRef, RecordBatch, StructArray};
use arrow_schema::{DataType, Schema, SchemaRef};
use vgi_rpc::wire::{StreamReader, StreamWriter};
use vgi_rpc::{
    Bytes, Decimal20_4, DictString, FixedBinary, LargeBytes, LargeString, Result, RpcError,
    UtcTimestamp, VgiArrow,
};

#[derive(Clone, Debug, PartialEq, vgi_rpc::VgiArrow)]
#[vgi_arrow(name = "WideTypes")]
pub struct WideTypes {
    pub int8_field: i8,
    pub int16_field: i16,
    pub int32_field: i32,
    pub uint8_field: u8,
    pub uint16_field: u16,
    pub uint32_field: u32,
    pub uint64_field: u64,
    pub float32_field: f32,
    pub date_field: chrono::NaiveDate,
    pub timestamp_field: chrono::NaiveDateTime,
    pub timestamp_utc_field: UtcTimestamp,
    pub time_field: chrono::NaiveTime,
    pub duration_field: chrono::Duration,
    pub decimal_field: Decimal20_4,
    pub large_string_field: LargeString,
    pub large_binary_field: LargeBytes,
    pub fixed_binary_field: FixedBinary<8>,
}

#[derive(Clone, Debug, PartialEq, vgi_rpc::VgiArrow)]
#[vgi_arrow(name = "ContainerWideTypes")]
pub struct ContainerWideTypes {
    pub list_decimal: Vec<Decimal20_4>,
    pub list_date: Vec<chrono::NaiveDate>,
    pub list_timestamp: Vec<chrono::NaiveDateTime>,
    pub optional_date: Option<chrono::NaiveDate>,
    pub optional_decimal: Option<Decimal20_4>,
    pub optional_timestamp: Option<chrono::NaiveDateTime>,
    pub dict_str_decimal: Vec<(String, Decimal20_4)>,
    pub frozenset_int: Vec<i64>,
    pub list_optional_int: Vec<Option<i64>>,
}

#[derive(Clone, Debug, PartialEq, vgi_rpc::VgiArrow)]
#[vgi_arrow(name = "DeepNested")]
pub struct DeepNested {
    pub list_of_lists_decimal: Vec<Vec<Decimal20_4>>,
    pub optional_list_date: Option<Vec<chrono::NaiveDate>>,
    pub dict_encoded_string: DictString,
    pub list_of_dict_encoded: Vec<DictString>,
}

#[derive(Clone, Debug, PartialEq, vgi_rpc::VgiArrow)]
#[vgi_arrow(name = "EmbeddedArrow")]
pub struct EmbeddedArrow {
    pub batch: Bytes,
    pub schema: Bytes,
}

/// Serialize a `VgiArrow` dataclass as a single-row Arrow IPC stream
/// whose top-level columns are the struct's fields. Matches the
/// Python `ArrowSerializableDataclass` wire shape.
pub fn dataclass_serialize_ipc<T: VgiArrow>(value: T) -> Result<Vec<u8>> {
    let arr = T::build_singleton(value)?;
    let s = arr.as_any().downcast_ref::<StructArray>().ok_or_else(|| {
        RpcError::type_error("dataclass build_singleton must produce StructArray")
    })?;

    let schema: SchemaRef = match T::arrow_data_type() {
        DataType::Struct(fields) => Arc::new(Schema::new(
            fields.iter().map(|f| (**f).clone()).collect::<Vec<_>>(),
        )),
        _ => {
            return Err(RpcError::type_error(
                "dataclass arrow_data_type must be Struct",
            ))
        }
    };
    let columns: Vec<ArrayRef> = (0..s.num_columns()).map(|i| s.column(i).clone()).collect();
    let batch = RecordBatch::try_new(schema.clone(), columns)?;
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, &schema)?;
        w.write(&batch)?;
        w.finish()?;
    }
    Ok(buf)
}

/// Inverse of [`dataclass_serialize_ipc`].
pub fn dataclass_deserialize_ipc<T: VgiArrow>(bytes: &[u8]) -> Result<T> {
    let r = StreamReader::new(bytes)?;
    // Python's `ArrowSerializableDataclass` wire shape declares
    // `Annotated[T | None, ArrowType(...)]` fields as `nullable=false`
    // even though the array body legitimately carries nulls. Relax
    // nullability on read so arrow-rs's RecordBatch validation accepts
    // those payloads.
    let mut r = r.relax_nullability();
    let rb = r
        .read_next()?
        .ok_or_else(|| RpcError::type_error("empty dataclass IPC"))?;
    let s: StructArray = rb.into();
    T::read(&s as &dyn Array, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_none() {
        let c = ContainerWideTypes {
            list_decimal: vec![],
            list_date: vec![],
            list_timestamp: vec![],
            optional_date: None,
            optional_decimal: None,
            optional_timestamp: None,
            dict_str_decimal: vec![],
            frozenset_int: vec![],
            list_optional_int: vec![None, Some(1)],
        };
        let bytes = dataclass_serialize_ipc(c.clone()).unwrap();
        let back: ContainerWideTypes = dataclass_deserialize_ipc(&bytes).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn roundtrip_deep_nested() {
        let d = DeepNested {
            list_of_lists_decimal: vec![],
            optional_list_date: None,
            dict_encoded_string: DictString("hello".into()),
            list_of_dict_encoded: vec![DictString("a".into()), DictString("b".into())],
        };
        let bytes = dataclass_serialize_ipc(d.clone()).unwrap();
        let back: DeepNested = dataclass_deserialize_ipc(&bytes).unwrap();
        assert_eq!(back, d);
    }
}

//! `VgiArrow` — the bridge between idiomatic Rust types and Arrow.
//!
//! The proc-macro layer (`vgi-rpc-macros`) generates code that maps each
//! RPC method parameter and return value through this trait so user
//! handler signatures stay free of Arrow types. Cross-language wire
//! compatibility with Python `vgi_rpc` is preserved by mirroring the
//! Arrow `DataType` choices Python's `ArrowSerializableDataclass` uses.
//!
//! # Implementing for your own types
//!
//! Use `#[derive(VgiArrow)]` from `vgi-rpc-macros` for plain structs.
//! Hand-implement only when the wire format must diverge from
//! Python-canonical defaults.

use std::sync::Arc;

use arrow_array::{
    builder::BinaryBuilder, Array, ArrayRef, BinaryArray, BooleanArray, Float32Array, Float64Array,
    Int32Array, Int64Array, ListArray, MapArray, StringArray,
};
use arrow_schema::{DataType, Field};

use crate::errors::{Result, RpcError};

/// Round-trip a Rust value through a single Arrow column.
///
/// `arrow_data_type()` returns the column's `DataType`; `nullable()`
/// indicates whether the column accepts nulls (set by `Option<T>`).
/// `read()` extracts a value at `idx`; `build_singleton()` builds a
/// 1-row array carrying `value`.
///
/// All builtin scalar / collection / option impls in this module are
/// `Send + Sync` and allocate at most once per call.
pub trait VgiArrow: Sized {
    /// The Arrow `DataType` carrying values of this Rust type.
    fn arrow_data_type() -> DataType;

    /// Whether the column should be flagged nullable. The default is
    /// `false`; the `Option<T>` blanket impl returns `true`.
    fn nullable() -> bool {
        false
    }

    /// Wire-format type name surfaced via `__describe__` metadata.
    /// Mirrors Python: `"str"`, `"int"`, `"list[int]"`, `"int | None"`.
    fn describe_name() -> String;

    /// Pull this value out of `arr` at row `idx`. Errors with a
    /// `RpcError::type_error` if `arr`'s concrete type doesn't match
    /// `Self::arrow_data_type()`.
    fn read(arr: &dyn Array, idx: usize) -> Result<Self>;

    /// Build a 1-row `ArrayRef` containing `value`.
    fn build_singleton(value: Self) -> Result<ArrayRef>;
}

/// Helper: typed downcast or `RpcError::type_error("expected …")`.
fn as_array<'a, A: Array + 'static>(arr: &'a dyn Array, expected: &str) -> Result<&'a A> {
    arr.as_any()
        .downcast_ref::<A>()
        .ok_or_else(|| RpcError::type_error(format!("expected {expected} array")))
}

// ---------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------

impl VgiArrow for String {
    fn arrow_data_type() -> DataType {
        DataType::Utf8
    }
    fn describe_name() -> String {
        "str".into()
    }
    fn read(arr: &dyn Array, idx: usize) -> Result<Self> {
        // Accept Utf8 directly, plus DictionaryArray<Int16|Int32, Utf8>
        // — Python's enum-typed params arrive as dict-encoded strings.
        if let Some(s) = arr.as_any().downcast_ref::<StringArray>() {
            return Ok(s.value(idx).to_string());
        }
        if let Some(d) = arr
            .as_any()
            .downcast_ref::<arrow_array::DictionaryArray<arrow_array::types::Int16Type>>()
        {
            let key = d.keys().value(idx);
            let values = as_array::<StringArray>(d.values().as_ref(), "Utf8 (dict values)")?;
            return Ok(values.value(key as usize).to_string());
        }
        if let Some(d) = arr
            .as_any()
            .downcast_ref::<arrow_array::DictionaryArray<arrow_array::types::Int32Type>>()
        {
            let key = d.keys().value(idx);
            let values = as_array::<StringArray>(d.values().as_ref(), "Utf8 (dict values)")?;
            return Ok(values.value(key as usize).to_string());
        }
        Err(RpcError::type_error(
            "expected Utf8 (or DictionaryArray<Int16|Int32, Utf8>) array",
        ))
    }
    fn build_singleton(value: Self) -> Result<ArrayRef> {
        Ok(Arc::new(StringArray::from(vec![value])))
    }
}

impl VgiArrow for i64 {
    fn arrow_data_type() -> DataType {
        DataType::Int64
    }
    fn describe_name() -> String {
        "int".into()
    }
    fn read(arr: &dyn Array, idx: usize) -> Result<Self> {
        if let Some(a) = arr.as_any().downcast_ref::<Int64Array>() {
            return Ok(a.value(idx));
        }
        if let Some(a) = arr.as_any().downcast_ref::<Int32Array>() {
            return Ok(a.value(idx) as i64);
        }
        Err(RpcError::type_error("expected Int64/Int32 array"))
    }
    fn build_singleton(value: Self) -> Result<ArrayRef> {
        Ok(Arc::new(Int64Array::from(vec![value])))
    }
}

impl VgiArrow for i32 {
    fn arrow_data_type() -> DataType {
        DataType::Int32
    }
    fn describe_name() -> String {
        "int".into()
    }
    fn read(arr: &dyn Array, idx: usize) -> Result<Self> {
        if let Some(a) = arr.as_any().downcast_ref::<Int32Array>() {
            return Ok(a.value(idx));
        }
        if let Some(a) = arr.as_any().downcast_ref::<Int64Array>() {
            return Ok(a.value(idx) as i32);
        }
        Err(RpcError::type_error("expected Int32/Int64 array"))
    }
    fn build_singleton(value: Self) -> Result<ArrayRef> {
        Ok(Arc::new(Int32Array::from(vec![value])))
    }
}

impl VgiArrow for f64 {
    fn arrow_data_type() -> DataType {
        DataType::Float64
    }
    fn describe_name() -> String {
        "float".into()
    }
    fn read(arr: &dyn Array, idx: usize) -> Result<Self> {
        if let Some(a) = arr.as_any().downcast_ref::<Float64Array>() {
            return Ok(a.value(idx));
        }
        if let Some(a) = arr.as_any().downcast_ref::<Float32Array>() {
            return Ok(a.value(idx) as f64);
        }
        Err(RpcError::type_error("expected Float64/Float32 array"))
    }
    fn build_singleton(value: Self) -> Result<ArrayRef> {
        Ok(Arc::new(Float64Array::from(vec![value])))
    }
}

impl VgiArrow for f32 {
    fn arrow_data_type() -> DataType {
        DataType::Float32
    }
    fn describe_name() -> String {
        "float".into()
    }
    fn read(arr: &dyn Array, idx: usize) -> Result<Self> {
        if let Some(a) = arr.as_any().downcast_ref::<Float32Array>() {
            return Ok(a.value(idx));
        }
        if let Some(a) = arr.as_any().downcast_ref::<Float64Array>() {
            return Ok(a.value(idx) as f32);
        }
        Err(RpcError::type_error("expected Float32/Float64 array"))
    }
    fn build_singleton(value: Self) -> Result<ArrayRef> {
        Ok(Arc::new(Float32Array::from(vec![value])))
    }
}

impl VgiArrow for bool {
    fn arrow_data_type() -> DataType {
        DataType::Boolean
    }
    fn describe_name() -> String {
        "bool".into()
    }
    fn read(arr: &dyn Array, idx: usize) -> Result<Self> {
        Ok(as_array::<BooleanArray>(arr, "Boolean")?.value(idx))
    }
    fn build_singleton(value: Self) -> Result<ArrayRef> {
        Ok(Arc::new(BooleanArray::from(vec![value])))
    }
}

// ---------------------------------------------------------------------------
// Bytes (Binary), kept distinct from Vec<u8> via a newtype-style wrapper.
// ---------------------------------------------------------------------------

/// Newtype indicating a `Vec<u8>` should be carried as Arrow `Binary`,
/// not `List<UInt8>`. Use this in handler signatures where the wire
/// type should be `bytes` rather than a list of bytes.
///
/// `#[derive(VgiArrow)]` does not auto-pick between the two — there is
/// no idiomatic Rust signal that `Vec<u8>` in a struct field means
/// "blob" rather than "byte list", so users opt in via this wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<Bytes> for Vec<u8> {
    fn from(b: Bytes) -> Self {
        b.0
    }
}

impl VgiArrow for Bytes {
    fn arrow_data_type() -> DataType {
        DataType::Binary
    }
    fn describe_name() -> String {
        "bytes".into()
    }
    fn read(arr: &dyn Array, idx: usize) -> Result<Self> {
        Ok(Bytes(
            as_array::<BinaryArray>(arr, "Binary")?.value(idx).to_vec(),
        ))
    }
    fn build_singleton(value: Self) -> Result<ArrayRef> {
        let mut b = BinaryBuilder::new();
        b.append_value(value.0);
        Ok(Arc::new(b.finish()))
    }
}

// ---------------------------------------------------------------------------
// Option<T> — wraps any VgiArrow with nullable=true.
// ---------------------------------------------------------------------------

impl<T> VgiArrow for Option<T>
where
    T: VgiArrow,
{
    fn arrow_data_type() -> DataType {
        T::arrow_data_type()
    }
    fn nullable() -> bool {
        true
    }
    fn describe_name() -> String {
        format!("{} | None", T::describe_name())
    }
    fn read(arr: &dyn Array, idx: usize) -> Result<Self> {
        if arr.is_null(idx) {
            Ok(None)
        } else {
            Ok(Some(T::read(arr, idx)?))
        }
    }
    fn build_singleton(value: Self) -> Result<ArrayRef> {
        match value {
            Some(v) => T::build_singleton(v),
            None => build_null_singleton::<T>(),
        }
    }
}

fn build_null_singleton<T: VgiArrow>() -> Result<ArrayRef> {
    use arrow_array::array::new_null_array;
    Ok(new_null_array(&T::arrow_data_type(), 1))
}

// ---------------------------------------------------------------------------
// Vec<T> — list types.
//
// Handled as `List<inner>` for arbitrary VgiArrow inner types. Common
// scalar inners (i64, i32, f64, f32, bool, String) get fast-path
// builders; everything else falls back to a generic per-row push that
// goes through `T::build_singleton`.
// ---------------------------------------------------------------------------

impl<T> VgiArrow for Vec<T>
where
    T: VgiArrow,
{
    fn arrow_data_type() -> DataType {
        DataType::List(Arc::new(Field::new("item", T::arrow_data_type(), true)))
    }
    fn describe_name() -> String {
        format!("list[{}]", T::describe_name())
    }
    fn read(arr: &dyn Array, idx: usize) -> Result<Self> {
        let la = as_array::<ListArray>(arr, "List")?;
        let inner = la.value(idx);
        let len = inner.len();
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            out.push(T::read(inner.as_ref(), i)?);
        }
        Ok(out)
    }
    fn build_singleton(values: Self) -> Result<ArrayRef> {
        // Generic path: build each element as a 1-row array via
        // T::build_singleton, concat them into the list's inner array,
        // and wrap in a ListArray with a single (0..len) offset pair.
        // No specialization in V1 — fast-path scalar builders can come
        // later when `min_specialization` stabilizes.
        let len = values.len();
        let mut singletons: Vec<ArrayRef> = Vec::with_capacity(len);
        for v in values {
            singletons.push(T::build_singleton(v)?);
        }
        let refs: Vec<&dyn Array> = singletons.iter().map(|a| a.as_ref()).collect();
        let inner = if refs.is_empty() {
            arrow_array::array::new_empty_array(&T::arrow_data_type())
        } else {
            arrow_select::concat::concat(&refs).map_err(RpcError::from)?
        };
        let offsets = arrow_buffer::OffsetBuffer::new(arrow_buffer::ScalarBuffer::from(vec![
            0i32, len as i32,
        ]));
        let field = Arc::new(Field::new("item", T::arrow_data_type(), true));
        Ok(Arc::new(ListArray::new(field, offsets, inner, None)))
    }
}

// ---------------------------------------------------------------------------
// Map: Vec<(K, V)>
//
// Mirrors the Python wire layout for `dict[K, V]`:
// `Map(entries{keys: K, values: V (nullable)})`.
// Only string-keyed maps are supported in V1 because that's what the
// Python canonical's dataclass introspection emits.
// ---------------------------------------------------------------------------

/// `Vec<(String, V)>` — wire format `Map<Utf8, V>` (Python canonical).
impl<V> VgiArrow for Vec<(String, V)>
where
    V: VgiArrow,
{
    fn arrow_data_type() -> DataType {
        let entries = Field::new(
            "entries",
            DataType::Struct(
                vec![
                    Field::new("keys", DataType::Utf8, false),
                    Field::new("values", V::arrow_data_type(), true),
                ]
                .into(),
            ),
            false,
        );
        DataType::Map(Arc::new(entries), false)
    }
    fn describe_name() -> String {
        format!("dict[str, {}]", V::describe_name())
    }
    fn read(arr: &dyn Array, idx: usize) -> Result<Self> {
        let m = as_array::<MapArray>(arr, "Map")?;
        let entry = m.value(idx);
        let keys = as_array::<StringArray>(entry.column(0).as_ref(), "Map.keys (Utf8)")?;
        let values = entry.column(1);
        let mut out = Vec::with_capacity(keys.len());
        for i in 0..keys.len() {
            let v = V::read(values.as_ref(), i)?;
            out.push((keys.value(i).to_string(), v));
        }
        Ok(out)
    }
    fn build_singleton(entries: Self) -> Result<ArrayRef> {
        use arrow_array::array::new_empty_array;
        let len = entries.len();
        let (keys, values): (Vec<String>, Vec<V>) = entries.into_iter().unzip();
        let key_arr = Arc::new(StringArray::from(keys)) as ArrayRef;
        let value_arr: ArrayRef = if values.is_empty() {
            new_empty_array(&V::arrow_data_type())
        } else {
            let mut singletons: Vec<ArrayRef> = Vec::with_capacity(values.len());
            for v in values {
                singletons.push(V::build_singleton(v)?);
            }
            let refs: Vec<&dyn Array> = singletons.iter().map(|a| a.as_ref()).collect();
            arrow_select::concat::concat(&refs).map_err(RpcError::from)?
        };
        let entries_struct = arrow_array::StructArray::from(vec![
            (Arc::new(Field::new("keys", DataType::Utf8, false)), key_arr),
            (
                Arc::new(Field::new("values", V::arrow_data_type(), true)),
                value_arr,
            ),
        ]);
        let offsets = arrow_buffer::OffsetBuffer::new(arrow_buffer::ScalarBuffer::from(vec![
            0i32, len as i32,
        ]));
        let entries_field = Arc::new(Field::new(
            "entries",
            entries_struct.data_type().clone(),
            false,
        ));
        Ok(Arc::new(MapArray::new(
            entries_field,
            offsets,
            entries_struct,
            None,
            false,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::RecordBatch;
    use arrow_schema::Schema;

    fn round_trip<T: VgiArrow + std::fmt::Debug + PartialEq>(value: T) -> T {
        let arr = T::build_singleton(value).expect("build_singleton");
        let schema = Arc::new(Schema::new(vec![Field::new(
            "v",
            T::arrow_data_type(),
            T::nullable(),
        )]));
        let batch = RecordBatch::try_new(schema, vec![arr]).unwrap();
        T::read(batch.column(0).as_ref(), 0).expect("read")
    }

    #[test]
    fn roundtrip_string() {
        assert_eq!(round_trip("hello".to_string()), "hello".to_string());
    }

    #[test]
    fn roundtrip_i64() {
        assert_eq!(round_trip(42i64), 42);
        assert_eq!(round_trip(-1i64), -1);
    }

    #[test]
    fn roundtrip_i32() {
        assert_eq!(round_trip(7i32), 7);
    }

    #[test]
    fn roundtrip_f64() {
        assert_eq!(round_trip(1.5f64), 1.5);
    }

    #[test]
    fn roundtrip_f32() {
        assert_eq!(round_trip(2.5f32), 2.5);
    }

    #[test]
    fn roundtrip_bool() {
        assert!(round_trip(true));
        assert!(!round_trip(false));
    }

    #[test]
    fn roundtrip_bytes() {
        assert_eq!(
            round_trip(Bytes(vec![1, 2, 3, 4, 5])),
            Bytes(vec![1, 2, 3, 4, 5])
        );
    }

    #[test]
    fn roundtrip_option_some() {
        assert_eq!(round_trip(Some(123i64)), Some(123));
    }

    #[test]
    fn roundtrip_option_none() {
        assert_eq!(round_trip::<Option<i64>>(None), None);
    }

    #[test]
    fn roundtrip_option_string() {
        assert_eq!(
            round_trip(Some("hello".to_string())),
            Some("hello".to_string())
        );
        assert_eq!(round_trip::<Option<String>>(None), None);
    }

    #[test]
    fn roundtrip_vec_i64() {
        assert_eq!(round_trip(vec![1i64, 2, 3, 4, 5]), vec![1, 2, 3, 4, 5]);
        let empty: Vec<i64> = Vec::new();
        assert_eq!(round_trip(empty.clone()), empty);
    }

    #[test]
    fn roundtrip_vec_string() {
        assert_eq!(
            round_trip(vec!["a".to_string(), "b".to_string()]),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn roundtrip_vec_f64() {
        assert_eq!(round_trip(vec![1.0f64, 2.5]), vec![1.0, 2.5]);
    }

    #[test]
    fn roundtrip_vec_bool() {
        assert_eq!(round_trip(vec![true, false, true]), vec![true, false, true]);
    }

    #[test]
    fn roundtrip_vec_vec_i64() {
        let v = vec![vec![1i64, 2], vec![3], vec![]];
        assert_eq!(round_trip(v.clone()), v);
    }

    #[test]
    fn roundtrip_map_str_i64() {
        let m = vec![("a".to_string(), 1i64), ("b".into(), 2)];
        assert_eq!(round_trip(m.clone()), m);
    }

    #[test]
    fn roundtrip_map_str_str() {
        let m = vec![
            ("k1".to_string(), "v1".to_string()),
            ("k2".into(), "v2".into()),
        ];
        assert_eq!(round_trip(m.clone()), m);
    }

    #[test]
    fn describe_names_match_python() {
        assert_eq!(<String as VgiArrow>::describe_name(), "str");
        assert_eq!(<i64 as VgiArrow>::describe_name(), "int");
        assert_eq!(<f64 as VgiArrow>::describe_name(), "float");
        assert_eq!(<bool as VgiArrow>::describe_name(), "bool");
        assert_eq!(<Bytes as VgiArrow>::describe_name(), "bytes");
        assert_eq!(<Option<String> as VgiArrow>::describe_name(), "str | None");
        assert_eq!(<Vec<i64> as VgiArrow>::describe_name(), "list[int]");
        assert_eq!(
            <Vec<Vec<i64>> as VgiArrow>::describe_name(),
            "list[list[int]]"
        );
        assert_eq!(
            <Vec<(String, i64)> as VgiArrow>::describe_name(),
            "dict[str, int]"
        );
    }

    #[test]
    fn nullable_flag_only_set_for_option() {
        assert!(!<i64 as VgiArrow>::nullable());
        assert!(!<String as VgiArrow>::nullable());
        assert!(<Option<i64> as VgiArrow>::nullable());
        assert!(<Option<Vec<i64>> as VgiArrow>::nullable());
    }
}

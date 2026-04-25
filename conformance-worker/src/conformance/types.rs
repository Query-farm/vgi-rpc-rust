//! Conformance types: Point, BoundingBox, AllTypes, RichHeader, ConformanceHeader.
//!
//! Each implements an `arrow_schema` producer and IPC serialize/deserialize.
//! These mirror the canonical Python classes byte-for-byte on the wire.

use std::sync::Arc;

use arrow_array::{
    builder::{Int64Builder, StringBuilder},
    Array, ArrayRef, BinaryArray, BooleanArray, Float32Array, Float64Array, Int32Array, Int64Array,
    ListArray, MapArray, RecordBatch, StringArray, StructArray,
};
use arrow_schema::{DataType, Field, Fields, Schema, SchemaRef};
use vgi_rpc::wire::{StreamReader, StreamWriter};
use vgi_rpc::{Result, RpcError};

/// Downcast `a` to concrete Arrow array type `A`, returning a typed
/// `TypeError` naming the offending field instead of panicking on a
/// malformed batch.
fn as_array<'a, A: Array + 'static>(a: &'a dyn Array, field: &str) -> Result<&'a A> {
    a.as_any()
        .downcast_ref::<A>()
        .ok_or_else(|| RpcError::type_error(format!("{field}: unexpected array type")))
}

// ---------------------------------------------------------------------------
// Point
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

pub fn point_fields() -> Fields {
    vec![
        Field::new("x", DataType::Float64, false),
        Field::new("y", DataType::Float64, false),
    ]
    .into()
}
pub fn point_schema() -> SchemaRef {
    Arc::new(Schema::new(point_fields()))
}

impl Point {
    pub fn serialize_ipc(&self) -> Result<Vec<u8>> {
        let schema = point_schema();
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Float64Array::from(vec![self.x])) as ArrayRef,
                Arc::new(Float64Array::from(vec![self.y])) as ArrayRef,
            ],
        )?;
        let mut buf = Vec::new();
        {
            let mut w = StreamWriter::new(&mut buf, &schema)?;
            w.write(&batch, None)?;
            w.finish()?;
        }
        Ok(buf)
    }

    pub fn deserialize_ipc(bytes: &[u8]) -> Result<Self> {
        let mut r = StreamReader::new(bytes)?;
        let rb = r
            .read_next()?
            .ok_or_else(|| RpcError::type_error("empty Point IPC stream"))?;
        let batch = rb.batch;
        let schema = batch.schema();
        let x_idx = schema
            .index_of("x")
            .map_err(|_| RpcError::type_error("Point IPC missing 'x'"))?;
        let y_idx = schema
            .index_of("y")
            .map_err(|_| RpcError::type_error("Point IPC missing 'y'"))?;
        let x = batch
            .column(x_idx)
            .as_any()
            .downcast_ref::<Float64Array>()
            .ok_or_else(|| RpcError::type_error("Point.x not f64"))?
            .value(0);
        let y = batch
            .column(y_idx)
            .as_any()
            .downcast_ref::<Float64Array>()
            .ok_or_else(|| RpcError::type_error("Point.y not f64"))?
            .value(0);
        Ok(Point { x, y })
    }
}

// ---------------------------------------------------------------------------
// BoundingBox
// ---------------------------------------------------------------------------

pub fn bounding_box_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("top_left", DataType::Struct(point_fields()), false),
        Field::new("bottom_right", DataType::Struct(point_fields()), false),
        Field::new("label", DataType::Utf8, false),
    ]))
}

// ---------------------------------------------------------------------------
// ConformanceHeader
// ---------------------------------------------------------------------------

pub fn conformance_header_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("total_expected", DataType::Int64, false),
        Field::new("description", DataType::Utf8, false),
    ]))
}

pub fn build_conformance_header_batch(total: i64, description: &str) -> Result<RecordBatch> {
    let schema = conformance_header_schema();
    let arrs: Vec<ArrayRef> = vec![
        Arc::new(Int64Array::from(vec![total])),
        Arc::new(StringArray::from(vec![description.to_string()])),
    ];
    Ok(RecordBatch::try_new(schema, arrs)?)
}

// ---------------------------------------------------------------------------
// AllTypes / RichHeader — share the same field layout
// ---------------------------------------------------------------------------

fn dict_enum_type() -> DataType {
    DataType::Dictionary(Box::new(DataType::Int16), Box::new(DataType::Utf8))
}

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

fn map_str_str_type() -> DataType {
    let entries = Field::new(
        "entries",
        DataType::Struct(
            vec![
                Field::new("keys", DataType::Utf8, false),
                Field::new("values", DataType::Utf8, true),
            ]
            .into(),
        ),
        false,
    );
    DataType::Map(Arc::new(entries), false)
}

fn list_int_type() -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Int64, true)))
}
fn list_str_type() -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Utf8, true)))
}
fn list_point_type() -> DataType {
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(point_fields()),
        true,
    )))
}
fn nested_list_int_type() -> DataType {
    DataType::List(Arc::new(Field::new("item", list_int_type(), true)))
}

/// Schema for both AllTypes and RichHeader (they are identical in fields).
pub fn all_types_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("str_field", DataType::Utf8, false),
        Field::new("bytes_field", DataType::Binary, false),
        Field::new("int_field", DataType::Int64, false),
        Field::new("float_field", DataType::Float64, false),
        Field::new("bool_field", DataType::Boolean, false),
        Field::new("list_of_int", list_int_type(), false),
        Field::new("list_of_str", list_str_type(), false),
        Field::new("dict_field", map_str_i64_type(), false),
        Field::new("enum_field", dict_enum_type(), false),
        Field::new("nested_point", DataType::Struct(point_fields()), false),
        Field::new("optional_str", DataType::Utf8, true),
        Field::new("optional_int", DataType::Int64, true),
        Field::new("optional_nested", DataType::Struct(point_fields()), true),
        Field::new("list_of_nested", list_point_type(), false),
        Field::new("annotated_int32", DataType::Int32, false),
        Field::new("annotated_float32", DataType::Float32, false),
        Field::new("nested_list", nested_list_int_type(), false),
        Field::new("dict_str_str", map_str_str_type(), false),
    ]))
}

/// Plain-data representation, used as both input and output for dataclass-echo.
#[derive(Clone, Debug)]
pub struct AllTypes {
    pub str_field: String,
    pub bytes_field: Vec<u8>,
    pub int_field: i64,
    pub float_field: f64,
    pub bool_field: bool,
    pub list_of_int: Vec<i64>,
    pub list_of_str: Vec<String>,
    pub dict_field: Vec<(String, i64)>,
    pub enum_field: String,
    pub nested_point: Point,
    pub optional_str: Option<String>,
    pub optional_int: Option<i64>,
    pub optional_nested: Option<Point>,
    pub list_of_nested: Vec<Point>,
    pub nested_list: Vec<Vec<i64>>,
    pub annotated_int32: i32,
    pub annotated_float32: f32,
    pub dict_str_str: Vec<(String, String)>,
}

impl AllTypes {
    pub fn to_record_batch(&self) -> Result<RecordBatch> {
        use arrow_array::builder::{
            ListBuilder, MapBuilder, MapFieldNames, StringDictionaryBuilder,
        };
        use arrow_array::types::Int16Type;

        let schema = all_types_schema();
        let mut arrs: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());

        arrs.push(Arc::new(StringArray::from(vec![self.str_field.clone()])));
        arrs.push(Arc::new(BinaryArray::from_vec(vec![&self.bytes_field])));
        arrs.push(Arc::new(Int64Array::from(vec![self.int_field])));
        arrs.push(Arc::new(Float64Array::from(vec![self.float_field])));
        arrs.push(Arc::new(BooleanArray::from(vec![self.bool_field])));

        // list_of_int
        let mut lb = ListBuilder::new(Int64Builder::new());
        for v in &self.list_of_int {
            lb.values().append_value(*v);
        }
        lb.append(true);
        arrs.push(Arc::new(lb.finish()));

        // list_of_str
        let mut lb = ListBuilder::new(StringBuilder::new());
        for v in &self.list_of_str {
            lb.values().append_value(v);
        }
        lb.append(true);
        arrs.push(Arc::new(lb.finish()));

        // dict_field
        let mut mb = MapBuilder::new(
            Some(MapFieldNames {
                entry: "entries".into(),
                key: "keys".into(),
                value: "values".into(),
            }),
            StringBuilder::new(),
            Int64Builder::new(),
        );
        for (k, v) in &self.dict_field {
            mb.keys().append_value(k);
            mb.values().append_value(*v);
        }
        mb.append(true)?;
        arrs.push(Arc::new(mb.finish()));

        // enum
        let mut db = StringDictionaryBuilder::<Int16Type>::new();
        db.append_value(&self.enum_field);
        arrs.push(Arc::new(db.finish()));

        // nested_point
        arrs.push(Arc::new(struct_from_point(&self.nested_point)?));

        // optional_str / optional_int
        arrs.push(Arc::new(StringArray::from(vec![self.optional_str.clone()])));
        arrs.push(Arc::new(Int64Array::from(vec![self.optional_int])));

        // optional_nested
        arrs.push(Arc::new(struct_from_optional_point(
            self.optional_nested.as_ref(),
        )?));

        // list_of_nested
        arrs.push(Arc::new(list_of_points(&self.list_of_nested)?));

        // annotated_int32 / annotated_float32
        arrs.push(Arc::new(Int32Array::from(vec![self.annotated_int32])));
        arrs.push(Arc::new(Float32Array::from(vec![self.annotated_float32])));

        // nested_list
        let mut lb = ListBuilder::new(ListBuilder::new(Int64Builder::new()));
        for inner in &self.nested_list {
            {
                let ib = lb.values();
                for v in inner {
                    ib.values().append_value(*v);
                }
                ib.append(true);
            }
        }
        lb.append(true);
        arrs.push(Arc::new(lb.finish()));

        // dict_str_str
        let mut mb = MapBuilder::new(
            Some(MapFieldNames {
                entry: "entries".into(),
                key: "keys".into(),
                value: "values".into(),
            }),
            StringBuilder::new(),
            StringBuilder::new(),
        );
        for (k, v) in &self.dict_str_str {
            mb.keys().append_value(k);
            mb.values().append_value(v);
        }
        mb.append(true)?;
        arrs.push(Arc::new(mb.finish()));

        Ok(RecordBatch::try_new(schema, arrs)?)
    }

    pub fn serialize_ipc(&self) -> Result<Vec<u8>> {
        let batch = self.to_record_batch()?;
        let mut buf = Vec::new();
        {
            let mut w = StreamWriter::new(&mut buf, &all_types_schema())?;
            w.write(&batch, None)?;
            w.finish()?;
        }
        Ok(buf)
    }

    pub fn deserialize_ipc(bytes: &[u8]) -> Result<Self> {
        let mut r = StreamReader::new(bytes)?;
        let rb = r
            .read_next()?
            .ok_or_else(|| RpcError::type_error("empty AllTypes IPC"))?;
        let batch = rb.batch;
        AllTypes::from_record_batch(&batch)
    }

    pub fn from_record_batch(batch: &RecordBatch) -> Result<Self> {
        use arrow_array::types::Int16Type;
        use arrow_array::DictionaryArray;

        let schema = batch.schema();
        let col = |name: &str| -> Result<&dyn Array> {
            let idx = schema
                .index_of(name)
                .map_err(|_| RpcError::type_error(format!("AllTypes missing {name}")))?;
            Ok(batch.column(idx).as_ref())
        };

        let str_field = as_array::<StringArray>(col("str_field")?, "str_field")?
            .value(0)
            .to_string();
        let bytes_field = as_array::<BinaryArray>(col("bytes_field")?, "bytes_field")?
            .value(0)
            .to_vec();
        let int_field = as_array::<Int64Array>(col("int_field")?, "int_field")?.value(0);
        let float_field = as_array::<Float64Array>(col("float_field")?, "float_field")?.value(0);
        let bool_field = as_array::<BooleanArray>(col("bool_field")?, "bool_field")?.value(0);

        let list_of_int = {
            let la = as_array::<ListArray>(col("list_of_int")?, "list_of_int")?;
            let vals = la.value(0);
            let a = as_array::<Int64Array>(vals.as_ref(), "list_of_int[i]")?;
            (0..a.len()).map(|i| a.value(i)).collect()
        };

        let list_of_str = {
            let la = as_array::<ListArray>(col("list_of_str")?, "list_of_str")?;
            let vals = la.value(0);
            let a = as_array::<StringArray>(vals.as_ref(), "list_of_str[i]")?;
            (0..a.len()).map(|i| a.value(i).to_string()).collect()
        };

        let dict_field = {
            let ma = as_array::<MapArray>(col("dict_field")?, "dict_field")?;
            let entry = ma.value(0);
            let keys = as_array::<StringArray>(entry.column(0).as_ref(), "dict_field.keys")?;
            let vals = as_array::<Int64Array>(entry.column(1).as_ref(), "dict_field.values")?;
            (0..keys.len())
                .map(|i| (keys.value(i).to_string(), vals.value(i)))
                .collect()
        };

        let enum_field = {
            let ea = col("enum_field")?;
            if let Some(d) = ea.as_any().downcast_ref::<DictionaryArray<Int16Type>>() {
                let key = d.keys().value(0);
                let values =
                    as_array::<StringArray>(d.values().as_ref(), "enum_field.dict_values")?;
                values.value(key as usize).to_string()
            } else if let Some(s) = ea.as_any().downcast_ref::<StringArray>() {
                s.value(0).to_string()
            } else {
                return Err(RpcError::type_error("enum_field not dict/string"));
            }
        };

        let nested_point = point_from_struct(
            as_array::<StructArray>(col("nested_point")?, "nested_point")?,
            0,
        )?;

        let optional_str = {
            let a = as_array::<StringArray>(col("optional_str")?, "optional_str")?;
            if a.is_null(0) {
                None
            } else {
                Some(a.value(0).to_string())
            }
        };
        let optional_int = {
            let a = as_array::<Int64Array>(col("optional_int")?, "optional_int")?;
            if a.is_null(0) {
                None
            } else {
                Some(a.value(0))
            }
        };
        let optional_nested = {
            let s = as_array::<StructArray>(col("optional_nested")?, "optional_nested")?;
            if s.is_null(0) {
                None
            } else {
                Some(point_from_struct(s, 0)?)
            }
        };

        let list_of_nested = {
            let la = as_array::<ListArray>(col("list_of_nested")?, "list_of_nested")?;
            let vals = la.value(0);
            let sa = as_array::<StructArray>(vals.as_ref(), "list_of_nested[i]")?;
            (0..sa.len())
                .map(|i| point_from_struct(sa, i))
                .collect::<Result<_>>()?
        };

        let annotated_int32 =
            as_array::<Int32Array>(col("annotated_int32")?, "annotated_int32")?.value(0);
        let annotated_float32 =
            as_array::<Float32Array>(col("annotated_float32")?, "annotated_float32")?.value(0);

        let nested_list = {
            let la = as_array::<ListArray>(col("nested_list")?, "nested_list")?;
            let vals = la.value(0);
            let ll = as_array::<ListArray>(vals.as_ref(), "nested_list[i]")?;
            (0..ll.len())
                .map(|i| {
                    let iv = ll.value(i);
                    let ia = as_array::<Int64Array>(iv.as_ref(), "nested_list[i][j]")?;
                    Ok((0..ia.len()).map(|j| ia.value(j)).collect())
                })
                .collect::<Result<Vec<Vec<i64>>>>()?
        };

        let dict_str_str = {
            let ma = as_array::<MapArray>(col("dict_str_str")?, "dict_str_str")?;
            let entry = ma.value(0);
            let keys = as_array::<StringArray>(entry.column(0).as_ref(), "dict_str_str.keys")?;
            let vals = as_array::<StringArray>(entry.column(1).as_ref(), "dict_str_str.values")?;
            (0..keys.len())
                .map(|i| (keys.value(i).to_string(), vals.value(i).to_string()))
                .collect()
        };

        Ok(AllTypes {
            str_field,
            bytes_field,
            int_field,
            float_field,
            bool_field,
            list_of_int,
            list_of_str,
            dict_field,
            enum_field,
            nested_point,
            optional_str,
            optional_int,
            optional_nested,
            list_of_nested,
            annotated_int32,
            annotated_float32,
            nested_list,
            dict_str_str,
        })
    }
}

fn struct_from_point(p: &Point) -> Result<StructArray> {
    let fields = point_fields();
    let x: ArrayRef = Arc::new(Float64Array::from(vec![p.x]));
    let y: ArrayRef = Arc::new(Float64Array::from(vec![p.y]));
    let cols: Vec<(Arc<Field>, ArrayRef)> = vec![(fields[0].clone(), x), (fields[1].clone(), y)];
    Ok(StructArray::from(cols))
}

fn struct_from_optional_point(p: Option<&Point>) -> Result<StructArray> {
    use arrow_buffer::NullBuffer;
    let fields = point_fields();
    match p {
        Some(pt) => Ok(struct_from_point(pt)?),
        None => {
            let x: ArrayRef = Arc::new(Float64Array::from(vec![Some(0.0)]));
            let y: ArrayRef = Arc::new(Float64Array::from(vec![Some(0.0)]));
            let nulls = NullBuffer::from(vec![false]);
            let cols: Vec<(Arc<Field>, ArrayRef)> =
                vec![(fields[0].clone(), x), (fields[1].clone(), y)];
            Ok(StructArray::try_new(
                fields,
                cols.into_iter().map(|(_, a)| a).collect(),
                Some(nulls),
            )?)
        }
    }
}

fn list_of_points(pts: &[Point]) -> Result<ListArray> {
    // We build the struct children manually because StructBuilder helpers
    // for externally-typed fields require care. Use low-level construction.
    let mut xs = Vec::with_capacity(pts.len());
    let mut ys = Vec::with_capacity(pts.len());
    for p in pts {
        xs.push(p.x);
        ys.push(p.y);
    }
    let fields = point_fields();
    let x_arr: ArrayRef = Arc::new(Float64Array::from(xs));
    let y_arr: ArrayRef = Arc::new(Float64Array::from(ys));
    let struct_arr = StructArray::try_new(fields.clone(), vec![x_arr, y_arr], None)?;
    let offsets = arrow_buffer::OffsetBuffer::new(arrow_buffer::ScalarBuffer::from(vec![
        0i32,
        pts.len() as i32,
    ]));
    let field = Arc::new(Field::new("item", DataType::Struct(fields), true));
    Ok(ListArray::new(field, offsets, Arc::new(struct_arr), None))
}

fn point_from_struct(s: &StructArray, i: usize) -> Result<Point> {
    let x = s
        .column_by_name("x")
        .ok_or_else(|| RpcError::type_error("struct missing x"))?
        .as_any()
        .downcast_ref::<Float64Array>()
        .ok_or_else(|| RpcError::type_error("struct.x not f64"))?
        .value(i);
    let y = s
        .column_by_name("y")
        .ok_or_else(|| RpcError::type_error("struct missing y"))?
        .as_any()
        .downcast_ref::<Float64Array>()
        .ok_or_else(|| RpcError::type_error("struct.y not f64"))?
        .value(i);
    Ok(Point { x, y })
}

// ---------------------------------------------------------------------------
// RichHeader builder (maps 1:1 to AllTypes but seeded deterministically)
// ---------------------------------------------------------------------------

const STATUS_CYCLE: [&str; 3] = ["pending", "active", "closed"];

pub fn build_rich_header(seed: i64) -> AllTypes {
    let optional_str = if seed % 2 == 0 {
        Some(format!("opt-{seed}"))
    } else {
        None
    };
    let optional_int = if seed % 2 == 1 { Some(seed * 3) } else { None };
    let optional_nested = if seed.rem_euclid(3) == 0 {
        Some(Point {
            x: seed as f64,
            y: 0.0,
        })
    } else {
        None
    };
    AllTypes {
        str_field: format!("seed-{seed}"),
        bytes_field: vec![
            (seed.rem_euclid(256)) as u8,
            ((seed + 1).rem_euclid(256)) as u8,
            ((seed + 2).rem_euclid(256)) as u8,
        ],
        int_field: seed * 7,
        float_field: (seed as f64) * 1.5,
        bool_field: seed % 2 == 0,
        list_of_int: vec![seed, seed + 1, seed + 2],
        list_of_str: vec![format!("item-{seed}"), format!("item-{}", seed + 1)],
        dict_field: vec![("a".into(), seed), ("b".into(), seed + 1)],
        enum_field: STATUS_CYCLE[(seed.rem_euclid(3)) as usize].to_string(),
        nested_point: Point {
            x: seed as f64,
            y: (seed * 2) as f64,
        },
        optional_str,
        optional_int,
        optional_nested,
        list_of_nested: vec![Point {
            x: seed as f64,
            y: (seed + 1) as f64,
        }],
        nested_list: vec![vec![seed, seed + 1], vec![seed + 2]],
        annotated_int32: (seed.rem_euclid(1000)) as i32,
        annotated_float32: (seed as f32) / 3.0,
        dict_str_str: vec![("key".into(), format!("val-{seed}"))],
    }
}

// ---------------------------------------------------------------------------
// Dynamic-schema helpers
// ---------------------------------------------------------------------------

pub fn build_dynamic_schema(include_strings: bool, include_floats: bool) -> SchemaRef {
    let mut fields: Vec<Field> = vec![Field::new("index", DataType::Int64, true)];
    if include_strings {
        fields.push(Field::new("label", DataType::Utf8, true));
    }
    if include_floats {
        fields.push(Field::new("score", DataType::Float64, true));
    }
    Arc::new(Schema::new(fields))
}

/// Build a BoundingBox record batch (for echo_bounding_box).
pub fn bounding_box_batch(top: &Point, bot: &Point, label: &str) -> Result<RecordBatch> {
    let schema = bounding_box_schema();
    let tl = struct_from_point(top)?;
    let br = struct_from_point(bot)?;
    let arrs: Vec<ArrayRef> = vec![
        Arc::new(tl),
        Arc::new(br),
        Arc::new(StringArray::from(vec![label.to_string()])),
    ];
    Ok(RecordBatch::try_new(schema, arrs)?)
}

pub fn bounding_box_from_batch(batch: &RecordBatch) -> Result<(Point, Point, String)> {
    let schema = batch.schema();
    let tl = batch
        .column(schema.index_of("top_left")?)
        .as_any()
        .downcast_ref::<StructArray>()
        .ok_or_else(|| RpcError::type_error("top_left not struct"))?;
    let br = batch
        .column(schema.index_of("bottom_right")?)
        .as_any()
        .downcast_ref::<StructArray>()
        .ok_or_else(|| RpcError::type_error("bottom_right not struct"))?;
    let label = batch
        .column(schema.index_of("label")?)
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| RpcError::type_error("label not utf8"))?
        .value(0)
        .to_string();
    Ok((point_from_struct(tl, 0)?, point_from_struct(br, 0)?, label))
}

pub fn serialize_bounding_box_ipc(top: &Point, bot: &Point, label: &str) -> Result<Vec<u8>> {
    let schema = bounding_box_schema();
    let batch = bounding_box_batch(top, bot, label)?;
    let mut buf = Vec::new();
    {
        let mut w = StreamWriter::new(&mut buf, &schema)?;
        w.write(&batch, None)?;
        w.finish()?;
    }
    Ok(buf)
}

pub fn deserialize_bounding_box_ipc(bytes: &[u8]) -> Result<(Point, Point, String)> {
    let mut r = StreamReader::new(bytes)?;
    let rb = r
        .read_next()?
        .ok_or_else(|| RpcError::type_error("empty BoundingBox IPC"))?;
    bounding_box_from_batch(&rb.batch)
}

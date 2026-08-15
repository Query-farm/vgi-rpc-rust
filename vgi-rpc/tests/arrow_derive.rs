//! Round-trip tests for `#[derive(VgiArrow)]`.
//!
//! Covers a flat struct, a nested struct, a struct with optional + list +
//!   map fields, and the 18-field `AllTypes` shape that mirrors the
//!   Python conformance dataclass.

use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_schema::{DataType, Field, Schema};
use vgi_rpc::{Bytes, VgiArrow};

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

#[derive(VgiArrow, Debug, PartialEq, Clone)]
#[vgi_arrow(name = "Point")]
struct Point {
    x: f64,
    y: f64,
}

#[test]
fn point_roundtrip() {
    let p = Point { x: 1.5, y: 2.5 };
    let out = round_trip(Point { x: 1.5, y: 2.5 });
    assert_eq!(out, p);
}

#[test]
fn point_describe_name_uses_attribute() {
    assert_eq!(<Point as VgiArrow>::describe_name(), "Point");
}

#[test]
fn point_data_type_is_struct_of_two_f64s() {
    use arrow_schema::DataType;
    let dt = <Point as VgiArrow>::arrow_data_type();
    match dt {
        DataType::Struct(fields) => {
            assert_eq!(fields.len(), 2);
            assert_eq!(fields[0].name(), "x");
            assert_eq!(fields[0].data_type(), &DataType::Float64);
            assert_eq!(fields[1].name(), "y");
            assert_eq!(fields[1].data_type(), &DataType::Float64);
        }
        other => panic!("expected Struct, got {other:?}"),
    }
}

#[derive(VgiArrow, Debug, PartialEq)]
struct BoundingBox {
    top_left: Point,
    bottom_right: Point,
    label: String,
}

#[test]
fn bounding_box_nested_struct_roundtrip() {
    let bb = BoundingBox {
        top_left: Point { x: 0.0, y: 0.0 },
        bottom_right: Point { x: 10.0, y: 20.0 },
        label: "region-a".into(),
    };
    let cloned = BoundingBox {
        top_left: Point { x: 0.0, y: 0.0 },
        bottom_right: Point { x: 10.0, y: 20.0 },
        label: "region-a".into(),
    };
    assert_eq!(round_trip(bb), cloned);
}

#[test]
fn bounding_box_describe_name_defaults_to_struct_ident() {
    assert_eq!(<BoundingBox as VgiArrow>::describe_name(), "BoundingBox");
}

#[derive(VgiArrow, Debug, PartialEq)]
struct WithOptionAndList {
    name: String,
    maybe_count: Option<i64>,
    tags: Vec<String>,
    coords: Vec<Point>,
    extras: Vec<(String, i64)>,
}

#[test]
fn struct_with_options_lists_and_maps_roundtrips() {
    let v = WithOptionAndList {
        name: "row".into(),
        maybe_count: Some(7),
        tags: vec!["a".into(), "b".into()],
        coords: vec![Point { x: 1.0, y: 2.0 }, Point { x: 3.0, y: 4.0 }],
        extras: vec![("k1".into(), 1), ("k2".into(), 2)],
    };
    let cloned = WithOptionAndList {
        name: "row".into(),
        maybe_count: Some(7),
        tags: vec!["a".into(), "b".into()],
        coords: vec![Point { x: 1.0, y: 2.0 }, Point { x: 3.0, y: 4.0 }],
        extras: vec![("k1".into(), 1), ("k2".into(), 2)],
    };
    assert_eq!(round_trip(v), cloned);
}

#[test]
fn struct_with_none_option_field() {
    let v = WithOptionAndList {
        name: "no-count".into(),
        maybe_count: None,
        tags: vec![],
        coords: vec![],
        extras: vec![],
    };
    let cloned = WithOptionAndList {
        name: "no-count".into(),
        maybe_count: None,
        tags: vec![],
        coords: vec![],
        extras: vec![],
    };
    assert_eq!(round_trip(v), cloned);
}

// 18-field shape mirroring conformance-worker/src/conformance/types.rs::AllTypes.
// Excludes the dictionary-encoded enum field (V2) and the bytes_field
// uses the `Bytes` newtype.
#[derive(VgiArrow, Debug, PartialEq, Clone)]
struct AllTypes {
    str_field: String,
    bytes_field: Bytes,
    int_field: i64,
    float_field: f64,
    bool_field: bool,
    list_of_int: Vec<i64>,
    list_of_str: Vec<String>,
    dict_field: Vec<(String, i64)>,
    nested_point: Point,
    optional_str: Option<String>,
    optional_int: Option<i64>,
    optional_nested: Option<Point>,
    list_of_nested: Vec<Point>,
    annotated_int32: i32,
    annotated_float32: f32,
    nested_list: Vec<Vec<i64>>,
    dict_str_str: Vec<(String, String)>,
}

#[test]
fn all_types_roundtrip() {
    let v = AllTypes {
        str_field: "hello".into(),
        bytes_field: Bytes(vec![1, 2, 3, 4]),
        int_field: 42,
        float_field: 1.5,
        bool_field: true,
        list_of_int: vec![1, 2, 3],
        list_of_str: vec!["a".into(), "b".into()],
        dict_field: vec![("k1".into(), 10), ("k2".into(), 20)],
        nested_point: Point { x: 1.0, y: 2.0 },
        optional_str: Some("set".into()),
        optional_int: None,
        optional_nested: Some(Point { x: 5.0, y: 5.0 }),
        list_of_nested: vec![Point { x: 0.0, y: 1.0 }, Point { x: 2.0, y: 3.0 }],
        annotated_int32: 7,
        annotated_float32: 2.5,
        nested_list: vec![vec![1, 2], vec![3], vec![]],
        dict_str_str: vec![("a".into(), "1".into()), ("b".into(), "2".into())],
    };
    assert_eq!(round_trip(v.clone()), v);
}

// ---------------------------------------------------------------------------
// Raw identifiers
// ---------------------------------------------------------------------------

/// A field whose wire name collides with a Rust keyword.
///
/// The VGI protocol has several of these — `catalog_schema_contents_functions`
/// and friends carry a `type` column selecting which kind to list — so the
/// generated params structs must spell them `r#type`. `Ident::to_string()`
/// keeps the `r#`, which would put a column literally named `"r#type"` on the
/// wire and make every such request unreadable by a Python or C++ peer.
#[derive(VgiArrow, Debug, PartialEq, Clone)]
struct RawIdentFields {
    r#type: String,
    r#match: i64,
    normal: bool,
}

#[test]
fn raw_identifiers_keep_their_protocol_spelling() {
    let DataType::Struct(fields) = RawIdentFields::arrow_data_type() else {
        panic!("expected a struct type");
    };
    let names: Vec<&str> = fields.iter().map(|f| f.name().as_str()).collect();
    assert_eq!(
        names,
        vec!["type", "match", "normal"],
        "raw identifiers must lose their `r#` prefix in the Arrow column name",
    );
}

#[test]
fn raw_identifier_struct_round_trips() {
    let v = RawIdentFields {
        r#type: "scalar".into(),
        r#match: 7,
        normal: true,
    };
    assert_eq!(round_trip(v.clone()), v);
}

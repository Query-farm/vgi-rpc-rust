//! Tests for `#[derive(StreamState)]`.

use serde::{Deserialize, Serialize};
use vgi_rpc::stream_codec::StreamStateCodec;
use vgi_rpc::StreamState;

#[derive(StreamState, Serialize, Deserialize, Debug, PartialEq)]
struct Counter {
    total: i64,
    cur: i64,
}

#[test]
fn counter_roundtrip_via_derive() {
    let original = Counter { total: 10, cur: 3 };
    let bytes = original.encode().unwrap();
    let recovered = Counter::decode(&bytes).unwrap();
    assert_eq!(recovered, Counter { total: 10, cur: 3 });
}

#[test]
fn counter_decode_rejects_garbage() {
    assert!(Counter::decode(&[0xff, 0xff, 0xff]).is_err());
}

#[derive(StreamState, Serialize, Deserialize, Debug)]
#[stream_state(rebuild = "rebuild_dyn")]
struct DynState {
    cur: i64,
    include_floats: bool,
    #[serde(skip, default)]
    schema_label: String,
}

fn rebuild_dyn(s: &mut DynState) {
    s.schema_label = if s.include_floats {
        "with-floats".into()
    } else {
        "no-floats".into()
    };
}

#[test]
fn rebuild_runs_after_decode() {
    let original = DynState {
        cur: 5,
        include_floats: true,
        schema_label: "before".into(),
    };
    let bytes = original.encode().unwrap();
    let recovered = DynState::decode(&bytes).unwrap();
    assert_eq!(recovered.cur, 5);
    assert!(recovered.include_floats);
    assert_eq!(recovered.schema_label, "with-floats");
}

#[test]
fn rebuild_runs_with_alternate_branch() {
    let original = DynState {
        cur: 9,
        include_floats: false,
        schema_label: String::new(),
    };
    let bytes = original.encode().unwrap();
    let recovered = DynState::decode(&bytes).unwrap();
    assert_eq!(recovered.schema_label, "no-floats");
}

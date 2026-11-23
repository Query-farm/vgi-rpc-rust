//! `StateRef`, the object cache and argument references (protocol 3.4,
//! `STATE_REF_V1.md` §15). Mirrors the reference's `state_ref_exchange`,
//! `object_cache_stats`, `object_cache_age` and `resolve_argument_ref`.

use std::sync::Arc;

use arrow_array::{Array, ArrayRef, BinaryArray, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vgi_rpc::{
    service,
    stream::{ExchangeState, OutputCollector},
    stream_codec::{bincode_decode, bincode_encode, StreamStateCodec},
    Bytes, CallContext, Result, RpcServer, StateRef,
};

use super::wide_types::dataclass_serialize_ipc;

/// The deterministic payload every port builds (`state_ref_payload`):
/// compressible = the unit `"vgi-rpc StateRef conformance {seed} "` repeated
/// and truncated; incompressible = `SHA-256(seed || u64le(i))` blocks
/// concatenated and truncated.
pub fn state_ref_payload(size: i64, compressible: bool, seed: &str) -> Vec<u8> {
    if size <= 0 {
        return Vec::new();
    }
    let size = size as usize;
    if compressible {
        let unit = format!("vgi-rpc StateRef conformance {seed} ");
        return unit.as_bytes().iter().copied().cycle().take(size).collect();
    }
    let mut out = Vec::with_capacity(size + 32);
    let mut i: u64 = 0;
    while out.len() < size {
        let mut h = Sha256::new();
        h.update(seed.as_bytes());
        h.update(i.to_le_bytes());
        out.extend_from_slice(&h.finalize());
        i += 1;
    }
    out.truncate(size);
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn input_schema_fn() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "override",
        DataType::Binary,
        true,
    )]))
}

fn output_schema_fn() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("size", DataType::Int64, false),
        Field::new("sha256", DataType::Utf8, false),
        Field::new("form", DataType::Utf8, false),
        Field::new("ref", DataType::Binary, true),
    ]))
}

/// Resolve the stream's `StateRef` (or a presented one) on every exchange.
///
/// `value` is created by `ctx.state_ref` in the init handler and copied by
/// every turn; `padding` sits in the cursor itself (to drive the cursor
/// rule); `misuse` makes every exchange call `ctx.state_ref` (refused:
/// `state_ref_misuse`).
#[derive(Serialize, Deserialize)]
pub struct StateRefExchange {
    value: StateRef,
    padding: Vec<u8>,
    misuse: bool,
}

impl StreamStateCodec for StateRefExchange {
    fn encode(&self) -> Result<Vec<u8>> {
        bincode_encode(self)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        bincode_decode(bytes)
    }
}

impl ExchangeState for StateRefExchange {
    fn exchange(
        &mut self,
        input: &RecordBatch,
        out: &mut OutputCollector,
        ctx: &CallContext,
    ) -> Result<()> {
        if self.misuse {
            ctx.state_ref(b"a continuation may not create a StateRef")?;
        }
        let presented = input
            .column_by_name("override")
            .and_then(|c| c.as_any().downcast_ref::<BinaryArray>())
            .filter(|c| !c.is_empty() && !c.is_null(0))
            .map(|c| StateRef::from_encoded(c.value(0).to_vec()));
        let data = ctx.resolve(presented.as_ref().unwrap_or(&self.value))?;
        let encoded = self.value.encoded();
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(Int64Array::from(vec![data.len() as i64])),
            Arc::new(StringArray::from(vec![hex(&Sha256::digest(&data))])),
            Arc::new(StringArray::from(vec![self.value.form().as_str()])),
            Arc::new(BinaryArray::from(vec![encoded.as_deref()])),
        ];
        out.emit(RecordBatch::try_new(output_schema_fn(), arrays)?)
    }

    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

/// The worker process's object-cache counters (`ObjectCacheStatsResult`).
#[derive(Clone, Debug, PartialEq, vgi_rpc::VgiArrow)]
#[vgi_arrow(name = "ObjectCacheStatsResult")]
pub struct ObjectCacheStatsResult {
    pub resident_bytes: i64,
    pub entries: i64,
    pub max_bytes: i64,
    pub hits: i64,
    pub misses: i64,
    pub evictions: i64,
    pub fetches: i64,
}

pub struct StateRefSvc;

#[service]
impl StateRefSvc {
    /// Hold a `StateRef` of `state_ref_payload(size, compressible, seed)` and
    /// resolve it per exchange.
    #[exchange(
        state = StateRefExchange,
        input_schema = input_schema_fn,
        output_schema = output_schema_fn
    )]
    fn state_ref_exchange(
        &self,
        ctx: &CallContext,
        size: i64,
        compressible: bool,
        seed: String,
        misuse: bool,
        cursor_padding: i64,
    ) -> Result<StateRefExchange> {
        // Wrapped here, in the init handler: the one place it is allowed.
        let value = ctx.state_ref(state_ref_payload(size, compressible, &seed))?;
        let padding = state_ref_payload(cursor_padding, false, &format!("{seed}:padding"));
        Ok(StateRefExchange {
            value,
            padding,
            misuse,
        })
    }

    /// Return this worker process's object-cache counters.
    #[unary]
    fn object_cache_stats(&self) -> Result<Bytes> {
        let s = vgi_rpc::object_cache::default_object_cache().stats();
        let as_i64 = |n: u64| i64::try_from(n).unwrap_or(i64::MAX);
        Ok(Bytes(dataclass_serialize_ipc(ObjectCacheStatsResult {
            resident_bytes: as_i64(s.resident_bytes),
            entries: as_i64(s.entries),
            max_bytes: as_i64(s.max_bytes),
            hits: as_i64(s.hits),
            misses: as_i64(s.misses),
            evictions: as_i64(s.evictions),
            fetches: as_i64(s.fetches),
        })?))
    }

    /// Move every object-cache entry's `fetched_at` back by `seconds`; return
    /// how many (test hook for the one-day rule).
    #[unary]
    fn object_cache_age(&self, seconds: i64) -> Result<i64> {
        let n = vgi_rpc::object_cache::default_object_cache().age_entries(seconds as f64);
        Ok(n as i64)
    }

    /// Resolve an argument reference through the framework primitive; return
    /// the bytes' SHA-256 hex.
    #[unary]
    fn resolve_argument_ref(
        &self,
        ctx: &CallContext,
        r#ref: Bytes,
        size: i64,
        sha256: String,
    ) -> Result<String> {
        let size = u64::try_from(size).map_err(|_| {
            vgi_rpc::state_ref::invalid_arguments_ref(format!(
                "argument location size must be an integer >= 1, got {size}"
            ))
        })?;
        let data = ctx.resolve_argument_ref(&r#ref.0, size, &sha256)?;
        Ok(hex(&Sha256::digest(&data)))
    }
}

pub fn register(srv: &mut RpcServer) {
    StateRefSvc::register_with(srv, Arc::new(StateRefSvc));
}

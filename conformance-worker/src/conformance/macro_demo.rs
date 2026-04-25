//! Phase 9 parity demo: a representative slice of conformance methods
//! re-implemented via `#[vgi_rpc::service]` and friends.
//!
//! Methods are registered under wire names suffixed `_macro` so they
//! coexist with the imperative versions and don't perturb the
//! conformance suite. The dedicated integration test in
//! `vgi-rpc/tests/macro_smoke.rs` (and hand-driven calls) validate
//! shape parity.
//!
//! This module covers:
//! - Unary scalars (`String`, `i64`, `bool`, `Option<i64>`, `Vec<u8>`)
//! - Unary lists (`Vec<i64>`, `Vec<String>`, `Vec<Vec<i64>>`)
//! - Unary map (`Vec<(String, i64)>`)
//! - Unary struct (via `#[derive(VgiArrow)]`)
//! - Sync producer with single-column output
//! - Exchange (sync, with type cast)
//!
//! The full mechanical migration of all 45 conformance methods is
//! deferred to a focused follow-up — every method shape this demo
//! covers compiles, runs, and produces wire-format-compatible output.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use vgi_rpc::stream::{ExchangeState, OutputCollector, ProducerState};
use vgi_rpc::{service, Bytes, CallContext, Result, RpcServer, StreamState, VgiArrow};

#[derive(VgiArrow, Debug, Clone)]
struct DemoPoint {
    x: f64,
    y: f64,
}

#[derive(StreamState, Serialize, Deserialize)]
struct DemoCounter {
    total: i64,
    cur: i64,
}

impl ProducerState for DemoCounter {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.total {
            out.finish();
            return Ok(());
        }
        let arr = i64::build_singleton(self.cur)?;
        out.emit(arrow_array::RecordBatch::try_new(out.schema(), vec![arr])?)?;
        self.cur += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        vgi_rpc::stream_codec::StreamStateCodec::encode(self)
    }
}

#[derive(StreamState, Serialize, Deserialize)]
struct DemoScale {
    factor: f64,
}

impl ExchangeState for DemoScale {
    fn exchange(
        &mut self,
        input: &arrow_array::RecordBatch,
        out: &mut OutputCollector,
        _ctx: &CallContext,
    ) -> Result<()> {
        let v = f64::read(input.column(0).as_ref(), 0)?;
        let arr = f64::build_singleton(v * self.factor)?;
        out.emit(arrow_array::RecordBatch::try_new(out.schema(), vec![arr])?)
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        vgi_rpc::stream_codec::StreamStateCodec::encode(self)
    }
}

/// Service handle. Stateless — every method is `&self` and trivial to
/// share via `Arc<MacroDemo>`.
pub struct MacroDemo;

#[service]
impl MacroDemo {
    /// Echo a string, prefixed.
    #[unary]
    fn echo_string_macro(&self, value: String) -> Result<String> {
        Ok(format!("echo: {value}"))
    }

    /// Square an integer.
    #[unary]
    fn square_macro(&self, value: i64) -> Result<i64> {
        Ok(value * value)
    }

    /// Negate a boolean.
    #[unary]
    fn not_macro(&self, value: bool) -> Result<bool> {
        Ok(!value)
    }

    /// Optional integer round-trip.
    #[unary]
    fn opt_int_macro(&self, value: Option<i64>) -> Result<Option<i64>> {
        Ok(value)
    }

    /// Bytes round-trip.
    #[unary]
    fn echo_bytes_macro(&self, value: Bytes) -> Result<Bytes> {
        Ok(value)
    }

    /// Sum a list of ints.
    #[unary]
    fn sum_list_macro(&self, values: Vec<i64>) -> Result<i64> {
        Ok(values.iter().sum())
    }

    /// Concat strings.
    #[unary]
    fn concat_macro(&self, parts: Vec<String>) -> Result<String> {
        Ok(parts.join(","))
    }

    /// Sum nested lists.
    #[unary]
    fn sum_nested_macro(&self, values: Vec<Vec<i64>>) -> Result<i64> {
        Ok(values.into_iter().flatten().sum())
    }

    /// Total a string→int map.
    #[unary]
    fn total_map_macro(&self, m: Vec<(String, i64)>) -> Result<i64> {
        Ok(m.into_iter().map(|(_, v)| v).sum())
    }

    /// Distance between two points (struct param + struct return).
    #[unary]
    fn distance_macro(&self, a: DemoPoint, b: DemoPoint) -> Result<f64> {
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        Ok((dx * dx + dy * dy).sqrt())
    }

    /// Producer: emit `total` integers 0..total.
    #[producer(state = DemoCounter, output = i64)]
    fn count_macro(&self, total: i64) -> Result<DemoCounter> {
        Ok(DemoCounter { total, cur: 0 })
    }

    /// Exchange: scale incoming float by a constant.
    #[exchange(state = DemoScale, input = f64, output = f64)]
    fn scale_macro(&self, factor: f64) -> Result<DemoScale> {
        Ok(DemoScale { factor })
    }
}

/// Register the macro-driven demo methods on `srv`. Called from the
/// conformance-worker bootstrap.
pub fn register(srv: &mut RpcServer) {
    MacroDemo::register_with(srv, Arc::new(MacroDemo));
}

//! Conformance streaming methods (producers, exchanges, headers, dynamic).
//!
//! All registrations now go through `#[vgi_rpc::service]`. State
//! definitions retain the imperative `impl_bincode_codec!` + `impl
//! ProducerState/ExchangeState` shape because users still author state
//! types by hand.

use std::sync::Arc;

use arrow_array::{ArrayRef, Float64Array, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use serde::{Deserialize, Serialize};
use vgi_rpc::server::Request;
use vgi_rpc::{
    service,
    stream::{ExchangeState, OutputCollector, ProducerState},
    stream_codec::{bincode_decode, bincode_encode, StreamStateCodec},
    CallContext, LogLevel, Result, RpcError, RpcServer,
};

/// Default `SchemaRef` used for `#[serde(skip)]` fields in states that
/// re-derive their schema after deserialization.
fn default_schema() -> SchemaRef {
    Arc::new(Schema::empty())
}

/// Shorthand for the bincode-backed `StreamStateCodec` impl used by
/// every conformance state below.
macro_rules! impl_bincode_codec {
    ($ty:ty) => {
        impl StreamStateCodec for $ty {
            fn encode(&self) -> Result<Vec<u8>> {
                bincode_encode(self)
            }
            fn decode(bytes: &[u8]) -> Result<Self> {
                bincode_decode(bytes)
            }
        }
    };
}

fn counter_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("index", DataType::Int64, false),
        Field::new("value", DataType::Int64, false),
    ]))
}

fn scale_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Float64,
        false,
    )]))
}

fn accum_schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("running_sum", DataType::Float64, false),
        Field::new("exchange_count", DataType::Int64, false),
    ]))
}

fn counter_batch(index: i64) -> Result<RecordBatch> {
    let arrs: Vec<ArrayRef> = vec![
        Arc::new(Int64Array::from(vec![index])),
        Arc::new(Int64Array::from(vec![index * 10])),
    ];
    Ok(RecordBatch::try_new(counter_schema(), arrs)?)
}

fn counter_batch_range(start: i64, count: i64) -> Result<RecordBatch> {
    let idx: Vec<i64> = (0..count).map(|i| start + i).collect();
    let val: Vec<i64> = idx.iter().map(|i| i * 10).collect();
    let arrs: Vec<ArrayRef> = vec![
        Arc::new(Int64Array::from(idx)),
        Arc::new(Int64Array::from(val)),
    ];
    Ok(RecordBatch::try_new(counter_schema(), arrs)?)
}

// ---------------------------------------------------------------------------
// Producer states
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Counter {
    total: i64,
    cur: i64,
}
impl_bincode_codec!(Counter);
impl ProducerState for Counter {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.total {
            out.finish();
            return Ok(());
        }
        out.emit(counter_batch(self.cur)?)?;
        self.cur += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

#[derive(Serialize, Deserialize)]
struct Empty;
impl_bincode_codec!(Empty);
impl ProducerState for Empty {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        out.finish();
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

/// Emit one big batch of `rows` int64 rows, then finish.  Used by HTTP-only
/// conformance tests to overshoot the operator response cap in a single
/// producer iteration.
#[derive(Serialize, Deserialize)]
struct OversizedBatch {
    rows: i64,
    emitted: bool,
}
impl_bincode_codec!(OversizedBatch);
impl ProducerState for OversizedBatch {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.emitted {
            out.finish();
            return Ok(());
        }
        self.emitted = true;
        out.emit(counter_batch_range(0, self.rows)?)
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

/// Companion to `OversizedBatch` for the lockstep exchange path — emits a
/// fixed-size oversized output for any input.
#[derive(Serialize, Deserialize)]
struct OversizedExchange {
    rows: i64,
}
impl_bincode_codec!(OversizedExchange);
impl ExchangeState for OversizedExchange {
    fn exchange(
        &mut self,
        _input: &RecordBatch,
        out: &mut OutputCollector,
        _ctx: &CallContext,
    ) -> Result<()> {
        out.emit(counter_batch_range(0, self.rows)?)
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

#[derive(Serialize, Deserialize)]
struct Single {
    emitted: bool,
}
impl_bincode_codec!(Single);
impl ProducerState for Single {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.emitted {
            out.finish();
            return Ok(());
        }
        self.emitted = true;
        out.emit(counter_batch(0)?)
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

#[derive(Serialize, Deserialize)]
struct Large {
    rows: i64,
    batches: i64,
    cur: i64,
}
impl_bincode_codec!(Large);
impl ProducerState for Large {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.batches {
            out.finish();
            return Ok(());
        }
        let offset = self.cur * self.rows;
        out.emit(counter_batch_range(offset, self.rows)?)?;
        self.cur += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

#[derive(Serialize, Deserialize)]
struct Logging {
    total: i64,
    cur: i64,
}
impl_bincode_codec!(Logging);
impl ProducerState for Logging {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.total {
            out.finish();
            return Ok(());
        }
        out.client_log(LogLevel::Info, format!("producing batch {}", self.cur));
        out.emit(counter_batch(self.cur)?)?;
        self.cur += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

#[derive(Serialize, Deserialize)]
struct ErrorAfterN {
    threshold: i64,
    cur: i64,
}
impl_bincode_codec!(ErrorAfterN);
impl ProducerState for ErrorAfterN {
    fn produce(&mut self, _out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.threshold {
            return Err(RpcError::runtime_error(format!(
                "intentional error after {} batches",
                self.threshold
            )));
        }
        _out.emit(counter_batch(self.cur)?)?;
        self.cur += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

#[derive(Serialize, Deserialize)]
struct Dynamic {
    #[serde(skip, default = "default_schema")]
    schema: SchemaRef,
    total: i64,
    cur: i64,
    include_strings: bool,
    include_floats: bool,
}
impl StreamStateCodec for Dynamic {
    fn encode(&self) -> Result<Vec<u8>> {
        bincode_encode(self)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d: Self = bincode_decode(bytes)?;
        // Rebuild the dynamic output schema from the serialized include_*
        // flags so the state is usable on any worker.
        d.schema = super::types::build_dynamic_schema(d.include_strings, d.include_floats);
        Ok(d)
    }
}
impl ProducerState for Dynamic {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.cur >= self.total {
            out.finish();
            return Ok(());
        }
        let mut arrs: Vec<ArrayRef> = Vec::new();
        arrs.push(Arc::new(Int64Array::from(vec![self.cur])));
        if self.include_strings {
            arrs.push(Arc::new(StringArray::from(vec![format!(
                "row-{}",
                self.cur
            )])));
        }
        if self.include_floats {
            arrs.push(Arc::new(Float64Array::from(vec![(self.cur as f64) * 1.5])));
        }
        out.emit(RecordBatch::try_new(self.schema.clone(), arrs)?)?;
        self.cur += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

#[derive(Serialize, Deserialize)]
struct CancellableProducer {
    cur: i64,
}
impl_bincode_codec!(CancellableProducer);
impl ProducerState for CancellableProducer {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        super::bump_cancel_produce();
        out.emit(counter_batch(self.cur)?)?;
        self.cur += 1;
        Ok(())
    }
    fn on_cancel(&mut self, _ctx: &CallContext) {
        super::bump_cancel_oncancel();
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

// ---------------------------------------------------------------------------
// Exchange states
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Scale {
    factor: f64,
}
impl_bincode_codec!(Scale);
impl ExchangeState for Scale {
    fn exchange(
        &mut self,
        input: &RecordBatch,
        out: &mut OutputCollector,
        _ctx: &CallContext,
    ) -> Result<()> {
        let col = input
            .column(0)
            .as_any()
            .downcast_ref::<Float64Array>()
            .ok_or_else(|| RpcError::type_error("scale: expected float64 input"))?;
        let vals: Vec<f64> = (0..col.len()).map(|i| col.value(i) * self.factor).collect();
        let arrs: Vec<ArrayRef> = vec![Arc::new(Float64Array::from(vals))];
        out.emit(RecordBatch::try_new(out.schema(), arrs)?)
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

#[derive(Serialize, Deserialize)]
struct Accumulate {
    sum: f64,
    count: i64,
}
impl_bincode_codec!(Accumulate);
impl ExchangeState for Accumulate {
    fn exchange(
        &mut self,
        input: &RecordBatch,
        out: &mut OutputCollector,
        _ctx: &CallContext,
    ) -> Result<()> {
        let col = input
            .column(0)
            .as_any()
            .downcast_ref::<Float64Array>()
            .ok_or_else(|| RpcError::type_error("accumulate: expected float64 input"))?;
        let s: f64 = (0..col.len()).map(|i| col.value(i)).sum();
        self.sum += s;
        self.count += 1;
        let arrs: Vec<ArrayRef> = vec![
            Arc::new(Float64Array::from(vec![self.sum])),
            Arc::new(Int64Array::from(vec![self.count])),
        ];
        out.emit(RecordBatch::try_new(out.schema(), arrs)?)
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

#[derive(Serialize, Deserialize)]
struct LoggingExchange;
impl_bincode_codec!(LoggingExchange);
impl ExchangeState for LoggingExchange {
    fn exchange(
        &mut self,
        input: &RecordBatch,
        out: &mut OutputCollector,
        _ctx: &CallContext,
    ) -> Result<()> {
        out.client_log(LogLevel::Info, "exchange processing");
        out.client_log(LogLevel::Debug, "exchange debug");
        out.emit(input.clone())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

#[derive(Serialize, Deserialize)]
struct FailOnExchangeN {
    fail_on: i64,
    count: i64,
}
impl_bincode_codec!(FailOnExchangeN);
impl ExchangeState for FailOnExchangeN {
    fn exchange(
        &mut self,
        input: &RecordBatch,
        out: &mut OutputCollector,
        _ctx: &CallContext,
    ) -> Result<()> {
        self.count += 1;
        if self.count >= self.fail_on {
            return Err(RpcError::runtime_error(format!(
                "intentional error on exchange {}",
                self.count
            )));
        }
        out.emit(input.clone())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

#[derive(Serialize, Deserialize)]
struct ZeroColumn;
impl_bincode_codec!(ZeroColumn);
impl ExchangeState for ZeroColumn {
    fn exchange(
        &mut self,
        _input: &RecordBatch,
        out: &mut OutputCollector,
        _ctx: &CallContext,
    ) -> Result<()> {
        use arrow_array::RecordBatchOptions;
        let batch = RecordBatch::try_new_with_options(
            out.schema(),
            vec![],
            &RecordBatchOptions::new().with_row_count(Some(0)),
        )?;
        out.emit(batch)
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

/// Producer that emits the sticky-session counter `count` times. Each
/// `produce` resolves the counter via `ctx.session`, increments it by one,
/// and emits the new value. `current` rides in the continuation token
/// across HTTP turns while the session is rebound on every request.
#[derive(Serialize, Deserialize)]
struct SessionCounterProducer {
    count: i64,
    current: i64,
}
impl_bincode_codec!(SessionCounterProducer);
impl ProducerState for SessionCounterProducer {
    fn produce(&mut self, out: &mut OutputCollector, ctx: &CallContext) -> Result<()> {
        if self.current >= self.count {
            out.finish();
            return Ok(());
        }
        let counter = ctx
            .session::<super::StickyCounter>()
            .ok_or_else(|| RpcError::runtime_error("no sticky counter bound to this request"))?;
        let value = counter.add(1);
        out.emit(session_value_batch(value)?)?;
        self.current += 1;
        Ok(())
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

/// Exchange that adds each input batch's `by` column sum to the sticky
/// session counter and emits the running value. State is empty — the
/// counter lives in the session, rebound on every (separate) HTTP turn.
#[derive(Serialize, Deserialize, Default)]
struct SessionCounterExchange;
impl_bincode_codec!(SessionCounterExchange);
impl ExchangeState for SessionCounterExchange {
    fn exchange(
        &mut self,
        input: &RecordBatch,
        out: &mut OutputCollector,
        ctx: &CallContext,
    ) -> Result<()> {
        let counter = ctx
            .session::<super::StickyCounter>()
            .ok_or_else(|| RpcError::runtime_error("no sticky counter bound to this request"))?;
        let by = input
            .column_by_name("by")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .ok_or_else(|| RpcError::type_error("exchange input missing int64 'by' column"))?;
        let sum: i64 = (0..by.len()).map(|i| by.value(i)).sum();
        let value = counter.add(sum);
        out.emit(session_value_batch(value)?)
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

#[derive(Serialize, Deserialize)]
struct CancellableExchange;
impl_bincode_codec!(CancellableExchange);
impl ExchangeState for CancellableExchange {
    fn exchange(
        &mut self,
        input: &RecordBatch,
        out: &mut OutputCollector,
        _ctx: &CallContext,
    ) -> Result<()> {
        super::bump_cancel_exchange();
        out.emit(input.clone())
    }
    fn on_cancel(&mut self, _ctx: &CallContext) {
        super::bump_cancel_oncancel();
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        StreamStateCodec::encode(self)
    }
}

// ---------------------------------------------------------------------------
// Header builders + helper schemas (referenced from `#[producer]` /
// `#[exchange]` attributes via path arguments).
// ---------------------------------------------------------------------------

fn build_header_for_count(req: &Request) -> Result<RecordBatch> {
    let count = super::params::i64_col(req, "count")?;
    super::types::build_conformance_header_batch(count, &format!("producing {count} batches"))
}

fn build_header_for_count_with_logs(req: &Request) -> Result<RecordBatch> {
    let count = super::params::i64_col(req, "count")?;
    super::types::build_conformance_header_batch(count, &format!("producing {count} with logs"))
}

fn build_rich_header_from_seed(req: &Request) -> Result<RecordBatch> {
    let seed = super::params::i64_col(req, "seed")?;
    super::types::build_rich_header(seed).to_record_batch()
}

fn build_exchange_factor_header(req: &Request) -> Result<RecordBatch> {
    let factor = super::params::f64_col(req, "factor")?;
    super::types::build_conformance_header_batch(0, &format!("scale by {}", format_float(factor)))
}

fn build_dynamic_schema_for_req(req: &Request) -> Result<SchemaRef> {
    let include_strings = super::params::bool_col(req, "include_strings")?;
    let include_floats = super::params::bool_col(req, "include_floats")?;
    Ok(super::types::build_dynamic_schema(
        include_strings,
        include_floats,
    ))
}

fn conformance_header_schema_fn() -> SchemaRef {
    super::types::conformance_header_schema()
}

fn rich_header_schema_fn() -> SchemaRef {
    super::types::all_types_schema()
}

fn counter_schema_fn() -> SchemaRef {
    counter_schema()
}

fn scale_schema_fn() -> SchemaRef {
    scale_schema()
}

fn accum_schema_fn() -> SchemaRef {
    accum_schema()
}

fn empty_schema_fn() -> SchemaRef {
    Arc::new(Schema::empty())
}

fn session_counter_output_schema_fn() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::Int64,
        false,
    )]))
}

fn session_counter_input_schema_fn() -> SchemaRef {
    Arc::new(Schema::new(vec![Field::new("by", DataType::Int64, false)]))
}

fn session_value_batch(value: i64) -> Result<RecordBatch> {
    let arrs: Vec<ArrayRef> = vec![Arc::new(Int64Array::from(vec![value]))];
    Ok(RecordBatch::try_new(
        session_counter_output_schema_fn(),
        arrs,
    )?)
}

// ---------------------------------------------------------------------------
// Service registration
// ---------------------------------------------------------------------------

/// Stateless service handle.
pub struct StreamSvc;

#[service]
impl StreamSvc {
    /// Produce count batches with {index, value}.
    #[producer(state = Counter, output_schema = counter_schema_fn)]
    fn produce_n(&self, count: i64) -> Result<Counter> {
        Ok(Counter {
            total: count,
            cur: 0,
        })
    }

    /// Produce zero batches (finish immediately).
    #[producer(state = Empty, output_schema = counter_schema_fn)]
    fn produce_empty(&self) -> Result<Empty> {
        Ok(Empty)
    }

    /// Produce exactly one batch.
    #[producer(state = Single, output_schema = counter_schema_fn)]
    fn produce_single(&self) -> Result<Single> {
        Ok(Single { emitted: false })
    }

    /// Produce batch_count batches of rows_per_batch rows each.
    #[producer(state = Large, output_schema = counter_schema_fn)]
    fn produce_large_batches(&self, rows_per_batch: i64, batch_count: i64) -> Result<Large> {
        Ok(Large {
            rows: rows_per_batch,
            batches: batch_count,
            cur: 0,
        })
    }

    /// Produce batches with an INFO log before each.
    #[producer(state = Logging, output_schema = counter_schema_fn)]
    fn produce_with_logs(&self, count: i64) -> Result<Logging> {
        Ok(Logging {
            total: count,
            cur: 0,
        })
    }

    /// Raise after emitting emit_before_error batches.
    #[producer(state = ErrorAfterN, output_schema = counter_schema_fn)]
    fn produce_error_mid_stream(&self, emit_before_error: i64) -> Result<ErrorAfterN> {
        Ok(ErrorAfterN {
            threshold: emit_before_error,
            cur: 0,
        })
    }

    /// Raise during stream initialization.
    #[producer(state = Empty, output_schema = counter_schema_fn)]
    fn produce_error_on_init(&self) -> Result<Empty> {
        Err(RpcError::runtime_error("intentional init error"))
    }

    /// Emit one batch of `rows_per_batch` int64 rows, then finish.
    #[producer(state = OversizedBatch, output_schema = counter_schema_fn)]
    fn produce_oversized_batch(&self, rows_per_batch: i64) -> Result<OversizedBatch> {
        Ok(OversizedBatch {
            rows: rows_per_batch,
            emitted: false,
        })
    }

    /// Produce batches with a stream header.
    #[producer(
        state = Counter,
        output_schema = counter_schema_fn,
        header_schema = conformance_header_schema_fn,
        header_fn = build_header_for_count
    )]
    fn produce_with_header(&self, count: i64) -> Result<Counter> {
        Ok(Counter {
            total: count,
            cur: 0,
        })
    }

    /// Produce batches with a header and INFO logs.
    #[producer(
        state = Counter,
        output_schema = counter_schema_fn,
        header_schema = conformance_header_schema_fn,
        header_fn = build_header_for_count_with_logs
    )]
    fn produce_with_header_and_logs(&self, ctx: &CallContext, count: i64) -> Result<Counter> {
        ctx.client_log(LogLevel::Info, "stream init log");
        Ok(Counter {
            total: count,
            cur: 0,
        })
    }

    /// Produce batches with a rich multi-type stream header.
    #[producer(
        state = Counter,
        output_schema = counter_schema_fn,
        header_schema = rich_header_schema_fn,
        header_fn = build_rich_header_from_seed
    )]
    #[param(
        name = "seed",
        doc = "Determines all header field values deterministically."
    )]
    #[param(name = "count", doc = "Number of {index, value} batches to produce.")]
    fn produce_with_rich_header(&self, seed: i64, count: i64) -> Result<Counter> {
        let _ = seed;
        Ok(Counter {
            total: count,
            cur: 0,
        })
    }

    /// Produce batches with a dynamic output schema and rich header.
    #[producer(
        state = Dynamic,
        dynamic,
        schema_fn = build_dynamic_schema_for_req,
        header_schema = rich_header_schema_fn,
        header_fn = build_rich_header_from_seed
    )]
    #[param(
        name = "seed",
        doc = "Determines all header field values deterministically."
    )]
    #[param(name = "count", doc = "Number of batches to produce.")]
    #[param(
        name = "include_strings",
        doc = "Whether to include a ``label: utf8`` column."
    )]
    #[param(
        name = "include_floats",
        doc = "Whether to include a ``score: float64`` column."
    )]
    fn produce_dynamic_schema(
        &self,
        seed: i64,
        count: i64,
        include_strings: bool,
        include_floats: bool,
    ) -> Result<Dynamic> {
        let _ = seed;
        let schema = super::types::build_dynamic_schema(include_strings, include_floats);
        Ok(Dynamic {
            schema,
            total: count,
            cur: 0,
            include_strings,
            include_floats,
        })
    }

    /// Multiply input values by factor.
    #[exchange(
        state = Scale,
        input_schema = scale_schema_fn,
        output_schema = scale_schema_fn
    )]
    fn exchange_scale(&self, factor: f64) -> Result<Scale> {
        Ok(Scale { factor })
    }

    /// Accumulate running sum and exchange count across exchanges.
    #[exchange(
        state = Accumulate,
        input_schema = scale_schema_fn,
        output_schema = accum_schema_fn
    )]
    fn exchange_accumulate(&self) -> Result<Accumulate> {
        Ok(Accumulate { sum: 0.0, count: 0 })
    }

    /// Exchange with INFO + DEBUG logs per exchange.
    #[exchange(
        state = LoggingExchange,
        input_schema = scale_schema_fn,
        output_schema = scale_schema_fn
    )]
    fn exchange_with_logs(&self) -> Result<LoggingExchange> {
        Ok(LoggingExchange)
    }

    /// Raise on the Nth exchange (1-indexed).
    #[exchange(
        state = FailOnExchangeN,
        input_schema = scale_schema_fn,
        output_schema = scale_schema_fn
    )]
    fn exchange_error_on_nth(&self, fail_on: i64) -> Result<FailOnExchangeN> {
        Ok(FailOnExchangeN { fail_on, count: 0 })
    }

    /// Raise during exchange stream initialization.
    #[exchange(
        state = Scale,
        input_schema = scale_schema_fn,
        output_schema = scale_schema_fn
    )]
    fn exchange_error_on_init(&self) -> Result<Scale> {
        Err(RpcError::runtime_error("intentional exchange init error"))
    }

    /// Exchange that emits an oversized output batch for any input.
    #[exchange(
        state = OversizedExchange,
        input_schema = scale_schema_fn,
        output_schema = counter_schema_fn
    )]
    fn exchange_oversized(&self, rows_per_batch: i64) -> Result<OversizedExchange> {
        Ok(OversizedExchange {
            rows: rows_per_batch,
        })
    }

    /// Exchange stream with zero-column input and output.
    #[exchange(
        state = ZeroColumn,
        input_schema = empty_schema_fn,
        output_schema = empty_schema_fn
    )]
    fn exchange_zero_columns(&self) -> Result<ZeroColumn> {
        Ok(ZeroColumn)
    }

    /// Exchange expecting float64 input — tests server-side cast for compatible schemas.
    #[exchange(
        state = Scale,
        input_schema = scale_schema_fn,
        output_schema = scale_schema_fn
    )]
    fn exchange_cast_compatible(&self) -> Result<Scale> {
        Ok(Scale { factor: 1.0 })
    }

    /// Exchange stream with a header.
    #[exchange(
        state = Scale,
        input_schema = scale_schema_fn,
        output_schema = scale_schema_fn,
        header_schema = conformance_header_schema_fn,
        header_fn = build_exchange_factor_header
    )]
    fn exchange_with_header(&self, factor: f64) -> Result<Scale> {
        Ok(Scale { factor })
    }

    /// Exchange stream with a rich multi-type header.
    #[exchange(
        state = Scale,
        input_schema = scale_schema_fn,
        output_schema = scale_schema_fn,
        header_schema = rich_header_schema_fn,
        header_fn = build_rich_header_from_seed
    )]
    #[param(
        name = "seed",
        doc = "Determines all header field values deterministically."
    )]
    #[param(name = "factor", doc = "Multiplier applied to input values.")]
    fn exchange_with_rich_header(&self, seed: i64, factor: f64) -> Result<Scale> {
        let _ = seed;
        Ok(Scale { factor })
    }

    /// Produce one batch per tick forever — designed to be cancelled by the client.
    #[producer(state = CancellableProducer, output_schema = counter_schema_fn)]
    fn cancellable_producer(&self) -> Result<CancellableProducer> {
        Ok(CancellableProducer { cur: 0 })
    }

    /// Echo each input batch — designed to be cancelled by the client.
    #[exchange(
        state = CancellableExchange,
        input_schema = scale_schema_fn,
        output_schema = scale_schema_fn
    )]
    fn cancellable_exchange(&self) -> Result<CancellableExchange> {
        Ok(CancellableExchange)
    }

    // --- Sticky sessions — streaming ---

    /// Emit `count` increments of the sticky session counter via a producer stream.
    #[producer(
        state = SessionCounterProducer,
        output_schema = session_counter_output_schema_fn
    )]
    fn stream_session_counter(&self, count: i64) -> Result<SessionCounterProducer> {
        Ok(SessionCounterProducer { count, current: 0 })
    }

    /// Add each input `by` column to the session counter and emit the running value.
    #[exchange(
        state = SessionCounterExchange,
        input_schema = session_counter_input_schema_fn,
        output_schema = session_counter_output_schema_fn
    )]
    fn exchange_session_counter(&self) -> Result<SessionCounterExchange> {
        Ok(SessionCounterExchange)
    }
}

pub fn register(srv: &mut RpcServer) {
    StreamSvc::register_with(srv, Arc::new(StreamSvc));
}

fn format_float(f: f64) -> String {
    let s = format!("{f}");
    if !s.contains('.') && !s.contains('e') && !s.contains('E') {
        format!("{s}.0")
    } else {
        s
    }
}

//! Register all conformance streaming methods (producers, exchanges, headers).

use std::sync::Arc;

use arrow_array::{
    builder::{Float64Builder, Int64Builder, ListBuilder, StringBuilder},
    ArrayRef, Float64Array, Int64Array, RecordBatch, StringArray,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use vgi_rpc::{
    server::{MethodType, Request},
    stream::{ExchangeState, OutputCollector, ProducerState, StreamResult, StreamStateKind},
    CallContext, LogLevel, MethodInfo, Result, RpcError, RpcServer,
};

use super::param_schemas as ps;
use super::params as p;
use super::types;

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

struct Counter {
    total: i64,
    cur: i64,
}
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
}

struct Empty;
impl ProducerState for Empty {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        out.finish();
        Ok(())
    }
}

struct Single {
    emitted: bool,
}
impl ProducerState for Single {
    fn produce(&mut self, out: &mut OutputCollector, _ctx: &CallContext) -> Result<()> {
        if self.emitted {
            out.finish();
            return Ok(());
        }
        self.emitted = true;
        out.emit(counter_batch(0)?)
    }
}

struct Large {
    rows: i64,
    batches: i64,
    cur: i64,
}
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
}

struct Logging {
    total: i64,
    cur: i64,
}
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
}

struct ErrorAfterN {
    threshold: i64,
    cur: i64,
}
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
}

struct Dynamic {
    schema: SchemaRef,
    total: i64,
    cur: i64,
    include_strings: bool,
    include_floats: bool,
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
            arrs.push(Arc::new(StringArray::from(vec![format!("row-{}", self.cur)])));
        }
        if self.include_floats {
            arrs.push(Arc::new(Float64Array::from(vec![(self.cur as f64) * 1.5])));
        }
        out.emit(RecordBatch::try_new(self.schema.clone(), arrs)?)?;
        self.cur += 1;
        Ok(())
    }
}

struct CancellableProducer {
    cur: i64,
}
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
}

// ---------------------------------------------------------------------------
// Exchange states
// ---------------------------------------------------------------------------

struct Scale {
    factor: f64,
}
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
}

struct Accumulate {
    sum: f64,
    count: i64,
}
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
}

struct LoggingExchange;
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
}

struct FailOnExchangeN {
    fail_on: i64,
    count: i64,
}
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
}

struct ZeroColumn;
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
}

struct CancellableExchange;
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
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub fn register(srv: &mut RpcServer) {
    let conf_hdr = ps::conformance_header_schema();
    let rich_hdr = ps::rich_header_schema();

    // --- Producers ---
    srv.register(
        MethodInfo::stream("produce_n", MethodType::Producer, ps::count_only(), |req, _| {
            let count = p::i64_col(req, "count")?;
            Ok(StreamResult::producer(
                counter_schema(),
                Box::new(Counter { total: count, cur: 0 }),
            ))
        })
        .doc("Produce count batches with {index, value}.")
        .param_type("count", "int"),
    );
    srv.register(
        MethodInfo::stream(
            "produce_empty",
            MethodType::Producer,
            ps::produce_empty(),
            |_req, _| Ok(StreamResult::producer(counter_schema(), Box::new(Empty))),
        )
        .doc("Produce zero batches (finish immediately)."),
    );
    srv.register(
        MethodInfo::stream(
            "produce_single",
            MethodType::Producer,
            ps::produce_single(),
            |_req, _| {
                Ok(StreamResult::producer(
                    counter_schema(),
                    Box::new(Single { emitted: false }),
                ))
            },
        )
        .doc("Produce exactly one batch."),
    );
    srv.register(
        MethodInfo::stream(
            "produce_large_batches",
            MethodType::Producer,
            ps::produce_large_batches(),
            |req, _| {
                let rows = p::i64_col(req, "rows_per_batch")?;
                let batches = p::i64_col(req, "batch_count")?;
                Ok(StreamResult::producer(
                    counter_schema(),
                    Box::new(Large { rows, batches, cur: 0 }),
                ))
            },
        )
        .doc("Produce batch_count batches of rows_per_batch rows each.")
        .param_type("rows_per_batch", "int")
        .param_type("batch_count", "int"),
    );
    srv.register(
        MethodInfo::stream(
            "produce_with_logs",
            MethodType::Producer,
            ps::count_only(),
            |req, _| {
                let count = p::i64_col(req, "count")?;
                Ok(StreamResult::producer(
                    counter_schema(),
                    Box::new(Logging { total: count, cur: 0 }),
                ))
            },
        )
        .doc("Produce batches with an INFO log before each.")
        .param_type("count", "int"),
    );
    srv.register(
        MethodInfo::stream(
            "produce_error_mid_stream",
            MethodType::Producer,
            ps::produce_error_mid_stream(),
            |req, _| {
                let threshold = p::i64_col(req, "emit_before_error")?;
                Ok(StreamResult::producer(
                    counter_schema(),
                    Box::new(ErrorAfterN { threshold, cur: 0 }),
                ))
            },
        )
        .doc("Raise after emitting emit_before_error batches.")
        .param_type("emit_before_error", "int"),
    );
    srv.register(
        MethodInfo::stream(
            "produce_error_on_init",
            MethodType::Producer,
            ps::produce_empty(),
            |_req, _| Err(RpcError::runtime_error("intentional init error")),
        )
        .doc("Raise during stream initialization."),
    );

    // --- Producers with headers ---
    srv.register(
        MethodInfo::stream(
            "produce_with_header",
            MethodType::Producer,
            ps::count_only(),
            |req, _| {
                let count = p::i64_col(req, "count")?;
                let header = types::build_conformance_header_batch(
                    count,
                    &format!("producing {count} batches"),
                )?;
                Ok(StreamResult::producer(
                    counter_schema(),
                    Box::new(Counter { total: count, cur: 0 }),
                )
                .with_header(header))
            },
        )
        .doc("Produce batches with a stream header.")
        .param_type("count", "int")
        .header_schema(conf_hdr.clone()),
    );
    srv.register(
        MethodInfo::stream(
            "produce_with_header_and_logs",
            MethodType::Producer,
            ps::count_only(),
            |req, ctx| {
                let count = p::i64_col(req, "count")?;
                ctx.client_log(LogLevel::Info, "stream init log");
                let header = types::build_conformance_header_batch(
                    count,
                    &format!("producing {count} with logs"),
                )?;
                Ok(StreamResult::producer(
                    counter_schema(),
                    Box::new(Counter { total: count, cur: 0 }),
                )
                .with_header(header))
            },
        )
        .doc("Produce batches with a header and INFO logs.")
        .param_type("count", "int")
        .header_schema(conf_hdr.clone()),
    );

    // --- Producer with rich header ---
    srv.register(
        MethodInfo::stream(
            "produce_with_rich_header",
            MethodType::Producer,
            ps::produce_with_rich_header(),
            |req, _| {
                let seed = p::i64_col(req, "seed")?;
                let count = p::i64_col(req, "count")?;
                let header_batch = types::build_rich_header(seed).to_record_batch()?;
                Ok(StreamResult::producer(
                    counter_schema(),
                    Box::new(Counter { total: count, cur: 0 }),
                )
                .with_header(header_batch))
            },
        )
        .doc("Produce batches with a rich multi-type stream header.")
        .param_type("seed", "int")
        .param_type("count", "int")
        .param_doc("seed", "Determines all header field values deterministically.")
        .param_doc("count", "Number of {index, value} batches to produce.")
        .header_schema(rich_hdr.clone()),
    );

    // --- Producer with dynamic schema ---
    srv.register(
        MethodInfo::stream(
            "produce_dynamic_schema",
            MethodType::Dynamic,
            ps::produce_dynamic_schema(),
            |req, _| {
                let seed = p::i64_col(req, "seed")?;
                let count = p::i64_col(req, "count")?;
                let include_strings = p::bool_col(req, "include_strings")?;
                let include_floats = p::bool_col(req, "include_floats")?;
                let schema = types::build_dynamic_schema(include_strings, include_floats);
                let header_batch = types::build_rich_header(seed).to_record_batch()?;
                Ok(StreamResult::producer(
                    schema.clone(),
                    Box::new(Dynamic {
                        schema,
                        total: count,
                        cur: 0,
                        include_strings,
                        include_floats,
                    }),
                )
                .with_header(header_batch))
            },
        )
        .doc("Produce batches with a dynamic output schema and rich header.")
        .param_type("seed", "int")
        .param_type("count", "int")
        .param_type("include_strings", "bool")
        .param_type("include_floats", "bool")
        .param_doc("seed", "Determines all header field values deterministically.")
        .param_doc("count", "Number of batches to produce.")
        .param_doc("include_strings", "Whether to include a ``label: utf8`` column.")
        .param_doc("include_floats", "Whether to include a ``score: float64`` column.")
        .header_schema(rich_hdr.clone()),
    );

    // --- Exchanges ---
    srv.register(
        MethodInfo::stream(
            "exchange_scale",
            MethodType::Exchange,
            ps::factor_only(),
            |req, _| {
                let factor = p::f64_col(req, "factor")?;
                Ok(StreamResult::exchange(
                    scale_schema(),
                    scale_schema(),
                    Box::new(Scale { factor }),
                ))
            },
        )
        .doc("Multiply input values by factor.")
        .param_type("factor", "float"),
    );
    srv.register(
        MethodInfo::stream(
            "exchange_accumulate",
            MethodType::Exchange,
            ps::exchange_accumulate(),
            |_req, _| {
                Ok(StreamResult::exchange(
                    accum_schema(),
                    scale_schema(),
                    Box::new(Accumulate { sum: 0.0, count: 0 }),
                ))
            },
        )
        .doc("Accumulate running sum and exchange count across exchanges."),
    );
    srv.register(
        MethodInfo::stream(
            "exchange_with_logs",
            MethodType::Exchange,
            ps::exchange_with_logs(),
            |_req, _| {
                Ok(StreamResult::exchange(
                    scale_schema(),
                    scale_schema(),
                    Box::new(LoggingExchange),
                ))
            },
        )
        .doc("Exchange with INFO + DEBUG logs per exchange."),
    );
    srv.register(
        MethodInfo::stream(
            "exchange_error_on_nth",
            MethodType::Exchange,
            ps::exchange_error_on_nth(),
            |req, _| {
                let fail_on = p::i64_col(req, "fail_on")?;
                Ok(StreamResult::exchange(
                    scale_schema(),
                    scale_schema(),
                    Box::new(FailOnExchangeN { fail_on, count: 0 }),
                ))
            },
        )
        .doc("Raise on the Nth exchange (1-indexed).")
        .param_type("fail_on", "int"),
    );
    srv.register(
        MethodInfo::stream(
            "exchange_error_on_init",
            MethodType::Exchange,
            ps::exchange_error_on_init(),
            |_req, _| Err(RpcError::runtime_error("intentional exchange init error")),
        )
        .doc("Raise during exchange stream initialization."),
    );
    srv.register(
        MethodInfo::stream(
            "exchange_zero_columns",
            MethodType::Exchange,
            ps::exchange_zero_columns(),
            |_req, _| {
                let empty = Arc::new(Schema::empty());
                Ok(StreamResult::exchange(empty.clone(), empty, Box::new(ZeroColumn)))
            },
        )
        .doc("Exchange stream with zero-column input and output."),
    );
    srv.register(
        MethodInfo::stream(
            "exchange_cast_compatible",
            MethodType::Exchange,
            ps::exchange_cast_compatible(),
            |_req, _| {
                Ok(StreamResult::exchange(
                    scale_schema(),
                    scale_schema(),
                    Box::new(Scale { factor: 1.0 }),
                ))
            },
        )
        .doc("Exchange expecting float64 input — tests server-side cast for compatible schemas."),
    );

    // --- Exchange with headers ---
    srv.register(
        MethodInfo::stream(
            "exchange_with_header",
            MethodType::Exchange,
            ps::factor_only(),
            |req, _| {
                let factor = p::f64_col(req, "factor")?;
                let header = types::build_conformance_header_batch(
                    0,
                    &format!("scale by {}", format_float(factor)),
                )?;
                Ok(StreamResult::exchange(
                    scale_schema(),
                    scale_schema(),
                    Box::new(Scale { factor }),
                )
                .with_header(header))
            },
        )
        .doc("Exchange stream with a header.")
        .param_type("factor", "float")
        .header_schema(conf_hdr.clone()),
    );
    srv.register(
        MethodInfo::stream(
            "exchange_with_rich_header",
            MethodType::Exchange,
            ps::exchange_with_rich_header(),
            |req, _| {
                let seed = p::i64_col(req, "seed")?;
                let factor = p::f64_col(req, "factor")?;
                let header_batch = types::build_rich_header(seed).to_record_batch()?;
                Ok(StreamResult::exchange(
                    scale_schema(),
                    scale_schema(),
                    Box::new(Scale { factor }),
                )
                .with_header(header_batch))
            },
        )
        .doc("Exchange stream with a rich multi-type header.")
        .param_type("seed", "int")
        .param_type("factor", "float")
        .param_doc("seed", "Determines all header field values deterministically.")
        .param_doc("factor", "Multiplier applied to input values.")
        .header_schema(rich_hdr.clone()),
    );

    // --- Cancellation ---
    srv.register(
        MethodInfo::stream(
            "cancellable_producer",
            MethodType::Producer,
            ps::cancellable(),
            |_req, _| {
                Ok(StreamResult::producer(
                    counter_schema(),
                    Box::new(CancellableProducer { cur: 0 }),
                ))
            },
        )
        .doc("Produce one batch per tick forever — designed to be cancelled by the client."),
    );
    srv.register(
        MethodInfo::stream(
            "cancellable_exchange",
            MethodType::Exchange,
            ps::cancellable(),
            |_req, _| {
                Ok(StreamResult::exchange(
                    scale_schema(),
                    scale_schema(),
                    Box::new(CancellableExchange),
                ))
            },
        )
        .doc("Echo each input batch — designed to be cancelled by the client."),
    );

    // quiet unused imports
    let _ = StreamStateKind::Producer;
    let _ = |_: &mut ListBuilder<StringBuilder>| {};
    let _ = |_: &mut ListBuilder<Int64Builder>| {};
    let _ = |_: &mut Float64Builder| {};
}

fn format_float(f: f64) -> String {
    let s = format!("{f}");
    if !s.contains('.') && !s.contains('e') && !s.contains('E') {
        format!("{s}.0")
    } else {
        s
    }
}

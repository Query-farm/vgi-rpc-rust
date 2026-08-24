//! Streaming primitives: OutputCollector, ProducerState, ExchangeState, StreamResult.

use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_schema::{Schema, SchemaRef};

use crate::errors::{Result, RpcError};
use crate::log::{LogLevel, LogMessage};
use crate::wire::Metadata;

/// An entry in the output collector — either a data batch or a pending log.
pub(crate) enum Emitted {
    Batch {
        batch: RecordBatch,
        metadata: Option<Metadata>,
    },
    Log(LogMessage),
}

/// Accumulates batches and log messages for one streaming iteration.
pub struct OutputCollector {
    schema: SchemaRef,
    pub(crate) items: Vec<Emitted>,
    data_emitted: bool,
    finished: bool,
    is_producer: bool,
}

impl OutputCollector {
    pub(crate) fn new(schema: SchemaRef, is_producer: bool) -> Self {
        Self {
            schema,
            items: Vec::new(),
            data_emitted: false,
            finished: false,
            is_producer,
        }
    }

    /// The stream's output schema.
    pub fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    /// Emit a data batch. Schema must match `self.schema()` exactly.
    pub fn emit(&mut self, batch: RecordBatch) -> Result<()> {
        self.ensure_data_slot()?;
        if batch.schema() != self.schema {
            return Err(RpcError::runtime_error(format!(
                "emit(): schema mismatch — expected {:?}, got {:?}",
                self.schema.fields(),
                batch.schema().fields()
            )));
        }
        self.items.push(Emitted::Batch {
            batch,
            metadata: None,
        });
        self.data_emitted = true;
        Ok(())
    }

    /// Emit a data batch with per-batch custom metadata (e.g. VGI's
    /// `vgi_batch_index` / `vgi_partition_values#b64` ordering tags).
    pub fn emit_with_metadata(&mut self, batch: RecordBatch, metadata: Metadata) -> Result<()> {
        self.ensure_data_slot()?;
        if batch.schema() != self.schema {
            return Err(RpcError::runtime_error(format!(
                "emit_with_metadata(): schema mismatch — expected {:?}, got {:?}",
                self.schema.fields(),
                batch.schema().fields()
            )));
        }
        self.items.push(Emitted::Batch {
            batch,
            metadata: Some(metadata),
        });
        self.data_emitted = true;
        Ok(())
    }

    fn ensure_data_slot(&self) -> Result<()> {
        if self.data_emitted {
            return Err(RpcError::protocol_error(
                "only one data batch may be emitted per stream turn",
            ));
        }
        Ok(())
    }

    /// Mark the stream as finished (producer only).
    pub fn finish(&mut self) {
        self.finished = true;
    }

    pub fn finished(&self) -> bool {
        self.finished
    }

    /// Append a client-directed log message.
    pub fn client_log(&mut self, level: LogLevel, message: impl Into<String>) {
        self.items
            .push(Emitted::Log(LogMessage::new(level, message)));
    }

    /// Append a client-directed log message with extras.
    pub fn client_log_with(&mut self, msg: LogMessage) {
        self.items.push(Emitted::Log(msg));
    }

    pub fn is_producer(&self) -> bool {
        self.is_producer
    }
}

/// Server-driven producer state — called once per tick to emit at most one data batch.
pub trait ProducerState: Send {
    fn produce(&mut self, out: &mut OutputCollector, ctx: &CallContext) -> Result<()>;

    /// Optional cancel hook — invoked when the client signals cancellation.
    fn on_cancel(&mut self, _ctx: &CallContext) {}

    /// Serialize this state for stateless HTTP continuation. The default
    /// returns an error; override via [`crate::stream_codec::StreamStateCodec`]
    /// for any state type that will be served over HTTP. Pipe/unix
    /// transports never call this.
    fn encode_state(&self) -> Result<Vec<u8>> {
        Err(RpcError::runtime_error(
            "producer state does not implement encode_state(); \
             override this method or register the method via MethodInfo::stream_with_codec",
        ))
    }
}

/// Bidirectional exchange state — called once per client input batch.
pub trait ExchangeState: Send {
    fn exchange(
        &mut self,
        input: &RecordBatch,
        out: &mut OutputCollector,
        ctx: &CallContext,
    ) -> Result<()>;

    fn on_cancel(&mut self, _ctx: &CallContext) {}

    /// Serialize this state for stateless HTTP continuation. See
    /// [`ProducerState::encode_state`].
    fn encode_state(&self) -> Result<Vec<u8>> {
        Err(RpcError::runtime_error(
            "exchange state does not implement encode_state(); \
             override this method or register the method via MethodInfo::stream_with_codec",
        ))
    }
}

/// What a streaming method returns after init: its output/input schemas,
/// an optional header, and the state object.
pub struct StreamResult {
    pub output_schema: SchemaRef,
    /// `None` for producer streams, or a schema for exchange streams.
    pub input_schema: Option<SchemaRef>,
    pub state: StreamStateKind,
    /// Optional 1-row header batch produced at stream start.
    pub header: Option<RecordBatch>,
    /// Arbitrary metadata to attach to the header batch.
    pub header_metadata: Option<Metadata>,
}

pub enum StreamStateKind {
    Producer(Box<dyn ProducerState>),
    Exchange(Box<dyn ExchangeState>),
}

impl StreamResult {
    pub fn producer(schema: SchemaRef, state: Box<dyn ProducerState>) -> Self {
        Self {
            output_schema: schema,
            input_schema: None,
            state: StreamStateKind::Producer(state),
            header: None,
            header_metadata: None,
        }
    }

    pub fn exchange(
        output_schema: SchemaRef,
        input_schema: SchemaRef,
        state: Box<dyn ExchangeState>,
    ) -> Self {
        Self {
            output_schema,
            input_schema: Some(input_schema),
            state: StreamStateKind::Exchange(state),
            header: None,
            header_metadata: None,
        }
    }

    pub fn with_header(mut self, header: RecordBatch) -> Self {
        self.header = Some(header);
        self
    }
}

/// Build a [`crate::server::StateDecoder`] for a `ProducerState` that
/// also implements [`crate::stream_codec::StreamStateCodec`].
///
/// **Internal:** invoked by the `#[producer]` macro expansion; user
/// code should not call this directly.
// Only needs `StreamStateCodec` (the `stream-codec` feature), not the http stack.
// Gating on `stream-codec` lets producer/exchange workers build for wasm (no tokio).
#[cfg(feature = "stream-codec")]
#[doc(hidden)]
pub fn producer_decoder<S>() -> crate::server::StateDecoder
where
    S: ProducerState + crate::stream_codec::StreamStateCodec + 'static,
{
    Arc::new(|bytes: &[u8]| Ok(StreamStateKind::Producer(Box::new(S::decode(bytes)?))))
}

/// Build a [`crate::server::StateDecoder`] for an `ExchangeState`. See
/// [`producer_decoder`].
///
/// **Internal:** invoked by the `#[exchange]` macro expansion.
#[cfg(feature = "stream-codec")]
#[doc(hidden)]
pub fn exchange_decoder<S>() -> crate::server::StateDecoder
where
    S: ExchangeState + crate::stream_codec::StreamStateCodec + 'static,
{
    Arc::new(|bytes: &[u8]| Ok(StreamStateKind::Exchange(Box::new(S::decode(bytes)?))))
}

pub(crate) fn empty_schema() -> SchemaRef {
    Arc::new(Schema::empty())
}

// Re-export for trait bounds below.
pub use crate::server::CallContext;

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::Int64Array;
    use arrow_schema::{DataType, Field};

    fn batch(schema: SchemaRef, value: i64) -> RecordBatch {
        RecordBatch::try_new(schema, vec![Arc::new(Int64Array::from(vec![value]))]).unwrap()
    }

    #[test]
    fn collector_rejects_a_second_data_batch_as_protocol_error() {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Int64,
            false,
        )]));
        let mut out = OutputCollector::new(schema.clone(), true);

        out.emit(batch(schema.clone(), 1)).unwrap();
        let err = out
            .emit_with_metadata(batch(schema, 2), Metadata::default())
            .unwrap_err();

        assert_eq!(err.error_type, "ProtocolError");
        assert_eq!(out.items.len(), 1);
    }

    #[test]
    fn collector_allows_logs_after_data() {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Int64,
            false,
        )]));
        let mut out = OutputCollector::new(schema.clone(), true);

        out.emit(batch(schema, 1)).unwrap();
        out.client_log(LogLevel::Info, "still allowed");

        assert_eq!(out.items.len(), 2);
    }
}

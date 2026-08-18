//! Native Rust-client schema conformance against the Python reference worker.
//!
//! The ordinary shared suite drives Rust servers with a Python client. This
//! reverses the direction and proves that `HttpClient` preserves an explicitly
//! declared Arrow schema for all-null, empty, and populated exchange batches.

use std::env;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use arrow_array::builder::{Int32Builder, ListBuilder, StringBuilder};
use arrow_array::types::Int16Type;
use arrow_array::{
    new_empty_array, new_null_array, Array, ArrayRef, Decimal128Array, DictionaryArray,
    Float64Array, RecordBatch, StringArray, StructArray, TimestampMicrosecondArray,
};
use arrow_schema::{DataType, Field, Fields, Schema, SchemaRef, TimeUnit};

use vgi_rpc_client::{HttpClient, HttpStreamSession};

struct PythonWorker {
    child: Child,
    _stdout: BufReader<ChildStdout>,
    port: u16,
}

impl PythonWorker {
    fn start() -> Self {
        let python = env::var("VGI_RPC_PYTHON").unwrap_or_else(|_| "python3".to_string());
        let mut child = Command::new(&python)
            .args(["-m", "vgi_rpc.conformance.client_worker", "--http", "0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|err| panic!("start Python reference worker with {python:?}: {err}"));
        let stdout = child.stdout.take().expect("Python worker stdout pipe");
        let mut stdout = BufReader::new(stdout);
        let mut ready = String::new();
        stdout
            .read_line(&mut ready)
            .expect("read Python worker PORT line");
        let port = ready
            .trim()
            .strip_prefix("PORT:")
            .unwrap_or_else(|| panic!("expected Python worker PORT:<n>, got {ready:?}"))
            .parse::<u16>()
            .expect("parse Python worker port");

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_err() {
            assert!(
                Instant::now() < deadline,
                "Python worker did not accept connections on {addr}"
            );
            thread::sleep(Duration::from_millis(25));
        }

        Self {
            child,
            _stdout: stdout,
            port,
        }
    }
}

impl Drop for PythonWorker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn typed_exchange_schema() -> SchemaRef {
    let string_item = Arc::new(Field::new("item", DataType::Utf8, true));
    let score_item = Arc::new(Field::new("item", DataType::Int32, true));
    let nested_fields = Fields::from(vec![
        Field::new("name", DataType::Utf8, true),
        Field::new("scores", DataType::List(score_item), true),
    ]);
    Arc::new(Schema::new(vec![
        Field::new("nullable_float", DataType::Float64, true),
        Field::new("tags", DataType::List(string_item), true),
        Field::new(
            "category",
            DataType::Dictionary(Box::new(DataType::Int16), Box::new(DataType::Utf8)),
            true,
        ),
        Field::new(
            "event_time",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            true,
        ),
        Field::new("amount", DataType::Decimal128(18, 4), true),
        Field::new("nested", DataType::Struct(nested_fields), true),
    ]))
}

fn all_null_batch(schema: &SchemaRef) -> RecordBatch {
    let columns = schema
        .fields()
        .iter()
        .map(|field| new_null_array(field.data_type(), 1))
        .collect();
    RecordBatch::try_new(schema.clone(), columns).expect("all-null typed batch")
}

fn empty_batch(schema: &SchemaRef) -> RecordBatch {
    let columns = schema
        .fields()
        .iter()
        .map(|field| new_empty_array(field.data_type()))
        .collect();
    RecordBatch::try_new(schema.clone(), columns).expect("zero-row typed batch")
}

fn populated_batch(schema: &SchemaRef) -> RecordBatch {
    let mut tags = ListBuilder::new(StringBuilder::new());
    tags.values().append_value("red");
    tags.values().append_null();
    tags.values().append_value("blue");
    tags.append(true);

    let category: DictionaryArray<Int16Type> = vec![Some("alpha")].into_iter().collect();
    let event_time =
        TimestampMicrosecondArray::from(vec![Some(1_725_000_123_456_789i64)]).with_timezone("UTC");
    let amount = Decimal128Array::from(vec![Some(1_234_567i128)])
        .with_precision_and_scale(18, 4)
        .expect("decimal128(18, 4)");

    let mut scores = ListBuilder::new(Int32Builder::new());
    scores.values().append_value(7);
    scores.values().append_null();
    scores.values().append_value(11);
    scores.append(true);
    let nested_fields = match schema.field_with_name("nested").unwrap().data_type() {
        DataType::Struct(fields) => fields.clone(),
        other => panic!("nested field is not a struct: {other}"),
    };
    let nested = StructArray::try_new(
        nested_fields,
        vec![
            Arc::new(StringArray::from(vec![Some("node-a")])),
            Arc::new(scores.finish()),
        ],
        None,
    )
    .expect("nested struct array");

    let columns: Vec<ArrayRef> = vec![
        Arc::new(Float64Array::from(vec![Some(42.5)])),
        Arc::new(tags.finish()),
        Arc::new(category),
        Arc::new(event_time),
        Arc::new(amount),
        Arc::new(nested),
    ];
    RecordBatch::try_new(schema.clone(), columns).expect("populated typed batch")
}

fn assert_echo(session: &mut HttpStreamSession<'_>, expected: &RecordBatch) {
    let (actual, _) = session
        .exchange(expected, None)
        .expect("typed exchange request")
        .expect("typed exchange response batch");
    assert_eq!(actual.schema(), expected.schema());
    assert_eq!(actual.num_rows(), expected.num_rows());
    assert_eq!(actual.num_columns(), expected.num_columns());
    for (index, (actual, expected)) in actual.columns().iter().zip(expected.columns()).enumerate() {
        assert_eq!(
            actual.to_data(),
            expected.to_data(),
            "echoed column {index} differs"
        );
    }
}

#[test]
#[ignore = "requires the Python vgi-rpc reference worker"]
fn python_worker_preserves_declared_typed_exchange_schema() {
    let worker = PythonWorker::start();
    let mut client = HttpClient::connect(format!("http://127.0.0.1:{}", worker.port))
        .build()
        .expect("build Rust HTTP client");
    let params = RecordBatch::new_empty(Arc::new(Schema::empty()));
    let mut session = client
        .open_exchange("typed_exchange", &params, None, false)
        .expect("open typed exchange");

    let schema = typed_exchange_schema();
    assert_echo(&mut session, &all_null_batch(&schema));
    assert_echo(&mut session, &empty_batch(&schema));
    assert_echo(&mut session, &populated_batch(&schema));
}

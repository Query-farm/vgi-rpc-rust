//! Temporary module used to verify arrow-ipc flatbuffer types.
#![allow(dead_code)]

use arrow_ipc::{
    root_as_message, Buffer, FieldNode, KeyValue, KeyValueArgs, MessageBuilder, MessageHeader,
    RecordBatch, RecordBatchBuilder,
};
use flatbuffers::FlatBufferBuilder;

fn _probe(msg_bytes: &[u8], kv: &[(&str, &str)]) -> Vec<u8> {
    let msg = root_as_message(msg_bytes).unwrap();
    let version = msg.version();
    let header_type = msg.header_type();
    let body_length = msg.bodyLength();
    assert_eq!(header_type, MessageHeader::RecordBatch);
    let rb: RecordBatch = msg.header_as_record_batch().unwrap();

    let mut fbb = FlatBufferBuilder::new();

    // Copy nodes
    let src_nodes = rb.nodes().unwrap();
    let nodes: Vec<FieldNode> = src_nodes.iter().copied().collect();
    let nodes_vec = fbb.create_vector(&nodes);

    // Copy buffers
    let src_buffers = rb.buffers().unwrap();
    let buffers: Vec<Buffer> = src_buffers.iter().copied().collect();
    let buffers_vec = fbb.create_vector(&buffers);

    let new_rb = {
        let mut b = RecordBatchBuilder::new(&mut fbb);
        b.add_length(rb.length());
        b.add_nodes(nodes_vec);
        b.add_buffers(buffers_vec);
        b.finish()
    };

    // Build custom metadata
    let kvs: Vec<_> = kv
        .iter()
        .map(|(k, v)| {
            let k_off = fbb.create_string(k);
            let v_off = fbb.create_string(v);
            KeyValue::create(
                &mut fbb,
                &KeyValueArgs {
                    key: Some(k_off),
                    value: Some(v_off),
                },
            )
        })
        .collect();
    let md_vec = fbb.create_vector(&kvs);

    let mut mb = MessageBuilder::new(&mut fbb);
    mb.add_version(version);
    mb.add_header_type(header_type);
    mb.add_header(new_rb.as_union_value());
    mb.add_bodyLength(body_length);
    mb.add_custom_metadata(md_vec);
    let m = mb.finish();
    fbb.finish(m, None);
    fbb.finished_data().to_vec()
}

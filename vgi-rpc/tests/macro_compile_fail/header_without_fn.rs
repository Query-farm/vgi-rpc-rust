//! `header = T` without `header_fn = path` must fail.

use serde::{Deserialize, Serialize};
use vgi_rpc::stream::{OutputCollector, ProducerState};
use vgi_rpc::{service, CallContext, Result, StreamState};

struct Svc;

#[derive(StreamState, Serialize, Deserialize)]
struct St;

impl ProducerState for St {
    fn produce(&mut self, _: &mut OutputCollector, _: &CallContext) -> Result<()> {
        unimplemented!()
    }
    fn encode_state(&self) -> Result<Vec<u8>> {
        vgi_rpc::stream_codec::StreamStateCodec::encode(self)
    }
}

#[service]
impl Svc {
    #[producer(state = St, output = i64, header = i64)]
    fn count(&self, _total: i64) -> Result<St> {
        Ok(St)
    }
}

fn main() {}

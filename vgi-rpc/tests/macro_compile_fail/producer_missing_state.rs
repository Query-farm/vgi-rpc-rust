//! `#[producer]` without `state =` must fail.

use vgi_rpc::{service, Result};

struct Svc;

#[service]
impl Svc {
    #[producer(output = i64)]
    fn count(&self, _total: i64) -> Result<()> {
        unimplemented!()
    }
}

fn main() {}

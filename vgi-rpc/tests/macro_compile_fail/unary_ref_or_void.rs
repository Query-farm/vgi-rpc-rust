//! `#[unary]` returning `Result<RefOr<()>>` must fail: a void method has no
//! result for an `ExternalRef` to stand in for.

use vgi_rpc::{service, RefOr, Result};

struct Svc;

#[service]
impl Svc {
    #[unary]
    fn nothing(&self) -> Result<RefOr<()>> {
        unimplemented!()
    }
}

fn main() {}

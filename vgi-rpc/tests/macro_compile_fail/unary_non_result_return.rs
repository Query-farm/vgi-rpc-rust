//! `#[unary]` returning a bare type (not `Result<T>`) must fail.

use vgi_rpc::service;

struct Svc;

#[service]
impl Svc {
    #[unary]
    fn echo(&self, value: String) -> String {
        value
    }
}

fn main() {}

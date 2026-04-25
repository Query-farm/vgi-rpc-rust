//! Compile-fail UI tests for `#[vgi_rpc::service]` and friends.
//!
//! Driven by `trybuild`. Each `.rs` fixture under
//! `tests/macro_compile_fail/` is compiled in isolation; its expected
//! compiler output lives in the matching `.stderr` file. Update the
//! `.stderr` files with `TRYBUILD=overwrite cargo test --test macro_compile_fail`.

#[test]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/macro_compile_fail/*.rs");
}

//! Fuzz target for [`vgi_rpc::wire::StreamReader`].
//!
//! The wire reader parses hand-crafted flatbuffer-framed Arrow IPC
//! messages so it can expose per-message `custom_metadata` (which
//! `arrow-ipc`'s native reader doesn't surface). That parsing is the
//! crate's largest trust-the-bytes surface — anything that produces
//! a panic, infinite loop, or out-of-bounds read here is a defect
//! whether or not it would happen on legitimate Arrow IPC.
//!
//! What's asserted:
//! - `StreamReader::new` either returns `Ok(_)` or `Err(_)` — never
//!   panics, never unwinds.
//! - `read_next` likewise: arbitrary bytes must not crash the parser.
//! - `drain` runs to completion or returns `Err` cleanly.
//!
//! Run with:
//!
//! ```text
//! cargo install cargo-fuzz
//! cargo +nightly fuzz run wire_stream_reader
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use vgi_rpc::wire::StreamReader;

fuzz_target!(|data: &[u8]| {
    // `StreamReader::new` reads the schema message eagerly; both happy
    // path and rejection are acceptable. Anything else (panic / abort
    // / hang) is a defect.
    let mut reader = match StreamReader::new(data) {
        Ok(r) => r,
        Err(_) => return,
    };

    // Drain a few batches. Cap iterations so degenerate inputs that
    // produce an infinite stream of empty batches don't deadlock the
    // fuzzer.
    for _ in 0..32 {
        match reader.read_next() {
            Ok(Some(_batch)) => continue,
            Ok(None) => break,
            Err(_) => return,
        }
    }
    let _ = reader.drain();
});

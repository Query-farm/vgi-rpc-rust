//! `vgi-rpc-negotiating-client`: the Rust client under test for the shared
//! conformance hook `conformance_negotiating_client`
//! (`PROTOCOL_VERSIONS_V1.md` §9).
//!
//! `vgi-rpc-negotiating-client <base_url> <protocol> <version> <range>`
//! binds an [`HttpClient`] to `<protocol>`, declaring `<version>` as its newest
//! and supporting `<range>`, and answers one line per stdin line: `ping`
//! makes the no-argument unary call `ping` and prints
//! `{"ok": "<result>"}` or `{"error_kind": ..., "message": ...}`.

use std::io::{BufRead, Write};
use std::sync::Arc;

use arrow_array::{Array, RecordBatch, StringArray};
use vgi_rpc_client::http::HttpClient;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: vgi-rpc-negotiating-client <base_url> <protocol> <version> <range>");
        std::process::exit(2);
    }
    let mut client = match HttpClient::connect(args[1].clone())
        .protocol(args[2].clone())
        .protocol_version(args[3].clone())
        .protocol_version_range(args[4].clone())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("client: {}", e.message);
            std::process::exit(2);
        }
    };
    let params = RecordBatch::new_empty(Arc::new(arrow_schema::Schema::empty()));
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim() != "ping" {
            continue;
        }
        let reply = match client.call_unary("ping", &params, None) {
            Ok((batch, _)) => {
                let value = batch
                    .column_by_name("result")
                    .and_then(|c| {
                        c.as_any()
                            .downcast_ref::<StringArray>()
                            .map(|a| a.value(0).to_string())
                    })
                    .unwrap_or_default();
                serde_json::json!({ "ok": value })
            }
            Err(e) => serde_json::json!({
                "error_kind": e.error_kind.as_deref().unwrap_or(""),
                "message": e.message,
            }),
        };
        let _ = writeln!(out, "{reply}");
        let _ = out.flush();
    }
}

// Copyright 2025, 2026 Query Farm LLC - https://query.farm

//! Closing a subprocess transport must not depend on the child cooperating.
//!
//! `close()` drops stdin to signal EOF and then reaps the child. EOF is a
//! *request* to exit, though, and a worker that cannot reach its next read is
//! under no obligation to notice it. The case that matters is a stream
//! abandoned partway: the child is blocked writing into a stdout pipe nobody
//! drains any more, so it never sees the EOF — and a caller that waits
//! unboundedly for it to exit deadlocks against it.
//!
//! That is not hypothetical. It presented as a long-running harness stalling
//! partway through, pinned at 0% CPU with live children, at a position that
//! moved between runs — the signature of a race rather than a bad input.

#![cfg(unix)]

use std::time::{Duration, Instant};

use vgi_rpc_client::transport::{SubprocessTransport, Transport};

/// The grace period in `close()` plus enough slack for a loaded machine.
///
/// The assertion is about *boundedness*, not speed: before the fix this waited
/// forever, so any finite bound demonstrates it.
const BOUND: Duration = Duration::from_secs(20);

/// A child that never reads stdin and writes forever.
///
/// It fills the stdout pipe and blocks there, which is precisely the state a
/// worker reaches when its reader goes away mid-stream: EOF on stdin can never
/// be observed, because the process is parked in a write.
fn spawn_wedged() -> SubprocessTransport {
    SubprocessTransport::spawn(&[
        "sh",
        "-c",
        // `yes` writes without ever reading, so once the pipe fills it blocks.
        "exec yes wedged",
    ])
    .expect("spawn")
}

#[test]
fn close_does_not_wait_forever_for_a_child_that_never_exits() {
    let mut t = spawn_wedged();

    // Let it fill the pipe and park in a write. Without this the child might
    // still be starting, and the test would prove nothing.
    std::thread::sleep(Duration::from_millis(300));

    let start = Instant::now();
    t.close()
        .expect("close reports success even when it has to kill");
    let elapsed = start.elapsed();

    assert!(
        elapsed < BOUND,
        "close() took {elapsed:?} — it is waiting on a child that will never \
         exit on its own, which deadlocks the caller"
    );
}

#[test]
fn close_is_idempotent_and_still_bounded() {
    let mut t = spawn_wedged();
    std::thread::sleep(Duration::from_millis(300));

    t.close().expect("first close");
    // Drop runs close() again; a second call must not re-wait or panic on the
    // already-taken stdin.
    let start = Instant::now();
    t.close().expect("second close");
    assert!(start.elapsed() < BOUND, "second close blocked");
}

#[test]
fn a_cooperative_child_is_reaped_promptly_and_not_killed() {
    // The other half of the contract: the grace period must not become a
    // two-second tax on every well-behaved worker.
    let mut t = SubprocessTransport::spawn(&["sh", "-c", "cat"]).expect("spawn");

    let start = Instant::now();
    t.close().expect("close");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "a child that exits on EOF took {elapsed:?}; the grace period should \
         cost only a poll or two"
    );
}

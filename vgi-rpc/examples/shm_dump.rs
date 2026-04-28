//! Attach to an existing POSIX shared-memory segment and dump the
//! allocator state as JSON. Used by the cross-language compatibility
//! test in the canonical Python repo
//! (`~/Development/vgi-rpc/tests/test_shm_cross_language.py`).
//!
//! Usage:
//!   shm_dump --name <shm_name> --size <bytes>
//!
//! Output (stdout, JSON):
//!   {"size": <bytes>, "data_size": <bytes>, "num_allocs": <n>,
//!    "allocs": [[off, len], ...]}

#[cfg(feature = "shm")]
fn main() {
    use vgi_rpc::shm::{ShmSegment, HEADER_SIZE};
    let mut name: Option<String> = None;
    let mut size: Option<usize> = None;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                name = Some(args[i + 1].clone());
                i += 2;
            }
            "--size" => {
                size = Some(args[i + 1].parse().expect("size must be integer"));
                i += 2;
            }
            other => panic!("unknown arg: {other}"),
        }
    }
    let name = name.expect("--name required");
    let size = size.expect("--size required");
    let seg = ShmSegment::attach(&name, size, false).expect("attach");
    let allocator = seg.allocator();
    let allocs = allocator.dump_allocs();
    print!(
        "{{\"size\":{},\"data_size\":{},\"num_allocs\":{},\"allocs\":[",
        size,
        size - HEADER_SIZE,
        allocs.len(),
    );
    for (i, (off, len)) in allocs.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!("[{},{}]", off, len);
    }
    println!("]}}");
}

#[cfg(not(feature = "shm"))]
fn main() {
    eprintln!("shm_dump requires the `shm` feature");
    std::process::exit(2);
}

//! Small internal helpers.

/// Generate a short hex identifier (12 hex chars) suitable for a server_id.
///
/// Uses `rand::thread_rng` when the `http` feature is enabled (already a dep),
/// otherwise falls back to a process-id + nanosecond timestamp mix so the
/// library stays usable without the feature.
pub fn short_random_id() -> String {
    #[cfg(feature = "http")]
    {
        use rand::RngCore;
        let mut b = [0u8; 6];
        rand::thread_rng().fill_bytes(&mut b);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(12);
        for byte in b {
            s.push(HEX[(byte >> 4) as usize] as char);
            s.push(HEX[(byte & 0x0f) as usize] as char);
        }
        s
    }
    #[cfg(not(feature = "http"))]
    {
        // wasm32-wasi has no process ids (`std::process::id()` aborts); nanos
        // disambiguate within the single wasm process.
        #[cfg(not(target_arch = "wasm32"))]
        let pid = std::process::id() as u64;
        #[cfg(target_arch = "wasm32")]
        let pid: u64 = 0;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mix = pid.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(nanos);
        format!("{mix:012x}")
            .chars()
            .rev()
            .take(12)
            .collect::<String>()
    }
}

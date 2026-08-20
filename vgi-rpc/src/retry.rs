//! Retry helpers.
//!
//! Exponential-backoff + jitter schedule matching the Python / Go
//! reference clients. The crate ships server-only today; these helpers
//! are exposed for symmetry so a future client crate (or user code
//! talking to remote services) reuses the same semantics without
//! redefining the policy.

use std::time::Duration;

/// Configuration for a retry schedule.
///
/// Retries are disabled by default because an RPC may have side effects and a
/// connection failure does not reveal whether the server applied the call.
/// Set [`max_attempts`](Self::max_attempts) above `1` to opt into replaying
/// eligible HTTP requests.
#[derive(Clone, Debug)]
pub struct RetryConfig {
    /// Maximum number of attempts (including the first one). `1` disables retries.
    pub max_attempts: u32,
    /// Base delay for the first retry.
    pub base_delay: Duration,
    /// Maximum delay between attempts; the exponential curve caps here.
    pub max_delay: Duration,
    /// Multiplier applied to the delay each attempt (typically `2.0`).
    pub multiplier: f64,
    /// Random jitter fraction applied to each computed delay, in `[0, 1]`.
    /// `0.0` disables jitter.
    pub jitter: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 1,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
            jitter: 0.2,
        }
    }
}

impl RetryConfig {
    /// Convenience: `max_attempts=1` — no retries.
    pub fn disabled() -> Self {
        Self {
            max_attempts: 1,
            ..Default::default()
        }
    }

    /// Compute the sleep before attempt `n` (0-indexed).
    /// `n == 0` → caller is about to make the first attempt, no delay.
    /// `n == 1` → delay before the first retry, and so on.
    ///
    /// Jitter is drawn from a real per-call entropy source, so callers
    /// retrying in lockstep do **not** compute identical delays — that
    /// decorrelation is the entire point of jitter (it prevents a
    /// synchronized retry storm against a recovering server). For
    /// reproducible delays in tests, use [`delay_before_with_jitter`].
    ///
    /// [`delay_before_with_jitter`]: Self::delay_before_with_jitter
    pub fn delay_before(&self, attempt: u32) -> Duration {
        self.delay_before_with_jitter(attempt, jitter_fraction())
    }

    /// Like [`delay_before`](Self::delay_before) but with the jitter
    /// fraction supplied explicitly (in `[0, 1)`). Deterministic — used
    /// by tests, or by callers that want to plug their own RNG.
    pub fn delay_before_with_jitter(&self, attempt: u32, jitter_frac: f64) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        let exp = (attempt - 1) as i32;
        let base = self.base_delay.as_secs_f64() * self.multiplier.powi(exp);
        let mut d = base.min(self.max_delay.as_secs_f64());
        if self.jitter > 0.0 {
            let spread = d * self.jitter;
            d += spread * (jitter_frac.clamp(0.0, 1.0) * 2.0 - 1.0);
        }
        // Guard against a non-finite result (e.g. a NaN `multiplier`)
        // before `from_secs_f64`, which would otherwise panic.
        if !d.is_finite() {
            d = self.max_delay.as_secs_f64();
        }
        Duration::from_secs_f64(d.max(0.0))
    }

    /// Iterator over per-attempt delays (`attempt = 0..max_attempts`).
    pub fn schedule(&self) -> impl Iterator<Item = Duration> + '_ {
        (0..self.max_attempts).map(move |n| self.delay_before(n))
    }
}

/// A jitter fraction in `[0, 1)` drawn from a real per-call entropy
/// source: the wall clock's sub-second component mixed with a
/// thread-local sequence counter, run through splitmix64. Not
/// cryptographic — jitter does not need to be — but it does give every
/// caller a distinct value, which a fixed hash of the attempt number
/// (the previous implementation) did not.
fn jitter_fraction() -> f64 {
    use std::cell::Cell;
    use std::time::{SystemTime, UNIX_EPOCH};

    thread_local! {
        static SEQ: Cell<u64> = const { Cell::new(0) };
    }
    let seq = SEQ.with(|c| {
        let v = c.get().wrapping_add(1);
        c.set(v);
        v
    });
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    // splitmix64 over the combined entropy.
    let mut x = nanos
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(seq.wrapping_mul(0xD1B5_4A32_D192_ED03));
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    (x as f64) / (u64::MAX as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_attempt_has_no_delay() {
        let cfg = RetryConfig::default();
        assert_eq!(cfg.delay_before(0), Duration::ZERO);
    }

    #[test]
    fn exponential_growth_capped_at_max() {
        let cfg = RetryConfig {
            max_attempts: 6,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(400),
            multiplier: 2.0,
            jitter: 0.0,
        };
        let delays: Vec<Duration> = cfg.schedule().collect();
        assert_eq!(delays[0], Duration::ZERO);
        assert_eq!(delays[1], Duration::from_millis(100));
        assert_eq!(delays[2], Duration::from_millis(200));
        assert_eq!(delays[3], Duration::from_millis(400)); // capped
        assert_eq!(delays[4], Duration::from_millis(400));
    }

    #[test]
    fn disabled_yields_single_zero_delay() {
        let cfg = RetryConfig::disabled();
        let delays: Vec<Duration> = cfg.schedule().collect();
        assert_eq!(delays, vec![Duration::ZERO]);
    }

    #[test]
    fn retries_are_opt_in() {
        assert_eq!(RetryConfig::default().max_attempts, 1);
    }

    #[test]
    fn jitter_stays_non_negative() {
        let cfg = RetryConfig {
            max_attempts: 10,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_secs(1),
            multiplier: 2.0,
            jitter: 0.9,
        };
        for d in cfg.schedule() {
            assert!(d >= Duration::ZERO);
        }
    }

    #[test]
    fn jitter_is_not_deterministic_across_calls() {
        // The whole point of jitter: two callers (or the same caller
        // twice) must not compute identical delays for the same attempt.
        let cfg = RetryConfig {
            max_attempts: 2,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
            jitter: 0.5,
        };
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            seen.insert(cfg.delay_before(1).as_nanos());
        }
        assert!(
            seen.len() > 1,
            "jitter produced identical delays on every call"
        );
    }

    #[test]
    fn explicit_jitter_fraction_is_reproducible() {
        let cfg = RetryConfig {
            max_attempts: 2,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
            jitter: 0.5,
        };
        let a = cfg.delay_before_with_jitter(1, 0.25);
        let b = cfg.delay_before_with_jitter(1, 0.25);
        assert_eq!(a, b);
        // A different fraction yields a different delay.
        assert_ne!(a, cfg.delay_before_with_jitter(1, 0.75));
    }

    #[test]
    fn non_finite_multiplier_does_not_panic() {
        let cfg = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: f64::NAN,
            jitter: 0.0,
        };
        // Must clamp to a finite delay rather than panicking in
        // `Duration::from_secs_f64`.
        let _ = cfg.delay_before_with_jitter(2, 0.0);
    }
}

//! Retry helpers.
//!
//! Exponential-backoff + jitter schedule matching the Python / Go
//! reference clients. The crate ships server-only today; these helpers
//! are exposed for symmetry so a future client crate (or user code
//! talking to remote services) reuses the same semantics without
//! redefining the policy.

use std::time::Duration;

/// Configuration for a retry schedule.
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
            max_attempts: 3,
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
    pub fn delay_before(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        let exp = (attempt - 1) as i32;
        let base = self.base_delay.as_secs_f64() * self.multiplier.powi(exp);
        let mut d = base.min(self.max_delay.as_secs_f64());
        if self.jitter > 0.0 {
            let spread = d * self.jitter;
            // Deterministic jitter derived from attempt number so tests are
            // stable; production callers should wrap a proper RNG if they
            // want full randomness.
            let frac =
                ((attempt as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) as f64) / (u64::MAX as f64);
            d += spread * (frac * 2.0 - 1.0);
        }
        Duration::from_secs_f64(d.max(0.0))
    }

    /// Iterator over per-attempt delays (`attempt = 0..max_attempts`).
    pub fn schedule(&self) -> impl Iterator<Item = Duration> + '_ {
        (0..self.max_attempts).map(move |n| self.delay_before(n))
    }
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
}

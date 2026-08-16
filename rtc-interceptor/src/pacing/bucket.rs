//! Token-bucket pacer core — leaky-bucket rate limiter.
//!
//! Token-bucket semantics with tokens in **bits** (checks `8*len`),
//! refilled at `rate_bps`, capped at `burst_bits`, starting full.

use std::time::{Duration, Instant};

/// Burst size derived from rate and interval.
///
/// ```go
/// f := float64(time.Second.Milliseconds() / interval.Milliseconds())
/// return max(8*1500, int(float64(rate)/f))
/// ```
fn burst_for(rate_bps: usize, interval: Duration) -> usize {
    let interval_ms = interval.as_millis() as f64;
    let interval_ms = if interval_ms == 0.0 { 1.0 } else { interval_ms };
    let f = 1000.0 / interval_ms;
    let by_rate = (rate_bps as f64 / f) as usize;
    by_rate.max(8 * 1500)
}

/// Token bucket that is a pure function of the `Instant` handed in.
#[derive(Debug, Clone)]
pub(crate) struct TokenBucket {
    rate_bps: f64,
    burst_bits: f64,
    tokens: f64,
    last: Option<Instant>,
}

impl TokenBucket {
    pub(crate) fn new(rate_bps: usize, interval: Duration) -> Self {
        let burst = burst_for(rate_bps, interval) as f64;
        Self {
            rate_bps: rate_bps as f64,
            burst_bits: burst,
            tokens: burst,
            last: None,
        }
    }

    pub(crate) fn set_rate(&mut self, rate_bps: usize, interval: Duration) {
        let burst = burst_for(rate_bps, interval) as f64;
        // Cap existing tokens to new burst so limit drop is immediate.
        self.tokens = self.tokens.min(burst);
        self.rate_bps = rate_bps as f64;
        self.burst_bits = burst;
    }

    /// Refill tokens to `now` without consuming, return available bits.
    pub(crate) fn budget(&mut self, now: Instant) -> f64 {
        match self.last {
            None => {
                self.last = Some(now);
                // Starts full.
                self.tokens
            }
            Some(last) => {
                if now <= last {
                    return self.tokens;
                }
                let elapsed = now.duration_since(last).as_secs_f64();
                self.tokens = (self.tokens + elapsed * self.rate_bps).min(self.burst_bits);
                self.last = Some(now);
                self.tokens
            }
        }
    }

    /// Consume `n_bits` if budget allows at `now`.
    pub(crate) fn allow_n(&mut self, now: Instant, n_bits: usize) -> bool {
        let n = n_bits as f64;
        let budget = self.budget(now);
        if budget >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// How long from `now` until `n_bits` can be afforded.
    pub(crate) fn time_until(&mut self, now: Instant, n_bits: usize) -> Duration {
        let n = n_bits as f64;
        let budget = self.budget(now);
        if budget >= n {
            Duration::ZERO
        } else if self.rate_bps <= 0.0 {
            // No progress possible — return a long interval so caller wakes periodically but never drains.
            Duration::from_secs(3600)
        } else {
            let needed = n - budget;
            Duration::from_secs_f64(needed / self.rate_bps)
        }
    }

    #[cfg(test)]
    pub(crate) fn tokens_for_test(&self) -> f64 {
        self.tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_matches_reference() {
        // 1_000_000 bps, 5ms → burst 12_000 (8*1500)
        assert_eq!(burst_for(1_000_000, Duration::from_millis(5)), 12000);
        // 1_000_000 bps, 1ms → rate/f = 1000, still 12k
        assert_eq!(burst_for(1_000_000, Duration::from_millis(1)), 12000);
        // 10_000_000 bps, 5ms → 50k, >12k
        assert_eq!(burst_for(10_000_000, Duration::from_millis(5)), 50000);
    }

    #[test]
    fn budget_refill() {
        let mut b = TokenBucket::new(1_000_000, Duration::from_millis(5));
        let t0 = Instant::now();
        assert_eq!(b.budget(t0), 12000.0);
        assert!(b.allow_n(t0, 8000));
        assert_eq!(b.budget(t0), 4000.0);
        // +5ms refills 5000 bits → 9000
        let t1 = t0 + Duration::from_millis(5);
        assert!((b.budget(t1) - 9000.0).abs() < 1.0);
    }

    #[test]
    fn time_until() {
        let mut b = TokenBucket::new(1_000_000, Duration::from_millis(5));
        let t0 = Instant::now();
        b.allow_n(t0, 12000);
        assert_eq!(b.budget(t0), 0.0);
        let wait = b.time_until(t0, 8000);
        // 8000 bits / 1e6 bps = 8ms
        assert!(wait >= Duration::from_millis(7) && wait <= Duration::from_millis(9));
    }
}

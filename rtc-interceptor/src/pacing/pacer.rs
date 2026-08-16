//! The leaky bucket a pacer meters packets through.

use std::time::{Duration, Instant};

/// Smallest burst any pacer allows, in bits.
///
/// One maximum-sized packet: 1500 bytes, 12 000 bits. A burst below one packet would mean the
/// common case never becomes affordable by waiting, so every packet would take the
/// larger-than-burst path and the rate would stop being enforced at all.
pub const MIN_BURST_BITS: f64 = 8.0 * 1500.0;

/// A token bucket in bits, refilled from elapsed time.
///
/// Unlike upstream's `rate.Limiter`, nothing here reads a clock: the budget is a pure function of
/// the instants handed in. That is what makes a release schedule reproducible in a test rather
/// than merely eventually-correct — pion cannot assert its own schedule without a fake clock.
#[derive(Debug, Clone)]
pub struct Pacer {
    /// Target rate in bits per second.
    bitrate: f64,
    /// Maximum accumulated budget, in bits.
    burst_bits: f64,
    /// Currently available budget, in bits.
    budget_bits: f64,
    /// When the budget was last brought up to date.
    last_refill: Option<Instant>,
}

impl Pacer {
    /// A bucket paced at `bits_per_second`, starting full.
    ///
    /// Starting full rather than empty lets a connection send immediately instead of waiting out
    /// one burst's worth of accumulation, which is what upstream's limiter does too.
    pub fn new(bits_per_second: f64) -> Self {
        let burst_bits = Self::burst_for(bits_per_second);
        Self {
            bitrate: bits_per_second.max(0.0),
            burst_bits,
            budget_bits: burst_bits,
            last_refill: None,
        }
    }

    /// Override the burst size, in bits.
    pub fn with_burst_bits(mut self, burst_bits: f64) -> Self {
        self.burst_bits = burst_bits.max(MIN_BURST_BITS);
        self.budget_bits = self.budget_bits.min(self.burst_bits);
        self
    }

    /// The burst that goes with a rate: a tenth of a second's worth, floored at one packet.
    fn burst_for(bits_per_second: f64) -> f64 {
        (bits_per_second / 10.0).max(MIN_BURST_BITS)
    }

    /// The rate currently being paced at, in bits per second.
    pub fn target_bitrate(&self) -> f64 {
        self.bitrate
    }

    /// Change the rate.
    ///
    /// Synchronous and immediate, because this is what a bandwidth estimator drives: it computes
    /// a new target and the very next release must respect it. Accumulated budget is kept but
    /// clamped to the new burst, so lowering the rate cannot leave a large budget behind that
    /// would let a burst out at the old rate.
    pub fn set_target_bitrate(&mut self, bits_per_second: f64) {
        self.bitrate = bits_per_second.max(0.0);
        self.burst_bits = Self::burst_for(self.bitrate);
        self.budget_bits = self.budget_bits.min(self.burst_bits);
    }

    /// Bring the budget up to `now`.
    pub fn refill(&mut self, now: Instant) {
        if let Some(last) = self.last_refill {
            let elapsed = now.saturating_duration_since(last).as_secs_f64();
            self.budget_bits = (self.budget_bits + elapsed * self.bitrate).min(self.burst_bits);
        }
        self.last_refill = Some(now);
    }

    /// Whether `bits` can be sent now.
    pub fn can_afford(&self, bits: f64) -> bool {
        self.budget_bits >= bits
    }

    /// Spend `bits` from the budget.
    ///
    /// The budget is allowed to go negative on a packet larger than a full burst; otherwise such
    /// a packet could never be sent at all, and a stalled queue is worse than a momentary
    /// overshoot.
    pub fn consume(&mut self, bits: f64) {
        self.budget_bits -= bits;
    }

    /// How long until `bits` becomes affordable.
    ///
    /// `Duration::ZERO` when it already is. At a zero rate nothing ever becomes affordable, which
    /// the caller must treat as "no deadline" rather than waiting forever.
    pub fn time_until_affordable(&self, bits: f64) -> Option<Duration> {
        if self.budget_bits >= bits {
            return Some(Duration::ZERO);
        }
        if self.bitrate <= 0.0 {
            return None;
        }
        Some(Duration::from_secs_f64(
            (bits - self.budget_bits) / self.bitrate,
        ))
    }

    /// The instant `bits` becomes affordable, given the last refill.
    pub fn affordable_at(&self, bits: f64) -> Option<Instant> {
        let last = self.last_refill?;
        self.time_until_affordable(bits).map(|wait| last + wait)
    }

    /// The available budget, in bits.
    pub fn budget_bits(&self) -> f64 {
        self.budget_bits
    }

    /// The maximum the budget can accumulate to, in bits.
    ///
    /// Anything larger than this can never be afforded by waiting, however long the wait — the
    /// budget caps here — so a caller queueing by affordability has to special-case it.
    pub fn burst_bits(&self) -> f64 {
        self.burst_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1 Mb/s, with a burst big enough to be interesting but small enough to exhaust.
    fn pacer() -> Pacer {
        Pacer::new(1_000_000.0).with_burst_bits(MIN_BURST_BITS)
    }

    #[test]
    fn a_new_bucket_starts_full() {
        let pacer = pacer();
        assert_eq!(MIN_BURST_BITS, pacer.budget_bits());
        assert!(pacer.can_afford(MIN_BURST_BITS));
    }

    #[test]
    fn spending_reduces_the_budget() {
        let mut pacer = pacer();
        pacer.consume(1000.0);
        assert_eq!(MIN_BURST_BITS - 1000.0, pacer.budget_bits());
    }

    /// The budget is a function of elapsed time, not of how often refill happens to be called.
    #[test]
    fn the_budget_refills_from_elapsed_time() {
        let now = Instant::now();
        let mut pacer = pacer();
        pacer.refill(now);
        pacer.consume(pacer.budget_bits());
        assert_eq!(0.0, pacer.budget_bits());

        // At 1 Mb/s, 10 ms is 10 000 bits.
        pacer.refill(now + Duration::from_millis(10));
        assert!(
            (pacer.budget_bits() - 10_000.0).abs() < 1.0,
            "{}",
            pacer.budget_bits()
        );
    }

    #[test]
    fn refilling_in_steps_matches_refilling_at_once() {
        let now = Instant::now();

        let mut stepped = pacer();
        stepped.refill(now);
        stepped.consume(stepped.budget_bits());
        for step in 1..=10 {
            stepped.refill(now + Duration::from_millis(step));
        }

        let mut at_once = pacer();
        at_once.refill(now);
        at_once.consume(at_once.budget_bits());
        at_once.refill(now + Duration::from_millis(10));

        assert!((stepped.budget_bits() - at_once.budget_bits()).abs() < 1.0);
    }

    /// The bucket cannot fill beyond its burst, or an idle connection would accumulate an
    /// unbounded allowance and release it all at once the moment it resumed.
    #[test]
    fn the_budget_is_capped_at_the_burst() {
        let now = Instant::now();
        let mut pacer = pacer();
        pacer.refill(now);
        pacer.refill(now + Duration::from_secs(60));

        assert_eq!(MIN_BURST_BITS, pacer.budget_bits());
    }

    #[test]
    fn the_time_until_affordable_is_zero_when_it_already_is() {
        let pacer = pacer();
        assert_eq!(Some(Duration::ZERO), pacer.time_until_affordable(100.0));
    }

    #[test]
    fn the_time_until_affordable_scales_with_the_shortfall() {
        let now = Instant::now();
        let mut pacer = pacer();
        pacer.refill(now);
        pacer.consume(pacer.budget_bits());

        // 10 000 bits short at 1 Mb/s is 10 ms.
        let wait = pacer
            .time_until_affordable(10_000.0)
            .expect("a finite wait");
        assert!((wait.as_secs_f64() - 0.010).abs() < 0.0005, "got {wait:?}");
        assert_eq!(Some(now + wait), pacer.affordable_at(10_000.0));
    }

    /// At a zero rate nothing ever becomes affordable. Reporting a deadline anyway would have the
    /// driver wake for a release that can never happen.
    #[test]
    fn nothing_becomes_affordable_at_a_zero_rate() {
        let now = Instant::now();
        let mut pacer = Pacer::new(0.0);
        pacer.refill(now);
        pacer.consume(pacer.budget_bits());

        assert_eq!(None, pacer.time_until_affordable(1000.0));
        assert_eq!(None, pacer.affordable_at(1000.0));
    }

    #[test]
    fn changing_the_rate_changes_how_fast_the_budget_refills() {
        let now = Instant::now();
        let mut pacer = pacer();
        pacer.refill(now);
        pacer.consume(pacer.budget_bits());

        pacer.set_target_bitrate(2_000_000.0);
        pacer.refill(now + Duration::from_millis(10));

        // Twice the rate, twice the budget for the same elapsed time.
        assert!(
            (pacer.budget_bits() - 20_000.0).abs() < 1.0,
            "{}",
            pacer.budget_bits()
        );
        assert_eq!(2_000_000.0, pacer.target_bitrate());
    }

    /// Lowering the rate must not leave a budget accumulated at the old one, or the first thing
    /// after a rate cut would be a burst at the rate that was just abandoned.
    #[test]
    fn lowering_the_rate_clamps_the_budget_to_the_new_burst() {
        let now = Instant::now();
        let mut pacer = Pacer::new(100_000_000.0);
        pacer.refill(now);
        let before = pacer.budget_bits();

        pacer.set_target_bitrate(1000.0);

        assert!(pacer.budget_bits() < before);
        assert_eq!(
            MIN_BURST_BITS,
            pacer.budget_bits(),
            "clamped to the floor burst"
        );
    }

    #[test]
    fn a_negative_rate_is_treated_as_zero() {
        let mut pacer = Pacer::new(-5.0);
        assert_eq!(0.0, pacer.target_bitrate());
        pacer.set_target_bitrate(-1.0);
        assert_eq!(0.0, pacer.target_bitrate());
    }

    /// A packet larger than a full burst must still get out. Refusing it would stall the queue
    /// permanently behind a packet that can never become affordable.
    #[test]
    fn a_packet_larger_than_the_burst_can_still_be_sent() {
        let now = Instant::now();
        let mut pacer = pacer();
        pacer.refill(now);

        let oversized = MIN_BURST_BITS * 2.0;
        assert!(!pacer.can_afford(oversized));

        // Even after waiting, the budget caps at the burst — so the caller has to spend anyway.
        pacer.refill(now + Duration::from_secs(10));
        assert!(!pacer.can_afford(oversized));

        pacer.consume(oversized);
        assert!(
            pacer.budget_bits() < 0.0,
            "the overshoot is paid back over time"
        );

        pacer.refill(now + Duration::from_secs(20));
        assert_eq!(
            MIN_BURST_BITS,
            pacer.budget_bits(),
            "and recovers to the burst"
        );
    }
}

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
    /// The burst the caller chose, or `None` to derive it from the rate.
    ///
    /// Only the *intent* is stored, never the resulting burst: a burst chosen by the caller is a
    /// property of the sender — how much it is willing to put on the wire at once — while a
    /// derived one is a property of the rate and has to follow it. Keeping the computed value in
    /// a field instead would lose which of the two it was the moment it was written, and
    /// [`Pacer::set_target_bitrate`] could not tell whether it was allowed to replace it.
    configured_burst_bits: Option<f64>,
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
        Self {
            bitrate: bits_per_second.max(0.0),
            configured_burst_bits: None,
            budget_bits: Self::burst_for(bits_per_second),
            last_refill: None,
        }
    }

    /// Override the burst size, in bits.
    ///
    /// A burst set here is kept across rate changes. Deriving it from the rate is only a default;
    /// once the caller has said how much it is willing to release at once, an estimator raising
    /// the rate must not quietly widen that.
    pub fn with_burst_bits(mut self, burst_bits: f64) -> Self {
        self.configured_burst_bits = Some(burst_bits.max(MIN_BURST_BITS));
        self.budget_bits = self.budget_bits.min(self.burst_bits());
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
    ///
    /// A burst set through [`Pacer::with_burst_bits`] survives this; only a burst that was derived
    /// from the rate follows the rate.
    pub fn set_target_bitrate(&mut self, bits_per_second: f64) {
        self.bitrate = bits_per_second.max(0.0);
        self.budget_bits = self.budget_bits.min(self.burst_bits());
    }

    /// Bring the budget up to `now`.
    pub fn refill(&mut self, now: Instant) {
        if let Some(last) = self.last_refill {
            let elapsed = now.saturating_duration_since(last).as_secs_f64();
            self.budget_bits = (self.budget_bits + elapsed * self.bitrate).min(self.burst_bits());
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

    /// Whether `bits` may be released now.
    ///
    /// A packet larger than a full burst can never be *afforded* — the budget caps at the burst —
    /// so it is released once the budget has refilled to that cap, which is as long as waiting can
    /// possibly help. Gating on a full budget rather than releasing unconditionally is what keeps
    /// a run of oversized packets paced: each drives the budget negative and the next must wait
    /// for it to recover, so they leave at the target rate instead of all at once.
    pub fn can_release(&self, bits: f64) -> bool {
        let burst_bits = self.burst_bits();
        if bits > burst_bits {
            return self.budget_bits >= burst_bits;
        }
        self.budget_bits >= bits
    }

    /// The instant `bits` may be released, per [`Pacer::can_release`].
    pub fn releasable_at(&self, bits: f64) -> Option<Instant> {
        self.affordable_at(bits.min(self.burst_bits()))
    }

    /// The maximum the budget can accumulate to, in bits.
    ///
    /// Anything larger than this can never be afforded by waiting, however long the wait — the
    /// budget caps here — which is why release is asked for through [`Pacer::can_release`] rather
    /// than [`Pacer::can_afford`].
    pub fn burst_bits(&self) -> f64 {
        self.configured_burst_bits
            .unwrap_or_else(|| Self::burst_for(self.bitrate))
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
        // A derived burst, so the burst grows with the rate and does not cap what is asserted.
        let mut pacer = Pacer::new(1_000_000.0);
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

    /// A burst the caller chose is not a function of the rate. Losing it on the first estimator
    /// update would silently change how bursty the sender is, long after it was configured.
    #[test]
    fn a_configured_burst_survives_a_rate_change() {
        let mut pacer = Pacer::new(1_000_000.0).with_burst_bits(MIN_BURST_BITS);
        assert_eq!(MIN_BURST_BITS, pacer.burst_bits());

        pacer.set_target_bitrate(100_000_000.0);

        assert_eq!(
            MIN_BURST_BITS,
            pacer.burst_bits(),
            "a rate change must not widen a burst the caller set"
        );
        assert_eq!(100_000_000.0, pacer.target_bitrate());
    }

    /// The derived default still tracks the rate — pinning is opt-in, not the new default.
    #[test]
    fn a_derived_burst_follows_the_rate() {
        let mut pacer = Pacer::new(1_000_000.0);
        assert_eq!(100_000.0, pacer.burst_bits());

        pacer.set_target_bitrate(2_000_000.0);

        assert_eq!(200_000.0, pacer.burst_bits());
    }

    /// A packet larger than the burst waits for a full budget rather than going unconditionally,
    /// so a run of them leaves at the target rate instead of all at once.
    #[test]
    fn an_oversized_packet_waits_for_a_full_budget() {
        let now = Instant::now();
        let mut pacer = pacer();
        pacer.refill(now);
        let oversized = MIN_BURST_BITS * 2.0;

        assert!(pacer.can_release(oversized), "a full budget releases it");
        pacer.consume(oversized);
        assert!(
            !pacer.can_release(oversized),
            "the next one waits for the debt to be repaid"
        );

        // The wait is the debt at the target rate, which is what paces a run of them.
        let at = pacer.releasable_at(oversized).expect("a finite wait");
        assert_eq!(
            Some(Duration::from_secs_f64(oversized / 1_000_000.0)),
            pacer.time_until_affordable(MIN_BURST_BITS)
        );
        pacer.refill(at);
        assert!(pacer.can_release(oversized), "and then it goes");
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

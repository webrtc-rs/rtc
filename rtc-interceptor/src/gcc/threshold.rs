//! The adaptive threshold the delay trend is compared against.

use std::time::{Duration, Instant};

/// Starting threshold, in milliseconds — draft-ietf-rmcat-gcc-02 §5.4.
pub const DEFAULT_INITIAL_MS: f64 = 12.5;

/// A threshold that follows the trend it is judging.
///
/// # Why it adapts
///
/// A fixed threshold cannot work on both a datacentre path and a mobile one: set low enough to
/// detect congestion on a link with microseconds of jitter, it fires constantly on a link with
/// tens of milliseconds of it. Worse, a fixed threshold is what lets a GCC flow be starved by a
/// concurrent loss-based flow — the queue grows past the fixed point, GCC backs off, the other flow
/// takes the space, and GCC never comes back.
///
/// So the threshold rises when the trend is outside it and falls when the trend is inside, slowly,
/// and at different rates: `K_u` (moving away) is larger than `K_d` (moving back), so it yields
/// quickly to a genuine overuse and returns to sensitivity only gradually.
#[derive(Debug, Clone, Copy)]
pub struct AdaptiveThreshold {
    /// Current threshold, in milliseconds. Compared against `|estimate|`.
    value_ms: f64,
    /// Gain when the estimate is outside the threshold.
    increase_gain: f64,
    /// Gain when the estimate is inside it.
    decrease_gain: f64,
    /// When it was last updated, for the time-scaled adaptation.
    last_update: Option<Instant>,
}

impl Default for AdaptiveThreshold {
    fn default() -> Self {
        Self {
            value_ms: DEFAULT_INITIAL_MS,
            increase_gain: 0.01,
            decrease_gain: 0.00018,
            last_update: None,
        }
    }
}

impl AdaptiveThreshold {
    /// A threshold at the draft's starting value.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current threshold, in milliseconds.
    pub fn value_ms(&self) -> f64 {
        self.value_ms
    }

    /// Move the threshold towards `estimate_ms`, given how long since the last update.
    ///
    /// Returns the updated threshold. `now` is a parameter rather than read from a clock: upstream
    /// reads `time.Now()` here, which is why its own threshold tests cannot pin a trajectory.
    pub fn update(&mut self, now: Instant, estimate_ms: f64) -> f64 {
        let elapsed = match self.last_update {
            Some(last) => now.saturating_duration_since(last),
            None => {
                self.last_update = Some(now);
                return self.value_ms;
            }
        };
        self.last_update = Some(now);

        let magnitude = estimate_ms.abs();

        // A wild sample is not evidence about where the threshold belongs; it is evidence that
        // something transient happened. Letting it drag the threshold up would blind the detector
        // to the sustained growth that follows.
        if magnitude > self.value_ms + 15.0 {
            return self.value_ms;
        }

        let gain = if magnitude > self.value_ms {
            self.increase_gain
        } else {
            self.decrease_gain
        };

        // Time-scaled, and capped: a long gap between reports must not move the threshold by an
        // unbounded amount.
        let elapsed_ms = elapsed.as_secs_f64() * 1_000.0;
        let step = gain * (magnitude - self.value_ms) * elapsed_ms.min(100.0);
        self.value_ms = (self.value_ms + step).clamp(6.0, 600.0);

        self.value_ms
    }

    /// How long since this threshold was last updated, if ever.
    pub fn since_update(&self, now: Instant) -> Option<Duration> {
        self.last_update
            .map(|last| now.saturating_duration_since(last))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_starts_at_the_drafts_value() {
        assert_eq!(DEFAULT_INITIAL_MS, AdaptiveThreshold::new().value_ms());
    }

    /// A trend that stays outside pushes the threshold **up**, so a persistently jittery path stops
    /// being read as persistently congested.
    #[test]
    fn a_trend_outside_the_threshold_raises_it() {
        let epoch = Instant::now();
        let mut threshold = AdaptiveThreshold::new();
        threshold.update(epoch, 20.0);

        for step in 1..=50u64 {
            threshold.update(epoch + Duration::from_millis(step * 20), 20.0);
        }

        assert!(
            threshold.value_ms() > DEFAULT_INITIAL_MS,
            "threshold should have risen, got {}",
            threshold.value_ms()
        );
    }

    /// A trend inside brings it back **down**, so sensitivity returns once the path settles.
    #[test]
    fn a_trend_inside_the_threshold_lowers_it() {
        let epoch = Instant::now();
        let mut threshold = AdaptiveThreshold::new();
        threshold.update(epoch, 0.0);

        for step in 1..=500u64 {
            threshold.update(epoch + Duration::from_millis(step * 20), 0.0);
        }

        assert!(
            threshold.value_ms() < DEFAULT_INITIAL_MS,
            "threshold should have fallen, got {}",
            threshold.value_ms()
        );
    }

    /// Up faster than down: the threshold yields quickly to overuse and returns to sensitivity
    /// slowly. Symmetric gains would make it oscillate with the very signal it is judging.
    #[test]
    fn it_rises_faster_than_it_falls() {
        let epoch = Instant::now();

        let mut rising = AdaptiveThreshold::new();
        rising.update(epoch, 25.0);
        let mut falling = AdaptiveThreshold::new();
        falling.update(epoch, 0.0);

        for step in 1..=25u64 {
            let at = epoch + Duration::from_millis(step * 20);
            rising.update(at, 25.0);
            falling.update(at, 0.0);
        }

        let rose = rising.value_ms() - DEFAULT_INITIAL_MS;
        let fell = DEFAULT_INITIAL_MS - falling.value_ms();
        assert!(
            rose > fell,
            "K_u must exceed K_d: rose by {rose}, fell by {fell}"
        );
    }

    /// A single wild sample is transient, not evidence. Letting it drag the threshold up would
    /// blind the detector to sustained growth immediately afterwards.
    #[test]
    fn an_outlier_does_not_move_it() {
        let epoch = Instant::now();
        let mut threshold = AdaptiveThreshold::new();
        threshold.update(epoch, 0.0);

        let before = threshold.value_ms();
        threshold.update(epoch + Duration::from_millis(20), 5_000.0);

        assert_eq!(
            before,
            threshold.value_ms(),
            "an absurd sample must be ignored, not absorbed"
        );
    }

    /// Bounded at both ends, so neither a long quiet spell nor a long storm drives it somewhere it
    /// cannot come back from.
    #[test]
    fn it_stays_within_bounds() {
        let epoch = Instant::now();

        let mut low = AdaptiveThreshold::new();
        low.update(epoch, 0.0);
        for step in 1..=100_000u64 {
            low.update(epoch + Duration::from_millis(step * 20), 0.0);
        }
        assert!(low.value_ms() >= 6.0, "floor breached: {}", low.value_ms());

        let mut high = AdaptiveThreshold::new();
        high.update(epoch, 0.0);
        for step in 1..=100_000u64 {
            // Just outside the current threshold each time, so it is never treated as an outlier.
            let target = high.value_ms() + 1.0;
            high.update(epoch + Duration::from_millis(step * 20), target);
        }
        assert!(
            high.value_ms() <= 600.0,
            "ceiling breached: {}",
            high.value_ms()
        );
    }
}

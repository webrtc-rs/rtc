use super::trendline::OveruseSignal;
use std::time::{Duration, Instant};

/// Internal state of the AIMD rate controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Holding the current estimate after a recent decrease.
    Hold,
    /// Multiplicatively increasing toward available bandwidth.
    Increase,
    /// Multiplicatively decreasing in response to overuse.
    Decrease,
}

/// AIMD rate controller.
///
/// Translates delay-based overuse signals and packet-loss fractions into a
/// target send bitrate, following RFC 8698 / draft-ietf-rmcat-gcc-02 §5.5.
///
/// # Rate adaptation rules
///
/// | Signal     | Action                                              |
/// |------------|-----------------------------------------------------|
/// | Overusing  | Decrease: `estimate × 0.85`                         |
/// | Normal     | Increase: `estimate × 1.08^dt_sec`                  |
/// | Underusing | Increase (same as Normal)                           |
/// | Loss > 10% | Additional decrease: `estimate × (1 - 0.5 × loss)` |
///
/// After a decrease the controller enters `Hold` for [`HOLD_DURATION`] before
/// switching back to `Increase`, preventing rapid oscillation.
pub(crate) struct AimdRateController {
    estimate_bps: f64,
    min_bps: f64,
    max_bps: f64,
    state: State,
    last_update: Option<Instant>,
    last_decrease: Option<Instant>,
}

/// How long to hold the estimate after a multiplicative decrease.
const HOLD_DURATION: Duration = Duration::from_millis(250);

impl AimdRateController {
    pub(crate) fn new(min_bps: f64, max_bps: f64) -> Self {
        // Start at min or 300 kbps, whichever is larger, capped by max.
        let initial = min_bps.max(300_000.0).min(max_bps);
        Self {
            estimate_bps: initial,
            min_bps,
            max_bps,
            state: State::Hold,
            last_update: None,
            last_decrease: None,
        }
    }

    /// Update the rate estimate and return the new target in bps.
    ///
    /// # Parameters
    /// - `signal`: delay-based overuse signal from the trendline filter
    /// - `loss_fraction`: fraction of lost packets in the latest feedback window (`0.0`–`1.0`)
    /// - `now`: current wall-clock time for computing the elapsed interval
    pub(crate) fn update(
        &mut self,
        signal: OveruseSignal,
        loss_fraction: f64,
        now: Instant,
    ) -> f64 {
        let dt_s = self
            .last_update
            .map(|t| now.duration_since(t).as_secs_f64().min(1.0))
            .unwrap_or(0.1);
        self.last_update = Some(now);

        // State machine transitions.
        self.state = match signal {
            OveruseSignal::Overusing => State::Decrease,
            OveruseSignal::Normal | OveruseSignal::Underusing => {
                match self.state {
                    State::Decrease | State::Hold => {
                        // After a decrease, hold briefly before increasing.
                        let held_long_enough = self
                            .last_decrease
                            .map(|t| now.duration_since(t) >= HOLD_DURATION)
                            .unwrap_or(true);
                        if held_long_enough {
                            State::Increase
                        } else {
                            State::Hold
                        }
                    }
                    State::Increase => State::Increase,
                }
            }
        };

        // Apply the rate adjustment.
        match self.state {
            State::Increase => {
                // Multiplicative increase: 8 % per second.
                let alpha = 1.08f64.powf(dt_s);
                self.estimate_bps = (self.estimate_bps * alpha).min(self.max_bps);
            }
            State::Decrease => {
                // Multiplicative decrease × 0.85; immediately enter Hold.
                self.estimate_bps = (self.estimate_bps * 0.85).max(self.min_bps);
                self.last_decrease = Some(now);
                self.state = State::Hold;
            }
            State::Hold => {}
        }

        // Loss-based adjustment (applied additively after delay-based control).
        // > 10 % loss → reduce further; < 2 % → no-op (delay controller allows increase).
        if loss_fraction > 0.1 {
            let factor = 1.0 - 0.5 * loss_fraction;
            self.estimate_bps = (self.estimate_bps * factor).max(self.min_bps);
        }

        self.estimate_bps
    }

    pub(crate) fn estimate_bps(&self) -> f64 {
        self.estimate_bps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increase_on_normal() {
        let mut ctrl = AimdRateController::new(30_000.0, 2_500_000.0);
        // Seed with one update so last_update is set.
        let t0 = Instant::now();
        ctrl.update(OveruseSignal::Normal, 0.0, t0);
        let after = ctrl.update(OveruseSignal::Normal, 0.0, t0 + Duration::from_secs(1));
        // After 1 second of Normal, rate should have increased.
        assert!(after > 300_000.0, "rate should increase on Normal: {after}");
    }

    #[test]
    fn test_decrease_on_overuse() {
        let mut ctrl = AimdRateController::new(30_000.0, 2_500_000.0);
        let t0 = Instant::now();
        // Warm up to 1 Mbps.
        ctrl.estimate_bps = 1_000_000.0;
        let after = ctrl.update(OveruseSignal::Overusing, 0.0, t0);
        assert!(
            after < 1_000_000.0,
            "rate should decrease on Overuse: {after}"
        );
        assert!(
            (after - 850_000.0).abs() < 5_000.0,
            "decrease should be ~×0.85: {after}"
        );
    }

    #[test]
    fn test_hold_after_decrease() {
        let mut ctrl = AimdRateController::new(30_000.0, 2_500_000.0);
        let t0 = Instant::now();
        ctrl.estimate_bps = 1_000_000.0;
        ctrl.update(OveruseSignal::Overusing, 0.0, t0);
        let after_hold = ctrl.update(OveruseSignal::Normal, 0.0, t0 + Duration::from_millis(100));
        // Still in hold window — rate must not increase.
        assert!(
            (after_hold - ctrl.estimate_bps).abs() < 1.0,
            "should be holding: {after_hold}"
        );
    }

    #[test]
    fn test_loss_reduces_rate() {
        let mut ctrl = AimdRateController::new(30_000.0, 2_500_000.0);
        let t0 = Instant::now();
        ctrl.estimate_bps = 1_000_000.0;
        let after = ctrl.update(OveruseSignal::Normal, 0.15, t0); // 15 % loss
        assert!(after < 1_000_000.0, "loss should reduce rate: {after}");
    }

    #[test]
    fn test_clamped_at_min() {
        let mut ctrl = AimdRateController::new(100_000.0, 2_500_000.0);
        ctrl.estimate_bps = 101_000.0;
        let t0 = Instant::now();
        // Multiple overuse decreases should not go below min.
        for _ in 0..20 {
            ctrl.update(OveruseSignal::Overusing, 0.5, t0);
        }
        assert!(
            ctrl.estimate_bps >= 100_000.0,
            "should not fall below min: {}",
            ctrl.estimate_bps
        );
    }

    #[test]
    fn test_clamped_at_max() {
        let mut ctrl = AimdRateController::new(30_000.0, 500_000.0);
        let t0 = Instant::now();
        ctrl.estimate_bps = 490_000.0;
        // Many seconds of Normal should not exceed max.
        for i in 0..20u64 {
            ctrl.update(OveruseSignal::Normal, 0.0, t0 + Duration::from_secs(i));
        }
        assert!(
            ctrl.estimate_bps <= 500_000.0,
            "should not exceed max: {}",
            ctrl.estimate_bps
        );
    }
}

//! The loss-based half: what to do when packets vanish without the queue growing.

use std::time::{Duration, Instant};

/// Below this loss fraction the path is considered healthy and the rate may climb.
pub const DEFAULT_LOW_LOSS: f64 = 0.02;

/// Above this the path is considered congested and the rate must fall.
pub const DEFAULT_HIGH_LOSS: f64 = 0.10;

/// How long between changes, so each is observed before the next.
pub const DEFAULT_LOSS_INTERVAL: Duration = Duration::from_millis(200);

/// Loss-based congestion control, per draft-ietf-rmcat-gcc-02 §5.5.
///
/// # Why delay is not enough
///
/// A path can drop packets without ever queueing them — a wireless link with interference, or a
/// bottleneck whose buffer is so shallow that it overflows before the delay signal moves. The
/// delay-based half sees nothing there, so without this a sender keeps pushing into a link that is
/// discarding a tenth of what it sends.
///
/// Between the two thresholds nothing happens. That band is deliberate: a few per cent loss is
/// normal on a wireless link and reacting to it would give up capacity permanently.
///
/// # Divergence from upstream (D4)
///
/// **This controller may move the target on its own.** Upstream's cannot: its `latestBitrate` is
/// only written inside `onDelayUpdate` (`send_side_bwe.go:304`), so on a lossy link *without*
/// queueing delay its loss estimate is computed and then never applied — exactly the case this
/// exists for. That is a bug rather than a design choice, and it is not inherited.
#[derive(Debug, Clone)]
pub struct LossController {
    /// Current loss-based target, in bits per second.
    target: f64,
    min: f64,
    max: f64,
    low: f64,
    high: f64,
    interval: Duration,
    /// Exponentially-weighted average loss, so one bad report does not swing the target.
    average_loss: Option<f64>,
    last_change: Option<Instant>,
}

impl LossController {
    /// A controller starting at `initial`, clamped to `min..=max`.
    pub fn new(initial: f64, min: f64, max: f64) -> Self {
        Self {
            target: initial.clamp(min, max),
            min,
            max,
            low: DEFAULT_LOW_LOSS,
            high: DEFAULT_HIGH_LOSS,
            interval: DEFAULT_LOSS_INTERVAL,
            average_loss: None,
            last_change: None,
        }
    }

    /// The current loss-based target, in bits per second.
    pub fn target(&self) -> f64 {
        self.target
    }

    /// The smoothed loss fraction, if any feedback has arrived.
    pub fn average_loss(&self) -> Option<f64> {
        self.average_loss
    }

    /// Fold in one batch of feedback: `lost` of `total` packets did not arrive.
    pub fn update(&mut self, now: Instant, lost: usize, total: usize) -> f64 {
        if total == 0 {
            return self.target;
        }

        let sample = lost as f64 / total as f64;
        // Smoothed, but the raw sample still has a say below — a sudden collapse should not have to
        // wait for the average to catch up.
        let average = match self.average_loss {
            Some(previous) => 0.8 * previous + 0.2 * sample,
            None => sample,
        };
        self.average_loss = Some(average);

        if let Some(last) = self.last_change
            && now.saturating_duration_since(last) < self.interval
        {
            return self.target;
        }

        if average.max(sample) < self.low {
            // Healthy: probe for more.
            self.target = (self.target * 1.05).clamp(self.min, self.max);
            self.last_change = Some(now);
        } else if average.min(sample) > self.high {
            // Losing badly: back off in proportion to how badly.
            self.target = (self.target * (1.0 - 0.5 * average)).clamp(self.min, self.max);
            self.last_change = Some(now);
        }
        // Between the thresholds: hold. A few per cent loss is normal, and reacting to it would
        // give up capacity permanently.

        self.target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: f64 = 100_000.0;
    const MAX: f64 = 10_000_000.0;

    fn controller() -> LossController {
        LossController::new(1_000_000.0, MIN, MAX)
    }

    /// Heavy loss brings the target down — and does so on its own, with no delay signal anywhere.
    /// This is D4: upstream computes this and then never applies it.
    #[test]
    fn heavy_loss_lowers_the_target_on_its_own() {
        let epoch = Instant::now();
        let mut controller = controller();
        let before = controller.target();

        let mut at = epoch;
        for _ in 0..10 {
            at += DEFAULT_LOSS_INTERVAL;
            controller.update(at, 20, 100);
        }

        assert!(
            controller.target() < before,
            "20% loss must lower the target: {before} → {}",
            controller.target()
        );
    }

    /// A healthy path climbs.
    #[test]
    fn a_clean_path_raises_the_target() {
        let epoch = Instant::now();
        let mut controller = controller();
        let before = controller.target();

        let mut at = epoch;
        for _ in 0..10 {
            at += DEFAULT_LOSS_INTERVAL;
            controller.update(at, 0, 100);
        }

        assert!(
            controller.target() > before,
            "a lossless path should be probed: {before} → {}",
            controller.target()
        );
    }

    /// The band between the thresholds is where nothing happens. A few per cent loss is normal on a
    /// wireless link, and reacting to it would give up capacity for good.
    #[test]
    fn moderate_loss_changes_nothing() {
        let epoch = Instant::now();
        let mut controller = controller();
        let before = controller.target();

        let mut at = epoch;
        for _ in 0..20 {
            at += DEFAULT_LOSS_INTERVAL;
            // 5%: above the 2% floor, below the 10% ceiling.
            controller.update(at, 5, 100);
        }

        assert_eq!(
            before,
            controller.target(),
            "loss inside the band must not move the target"
        );
    }

    /// Worse loss backs off harder — the reaction is proportional, not a fixed step.
    #[test]
    fn the_backoff_is_proportional_to_the_loss() {
        let epoch = Instant::now();
        let mut mild = controller();
        let mut severe = controller();

        let mut at = epoch;
        for _ in 0..5 {
            at += DEFAULT_LOSS_INTERVAL;
            mild.update(at, 12, 100);
            severe.update(at, 50, 100);
        }

        assert!(
            severe.target() < mild.target(),
            "50% loss should back off further than 12%: {} vs {}",
            severe.target(),
            mild.target()
        );
    }

    /// Empty feedback says nothing, and must not be read as a perfect path.
    #[test]
    fn empty_feedback_changes_nothing() {
        let epoch = Instant::now();
        let mut controller = controller();
        let before = controller.target();

        assert_eq!(before, controller.update(epoch, 0, 0));
        assert_eq!(None, controller.average_loss());
    }

    /// One clamp, from configuration (D3). Upstream clamps this controller to a hard-coded
    /// 100 kb/s–100 Mb/s that ignores the configured range entirely.
    #[test]
    fn the_target_stays_within_configured_bounds() {
        let epoch = Instant::now();
        let mut controller = LossController::new(MIN, MIN, 400_000.0);

        let mut at = epoch;
        for _ in 0..500 {
            at += DEFAULT_LOSS_INTERVAL;
            controller.update(at, 0, 100);
        }
        assert!(
            controller.target() <= 400_000.0,
            "ceiling breached: {}",
            controller.target()
        );

        for _ in 0..500 {
            at += DEFAULT_LOSS_INTERVAL;
            controller.update(at, 90, 100);
        }
        assert!(
            controller.target() >= MIN,
            "floor breached: {}",
            controller.target()
        );
    }
}

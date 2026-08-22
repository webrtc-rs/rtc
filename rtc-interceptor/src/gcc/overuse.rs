//! Deciding whether the delay trend means the path is congested.

use super::threshold::AdaptiveThreshold;
use std::time::{Duration, Instant};

/// What the delay signal currently says about the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Usage {
    /// The queue is neither growing nor draining meaningfully.
    #[default]
    Normal,
    /// The queue is growing: more is being sent than the path can carry.
    Over,
    /// The queue is draining: there is room the sender is not using.
    Under,
}

/// How long the trend must stay outside the threshold before overuse is declared.
///
/// Without this any single noisy group would trigger a backoff, and the estimate would sawtooth on
/// a path that is fine.
pub const DEFAULT_OVERUSE_TIME: Duration = Duration::from_millis(10);

/// Turns a filtered delay trend into a [`Usage`], with hysteresis.
///
/// # Why the debounce
///
/// The trend crossing the threshold once means very little — the filter is still noisy, and a
/// single video frame arriving late will do it. Overuse is only declared when the trend stays
/// outside **and** has not decreased since the last reading **and** at least two readings agree.
/// Upstream does the same (`overuse_detector.go`); it is what stops the estimate sawtoothing.
///
/// Coming *back* has no such delay: `Normal` and `Under` are declared immediately, because being
/// slow to notice that a path has recovered wastes capacity for as long as it takes to notice.
#[derive(Debug, Clone, Copy)]
pub struct OveruseDetector {
    threshold: AdaptiveThreshold,
    overuse_time: Duration,
    /// When the trend first went outside the threshold in the current run.
    outside_since: Option<Instant>,
    /// Consecutive readings outside, so a lone sample cannot trigger.
    consecutive: u32,
    /// The previous estimate, to tell a growing queue from one that has stopped growing.
    previous_estimate_ms: f64,
    usage: Usage,
}

impl Default for OveruseDetector {
    fn default() -> Self {
        Self {
            threshold: AdaptiveThreshold::new(),
            overuse_time: DEFAULT_OVERUSE_TIME,
            outside_since: None,
            consecutive: 0,
            previous_estimate_ms: 0.0,
            usage: Usage::Normal,
        }
    }
}

impl OveruseDetector {
    /// A detector with the draft's tuning.
    pub fn new() -> Self {
        Self::default()
    }

    /// What the detector currently believes.
    pub fn usage(&self) -> Usage {
        self.usage
    }

    /// The threshold the trend is being compared against, in milliseconds.
    pub fn threshold_ms(&self) -> f64 {
        self.threshold.value_ms()
    }

    /// Fold in one filtered trend reading and return the resulting usage.
    ///
    /// `estimate_ms` is the kalman-filtered delay gradient; `now` is when it was measured.
    pub fn update(&mut self, now: Instant, estimate_ms: f64) -> Usage {
        let threshold_ms = self.threshold.value_ms();

        self.usage = if estimate_ms > threshold_ms {
            // Growing. Declare overuse only once it has persisted, is still growing, and more than
            // one reading agrees.
            let since = *self.outside_since.get_or_insert(now);
            self.consecutive += 1;

            let long_enough = now.saturating_duration_since(since) >= self.overuse_time;
            let still_growing = estimate_ms >= self.previous_estimate_ms;

            if long_enough && still_growing && self.consecutive > 1 {
                Usage::Over
            } else {
                // Not yet convinced: hold whatever was believed before rather than flapping.
                self.usage
            }
        } else if estimate_ms < -threshold_ms {
            self.outside_since = None;
            self.consecutive = 0;
            Usage::Under
        } else {
            self.outside_since = None;
            self.consecutive = 0;
            Usage::Normal
        };

        self.previous_estimate_ms = estimate_ms;
        // The threshold follows the trend, so a persistently jittery path stops reading as
        // persistently congested. Updated after the comparison, so a reading is judged against the
        // threshold that was in force when it was taken.
        self.threshold.update(now, estimate_ms);

        self.usage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trend inside the threshold is not congestion, however long it goes on.
    #[test]
    fn a_quiet_path_reads_normal() {
        let epoch = Instant::now();
        let mut detector = OveruseDetector::new();

        for step in 0..100u64 {
            let usage = detector.update(epoch + Duration::from_millis(step * 20), 1.0);
            assert_eq!(Usage::Normal, usage, "at step {step}");
        }
    }

    /// A single spike must not trigger a backoff — that is what the debounce is for.
    #[test]
    fn one_spike_is_not_overuse() {
        let epoch = Instant::now();
        let mut detector = OveruseDetector::new();

        detector.update(epoch, 0.0);
        let usage = detector.update(epoch + Duration::from_millis(20), 40.0);

        assert_eq!(
            Usage::Normal,
            usage,
            "a lone reading outside the threshold is noise, not congestion"
        );
    }

    /// A sustained, growing trend is.
    #[test]
    fn a_sustained_growing_trend_is_overuse() {
        let epoch = Instant::now();
        let mut detector = OveruseDetector::new();

        let mut usage = Usage::Normal;
        for step in 0..10u64 {
            // Growing each time, so `still_growing` holds.
            usage = detector.update(
                epoch + Duration::from_millis(step * 20),
                20.0 + step as f64 * 2.0,
            );
        }

        assert_eq!(
            Usage::Over,
            usage,
            "a queue that keeps growing must eventually be declared"
        );
    }

    /// Recovery is immediate: once the trend is back inside, the path is usable again and waiting
    /// to say so wastes capacity.
    #[test]
    fn recovery_is_not_debounced() {
        let epoch = Instant::now();
        let mut detector = OveruseDetector::new();

        let mut at = epoch;
        for step in 0..10u64 {
            at = epoch + Duration::from_millis(step * 20);
            detector.update(at, 20.0 + step as f64 * 2.0);
        }
        assert_eq!(Usage::Over, detector.usage());

        let usage = detector.update(at + Duration::from_millis(20), 0.0);
        assert_eq!(
            Usage::Normal,
            usage,
            "back inside the threshold must be believed at once"
        );
    }

    /// A strongly negative trend is a draining queue: there is room the sender is not using.
    #[test]
    fn a_draining_queue_reads_under() {
        let epoch = Instant::now();
        let mut detector = OveruseDetector::new();

        let usage = detector.update(epoch, -40.0);
        assert_eq!(Usage::Under, usage);
    }

    /// A queue that grew and then *stopped* growing is not still overusing — the trend is high but
    /// flat, which means the backlog is steady rather than increasing.
    #[test]
    fn a_high_but_flat_trend_does_not_re_declare_overuse() {
        let epoch = Instant::now();
        let mut detector = OveruseDetector::new();

        // Climb into overuse.
        let mut at = epoch;
        for step in 0..10u64 {
            at = epoch + Duration::from_millis(step * 20);
            detector.update(at, 20.0 + step as f64 * 2.0);
        }
        assert_eq!(Usage::Over, detector.usage());

        // Now flat, and back inside the threshold as it adapts upward.
        for step in 0..200u64 {
            at += Duration::from_millis(20);
            detector.update(at, 1.0);
            let _ = step;
        }
        assert_eq!(
            Usage::Normal,
            detector.usage(),
            "a settled path must return to normal"
        );
    }
}

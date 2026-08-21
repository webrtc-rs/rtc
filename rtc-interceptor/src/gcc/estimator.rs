//! `Gcc`: the delay half and the loss half, combined.

use super::loss::LossController;
use super::overuse::OveruseDetector;
use super::rate_calc::RateCalculator;
use super::rate_control::RateController;
use super::slope::SlopeEstimator;
use crate::cc::estimator::{BandwidthEstimator, EstimatorStats};
use crate::rtpfb::acknowledgement::PacketReport;
use std::time::Instant;

/// Rate to start from when nothing is known yet.
pub const DEFAULT_INITIAL_BITRATE: f64 = 300_000.0;
/// Floor. Below this a video call is not worth having.
pub const DEFAULT_MIN_BITRATE: f64 = 100_000.0;
/// Ceiling.
pub const DEFAULT_MAX_BITRATE: f64 = 100_000_000.0;

/// Google Congestion Control.
///
/// # The two halves
///
/// ```text
/// reports ─┬─▶ SlopeEstimator ─▶ OveruseDetector ─▶ RateController ─┐
///          │   group, filter      usage + adaptive   AIMD           ├─▶ min ─▶ target
///          │                      threshold                         │
///          ├─▶ RateCalculator ────────────────────────────────────▶─┘
///          │   what is actually arriving
///          └─▶ LossController ────────────────────────────────────▶─┘
/// ```
///
/// The two are combined by **`min`**: whichever signal is more pessimistic wins. A path can be
/// congested in either way independently — a deep buffer queues without losing, a shallow or lossy
/// one loses without queueing — so neither half alone is sufficient and taking the lower of the two
/// is the only combination that responds to both.
///
/// # Deliberate divergences from upstream
///
/// - **D3 — one clamp.** Applied once, here, from configuration. Upstream clamps inside the loss
///   controller to a hard-coded 100 kb/s–100 Mb/s *and* again in the rate controller to the
///   configured range, and the two disagree.
/// - **D4 — loss may move the target alone.** See [`LossController`].
/// - **No hidden headroom.** [`target_bitrate`](Self::target_bitrate) is what the pacer is asked
///   for. Upstream's pacer silently multiplies by 1.5, so its reported target and its wire rate
///   differ by half again.
/// - **No clock.** Every instant is a parameter, which is what makes a bitrate trajectory
///   reproducible.
pub struct Gcc {
    slope: SlopeEstimator,
    detector: OveruseDetector,
    rate: RateCalculator,
    delay_control: RateController,
    loss_control: LossController,
    min: f64,
    max: f64,
    target: f64,
}

impl Default for Gcc {
    fn default() -> Self {
        Self::new(
            DEFAULT_INITIAL_BITRATE,
            DEFAULT_MIN_BITRATE,
            DEFAULT_MAX_BITRATE,
        )
    }
}

impl Gcc {
    /// An estimator starting at `initial`, held within `min..=max`.
    pub fn new(initial: f64, min: f64, max: f64) -> Self {
        let initial = initial.clamp(min, max);
        Self {
            slope: SlopeEstimator::new(),
            detector: OveruseDetector::new(),
            rate: RateCalculator::default(),
            delay_control: RateController::new(initial, min, max),
            loss_control: LossController::new(initial, min, max),
            min,
            max,
            target: initial,
        }
    }

    /// The delay-based half's current target, in bits per second.
    pub fn delay_based_bitrate(&self) -> f64 {
        self.delay_control.target()
    }

    /// The loss-based half's current target, in bits per second.
    pub fn loss_based_bitrate(&self) -> f64 {
        self.loss_control.target()
    }
}

impl BandwidthEstimator for Gcc {
    fn on_reports(&mut self, now: Instant, reports: &[PacketReport]) {
        if reports.is_empty() {
            return;
        }

        // Delay: group, filter, detect, control.
        let mut usage = self.detector.usage();
        for report in reports {
            if report.arrived {
                self.rate.add(now, report.size);
            }
            if let Some(trend) = self.slope.accumulate(report) {
                usage = self.detector.update(trend.at, trend.estimate_ms);
            }
        }

        let received = self.rate.rate_bits_per_second(now);
        let delay_target = self.delay_control.update(now, usage, received);

        // Loss: a fraction over this batch.
        let lost = reports.iter().filter(|report| !report.arrived).count();
        let loss_target = self.loss_control.update(now, lost, reports.len());

        // Whichever half is more pessimistic wins, clamped once (D3).
        self.target = delay_target.min(loss_target).clamp(self.min, self.max);
    }

    fn target_bitrate(&self) -> f64 {
        self.target
    }

    fn stats(&self) -> EstimatorStats {
        EstimatorStats {
            delay_based_bitrate: Some(self.delay_control.target()),
            loss_based_bitrate: Some(self.loss_control.target()),
            packet_loss: self.loss_control.average_loss(),
            round_trip_time: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
    use std::time::Duration;

    fn report(id: u64, departure: Instant, arrival_ms: Option<u64>) -> PacketReport {
        PacketReport {
            ssrc: 1,
            id,
            rtp_sequence_number: id as u16,
            is_twcc: true,
            twcc_sequence_number: id as u16,
            size: 1500,
            arrived: arrival_ms.is_some(),
            departure,
            arrival: arrival_ms.map(Duration::from_millis),
            ecn: Ecn::default(),
        }
    }

    /// Empty feedback says nothing and must not move anything.
    #[test]
    fn empty_feedback_changes_nothing() {
        let epoch = Instant::now();
        let mut gcc = Gcc::default();
        let before = gcc.target_bitrate();

        gcc.on_reports(epoch, &[]);

        assert_eq!(before, gcc.target_bitrate());
    }

    /// The more pessimistic half wins. Here loss is catastrophic while delay is quiet, so the
    /// combined target must follow loss — which is the whole point of the `min`.
    #[test]
    fn the_more_pessimistic_half_wins() {
        let epoch = Instant::now();
        let mut gcc = Gcc::default();

        let mut at = epoch;
        for batch in 0..20u64 {
            at = epoch + Duration::from_millis(batch * 200);
            // Half the packets vanish; the ones that arrive do so promptly.
            let reports: Vec<PacketReport> = (0..10)
                .map(|index| {
                    let id = batch * 10 + index;
                    let departure = at + Duration::from_millis(index * 10);
                    let arrival = (index % 2 == 0).then(|| batch * 200 + index * 10 + 20);
                    report(id, departure, arrival)
                })
                .collect();
            gcc.on_reports(at, &reports);
        }

        assert!(
            gcc.target_bitrate() <= gcc.loss_based_bitrate() + 1.0,
            "the combined target must not exceed the loss half: {} vs {}",
            gcc.target_bitrate(),
            gcc.loss_based_bitrate()
        );
        assert!(
            gcc.target_bitrate() < DEFAULT_INITIAL_BITRATE,
            "50% loss must bring the target down, got {}",
            gcc.target_bitrate()
        );
    }

    /// One clamp, applied once at the combination point (D3).
    #[test]
    fn the_target_stays_within_configured_bounds() {
        let epoch = Instant::now();
        let mut gcc = Gcc::new(200_000.0, 150_000.0, 250_000.0);

        let mut at = epoch;
        for batch in 0..50u64 {
            at = epoch + Duration::from_millis(batch * 200);
            let reports: Vec<PacketReport> = (0..10)
                .map(|index| {
                    let id = batch * 10 + index;
                    let departure = at + Duration::from_millis(index * 10);
                    report(id, departure, Some(batch * 200 + index * 10 + 20))
                })
                .collect();
            gcc.on_reports(at, &reports);

            assert!(
                (150_000.0..=250_000.0).contains(&gcc.target_bitrate()),
                "target left its bounds: {}",
                gcc.target_bitrate()
            );
        }
    }

    /// The stats expose both halves, so an application can see *why* the target is where it is
    /// rather than only what it is.
    #[test]
    fn stats_report_both_halves() {
        let epoch = Instant::now();
        let mut gcc = Gcc::default();
        gcc.on_reports(epoch, &[report(0, epoch, Some(20)), report(1, epoch, None)]);

        let stats = gcc.stats();
        assert!(stats.delay_based_bitrate.is_some());
        assert!(stats.loss_based_bitrate.is_some());
        assert!(stats.packet_loss.is_some());
    }
}

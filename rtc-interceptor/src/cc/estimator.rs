//! The seam a congestion control algorithm plugs into.

use crate::rtpfb::acknowledgement::PacketReport;
use std::time::Instant;

/// A congestion control algorithm: acknowledged packets in, a target bitrate out.
///
/// # Why this is not an `Interceptor`
///
/// An estimator does not transform packets, it observes them. Making it an interceptor would give
/// it a position in the chain ordering it does not need, four bind methods it has no use for, and —
/// fatally — bury it inside a `Box<dyn Interceptor>` the application cannot reach.
/// `CongestionControlInterceptor` is the interceptor; this is the algorithm it drives.
///
/// # Why the seam is here rather than at the RTCP packet
///
/// Upstream's equivalent interface has six methods, of which one returns a writer, one takes raw
/// RTCP, and one takes a callback. A custom estimator there must parse feedback, own a history of
/// sent packets, own a pacer, and correctly wrap a writer — four responsibilities that have nothing
/// to do with the algorithm, reimplemented per algorithm.
///
/// Here [`PacketReport`] is already resolved by [`History`](crate::History): departure joined with
/// arrival, per packet, in send order. What is left is a function from acknowledgements to a number,
/// which is what a congestion control algorithm actually is.
///
/// # Clocks
///
/// There are none. Every instant arrives as a parameter, so a test can pin an exact bitrate
/// trajectory for a given feedback sequence rather than asserting that something eventually
/// happens.
pub trait BandwidthEstimator: Send + Sync {
    /// Packets whose fate the remote has now reported, in send order.
    ///
    /// Each report carries the instant it *left* this endpoint — the pacer's release instant, not
    /// the instant the application enqueued it — the instant it arrived on the receiver's clock,
    /// its size, and whether it arrived at all. That is everything a delay-based or loss-based
    /// estimator needs.
    ///
    /// May be called with an empty slice; an implementation should treat that as "no news".
    fn on_reports(&mut self, now: Instant, reports: &[PacketReport]);

    /// The current estimate, in bits per second.
    ///
    /// Read after every [`on_reports`](Self::on_reports) and after every
    /// [`handle_timeout`](Self::handle_timeout); a change is what reaches the pacer.
    fn target_bitrate(&self) -> f64;

    /// Periodic work, for an estimator that has any. Most do not.
    fn handle_timeout(&mut self, _now: Instant) {}

    /// When this estimator next wants waking, or `None` if it does not.
    ///
    /// `None` when idle, and the instant must advance — a deadline at or before the `now` just
    /// handed to [`handle_timeout`](Self::handle_timeout) is a busy-loop that wakes the whole chain.
    fn poll_timeout(&self) -> Option<Instant> {
        None
    }

    /// Whatever the algorithm wants to expose. Never load-bearing.
    fn stats(&self) -> EstimatorStats {
        EstimatorStats::default()
    }
}

/// What an estimator is willing to say about itself.
///
/// Deliberately a struct rather than upstream's `map[string]any`: a stringly-typed bag cannot be
/// read without knowing what the implementation happened to put in it. Fields are optional because
/// an estimator that does not compute one should say so rather than report a zero that reads like a
/// measurement.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[non_exhaustive]
pub struct EstimatorStats {
    /// The delay-based half of the estimate, in bits per second.
    pub delay_based_bitrate: Option<f64>,
    /// The loss-based half of the estimate, in bits per second.
    pub loss_based_bitrate: Option<f64>,
    /// Fraction of packets the remote reported lost, over whatever window the estimator uses.
    pub packet_loss: Option<f64>,
    /// Round trip time implied by the most recent feedback.
    pub round_trip_time: Option<std::time::Duration>,
}

/// An estimator that always says the same number.
///
/// Not a placeholder. It is the proof that [`BandwidthEstimator`] is usable with two methods, and
/// it is what the interceptor's own tests drive so that the interceptor's behaviour — recording
/// departures, resolving feedback, attaching the attribute — is separable from any algorithm's.
///
/// It is also a legitimate configuration: a fixed rate with a pacer in front of it is what an
/// application wants when the path is known and it would rather not have an algorithm second-guess
/// it.
#[derive(Debug, Clone, Copy)]
pub struct ConstantBitrate {
    bits_per_second: f64,
}

impl ConstantBitrate {
    /// An estimator fixed at `bits_per_second`.
    pub fn new(bits_per_second: f64) -> Self {
        Self { bits_per_second }
    }
}

impl BandwidthEstimator for ConstantBitrate {
    /// Nothing to learn from: the answer does not depend on the question.
    fn on_reports(&mut self, _now: Instant, _reports: &[PacketReport]) {}

    fn target_bitrate(&self) -> f64 {
        self.bits_per_second
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
    use std::time::Duration;

    fn report(id: u64, arrived: bool, departure: Instant) -> PacketReport {
        PacketReport {
            ssrc: 1,
            id,
            rtp_sequence_number: id as u16,
            is_twcc: true,
            twcc_sequence_number: id as u16,
            size: 1200,
            arrived,
            departure,
            arrival: arrived.then(|| Duration::from_millis(10)),
            ecn: Ecn::default(),
        }
    }

    /// The seam is two methods. If this ever needs a third to compile, the defaults have stopped
    /// carrying their weight and the trait has grown.
    #[test]
    fn an_estimator_needs_only_two_methods() {
        struct Minimal(f64);
        impl BandwidthEstimator for Minimal {
            fn on_reports(&mut self, _now: Instant, reports: &[PacketReport]) {
                // Something an algorithm plausibly does, so this is not vacuously minimal.
                let arrived = reports.iter().filter(|report| report.arrived).count();
                self.0 = 100_000.0 * arrived as f64;
            }
            fn target_bitrate(&self) -> f64 {
                self.0
            }
        }

        let epoch = Instant::now();
        let mut estimator = Minimal(0.0);
        estimator.on_reports(epoch, &[report(1, true, epoch), report(2, false, epoch)]);

        assert_eq!(100_000.0, estimator.target_bitrate());
        assert_eq!(None, estimator.poll_timeout(), "the default is idle");
        assert_eq!(EstimatorStats::default(), estimator.stats());
        estimator.handle_timeout(epoch + Duration::from_secs(1));
    }

    #[test]
    fn a_constant_estimator_ignores_what_it_is_told() {
        let epoch = Instant::now();
        let mut estimator = ConstantBitrate::new(750_000.0);

        assert_eq!(750_000.0, estimator.target_bitrate());
        estimator.on_reports(epoch, &[report(1, false, epoch)]);
        estimator.handle_timeout(epoch + Duration::from_secs(10));
        assert_eq!(
            750_000.0,
            estimator.target_bitrate(),
            "loss and time must not move a rate the application fixed"
        );
    }

    /// `Send + Sync` is a supertrait because the chain is, and a `Box<dyn BandwidthEstimator>`
    /// has to be storable in one.
    #[test]
    fn an_estimator_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ConstantBitrate>();
        assert_send_sync::<Box<dyn BandwidthEstimator>>();
    }
}

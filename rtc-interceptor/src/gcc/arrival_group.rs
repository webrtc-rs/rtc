//! Grouping acknowledgements into bursts, and measuring the delay gradient between them.

use crate::rtpfb::acknowledgement::PacketReport;
use std::time::{Duration, Instant};

/// Packets sent within this of each other are one burst.
///
/// A sender does not emit packets one at a time — a video frame is a burst — and the delay signal
/// lives *between* bursts, not inside them. Grouping too finely turns the pacer's own release
/// spacing into a delay measurement.
pub const DEFAULT_BURST_INTERVAL: Duration = Duration::from_millis(5);

/// A run of packets that departed together, and when they turned up.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ArrivalGroup {
    /// When the first packet of the group left.
    pub first_departure: Instant,
    /// When the last packet of the group left.
    pub departure: Instant,
    /// When the last packet of the group arrived, on the receiver's clock.
    pub arrival: Duration,
    /// How many packets the group holds.
    pub packets: usize,
    /// Total wire size, in bytes.
    pub size: usize,
}

/// The delay gradient between two consecutive groups.
///
/// This is the measurement everything downstream is built on: if the path is not queueing, packets
/// spread apart on arrival exactly as much as they were spread apart on departure, and this is
/// zero. A growing queue makes arrivals spread *more* than departures, and it goes positive.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InterGroupDelay {
    /// Arrival spread minus departure spread, in milliseconds. Positive means the queue is growing.
    pub delta_ms: f64,
    /// When the later group's last packet departed — the instant this measurement belongs to.
    pub at: Instant,
    /// Bytes in the later group, for the rate calculation downstream.
    pub size: usize,
}

/// Collects acknowledgements into bursts and emits the gradient between consecutive bursts.
///
/// # Difference from upstream
///
/// Upstream's accumulator emits a group only when the *next* group begins, so the final group is
/// never emitted (`arrival_group_accumulator.go:26-67`). Live that is invisible; in a test that
/// ends, the last measurement silently disappears. Here [`flush`](Self::flush) exists so a test can
/// close the stream, and the live path is unchanged.
#[derive(Debug, Clone)]
pub struct ArrivalGroupAccumulator {
    burst_interval: Duration,
    current: Option<ArrivalGroup>,
    previous: Option<ArrivalGroup>,
}

impl Default for ArrivalGroupAccumulator {
    fn default() -> Self {
        Self::new(DEFAULT_BURST_INTERVAL)
    }
}

impl ArrivalGroupAccumulator {
    /// An accumulator grouping packets sent within `burst_interval` of each other.
    pub fn new(burst_interval: Duration) -> Self {
        Self {
            burst_interval,
            current: None,
            previous: None,
        }
    }

    /// Feed one report. Returns a gradient when this report started a new group.
    ///
    /// Reports that did not arrive carry no timing and are skipped — loss is the loss controller's
    /// signal, not the delay controller's.
    pub fn accumulate(&mut self, report: &PacketReport) -> Option<InterGroupDelay> {
        let arrival = report.arrival?;
        if !report.arrived {
            return None;
        }

        let Some(current) = self.current.as_mut() else {
            self.current = Some(ArrivalGroup {
                first_departure: report.departure,
                departure: report.departure,
                arrival,
                packets: 1,
                size: report.size,
            });
            return None;
        };

        // Still the same burst: extend it.
        if report
            .departure
            .saturating_duration_since(current.first_departure)
            <= self.burst_interval
        {
            current.departure = current.departure.max(report.departure);
            current.arrival = current.arrival.max(arrival);
            current.packets += 1;
            current.size += report.size;
            return None;
        }

        // A new burst begins, so the one that just closed can be measured against its predecessor.
        let closed = *current;
        self.current = Some(ArrivalGroup {
            first_departure: report.departure,
            departure: report.departure,
            arrival,
            packets: 1,
            size: report.size,
        });

        let measurement = self.previous.map(|previous| gradient(&previous, &closed));
        self.previous = Some(closed);
        measurement
    }

    /// Close the stream, emitting the gradient for the group still open.
    ///
    /// Upstream has no equivalent and therefore drops its last group. Live that does not matter;
    /// for a test with a definite end it is the difference between measuring what happened and
    /// measuring all but the last of it.
    pub fn flush(&mut self) -> Option<InterGroupDelay> {
        let closed = self.current.take()?;
        let measurement = self.previous.map(|previous| gradient(&previous, &closed));
        self.previous = Some(closed);
        measurement
    }
}

/// Arrival spread minus departure spread, between two consecutive groups.
fn gradient(previous: &ArrivalGroup, current: &ArrivalGroup) -> InterGroupDelay {
    let arrival_delta = current.arrival.as_secs_f64() - previous.arrival.as_secs_f64();
    let departure_delta = current
        .departure
        .saturating_duration_since(previous.departure)
        .as_secs_f64();

    InterGroupDelay {
        delta_ms: (arrival_delta - departure_delta) * 1_000.0,
        at: current.departure,
        size: current.size,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtcp::transport_feedbacks::cc_feedback_report::Ecn;

    fn report(departure: Instant, arrival_ms: u64, size: usize) -> PacketReport {
        PacketReport {
            ssrc: 1,
            id: 0,
            rtp_sequence_number: 0,
            is_twcc: true,
            twcc_sequence_number: 0,
            size,
            arrived: true,
            departure,
            arrival: Some(Duration::from_millis(arrival_ms)),
            ecn: Ecn::default(),
        }
    }

    /// Packets sent inside the burst interval are one group, whatever their count.
    #[test]
    fn packets_sent_together_form_one_group() {
        let epoch = Instant::now();
        let mut accumulator = ArrivalGroupAccumulator::default();

        for offset in [0, 1, 2, 3, 4] {
            assert_eq!(
                None,
                accumulator.accumulate(&report(epoch + Duration::from_millis(offset), 100, 1200)),
                "nothing is emitted until a group closes"
            );
        }

        // 20 ms later is a new burst, which closes the first — but there is no predecessor yet.
        assert_eq!(
            None,
            accumulator.accumulate(&report(epoch + Duration::from_millis(20), 120, 1200))
        );
        let group = accumulator
            .flush()
            .expect("the second group closes against the first");
        assert_eq!(1200, group.size, "the second group holds one packet");
    }

    /// A path that is not queueing: arrivals spread exactly as much as departures, so the gradient
    /// is zero. This is the baseline everything else is measured against.
    #[test]
    fn a_path_that_does_not_queue_has_a_zero_gradient() {
        let epoch = Instant::now();
        let mut accumulator = ArrivalGroupAccumulator::default();
        let mut gradients = Vec::new();

        // One packet every 20 ms, arriving 20 ms apart.
        for burst in 0..5u64 {
            let departure = epoch + Duration::from_millis(burst * 20);
            if let Some(delay) = accumulate_and_flush(&mut accumulator, departure, 100 + burst * 20)
            {
                gradients.push(delay.delta_ms);
            }
        }

        assert!(
            gradients.iter().all(|delta| delta.abs() < 1e-6),
            "a non-queueing path must measure zero delay gradient: {gradients:?}"
        );
    }

    /// A queue building: arrivals spread *more* than departures, so the gradient goes positive.
    #[test]
    fn a_growing_queue_has_a_positive_gradient() {
        let epoch = Instant::now();
        let mut accumulator = ArrivalGroupAccumulator::default();
        let mut gradients = Vec::new();

        // Sent 20 ms apart, arriving 30 ms apart: 10 ms of queue per group.
        for burst in 0..5u64 {
            let departure = epoch + Duration::from_millis(burst * 20);
            if let Some(delay) = accumulate_and_flush(&mut accumulator, departure, 100 + burst * 30)
            {
                gradients.push(delay.delta_ms);
            }
        }

        assert!(!gradients.is_empty(), "no gradients were produced");
        assert!(
            gradients.iter().all(|delta| (*delta - 10.0).abs() < 1e-6),
            "each group should measure 10 ms of added delay: {gradients:?}"
        );
    }

    /// A queue draining: arrivals spread *less* than departures, so the gradient goes negative.
    #[test]
    fn a_draining_queue_has_a_negative_gradient() {
        let epoch = Instant::now();
        let mut accumulator = ArrivalGroupAccumulator::default();
        let mut gradients = Vec::new();

        for burst in 0..5u64 {
            let departure = epoch + Duration::from_millis(burst * 20);
            if let Some(delay) = accumulate_and_flush(&mut accumulator, departure, 200 + burst * 15)
            {
                gradients.push(delay.delta_ms);
            }
        }

        assert!(
            gradients.iter().all(|delta| *delta < 0.0),
            "a draining queue must measure negative: {gradients:?}"
        );
    }

    /// Lost packets carry no timing and must not be measured as though they arrived at zero.
    #[test]
    fn lost_packets_are_not_measured() {
        let epoch = Instant::now();
        let mut accumulator = ArrivalGroupAccumulator::default();

        let mut lost = report(epoch, 0, 1200);
        lost.arrived = false;
        lost.arrival = None;

        assert_eq!(None, accumulator.accumulate(&lost));
        assert_eq!(
            None,
            accumulator.flush(),
            "a lost packet must not open a group"
        );
    }

    /// One packet per burst, so every call closes the previous group.
    fn accumulate_and_flush(
        accumulator: &mut ArrivalGroupAccumulator,
        departure: Instant,
        arrival_ms: u64,
    ) -> Option<InterGroupDelay> {
        accumulator.accumulate(&report(departure, arrival_ms, 1200))
    }
}

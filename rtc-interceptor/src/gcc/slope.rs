//! Turning grouped acknowledgements into a filtered delay trend.

use super::arrival_group::{ArrivalGroupAccumulator, InterGroupDelay};
use super::kalman::Kalman;
use crate::rtpfb::acknowledgement::PacketReport;
use std::time::{Duration, Instant};

/// One filtered delay-gradient reading.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DelayTrend {
    /// The raw inter-group measurement, in milliseconds.
    pub measurement_ms: f64,
    /// The filtered trend, in milliseconds. This is what the overuse detector compares.
    pub estimate_ms: f64,
    /// When the measurement belongs to.
    pub at: Instant,
    /// Bytes in the group this reading closed, for the received-rate calculation.
    pub size: usize,
}

/// Grouping plus filtering: acknowledgements in, a delay trend out.
///
/// The two halves are separate types because they are separately testable — the accumulator against
/// hand-built arrival patterns, the filter against numeric sequences — and this joins them without
/// adding behaviour of its own.
#[derive(Debug, Clone, Default)]
pub struct SlopeEstimator {
    groups: ArrivalGroupAccumulator,
    kalman: Kalman,
}

impl SlopeEstimator {
    /// A slope estimator with the draft's default grouping and tuning.
    pub fn new() -> Self {
        Self::default()
    }

    /// A slope estimator grouping packets sent within `burst_interval` of each other.
    pub fn with_burst_interval(burst_interval: Duration) -> Self {
        Self {
            groups: ArrivalGroupAccumulator::new(burst_interval),
            kalman: Kalman::new(),
        }
    }

    /// The current filtered trend, in milliseconds.
    pub fn estimate_ms(&self) -> f64 {
        self.kalman.estimate()
    }

    /// Feed one report; returns a reading when a group closed.
    pub fn accumulate(&mut self, report: &PacketReport) -> Option<DelayTrend> {
        let delay = self.groups.accumulate(report)?;
        Some(self.filter(delay))
    }

    /// Close the stream, emitting the reading for the group still open.
    pub fn flush(&mut self) -> Option<DelayTrend> {
        let delay = self.groups.flush()?;
        Some(self.filter(delay))
    }

    fn filter(&mut self, delay: InterGroupDelay) -> DelayTrend {
        DelayTrend {
            measurement_ms: delay.delta_ms,
            estimate_ms: self.kalman.update(delay.delta_ms),
            at: delay.at,
            size: delay.size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtcp::transport_feedbacks::cc_feedback_report::Ecn;

    fn report(departure: Instant, arrival_ms: u64) -> PacketReport {
        PacketReport {
            ssrc: 1,
            id: 0,
            rtp_sequence_number: 0,
            is_twcc: true,
            twcc_sequence_number: 0,
            size: 1200,
            arrived: true,
            departure,
            arrival: Some(Duration::from_millis(arrival_ms)),
            ecn: Ecn::default(),
        }
    }

    /// End to end over the two halves: a non-queueing path reads flat.
    #[test]
    fn a_steady_path_reads_flat() {
        let epoch = Instant::now();
        let mut slope = SlopeEstimator::new();

        for burst in 0..40u64 {
            slope.accumulate(&report(
                epoch + Duration::from_millis(burst * 20),
                100 + burst * 20,
            ));
        }

        assert!(
            slope.estimate_ms().abs() < 1.0,
            "a steady path should read about zero, got {}",
            slope.estimate_ms()
        );
    }

    /// And a queue building reads positive and rising — the signal P7-05's detector triggers on.
    #[test]
    fn a_queueing_path_reads_positive() {
        let epoch = Instant::now();
        let mut slope = SlopeEstimator::new();

        for burst in 0..40u64 {
            slope.accumulate(&report(
                epoch + Duration::from_millis(burst * 20),
                100 + burst * 26,
            ));
        }

        assert!(
            slope.estimate_ms() > 3.0,
            "6 ms of queue per group should read clearly positive, got {}",
            slope.estimate_ms()
        );
    }

    /// The reading carries the group's size, which is what the received-rate calculation consumes.
    #[test]
    fn a_reading_carries_the_group_size() {
        let epoch = Instant::now();
        let mut slope = SlopeEstimator::new();

        slope.accumulate(&report(epoch, 100));
        slope.accumulate(&report(epoch + Duration::from_millis(20), 120));
        let reading = slope
            .accumulate(&report(epoch + Duration::from_millis(40), 140))
            .expect("the second group closes against the first");

        assert_eq!(1200, reading.size);
    }
}

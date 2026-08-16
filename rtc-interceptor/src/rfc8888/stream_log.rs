//! One remote stream's arrival record.

use crate::jitterbuffer::sequence::SequenceExtender;
use rtcp::transport_feedbacks::cc_feedback_report::{
    CcFeedbackMetricBlock, CcFeedbackReportBlock, Ecn,
};
use std::collections::HashMap;
use std::time::Instant;

/// The most packets one report block can describe, from the 16-bit `num_reports` field.
pub(crate) const MAX_REPORTS_PER_BLOCK: usize = 16384;

/// The arrival-time offset meaning "this packet arrived *after* the report timestamp".
const OFFSET_AFTER_REPORT: u16 = 0x1FFF;

/// The arrival-time offset meaning "longer ago than this field can express".
const OFFSET_TOO_OLD: u16 = 0x1FFE;

/// The largest offset that fits before the two reserved values above.
const OFFSET_MAX: u16 = 0x1FFD;

/// What was observed about one packet.
#[derive(Debug, Clone, Copy)]
struct PacketReport {
    arrival: Instant,
    ecn: Ecn,
}

/// Arrival times for one media stream, kept until they have been reported.
///
/// Sequence numbers are extended before use: the log spans an unbounded run of packets, and a
/// wrap would otherwise put a newer packet behind an older one.
#[derive(Debug)]
pub(crate) struct StreamLog {
    ssrc: u32,
    extender: SequenceExtender,
    /// The next sequence number a report should start from.
    next_to_report: u64,
    /// The highest sequence number seen.
    highest_received: u64,
    initialised: bool,
    log: HashMap<u64, PacketReport>,
}

impl StreamLog {
    pub(crate) fn new(ssrc: u32) -> Self {
        Self {
            ssrc,
            extender: SequenceExtender::new(),
            next_to_report: 0,
            highest_received: 0,
            initialised: false,
            log: HashMap::new(),
        }
    }

    /// Record a packet's arrival.
    ///
    /// Packets older than the report window are dropped: they have already been reported, and
    /// reporting them again would tell the sender a packet arrived twice.
    pub(crate) fn add(&mut self, arrival: Instant, sequence_number: u16, ecn: Ecn) {
        let extended = self.extender.extend(sequence_number);

        if !self.initialised {
            self.initialised = true;
            self.next_to_report = extended;
        }
        if extended < self.next_to_report {
            return;
        }

        self.log.insert(extended, PacketReport { arrival, ecn });
        self.highest_received = self.highest_received.max(extended);
    }

    /// Build the report block covering everything not yet reported.
    ///
    /// Offsets are measured back from `reference`, which is the instant the whole report is
    /// stamped with — every stream in a report shares it, so the sender can compare arrival times
    /// across streams.
    pub(crate) fn metrics_after(
        &mut self,
        reference: Instant,
        max_blocks: usize,
    ) -> CcFeedbackReportBlock {
        if self.log.is_empty() {
            return CcFeedbackReportBlock {
                media_ssrc: self.ssrc,
                begin_sequence: self.next_to_report as u16,
                metric_blocks: Vec::new(),
            };
        }

        // A report block cannot describe more packets than this, so the oldest end of the window
        // is given up rather than reporting a range the format cannot express.
        let mut count = self.highest_received - self.next_to_report + 1;
        if count > max_blocks as u64 {
            count = max_blocks as u64;
            let new_next = self.highest_received + 1 - count;
            self.log
                .retain(|&sequence_number, _| sequence_number >= new_next);
            self.next_to_report = new_next;
        }
        if count == 0 {
            return CcFeedbackReportBlock {
                media_ssrc: self.ssrc,
                begin_sequence: self.next_to_report as u16,
                metric_blocks: Vec::new(),
            };
        }

        let begin = self.next_to_report;
        let mut metric_blocks = Vec::with_capacity(count as usize);

        // Reporting only advances across a contiguous run from the start of the window. A packet
        // not yet seen may still arrive, so the window stops at the first gap and everything from
        // there is reported again next time — the sender needs to know the gap is still a gap.
        //
        // The advancing condition carries that on its own: once `next_to_report` stops at a gap,
        // `extended` keeps climbing past it and the two can never be equal again. Upstream also
        // tracks a separate `gapDetected` flag, which can only short-circuit work and never
        // changes the outcome; it is not reproduced here.
        for extended in begin..=self.highest_received {
            let report = self.log.get(&extended).copied();
            metric_blocks.push(match report {
                Some(report) => CcFeedbackMetricBlock {
                    received: true,
                    ecn: report.ecn,
                    arrival_time_offset: arrival_time_offset(reference, report.arrival),
                },
                None => CcFeedbackMetricBlock::default(),
            });

            if report.is_some() && extended == self.next_to_report {
                self.log.remove(&extended);
                self.next_to_report += 1;
            }
        }

        CcFeedbackReportBlock {
            media_ssrc: self.ssrc,
            begin_sequence: begin as u16,
            metric_blocks,
        }
    }

    /// Whether anything is waiting to be reported.
    pub(crate) fn is_empty(&self) -> bool {
        self.log.is_empty()
    }
}

/// How long before the report timestamp a packet arrived, in units of 1/1024 s.
///
/// Thirteen bits, with two of the values reserved: a packet that arrived *after* the report was
/// stamped reports `0x1FFF`, and one older than the field can express reports `0x1FFE`. Clamping
/// rather than wrapping matters — a wrapped offset would tell the sender a very old packet had
/// just arrived, which is exactly the measurement congestion control must not get wrong.
fn arrival_time_offset(reference: Instant, arrival: Instant) -> u16 {
    if arrival > reference {
        return OFFSET_AFTER_REPORT;
    }
    let offset = reference.duration_since(arrival).as_secs_f64() * 1024.0;
    if offset > f64::from(OFFSET_MAX) {
        return OFFSET_TOO_OLD;
    }
    offset as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn received(block: &CcFeedbackReportBlock) -> Vec<bool> {
        block
            .metric_blocks
            .iter()
            .map(|metric| metric.received)
            .collect()
    }

    #[test]
    fn an_empty_log_reports_nothing() {
        let mut log = StreamLog::new(1);
        let block = log.metrics_after(Instant::now(), MAX_REPORTS_PER_BLOCK);

        assert_eq!(1, block.media_ssrc);
        assert!(block.metric_blocks.is_empty());
    }

    #[test]
    fn a_contiguous_run_is_reported_once_and_then_forgotten() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        for offset in 0..3u16 {
            log.add(now, 100 + offset, Ecn::NotEct);
        }

        let block = log.metrics_after(now, MAX_REPORTS_PER_BLOCK);
        assert_eq!(100, block.begin_sequence);
        assert_eq!(vec![true, true, true], received(&block));

        assert!(
            log.is_empty(),
            "everything reported was contiguous, so nothing is held"
        );
        let second = log.metrics_after(now, MAX_REPORTS_PER_BLOCK);
        assert!(
            second.metric_blocks.is_empty(),
            "and it is not reported a second time"
        );
    }

    /// A gap may still be filled, so reporting stops advancing there — the sender needs to be
    /// told again, in case the packet turns up.
    #[test]
    fn reporting_stops_advancing_at_a_gap() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        log.add(now, 100, Ecn::NotEct);
        log.add(now, 102, Ecn::NotEct);

        let block = log.metrics_after(now, MAX_REPORTS_PER_BLOCK);
        assert_eq!(100, block.begin_sequence);
        assert_eq!(vec![true, false, true], received(&block));

        // 101 arrives late and is still inside the window.
        log.add(now, 101, Ecn::NotEct);
        let second = log.metrics_after(now, MAX_REPORTS_PER_BLOCK);
        assert_eq!(101, second.begin_sequence, "resumes where it stopped");
        assert_eq!(vec![true, true], received(&second));
    }

    #[test]
    fn a_packet_older_than_the_window_is_not_reported_again() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        log.add(now, 100, Ecn::NotEct);
        log.metrics_after(now, MAX_REPORTS_PER_BLOCK);

        log.add(now, 100, Ecn::NotEct);
        assert!(
            log.is_empty(),
            "already reported: saying so again would claim it arrived twice"
        );
    }

    #[test]
    fn the_window_gives_up_its_oldest_end_rather_than_overflowing_the_block() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        for offset in 0..10u16 {
            log.add(now, 100 + offset, Ecn::NotEct);
        }

        let block = log.metrics_after(now, 4);
        assert_eq!(4, block.metric_blocks.len(), "capped at the limit");
        assert_eq!(
            106, block.begin_sequence,
            "the newest four, since the oldest are the least useful"
        );
    }

    #[test]
    fn ecn_markings_are_carried_through() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        log.add(now, 100, Ecn::Ce);
        log.add(now, 101, Ecn::Ect1);

        let block = log.metrics_after(now, MAX_REPORTS_PER_BLOCK);
        assert_eq!(Ecn::Ce, block.metric_blocks[0].ecn);
        assert_eq!(Ecn::Ect1, block.metric_blocks[1].ecn);
    }

    #[test]
    fn a_sequence_number_wrap_does_not_reorder_the_window() {
        let now = Instant::now();
        let mut log = StreamLog::new(1);
        for sequence_number in [65534u16, 65535, 0, 1] {
            log.add(now, sequence_number, Ecn::NotEct);
        }

        let block = log.metrics_after(now, MAX_REPORTS_PER_BLOCK);
        assert_eq!(65534, block.begin_sequence);
        assert_eq!(
            vec![true, true, true, true],
            received(&block),
            "0 follows 65535 rather than opening a 65534-packet gap"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Arrival-time offsets
    // ---------------------------------------------------------------------------------------

    #[test]
    fn an_offset_is_measured_back_from_the_report_timestamp() {
        let now = Instant::now();
        // 1/1024 s per unit, so half a second is 512.
        assert_eq!(
            512,
            arrival_time_offset(now, now - Duration::from_millis(500))
        );
        assert_eq!(0, arrival_time_offset(now, now));
    }

    /// The two reserved values at the edges. Wrapping instead of clamping would tell the sender a
    /// very old packet had just arrived.
    #[test]
    fn offsets_clamp_at_both_edges() {
        let now = Instant::now();

        assert_eq!(
            OFFSET_AFTER_REPORT,
            arrival_time_offset(now, now + Duration::from_millis(1)),
            "arrived after the report was stamped"
        );

        // 0x1FFD units is a shade under 8 seconds; beyond that the field cannot express it.
        let far_past = now - Duration::from_secs(60);
        assert_eq!(OFFSET_TOO_OLD, arrival_time_offset(now, far_past));

        let at_limit = now - Duration::from_secs_f64(f64::from(OFFSET_MAX) / 1024.0);
        assert!(
            arrival_time_offset(now, at_limit) <= OFFSET_MAX,
            "the largest expressible offset is not mistaken for a reserved value"
        );
    }
}

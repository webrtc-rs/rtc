//! What was sent, joined with what the receiver said about it.

use super::acknowledgement::{Acknowledgement, PacketReport};
use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Records outgoing packets and matches incoming feedback against them.
///
/// The two feedback formats identify a packet differently — TWCC by its own transport-wide
/// sequence number, RFC 8888 by the stream's SSRC and RTP sequence number — so both indexes are
/// kept, pointing at one record.
#[derive(Debug, Default)]
pub struct History {
    /// Monotonic id, so reports come out in send order however sequence numbers wrap.
    next_id: u64,
    packets: HashMap<u64, PacketReport>,
    twcc_index: HashMap<u16, u64>,
    ssrc_sequence_index: HashMap<(u32, u16), u64>,
    /// Highest id acknowledged so far.
    highest_acknowledged: Option<u64>,
    /// Lowest id not yet reported to the consumer.
    next_to_report: u64,
}

impl History {
    /// An empty history.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many packets are being tracked.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Whether nothing is being tracked.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Record a packet as it leaves.
    ///
    /// `departure` must be the instant the packet was **released** to the network, not the
    /// instant the application handed it over. A pacer can hold a packet for tens of
    /// milliseconds, and counting that as network delay is exactly the error that makes a
    /// bandwidth estimate collapse (chain contract rule 3).
    #[allow(clippy::too_many_arguments)]
    pub fn add_outgoing(
        &mut self,
        ssrc: u32,
        rtp_sequence_number: u16,
        is_twcc: bool,
        twcc_sequence_number: u16,
        size: usize,
        departure: Instant,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        if is_twcc {
            self.twcc_index.insert(twcc_sequence_number, id);
        }
        self.ssrc_sequence_index
            .insert((ssrc, rtp_sequence_number), id);

        self.packets.insert(
            id,
            PacketReport {
                ssrc,
                id,
                rtp_sequence_number,
                is_twcc,
                twcc_sequence_number,
                size,
                arrived: false,
                departure,
                arrival: None,
                ecn: Ecn::NotEct,
            },
        );

        id
    }

    /// Apply TWCC feedback, returning the round trip time it implies.
    ///
    /// `None` when the feedback names a packet this endpoint has no record of — which happens
    /// routinely at startup and after the history has been pruned, and is not an error.
    pub fn on_twcc_feedback(
        &mut self,
        received_at: Instant,
        acknowledgement: Acknowledgement,
    ) -> Option<Duration> {
        let id = *self.twcc_index.get(&acknowledgement.sequence_number)?;
        self.apply(received_at, id, acknowledgement)
    }

    /// Apply RFC 8888 feedback for one stream, returning the round trip time it implies.
    pub fn on_ccfb_feedback(
        &mut self,
        received_at: Instant,
        ssrc: u32,
        acknowledgement: Acknowledgement,
    ) -> Option<Duration> {
        let id = *self
            .ssrc_sequence_index
            .get(&(ssrc, acknowledgement.sequence_number))?;
        self.apply(received_at, id, acknowledgement)
    }

    fn apply(
        &mut self,
        received_at: Instant,
        id: u64,
        acknowledgement: Acknowledgement,
    ) -> Option<Duration> {
        let packet = self.packets.get_mut(&id)?;

        packet.arrived = acknowledgement.arrived;
        packet.arrival = acknowledgement.arrival;
        packet.ecn = acknowledgement.ecn;

        if packet.arrived {
            self.highest_acknowledged = Some(match self.highest_acknowledged {
                Some(highest) => highest.max(id),
                None => id,
            });
        }

        // Round trip: this feedback arrived now, and the packet left then. Both instants are on
        // this endpoint's clock, so unlike the arrival times this is a real duration.
        Some(received_at.saturating_duration_since(packet.departure))
    }

    /// Take everything up to the highest *arrived* packet since the last call, in send order.
    ///
    /// Packets older than that which are still unreported are treated as lost and then dropped.
    /// Loss feedback alone does not advance the reporting window; losses are emitted when a later
    /// packet is reported as arrived.
    pub fn take_reports(&mut self) -> Vec<PacketReport> {
        let Some(highest) = self.highest_acknowledged else {
            return Vec::new();
        };
        if self.next_to_report > highest {
            return Vec::new();
        }

        let mut reports = Vec::new();
        for id in self.next_to_report..=highest {
            if let Some(packet) = self.packets.remove(&id) {
                if packet.is_twcc {
                    self.twcc_index.remove(&packet.twcc_sequence_number);
                }
                self.ssrc_sequence_index
                    .remove(&(packet.ssrc, packet.rtp_sequence_number));
                reports.push(packet);
            }
        }
        self.next_to_report = highest + 1;

        reports
    }

    /// Drop records of packets sent before `cutoff` that were never acknowledged.
    ///
    /// Without this the history grows without bound on a lossy path: an unacknowledged packet is
    /// never reported and never removed, so nothing else would ever release it.
    pub fn prune_before(&mut self, cutoff: Instant) {
        let stale: Vec<u64> = self
            .packets
            .iter()
            .filter(|(_, packet)| packet.departure < cutoff && !packet.arrived)
            .map(|(&id, _)| id)
            .collect();

        for id in stale {
            if let Some(packet) = self.packets.remove(&id) {
                // Only a TWCC packet has an entry under its transport-wide sequence number. A
                // non-TWCC packet carries whatever the caller passed — typically 0 — and removing
                // that key would evict whichever real TWCC packet holds it.
                if packet.is_twcc {
                    self.twcc_index.remove(&packet.twcc_sequence_number);
                }
                self.ssrc_sequence_index
                    .remove(&(packet.ssrc, packet.rtp_sequence_number));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn history_with_three_packets(now: Instant) -> History {
        let mut history = History::new();
        for sequence_number in 0..3u16 {
            history.add_outgoing(1, 100 + sequence_number, true, sequence_number, 1200, now);
        }
        history
    }

    #[test]
    fn feedback_for_an_unknown_packet_is_ignored() {
        let now = Instant::now();
        let mut history = History::new();

        assert_eq!(
            None,
            history.on_twcc_feedback(now, Acknowledgement::received(5, None, Ecn::NotEct)),
            "nothing was sent with that sequence number"
        );
        assert!(history.take_reports().is_empty());
    }

    #[test]
    fn twcc_feedback_matches_by_transport_wide_sequence_number() {
        let now = Instant::now();
        let mut history = history_with_three_packets(now);

        let rtt = history.on_twcc_feedback(
            now + Duration::from_millis(80),
            Acknowledgement::received(1, Some(Duration::from_millis(5)), Ecn::NotEct),
        );
        assert_eq!(Some(Duration::from_millis(80)), rtt);

        let reports = history.take_reports();
        assert_eq!(2, reports.len(), "everything up to the acknowledgement");
        assert_eq!(101, reports[1].rtp_sequence_number);
        assert!(reports[1].arrived);
        assert!(!reports[0].arrived, "never acknowledged, so a loss");
    }

    /// RFC 8888 names packets by the stream's own sequence number, so two streams can use the
    /// same one and must not be confused.
    #[test]
    fn ccfb_feedback_matches_by_ssrc_and_sequence_number() {
        let now = Instant::now();
        let mut history = History::new();
        history.add_outgoing(1, 500, false, 0, 1000, now);
        history.add_outgoing(2, 500, false, 0, 1000, now);

        history.on_ccfb_feedback(
            now + Duration::from_millis(50),
            2,
            Acknowledgement::received(500, Some(Duration::from_millis(1)), Ecn::Ce),
        );

        let reports = history.take_reports();
        assert_eq!(2, reports.len());
        assert!(
            !reports[0].arrived,
            "stream 1's packet was not acknowledged"
        );
        assert!(reports[1].arrived, "stream 2's was");
        assert_eq!(Ecn::Ce, reports[1].ecn);
    }

    /// Feedback naming a stream that never sent that sequence number must not match another
    /// stream that did. RFC 8888 numbers packets per stream, so the same sequence number is in
    /// use on every stream at once — matching on it alone would attribute one stream's arrival to
    /// another and corrupt both their delay estimates.
    ///
    /// Deterministic by construction: only stream 1 ever sent 500, so a lookup that ignores the
    /// SSRC can only match stream 1's packet, and a correct one can only fail.
    #[test]
    fn ccfb_feedback_for_a_sequence_number_another_stream_sent_does_not_match() {
        let now = Instant::now();
        let mut history = History::new();
        history.add_outgoing(1, 500, false, 0, 1000, now);

        assert_eq!(
            None,
            history.on_ccfb_feedback(
                now + Duration::from_millis(50),
                2,
                Acknowledgement::received(500, Some(Duration::from_millis(1)), Ecn::NotEct),
            ),
            "stream 2 never sent sequence 500"
        );
        assert!(
            history.take_reports().is_empty(),
            "and nothing was acknowledged, so stream 1's packet is still outstanding"
        );
    }

    #[test]
    fn nothing_is_reported_until_something_is_acknowledged() {
        let now = Instant::now();
        let mut history = history_with_three_packets(now);

        assert!(
            history.take_reports().is_empty(),
            "sent but not yet acknowledged"
        );
        assert_eq!(3, history.len(), "and still tracked");
    }

    /// A packet reported once must not be reported again: congestion control would count it
    /// twice, and a loss re-reported later looks like a reordered arrival.
    #[test]
    fn packets_are_reported_once() {
        let now = Instant::now();
        let mut history = history_with_three_packets(now);

        history.on_twcc_feedback(now, Acknowledgement::received(2, None, Ecn::NotEct));
        assert_eq!(3, history.take_reports().len());
        assert!(history.take_reports().is_empty());
        assert!(history.is_empty(), "and released");
    }

    #[test]
    fn later_feedback_reports_only_what_follows() {
        let now = Instant::now();
        let mut history = History::new();
        history.add_outgoing(1, 100, true, 0, 1200, now);
        history.add_outgoing(1, 101, true, 1, 1200, now);

        history.on_twcc_feedback(now, Acknowledgement::received(0, None, Ecn::NotEct));
        assert_eq!(1, history.take_reports().len());

        history.on_twcc_feedback(now, Acknowledgement::received(1, None, Ecn::NotEct));
        let reports = history.take_reports();
        assert_eq!(1, reports.len());
        assert_eq!(101, reports[0].rtp_sequence_number);
    }

    /// A packet reported as lost does not advance the reporting window on its own — otherwise a
    /// long run of losses would flush packets that have not been heard about yet.
    #[test]
    fn a_loss_alone_does_not_advance_the_window() {
        let now = Instant::now();
        let mut history = history_with_three_packets(now);

        history.on_twcc_feedback(now, Acknowledgement::lost(1));
        assert!(
            history.take_reports().is_empty(),
            "nothing has been acknowledged as arrived"
        );
        assert_eq!(3, history.len());
    }

    /// The round trip is measured between two instants on *this* endpoint's clock, unlike the
    /// arrival times, which are on the receiver's.
    #[test]
    fn the_round_trip_is_measured_locally() {
        let now = Instant::now();
        let mut history = History::new();
        history.add_outgoing(1, 100, true, 0, 1200, now);

        assert_eq!(
            Some(Duration::from_millis(120)),
            history.on_twcc_feedback(
                now + Duration::from_millis(120),
                Acknowledgement::received(0, Some(Duration::from_secs(9999)), Ecn::NotEct),
            ),
            "the receiver's arrival clock does not affect it"
        );
    }

    /// Without pruning, an unacknowledged packet is never reported and never removed, so a lossy
    /// path grows the history without bound.
    /// A non-TWCC packet carries a meaningless `twcc_sequence_number` (whatever the caller
    /// passed, typically 0) and was never entered into the TWCC index. Removing that key when it
    /// is released evicts whichever *real* TWCC packet happens to hold it, and that packet's
    /// feedback can then never match.
    #[test]
    fn releasing_a_non_twcc_packet_does_not_evict_a_twcc_packets_index_entry() {
        let now = Instant::now();
        let mut history = History::new();

        // The non-TWCC packet is sent *first*, so reporting it does not sweep up the TWCC one:
        // the reporting window runs to the highest arrived id, and anything below it is dropped
        // as a loss regardless. Ordering this way isolates the index eviction from that.
        history.add_outgoing(2, 200, false, 0, 1200, now);
        // A real TWCC packet holding transport-wide sequence 0, sent after.
        history.add_outgoing(1, 100, true, 0, 1200, now);

        // Release the non-TWCC packet by reporting it.
        history.on_ccfb_feedback(now, 2, Acknowledgement::received(200, None, Ecn::NotEct));
        history.take_reports();

        assert!(
            history
                .on_twcc_feedback(now, Acknowledgement::received(0, None, Ecn::NotEct))
                .is_some(),
            "the TWCC packet is still matchable by its transport-wide sequence number"
        );
    }

    /// The same hazard on the pruning path.
    #[test]
    fn pruning_a_non_twcc_packet_does_not_evict_a_twcc_packets_index_entry() {
        let now = Instant::now();
        let mut history = History::new();

        // Old, non-TWCC, carrying the default 0 it never registered.
        history.add_outgoing(2, 200, false, 0, 1200, now);
        // Recent, a real TWCC packet holding transport-wide sequence 0.
        history.add_outgoing(1, 100, true, 0, 1200, now + Duration::from_secs(5));

        history.prune_before(now + Duration::from_secs(1));

        assert!(
            history
                .on_twcc_feedback(
                    now + Duration::from_secs(5),
                    Acknowledgement::received(0, None, Ecn::NotEct)
                )
                .is_some(),
            "pruning the unrelated packet must not take the TWCC index entry with it"
        );
    }

    /// An acknowledged packet that has not been reported yet must survive pruning, or the arrival
    /// is lost and congestion control never hears about it.
    #[test]
    fn an_acknowledged_packet_is_not_pruned_before_it_is_reported() {
        let now = Instant::now();
        let mut history = History::new();
        history.add_outgoing(1, 100, true, 0, 1200, now);

        history.on_twcc_feedback(
            now + Duration::from_millis(50),
            Acknowledgement::received(0, None, Ecn::NotEct),
        );

        // Well past the cutoff, but it has been acknowledged and not yet collected.
        history.prune_before(now + Duration::from_secs(30));

        let reports = history.take_reports();
        assert_eq!(1, reports.len(), "the arrival survived to be reported");
        assert!(reports[0].arrived);
    }

    #[test]
    fn old_unacknowledged_packets_are_pruned() {
        let now = Instant::now();
        let mut history = History::new();
        history.add_outgoing(1, 100, true, 0, 1200, now);
        history.add_outgoing(1, 101, true, 1, 1200, now + Duration::from_secs(5));

        history.prune_before(now + Duration::from_secs(1));

        assert_eq!(1, history.len(), "only the recent one survives");
        assert_eq!(
            None,
            history.on_twcc_feedback(now, Acknowledgement::received(0, None, Ecn::NotEct)),
            "and the pruned one is no longer matchable"
        );
    }
}

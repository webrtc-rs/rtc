//! RACK-TLP loss detection ([RFC 8985], applied to SCTP as in `draft-ietf-tsvwg-rack-for-sctp`).
//!
//! The classic SCTP loss detectors have a blind spot. Fast retransmit needs three SACKs that
//! report a gap, and the T3-rtx timer waits a full retransmission timeout — one second at
//! minimum. A burst whose *tail* is lost, or the loss of the last few chunks of a message, leaves
//! nothing behind it to open a gap, so recovery falls to T3 and the connection sits idle for a
//! second with its congestion window collapsed to one MTU. On a path that drops a few datagrams a
//! second, that is most of the throughput.
//!
//! Two additions close the gap:
//!
//! * **RACK** declares a chunk lost when a chunk sent *after* it has been delivered and more than
//!   the delivered chunk's round-trip time (plus a small reordering allowance) has passed since
//!   it was sent. It needs no count of duplicate reports, and it also catches the loss of
//!   retransmissions' predecessors that fast retransmit has already given up on.
//! * **TLP** (tail loss probe, the "PTO") fires after roughly two round trips with no
//!   acknowledgement and re-sends the newest outstanding chunk — or lets new data go out — to
//!   solicit a SACK that either confirms delivery or exposes the gap for RACK. Probing is not
//!   loss: it neither collapses the congestion window nor counts toward association failure.
//!
//! [RFC 8985]: https://datatracker.ietf.org/doc/html/rfc8985

use super::windowed_min::WindowedMin;
use super::*;
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// Receiver's worst-case delayed-ACK, added to the probe timeout when a single chunk is
/// outstanding and the peer may hold its SACK back (`ACK_INTERVAL`).
const WORST_CASE_DELAYED_ACK: Duration = Duration::from_millis(200);

/// Slack added to the probe timeout when more than one chunk is outstanding.
const PTO_SLACK: Duration = Duration::from_millis(2);

/// Loss recoveries for which the reordering window stays widened after a spurious
/// retransmission was observed.
const INFLATED_RECOVERIES: u32 = 16;

/// SACK-reported chunks beyond the first hole that stand in for TCP's "three duplicate ACKs".
const DUP_THRESH: u32 = 3;

/// A TSN ordered by serial-number arithmetic ([RFC 1982]), so that a set of TSNs which spans the
/// 32-bit wrap iterates in the order the chunks were sent.
///
/// [RFC 1982]: https://datatracker.ietf.org/doc/html/rfc1982
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SerialTsn(pub(super) u32);

impl Ord for SerialTsn {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.0 == other.0 {
            Ordering::Equal
        } else if sna32lt(self.0, other.0) {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl PartialOrd for SerialTsn {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// RACK's view of the association's recent past.
#[derive(Debug, Default)]
pub(crate) struct RackState {
    /// Whether loss detection and probing are active at all.
    pub(crate) enabled: bool,
    /// Chunks sent exactly once and not yet acknowledged, in send order — the only chunks RACK
    /// reasons about. (Chunks already retransmitted have ambiguous timing, which is also why
    /// they are excluded from RTT sampling.) Entries for chunks that have since been abandoned
    /// or flagged for retransmission are dropped lazily, when a scan reaches them.
    pub(super) outstanding: BTreeSet<SerialTsn>,
    /// When, and as which TSN, the most recently *sent* chunk that has been delivered was sent
    /// (`RACK.xmit_ts`). Chunks of one burst share a timestamp (the instant the association was
    /// polled), so the TSN breaks the tie: within a burst, later TSN means sent later.
    delivered_sent: Option<(Instant, u32)>,
    /// The round-trip time measured by that chunk (`RACK.rtt`).
    delivered_rtt: Duration,
    /// The round-trip times of the last 30 s, for their minimum.
    min_rtt_samples: WindowedMin,
    /// Smallest recent round-trip time, as of the last SACK that found any sample in the window.
    min_rtt: Option<Duration>,
    /// Smoothed round-trip time, to microsecond resolution. The RTO manager's own estimate is in
    /// whole milliseconds, which on a LAN is zero.
    srtt: Option<Duration>,
    /// How long after the newest delivery a chunk sent before it is still given to arrive late.
    reo_wnd: Duration,
    /// Whether any chunk has ever been delivered out of the order it was sent in.
    pub(super) reordering_seen: bool,
    /// Highest TSN delivered so far, to notice that.
    highest_delivered: Option<u32>,
    /// Loss recoveries left during which `reo_wnd` stays widened.
    keep_inflated: u32,
}

impl RackState {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ..Default::default()
        }
    }

    /// Starts tracking a chunk that has just been sent for the first time.
    pub(crate) fn on_sent(&mut self, tsn: u32) {
        if self.enabled {
            self.outstanding.insert(SerialTsn(tsn));
        }
    }

    /// Stops tracking a chunk (acknowledged, retransmitted or abandoned).
    pub(crate) fn forget(&mut self, tsn: u32) {
        if self.enabled {
            self.outstanding.remove(&SerialTsn(tsn));
        }
    }

    /// Records the delivery of a chunk that was sent exactly once, at `sent`.
    pub(crate) fn on_delivered(&mut self, tsn: u32, sent: Instant, now: Instant) {
        if !self.enabled {
            return;
        }
        let rtt = now.saturating_duration_since(sent);
        self.on_rtt_sample(rtt, now);

        match self.highest_delivered {
            Some(highest) if !sna32lt(highest, tsn) => {
                // Delivered after a later chunk already was: reordering.
                self.reordering_seen = true;
            }
            _ => self.highest_delivered = Some(tsn),
        }
        if self
            .delivered_sent
            .is_none_or(|previous| Self::sent_after(sent, tsn, previous))
        {
            self.delivered_sent = Some((sent, tsn));
            self.delivered_rtt = rtt;
        }
    }

    /// Whether a chunk sent at `sent` as `tsn` was sent after the chunk `(at, other)`.
    fn sent_after(sent: Instant, tsn: u32, (at, other): (Instant, u32)) -> bool {
        sent > at || (sent == at && sna32gt(tsn, other))
    }

    fn on_rtt_sample(&mut self, rtt: Duration, now: Instant) {
        self.srtt = Some(match self.srtt {
            None => rtt,
            // RFC 6298: SRTT <- 7/8 SRTT + 1/8 R'.
            Some(srtt) => (srtt * 7 + rtt) / 8,
        });
        self.min_rtt_samples.push(now, rtt);
        self.min_rtt = Some(self.min_rtt_samples.min(now));
    }

    /// Recomputes the reordering window ([RFC 8985] §6.2, step 4).
    ///
    /// `confident_loss`: with no reordering ever seen, a hole behind a delivered chunk is loss,
    /// not lateness, once the sender is already recovering or three chunks have been reported
    /// beyond it — the window then collapses to zero and loss is declared at once.
    /// `spurious`: the SACK reported duplicate TSNs, i.e. something was retransmitted that had
    /// in fact arrived — evidence the window was too narrow.
    /// `recovering`: the sender is in loss recovery.
    ///
    /// [RFC 8985]: https://datatracker.ietf.org/doc/html/rfc8985
    pub(crate) fn update_reorder_window(
        &mut self,
        confident_loss: bool,
        spurious: bool,
        recovering: bool,
        now: Instant,
    ) {
        // Samples age out of the window; once none is left the last minimum stands.
        let windowed = self.min_rtt_samples.min(now);
        if !windowed.is_zero() {
            self.min_rtt = Some(windowed);
        }
        let base = self.min_rtt.map_or(Duration::ZERO, |min| min / 4);

        if confident_loss && !self.reordering_seen {
            self.reo_wnd = Duration::ZERO;
        } else if self.reo_wnd.is_zero() && !base.is_zero() {
            self.reo_wnd = base;
        }

        if spurious && !base.is_zero() {
            self.reo_wnd += base;
            self.keep_inflated = INFLATED_RECOVERIES;
        }

        if !recovering && self.keep_inflated > 0 {
            self.keep_inflated -= 1;
            if self.keep_inflated == 0 && !base.is_zero() {
                self.reo_wnd = base;
            }
        }

        // The window is bounded by the smoothed RTT, or a long-lived connection that once saw
        // heavy reordering would wait that long to notice every later loss.
        if let Some(srtt) = self.srtt {
            self.reo_wnd = self.reo_wnd.min(srtt);
        }
    }

    /// Whether a chunk sent at `sent` as `tsn` was sent after the newest delivered chunk (or
    /// nothing has been delivered yet), so that nothing delivered says anything about it.
    pub(crate) fn newer_than_delivered(&self, sent: Instant, tsn: u32) -> bool {
        self.delivered_sent
            .is_none_or(|delivered| Self::sent_after(sent, tsn, delivered))
    }

    /// When a chunk is to be declared lost: a round trip, plus the reordering window, after it
    /// was sent. Meaningful only for chunks that are not `newer_than_delivered`.
    pub(crate) fn loss_deadline(&self, sent: Instant) -> Instant {
        sent + self.delivered_rtt + self.reo_wnd
    }

    /// Probe timeout: two round trips, plus allowance for a peer that holds back the SACK for a
    /// lone chunk.
    pub(crate) fn probe_timeout(&self, in_flight_chunks: usize) -> Duration {
        match self.srtt {
            Some(srtt) => {
                2 * srtt
                    + if in_flight_chunks <= 1 {
                        WORST_CASE_DELAYED_ACK
                    } else {
                        PTO_SLACK
                    }
            }
            // No round trip measured yet: the initial RTO is the best estimate there is.
            None => Duration::from_secs(1),
        }
    }
}

impl Association {
    /// Starts tracking a chunk sent for the first time. Called as it enters the in-flight queue.
    pub(super) fn rack_on_first_send(&mut self, tsn: u32) {
        self.rack.on_sent(tsn);
    }

    /// RACK's bookkeeping after a SACK has been applied: refresh the reordering window, declare
    /// what is lost, and re-arm the timers.
    pub(super) fn rack_after_sack(&mut self, d: &ChunkSelectiveAck, now: Instant) {
        if !self.rack.enabled {
            return;
        }
        let reported_beyond_hole: u32 = d
            .gap_ack_blocks
            .iter()
            .map(|g| u32::from(g.end).saturating_sub(u32::from(g.start)) + 1)
            .sum();
        self.rack.update_reorder_window(
            self.in_fast_recovery || reported_beyond_hole >= DUP_THRESH,
            !d.duplicate_tsn.is_empty(),
            self.in_fast_recovery,
            now,
        );
        self.rack_detect_loss(now);
        self.schedule_probe(now);
    }

    /// Declares lost every outstanding chunk that RACK's rule condemns, flagging each for
    /// retransmission, and arms the reorder timer for the ones that are merely suspect.
    fn rack_detect_loss(&mut self, now: Instant) {
        let mut lost: Vec<u32> = Vec::new();
        let mut stale: Vec<SerialTsn> = Vec::new();
        let mut next_check: Option<Instant> = None;

        for &SerialTsn(tsn) in &self.rack.outstanding {
            let Some(chunk) = self.inflight_queue.get(tsn) else {
                stale.push(SerialTsn(tsn));
                continue;
            };
            if !chunk.is_outstanding() || chunk.nsent != 1 {
                stale.push(SerialTsn(tsn));
                continue;
            }
            // Already condemned by another detector and waiting its turn to go out.
            if chunk.retransmit || chunk.miss_indicator >= 3 {
                continue;
            }
            let Some(sent) = chunk.since else {
                stale.push(SerialTsn(tsn));
                continue;
            };
            if self.rack.newer_than_delivered(sent, tsn) {
                // Everything after this was sent later still: nothing delivered covers them.
                break;
            }
            let deadline = self.rack.loss_deadline(sent);
            if deadline <= now {
                lost.push(tsn);
            } else {
                next_check = Some(next_check.map_or(deadline, |t| t.min(deadline)));
            }
        }
        for tsn in stale {
            self.rack.outstanding.remove(&tsn);
        }

        self.timers.set(Timer::Rack, next_check);

        if lost.is_empty() {
            return;
        }
        for tsn in &lost {
            if let Some(chunk) = self.inflight_queue.get_mut(*tsn) {
                trace!("[{}] RACK: tsn={} is lost", self.side, tsn);
                chunk.retransmit = true;
            }
            self.rack.outstanding.remove(&SerialTsn(*tsn));
        }
        self.stats.add_rack_losses(lost.len());
        self.t3_retransmit_pending = true;
        // One loss event, one congestion response, however many chunks it took.
        self.enter_loss_recovery();
        self.awake_write_loop();
    }

    /// The congestion response to a loss event (RFC 9260 §7.2.4 / RFC 6582): halve once, and do
    /// not halve again until everything sent so far has been acknowledged.
    pub(super) fn enter_loss_recovery(&mut self) {
        if self.in_fast_recovery {
            return;
        }
        self.in_fast_recovery = true;
        self.fast_recover_exit_point = self.my_next_tsn.wrapping_sub(1);
        self.ssthresh = std::cmp::max(self.cwnd / 2, 4 * self.mtu);
        self.cwnd = self.ssthresh;
        self.partial_bytes_acked = 0;
        trace!(
            "[{}] updated cwnd={} ssthresh={} inflight={} (RACK)",
            self.side,
            self.cwnd,
            self.ssthresh,
            self.inflight_queue.get_num_bytes()
        );
    }

    /// The reorder timer fired: some suspect chunk may have run out of time.
    pub(super) fn on_rack_timeout(&mut self, now: Instant) {
        if !self.rack.enabled {
            return;
        }
        self.rack_detect_loss(now);
    }

    /// (Re)arms the probe timer: when data is outstanding, two round trips from now; otherwise
    /// off. Called whenever data goes out and whenever a SACK moves the window.
    pub(super) fn schedule_probe(&mut self, now: Instant) {
        if !self.rack.enabled {
            return;
        }
        if self.inflight_queue.is_empty() {
            self.timers.set(Timer::Pto, None);
            return;
        }
        let rto = Duration::from_millis(self.rto_mgr.get_rto());
        let pto = self.rack.probe_timeout(self.inflight_queue.len()).min(rto);
        self.timers.set(Timer::Pto, Some(now + pto));
    }

    /// The probe timer fired with nothing acknowledged for two round trips.
    pub(super) fn on_probe_timeout(&mut self, now: Instant) {
        if !self.rack.enabled || self.inflight_queue.is_empty() {
            return;
        }

        // New data, if there is room for it, is the best probe: it moves the transfer along
        // and its SACK answers the question too.
        if let Some(next) = self.pending_queue.peek() {
            let room = self.cwnd.min(self.rwnd) as usize;
            if self.inflight_queue.get_num_bytes() + next.user_data.len() <= room {
                self.awake_write_loop();
                return;
            }
        }

        // Otherwise re-send the newest outstanding chunk.
        let newest = self
            .inflight_queue
            .sorted
            .iter()
            .rev()
            .copied()
            .find(|&tsn| {
                self.inflight_queue
                    .get(tsn)
                    .is_some_and(ChunkPayloadData::is_outstanding)
            });
        if let Some(tsn) = newest
            && let Some(chunk) = self.inflight_queue.get_mut(tsn)
            && !chunk.retransmit
        {
            trace!("[{}] PTO: probing with tsn={}", self.side, tsn);
            chunk.retransmit = true;
            self.t3_retransmit_pending = true;
            self.stats.inc_pto_probes();
            self.awake_write_loop();
        }
        // The T3-rtx timer keeps running behind the probe: if even that goes unanswered, this
        // is a real timeout and is treated as one.
        let _ = now;
    }
}

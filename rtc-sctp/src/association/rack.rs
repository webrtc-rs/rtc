//! Time-based loss detection (RFC 8985 RACK-TLP) with the undo of a needless cut, for SCTP:
//! the SACK duplicate TSN list stands in for TCP's DSACK, and a TSN for a sequence number.

use crate::util::{sna32gt, sna32gte, sna32lt, sna32lte};
use rustc_hash::{FxHashMap, FxHashSet};
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The reordering window stays grown for this many recoveries after a duplicate report.
const REO_WND_PERSIST: u32 = 16;
/// Gap-acknowledged chunks that start recovery while no reordering has been seen.
const DUP_THRESH: u32 = 3;
/// The window over which the least round trip is kept.
const MIN_RTT_WINDOW: Duration = Duration::from_secs(300);
/// The longest a receiver may delay a SACK (RFC 9260 section 6.2).
const MAX_ACK_DELAY: Duration = Duration::from_millis(200);
/// The probe timeout before any round trip is measured.
const INITIAL_PTO: Duration = Duration::from_secs(1);
/// Resent TSNs remembered for telling a repeat of a resend from one the network made.
const RECENTLY_RESENT: usize = 4096;

/// A chunk the latest SACK acknowledged for the first time.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Delivered {
    pub(crate) tsn: u32,
    pub(crate) xmit_ts: Instant,
    pub(crate) nsent: u32,
    /// Set when the cumulative TSN reached it, so every chunk sent before it had arrived.
    pub(crate) cumulative: bool,
}

/// The window and threshold before the first of `cuts` cuts, and each TSN resent since it with
/// the instant of its resend.
#[derive(Debug)]
pub(crate) struct Undo {
    pub(crate) cwnd: u32,
    pub(crate) ssthresh: u32,
    resent: FxHashMap<u32, Instant>,
    pub(crate) cuts: u32,
}

/// The sender's RACK-TLP state for one association.
#[derive(Debug)]
pub(crate) struct Rack {
    /// The latest transmission time among delivered chunks, and that chunk's TSN.
    xmit_ts: Option<Instant>,
    end_tsn: u32,
    /// The round trip of the chunk most recently delivered.
    rtt: Duration,
    min_rtt: Option<(Duration, Instant)>,
    srtt: Option<Duration>,
    /// The highest TSN delivered so far.
    fack: Option<u32>,
    pub(crate) reordering_seen: bool,
    reo_wnd_mult: u32,
    reo_wnd_persist: u32,
    dsack_round: Option<u32>,
    /// Set while a loss probe is outstanding: the highest TSN sent when it went out.
    pub(crate) tlp_end_tsn: Option<u32>,
    /// The TSN a probe resent, when it resent one.
    pub(crate) tlp_resent_tsn: Option<u32>,
    pub(crate) sampled_since_probe: bool,
    undo: Option<Undo>,
    /// Set once a repeat names a TSN never resent: the network duplicates packets (RFC 3708).
    undo_off: bool,
    recently_resent: VecDeque<u32>,
    recently_resent_set: FxHashSet<u32>,
}

impl Default for Rack {
    fn default() -> Self {
        Self {
            xmit_ts: None,
            end_tsn: 0,
            rtt: Duration::ZERO,
            min_rtt: None,
            srtt: None,
            fack: None,
            reordering_seen: false,
            reo_wnd_mult: 1,
            reo_wnd_persist: 0,
            dsack_round: None,
            tlp_end_tsn: None,
            tlp_resent_tsn: None,
            sampled_since_probe: true,
            undo: None,
            undo_off: false,
            recently_resent: VecDeque::new(),
            recently_resent_set: FxHashSet::default(),
        }
    }
}

/// Whether a send at `t1` of `tsn1` came after a send at `t2` of `tsn2`.
fn sent_after(t1: Instant, tsn1: u32, t2: Instant, tsn2: u32) -> bool {
    t1 > t2 || (t1 == t2 && sna32gt(tsn1, tsn2))
}

/// Orders TSNs by serial number arithmetic.
fn tsn_order(a: u32, b: u32) -> Ordering {
    if a == b {
        Ordering::Equal
    } else if sna32lt(a, b) {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// What one pass of loss detection found.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Detection {
    pub(crate) lost: Vec<u32>,
    /// How long until the next chunk passes its deadline, when one is pending.
    pub(crate) timeout: Option<Duration>,
}

impl Rack {
    /// Steps 1 to 3 of RFC 8985 section 6.2, over the chunks one SACK delivered. The smoothed
    /// and least round trips sample only chunks that arrived in order, as TCP's timestamps do.
    pub(crate) fn on_delivered(&mut self, delivered: &mut [Delivered], now: Instant) {
        delivered.sort_by(|a, b| {
            a.xmit_ts
                .cmp(&b.xmit_ts)
                .then_with(|| tsn_order(a.tsn, b.tsn))
        });
        let mut sample = None;
        for d in delivered.iter() {
            let rtt = now.saturating_duration_since(d.xmit_ts);
            if d.nsent == 1 {
                if d.cumulative {
                    sample = Some(rtt);
                }
            } else if self.min_rtt.is_some_and(|(min, _)| rtt < min) {
                continue;
            }
            self.rtt = rtt;
            let later = match self.xmit_ts {
                Some(xmit_ts) => sent_after(d.xmit_ts, d.tsn, xmit_ts, self.end_tsn),
                None => true,
            };
            if later {
                self.xmit_ts = Some(d.xmit_ts);
                self.end_tsn = d.tsn;
            }
        }
        if let Some(rtt) = sample {
            self.on_rtt_sample(rtt, now);
        }

        delivered.sort_by(|a, b| tsn_order(a.tsn, b.tsn));
        for d in delivered.iter() {
            match self.fack {
                Some(fack) if !sna32gt(d.tsn, fack) => {
                    if sna32lt(d.tsn, fack) && d.nsent == 1 {
                        self.reordering_seen = true;
                    }
                }
                _ => self.fack = Some(d.tsn),
            }
        }
    }

    fn on_rtt_sample(&mut self, rtt: Duration, now: Instant) {
        let replace = match self.min_rtt {
            Some((min, at)) => rtt <= min || now.saturating_duration_since(at) > MIN_RTT_WINDOW,
            None => true,
        };
        if replace {
            self.min_rtt = Some((rtt, now));
        }
        self.srtt = Some(match self.srtt {
            Some(srtt) => (srtt * 7 + rtt) / 8,
            None => rtt,
        });
        self.sampled_since_probe = true;
    }

    /// Step 4: a duplicate report grows the window once per round trip, `next_tsn` marking it.
    pub(crate) fn on_ack(&mut self, cumulative_tsn: u32, duplicates: bool, next_tsn: u32) {
        if self
            .dsack_round
            .is_some_and(|round| sna32gte(cumulative_tsn.wrapping_add(1), round))
        {
            self.dsack_round = None;
        }
        if duplicates && self.dsack_round.is_none() {
            self.dsack_round = Some(next_tsn);
            self.reo_wnd_mult += 1;
            self.reo_wnd_persist = REO_WND_PERSIST;
        }
    }

    /// Each recovery that ends spends one of the grown window's recoveries.
    pub(crate) fn on_recovery_exit(&mut self) {
        self.reo_wnd_persist = self.reo_wnd_persist.saturating_sub(1);
        if self.reo_wnd_persist == 0 {
            self.reo_wnd_mult = 1;
        }
    }

    /// The reordering window: a quarter of the least round trip, plus a quarter of the smoothed
    /// one per later step, up to the smoothed one; zero while the gaps alone call a loss.
    pub(crate) fn reo_wnd(&self, in_recovery: bool, sacked: u32) -> Duration {
        if !self.reordering_seen && (in_recovery || sacked >= DUP_THRESH) {
            return Duration::ZERO;
        }
        let (Some((min_rtt, _)), Some(srtt)) = (self.min_rtt, self.srtt) else {
            return Duration::ZERO;
        };
        (min_rtt / 4 + srtt * (self.reo_wnd_mult - 1) / 4).min(srtt)
    }

    /// Step 5 over `(tsn, xmit_ts, nsent)` of each outstanding chunk not yet marked lost, in
    /// TSN order.
    pub(crate) fn detect_loss(
        &self,
        outstanding: impl IntoIterator<Item = (u32, Instant, u32)>,
        reo_wnd: Duration,
        now: Instant,
    ) -> Detection {
        let mut detection = Detection::default();
        let Some(rack_xmit_ts) = self.xmit_ts else {
            return detection;
        };
        for (tsn, xmit_ts, nsent) in outstanding {
            if sent_after(xmit_ts, tsn, rack_xmit_ts, self.end_tsn) {
                if nsent == 1 {
                    break;
                }
                continue;
            }
            let deadline = xmit_ts + self.rtt + reo_wnd;
            if deadline <= now {
                detection.lost.push(tsn);
            } else {
                let remaining = deadline - now;
                detection.timeout = Some(detection.timeout.map_or(remaining, |t| t.max(remaining)));
            }
        }
        detection
    }

    /// The probe timeout of RFC 8985 section 7.2, before the T3-rtx clamp.
    pub(crate) fn pto(&self, flight_of_one: bool) -> Duration {
        match self.srtt {
            Some(srtt) if flight_of_one => srtt * 2 + MAX_ACK_DELAY,
            Some(srtt) => srtt * 2,
            None => INITIAL_PTO,
        }
    }

    /// Keeps the window and threshold from before a cut; a cut while an earlier one is still
    /// pending joins it, so both are undone together or neither is.
    pub(crate) fn on_cut(&mut self, cwnd: u32, ssthresh: u32) {
        if self.undo_off {
            return;
        }
        match self.undo.as_mut() {
            Some(undo) => undo.cuts += 1,
            None => {
                self.undo = Some(Undo {
                    cwnd,
                    ssthresh,
                    resent: FxHashMap::default(),
                    cuts: 1,
                });
            }
        }
    }

    /// Records a resend; a TSN resent twice since a cut leaves that cut standing, since a
    /// repeat cannot tell which copy arrived second (RFC 3708 step A.3).
    pub(crate) fn on_resent(&mut self, tsn: u32, now: Instant) {
        if self.recently_resent_set.insert(tsn) {
            self.recently_resent.push_back(tsn);
            if self.recently_resent.len() > RECENTLY_RESENT
                && let Some(oldest) = self.recently_resent.pop_front()
            {
                self.recently_resent_set.remove(&oldest);
            }
        }
        if let Some(undo) = self.undo.as_mut()
            && undo.resent.insert(tsn, now).is_some()
        {
            self.undo = None;
        }
    }

    /// Drops every pending undo, as a retransmission timeout does.
    pub(crate) fn forget_cuts(&mut self) {
        self.undo = None;
        self.tlp_end_tsn = None;
        self.tlp_resent_tsn = None;
    }

    /// Reads a SACK's duplicate TSNs, and returns whether one named a resend since a cut: the
    /// original arrived, so the resend was needless and the path reorders.
    pub(crate) fn on_duplicates(&mut self, duplicates: &[u32]) -> bool {
        let mut needless_resend = false;
        for tsn in duplicates {
            if self.tlp_resent_tsn == Some(*tsn) {
                self.tlp_end_tsn = None;
                self.tlp_resent_tsn = None;
            }
            if !self.recently_resent_set.contains(tsn) {
                self.undo_off = true;
                self.undo = None;
            }
            if let Some(undo) = self.undo.as_mut()
                && undo.resent.remove(tsn).is_some()
            {
                needless_resend = true;
                self.reordering_seen = true;
            }
        }
        needless_resend
    }

    /// A resend acknowledged cumulatively with no duplicate report for one retransmission
    /// timeout `rto` repaired a loss, and the cuts pending with it stand.
    pub(crate) fn on_cumulative_ack(&mut self, cumulative_tsn: u32, now: Instant, rto: Duration) {
        if self.undo.as_ref().is_some_and(|undo| {
            undo.resent.iter().any(|(tsn, at)| {
                sna32lte(*tsn, cumulative_tsn) && now.saturating_duration_since(*at) > rto
            })
        }) {
            self.undo = None;
        }
    }

    /// Hands over the pending undo once every resend since its first cut proved needless.
    pub(crate) fn take_proven_undo(&mut self) -> Option<Undo> {
        if self
            .undo
            .as_ref()
            .is_some_and(|undo| undo.resent.is_empty())
        {
            self.undo.take()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivered(tsn: u32, xmit_ts: Instant, nsent: u32) -> Delivered {
        Delivered {
            tsn,
            xmit_ts,
            nsent,
            cumulative: true,
        }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn a_chunk_sent_well_before_the_latest_delivered_one_is_lost() {
        let t0 = Instant::now();
        let mut rack = Rack {
            reordering_seen: true,
            ..Rack::default()
        };
        rack.on_delivered(&mut [delivered(12, t0 + ms(20), 1)], t0 + ms(60));
        let reo_wnd = rack.reo_wnd(false, 1);

        assert_eq!(ms(10), reo_wnd);
        let found = rack.detect_loss(
            [(10, t0, 1), (11, t0 + ms(15), 1), (13, t0 + ms(21), 1)],
            reo_wnd,
            t0 + ms(60),
        );
        assert_eq!(vec![10], found.lost);
        assert_eq!(Some(ms(5)), found.timeout);
    }

    #[test]
    fn a_duplicate_report_grows_the_window_once_per_round_trip_up_to_the_smoothed_round_trip() {
        let t0 = Instant::now();
        let mut rack = Rack::default();
        rack.on_delivered(&mut [delivered(1, t0, 1)], t0 + ms(20));
        rack.reordering_seen = true;
        assert_eq!(ms(5), rack.reo_wnd(false, 0));

        rack.on_ack(1, true, 100);
        rack.on_ack(1, true, 120);
        assert_eq!(ms(10), rack.reo_wnd(false, 0));

        for round in 0..10 {
            rack.on_ack(100 + 20 * round, true, 120 + 20 * round);
        }
        assert_eq!(ms(20), rack.reo_wnd(false, 0));
    }

    #[test]
    fn the_grown_window_lasts_sixteen_recoveries() {
        let t0 = Instant::now();
        let mut rack = Rack::default();
        rack.on_delivered(&mut [delivered(1, t0, 1)], t0 + ms(40));
        rack.reordering_seen = true;
        rack.on_ack(1, true, 10);
        for _ in 0..15 {
            rack.on_recovery_exit();
        }
        assert_eq!(ms(20), rack.reo_wnd(false, 0));
        rack.on_recovery_exit();
        assert_eq!(ms(10), rack.reo_wnd(false, 0));
    }

    #[test]
    fn without_reordering_three_gap_acknowledged_chunks_close_the_window() {
        let t0 = Instant::now();
        let mut rack = Rack::default();
        rack.on_delivered(&mut [delivered(1, t0, 1)], t0 + ms(40));
        assert_eq!(Duration::ZERO, rack.reo_wnd(false, 3));
        assert_eq!(Duration::ZERO, rack.reo_wnd(true, 0));
        rack.on_delivered(&mut [delivered(5, t0, 1)], t0 + ms(40));
        rack.on_delivered(&mut [delivered(3, t0, 1)], t0 + ms(40));
        assert!(
            rack.reordering_seen,
            "an earlier chunk delivered after a later one"
        );
        assert_eq!(ms(10), rack.reo_wnd(false, 3));
    }

    #[test]
    fn a_resent_chunk_acknowledged_within_the_least_round_trip_moves_nothing() {
        let t0 = Instant::now();
        let mut rack = Rack::default();
        rack.on_delivered(&mut [delivered(1, t0, 1)], t0 + ms(40));
        rack.on_delivered(&mut [delivered(2, t0 + ms(70), 2)], t0 + ms(80));
        assert_eq!(
            Some(t0),
            rack.xmit_ts,
            "an ambiguous acknowledgement moves nothing"
        );
        assert!(
            !rack.reordering_seen,
            "a resent chunk says nothing about reordering"
        );
    }

    #[test]
    fn a_chunk_acknowledged_out_of_order_times_loss_but_gives_no_round_trip_sample() {
        let t0 = Instant::now();
        let mut rack = Rack::default();
        rack.on_delivered(&mut [delivered(1, t0, 1)], t0 + ms(40));
        let ahead = Delivered {
            cumulative: false,
            ..delivered(3, t0 + ms(40), 1)
        };
        rack.on_delivered(&mut [ahead], t0 + ms(41));

        assert_eq!(Some(ms(40)), rack.srtt);
        assert_eq!(Some(ms(40)), rack.min_rtt.map(|(min, _)| min));
        assert_eq!(
            ms(1),
            rack.rtt,
            "the latest delivery still times the deadlines"
        );
        assert_eq!(Some(t0 + ms(40)), rack.xmit_ts);
    }

    #[test]
    fn the_probe_waits_out_a_delayed_sack_when_one_chunk_is_in_flight() {
        let t0 = Instant::now();
        let mut rack = Rack::default();
        assert_eq!(INITIAL_PTO, rack.pto(false));
        rack.on_delivered(&mut [delivered(1, t0, 1)], t0 + ms(40));
        assert_eq!(ms(80), rack.pto(false));
        assert_eq!(ms(280), rack.pto(true));
    }

    #[test]
    fn a_repeat_of_every_resend_since_the_cut_proves_it_needless() {
        let t0 = Instant::now();
        let mut rack = Rack::default();
        rack.on_cut(100_000, 200_000);
        rack.on_resent(5, t0);
        rack.on_resent(6, t0);

        assert!(rack.on_duplicates(&[5]));
        assert!(
            rack.take_proven_undo().is_none(),
            "6 may still have been needed"
        );
        assert!(rack.on_duplicates(&[6]));
        let undo = rack.take_proven_undo().expect("both resends were needless");
        assert_eq!((100_000, 200_000, 1), (undo.cwnd, undo.ssthresh, undo.cuts));
    }

    #[test]
    fn a_chunk_resent_twice_leaves_its_cut_standing() {
        let t0 = Instant::now();
        let mut rack = Rack::default();
        rack.on_cut(100_000, 200_000);
        rack.on_resent(5, t0);
        rack.on_resent(5, t0 + ms(50));

        rack.on_duplicates(&[5]);
        assert!(
            rack.take_proven_undo().is_none(),
            "a repeat cannot say which copy it was"
        );
    }

    #[test]
    fn a_repeat_of_a_chunk_never_resent_turns_the_undo_off_for_good() {
        let t0 = Instant::now();
        let mut rack = Rack::default();
        rack.on_cut(100_000, 200_000);
        rack.on_resent(5, t0);

        assert!(!rack.on_duplicates(&[7]), "the network itself repeated 7");
        rack.on_duplicates(&[5]);
        assert!(rack.take_proven_undo().is_none());

        rack.on_cut(50_000, 100_000);
        rack.on_resent(9, t0 + ms(100));
        rack.on_duplicates(&[9]);
        assert!(
            rack.take_proven_undo().is_none(),
            "no undo for the rest of the association"
        );
    }

    #[test]
    fn past_the_first_step_the_window_grows_by_a_quarter_of_the_smoothed_round_trip() {
        let t0 = Instant::now();
        let mut rack = Rack::default();
        rack.on_delivered(&mut [delivered(1, t0, 1)], t0 + ms(40));
        rack.on_delivered(
            &mut [delivered(2, t0 + ms(40), 1)],
            t0 + ms(40) + Duration::from_micros(200),
        );
        rack.reordering_seen = true;
        // The least round trip reads 200 µs and the smoothed one 35.025 ms.
        rack.on_ack(1, true, 100);

        assert_eq!(Duration::from_nanos(8_806_250), rack.reo_wnd(false, 0));
    }

    #[test]
    fn a_repeat_within_one_retransmission_timeout_proves_the_resend_needless() {
        let t0 = Instant::now();
        let mut rack = Rack::default();
        rack.on_delivered(&mut [delivered(1, t0, 1)], t0 + ms(40));
        rack.on_cut(100_000, 200_000);
        rack.on_resent(5, t0 + ms(40));

        rack.on_cumulative_ack(5, t0 + ms(110), ms(1000));
        rack.on_duplicates(&[]);
        rack.on_cumulative_ack(5, t0 + ms(130), ms(1000));
        rack.on_duplicates(&[5]);
        assert!(
            rack.take_proven_undo().is_some(),
            "a repeat queued behind a burst of resends still counts"
        );
    }

    #[test]
    fn a_resend_acknowledged_with_no_repeat_for_one_retransmission_timeout_was_needed() {
        let t0 = Instant::now();
        let mut rack = Rack::default();
        rack.on_delivered(&mut [delivered(1, t0, 1)], t0 + ms(40));
        rack.on_cut(100_000, 200_000);
        rack.on_resent(5, t0 + ms(40));

        rack.on_cumulative_ack(5, t0 + ms(1050), ms(1000));
        rack.on_duplicates(&[5]);
        assert!(
            rack.take_proven_undo().is_none(),
            "the cut for a repaired loss stands"
        );
    }
}

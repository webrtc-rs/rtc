use crate::{Packet, TaggedPacket};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// RTP header extension URI for the playout-delay extension.
/// <http://www.webrtc.org/experiments/rtp-hdrext/playout-delay>
pub(crate) const PLAYOUT_DELAY_URI: &str =
    "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay";

/// Per-SSRC jitter buffer state.
///
/// Buffers incoming RTP packets in sequence order and releases them after
/// an adaptive playout delay computed from the RFC 3550 §A.8 jitter formula.
pub(crate) struct JitterBufferStream {
    /// RTP clock rate (e.g. 90 000 for video, 48 000 for Opus audio).
    clock_rate: u32,
    /// One-byte header-extension ID for playout-delay, if negotiated.
    playout_delay_ext_id: Option<u8>,
    /// Sorted packet buffer: (seq, arrival_time, scheduled_release, packet).
    buffer: VecDeque<(u16, Instant, Instant, TaggedPacket)>,
    /// Last sequence number released to the application (guards against late arrivals).
    last_released: Option<u16>,
    // --- RFC 3550 §A.8 adaptive delay state ---
    last_rtp_ts: u32,
    last_arrival: Instant,
    jitter: f64, // running estimate in RTP clock units
    started: bool,
    // --- Configuration ---
    pub(crate) target_delay: Duration,
    min_delay: Duration,
    max_delay: Duration,
}

impl JitterBufferStream {
    pub(crate) fn new(
        clock_rate: u32,
        playout_delay_ext_id: Option<u8>,
        initial_delay: Duration,
        min_delay: Duration,
        max_delay: Duration,
    ) -> Self {
        Self {
            clock_rate,
            playout_delay_ext_id,
            buffer: VecDeque::new(),
            last_released: None,
            last_rtp_ts: 0,
            last_arrival: Instant::now(),
            jitter: 0.0,
            started: false,
            target_delay: initial_delay.max(min_delay).min(max_delay),
            min_delay,
            max_delay,
        }
    }

    /// Returns `true` if sequence number `a` is strictly after `b` under u16 wrapping.
    #[inline]
    fn seq_is_after(a: u16, b: u16) -> bool {
        a != b && a.wrapping_sub(b) < 0x8000
    }

    /// Update the jitter estimate from a new packet and compute its scheduled release time.
    ///
    /// Jitter is only updated for packets that advance the RTP timestamp (i.e. the RTP
    /// timestamp difference is in the forward half of the u32 space, matching the same
    /// wrapping arithmetic used for sequence numbers). Out-of-order or duplicate
    /// timestamps are accepted into the buffer but do not corrupt the jitter estimate.
    fn compute_release(&mut self, now: Instant, rtp_ts: u32) -> Instant {
        if self.started {
            let rtp_diff = rtp_ts.wrapping_sub(self.last_rtp_ts);
            // Only update for forward-advancing RTP timestamps (rtp_diff in (0, 2^31)).
            if rtp_diff > 0
                && rtp_diff < 0x8000_0000
                && self.clock_rate > 0
                && let Some(arrival_diff) = now.checked_duration_since(self.last_arrival)
            {
                let arrival_diff = arrival_diff.as_secs_f64();
                let d = (arrival_diff * self.clock_rate as f64 - rtp_diff as f64).abs();
                // RFC 3550 §A.8: J(i) = J(i-1) + (|D(i,i-1)| - J(i-1)) / 16
                self.jitter += (d - self.jitter) / 16.0;

                // target = clamp(jitter_seconds × 3, min, max)
                let jitter_secs = self.jitter / self.clock_rate as f64 * 3.0;
                self.target_delay = Duration::from_secs_f64(jitter_secs)
                    .max(self.min_delay)
                    .min(self.max_delay);

                self.last_rtp_ts = rtp_ts;
                self.last_arrival = now;
            }
        } else {
            self.started = true;
            self.last_rtp_ts = rtp_ts;
            self.last_arrival = now;
        }
        now + self.target_delay
    }

    /// Parse a playout-delay RTP extension (3 bytes, 12-bit min + 12-bit max in 10 ms units).
    fn parse_playout_delay(data: &[u8]) -> Option<(Duration, Duration)> {
        if data.len() < 3 {
            return None;
        }
        let min_raw = ((data[0] as u16) << 4) | ((data[1] as u16) >> 4);
        let max_raw = (((data[1] as u16) & 0x0F) << 8) | (data[2] as u16);
        Some((
            Duration::from_millis(min_raw as u64 * 10),
            Duration::from_millis(max_raw as u64 * 10),
        ))
    }

    /// Insert a packet into the buffer in sequence order.
    ///
    /// Returns `false` if the packet is a late duplicate (already past `last_released`).
    pub(crate) fn insert(&mut self, now: Instant, pkt: TaggedPacket) -> bool {
        let (seq, rtp_ts) = match &pkt.message {
            Packet::Rtp(rtp) => (rtp.header.sequence_number, rtp.header.timestamp),
            _ => return false,
        };

        // Reject packets at or before the last released sequence.
        if let Some(last) = self.last_released
            && !Self::seq_is_after(seq, last)
        {
            return false;
        }

        // Compute the release time (this also updates target_delay via jitter estimate).
        let release = self.compute_release(now, rtp_ts);

        // Apply playout-delay extension hints from the sender for this packet only.
        // We compute effective bounds without permanently mutating the configured
        // min/max so that subsequent packets with different (or absent) hints are
        // not permanently clamped.
        let release = if let (Packet::Rtp(rtp), Some(ext_id)) =
            (&pkt.message, self.playout_delay_ext_id)
            && let Some(ext_bytes) = rtp.header.get_extension(ext_id)
            && let Some((sender_min, sender_max)) = Self::parse_playout_delay(ext_bytes.as_ref())
        {
            // Sender's min raises our floor; sender's max lowers our ceiling.
            let effective_min = self.min_delay.max(sender_min);
            let effective_max = self.max_delay.min(sender_max.max(effective_min));
            let clamped_delay = self.target_delay.max(effective_min).min(effective_max);
            now + clamped_delay
        } else {
            release
        };

        // Reject duplicate sequence numbers already in the buffer.
        if self.buffer.iter().any(|(s, _, _, _)| *s == seq) {
            return false;
        }

        // Insert at the correct sorted position (ascending sequence order).
        let pos = self
            .buffer
            .iter()
            .position(|(s, _, _, _)| Self::seq_is_after(*s, seq))
            .unwrap_or(self.buffer.len());
        self.buffer.insert(pos, (seq, now, release, pkt));
        true
    }

    /// Return the head packet if it is ready for release, or `None` if not yet.
    ///
    /// A packet is ready when `now >= release_time` or it has been held for `>= max_delay`.
    pub(crate) fn pop_ready(&mut self, now: Instant) -> Option<TaggedPacket> {
        if let Some(&(_, arrival, release, _)) = self.buffer.front() {
            let ready = now >= release || now.duration_since(arrival) >= self.max_delay;
            if ready {
                let (seq, _, _, pkt) = self.buffer.pop_front().unwrap();
                self.last_released = Some(seq);
                return Some(pkt);
            }
        }
        None
    }

    /// Earliest instant at which the driver should wake up to service this stream.
    pub(crate) fn next_wake_time(&self) -> Option<Instant> {
        self.buffer.front().map(|(_, arrival, release, _)| {
            let force_release = *arrival + self.max_delay;
            (*release).min(force_release)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::{TransportContext, TransportMessage};

    fn make_rtp(ssrc: u32, seq: u16, ts: u32) -> TaggedPacket {
        TransportMessage {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc,
                    sequence_number: seq,
                    timestamp: ts,
                    ..Default::default()
                },
                ..Default::default()
            }),
        }
    }

    #[test]
    fn test_seq_is_after() {
        assert!(JitterBufferStream::seq_is_after(1, 0));
        assert!(JitterBufferStream::seq_is_after(100, 99));
        assert!(!JitterBufferStream::seq_is_after(0, 1));
        // wraparound: 0 is after 0xffff
        assert!(JitterBufferStream::seq_is_after(0, 0xffff));
        // equal is not "after"
        assert!(!JitterBufferStream::seq_is_after(5, 5));
    }

    #[test]
    fn test_insert_in_order() {
        let delay = Duration::from_millis(50);
        let mut s = JitterBufferStream::new(90000, None, delay, delay, Duration::from_secs(1));
        let now = Instant::now();
        s.insert(now, make_rtp(1, 1, 0));
        s.insert(now, make_rtp(1, 2, 900));
        s.insert(now, make_rtp(1, 3, 1800));
        assert_eq!(s.buffer.len(), 3);
        assert_eq!(s.buffer[0].0, 1);
        assert_eq!(s.buffer[1].0, 2);
        assert_eq!(s.buffer[2].0, 3);
    }

    #[test]
    fn test_insert_out_of_order() {
        let delay = Duration::from_millis(50);
        let mut s = JitterBufferStream::new(90000, None, delay, delay, Duration::from_secs(1));
        let now = Instant::now();
        s.insert(now, make_rtp(1, 1, 0));
        s.insert(now, make_rtp(1, 3, 1800));
        s.insert(now, make_rtp(1, 2, 900)); // late, but within window
        assert_eq!(s.buffer.len(), 3);
        assert_eq!(s.buffer[0].0, 1);
        assert_eq!(s.buffer[1].0, 2); // reordered into correct position
        assert_eq!(s.buffer[2].0, 3);
    }

    #[test]
    fn test_pop_ready_not_yet() {
        let delay = Duration::from_millis(50);
        let mut s = JitterBufferStream::new(90000, None, delay, delay, Duration::from_secs(1));
        let now = Instant::now();
        s.insert(now, make_rtp(1, 1, 0));
        // Just after insertion — release time hasn't passed yet.
        assert!(s.pop_ready(now).is_none());
    }

    #[test]
    fn test_pop_ready_after_delay() {
        let delay = Duration::from_millis(50);
        let mut s = JitterBufferStream::new(90000, None, delay, delay, Duration::from_secs(1));
        let now = Instant::now();
        s.insert(now, make_rtp(1, 1, 0));
        let later = now + Duration::from_millis(100);
        let pkt = s.pop_ready(later);
        assert!(pkt.is_some());
        assert!(s.buffer.is_empty());
    }

    #[test]
    fn test_force_release_at_max_delay() {
        let delay = Duration::from_millis(50);
        let max = Duration::from_millis(200);
        let mut s = JitterBufferStream::new(90000, None, delay, delay, max);
        let now = Instant::now();
        s.insert(now, make_rtp(1, 1, 0));
        // Simulate a very late pop — past max_delay.
        let very_late = now + max + Duration::from_millis(1);
        assert!(s.pop_ready(very_late).is_some());
    }

    #[test]
    fn test_late_arrival_rejected() {
        let delay = Duration::from_millis(50);
        let mut s = JitterBufferStream::new(90000, None, delay, delay, Duration::from_secs(1));
        let now = Instant::now();
        s.insert(now, make_rtp(1, 5, 0));
        // Release seq 5.
        s.pop_ready(now + Duration::from_millis(100));
        // seq 4 (before released seq 5) should be rejected.
        let accepted = s.insert(now + Duration::from_millis(200), make_rtp(1, 4, 0));
        assert!(!accepted);
    }

    #[test]
    fn test_jitter_adapts_target_delay() {
        let initial = Duration::from_millis(5);
        let min = Duration::from_millis(5);
        let mut s = JitterBufferStream::new(90000, None, initial, min, Duration::from_secs(2));
        let base = Instant::now();
        let mut elapsed_ms = 0u64;
        // Feed packets with variable but strictly increasing arrival times to grow jitter.
        // RTP timestamps advance at 90 kHz rate while packet spacing alternates between
        // shorter and longer gaps, producing inter-arrival variation without time going
        // backwards.
        for i in 0u32..40 {
            elapsed_ms += if i % 2 == 0 { 50 } else { 15 };
            let arrival = base + Duration::from_millis(elapsed_ms);
            let ts = i * 3000; // 90kHz / 30fps = 3000 units per frame
            s.insert(arrival, make_rtp(1, i as u16 + 1, ts));
        }
        // After significant jitter, target_delay should be above initial 5ms.
        assert!(
            s.target_delay > initial,
            "target_delay {:?} should have grown above {:?}",
            s.target_delay,
            initial
        );
    }

    #[test]
    fn test_next_wake_time_is_min_of_release_and_force() {
        let delay = Duration::from_millis(50);
        let max = Duration::from_millis(200);
        let mut s = JitterBufferStream::new(90000, None, delay, delay, max);
        let now = Instant::now();
        s.insert(now, make_rtp(1, 1, 0));
        let wake = s.next_wake_time().expect("should have a wake time");
        // Wake time should be <= arrival + max_delay
        assert!(wake <= now + max + Duration::from_millis(1));
    }

    #[test]
    fn test_initial_delay_clamped_to_bounds() {
        let min = Duration::from_millis(20);
        let max = Duration::from_millis(200);

        // initial_delay above max_delay should be clamped down to max_delay
        let s_high = JitterBufferStream::new(
            90000,
            None,
            Duration::from_secs(5), // way above max
            min,
            max,
        );
        assert_eq!(
            s_high.target_delay, max,
            "initial_delay above max_delay must be clamped to max_delay"
        );

        // initial_delay below min_delay should be clamped up to min_delay
        let s_low = JitterBufferStream::new(
            90000,
            None,
            Duration::from_millis(1), // below min
            min,
            max,
        );
        assert_eq!(
            s_low.target_delay, min,
            "initial_delay below min_delay must be clamped to min_delay"
        );

        // initial_delay within bounds should be unchanged
        let mid = Duration::from_millis(100);
        let s_mid = JitterBufferStream::new(90000, None, mid, min, max);
        assert_eq!(
            s_mid.target_delay, mid,
            "initial_delay within bounds must be unchanged"
        );
    }
}

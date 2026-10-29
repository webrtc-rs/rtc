use log::warn;
use shared::time::SystemInstant;
use std::time::{Duration, Instant};

/// How old the wall-clock baseline of a stream may get before the next frame takes a new one.
const REBASE_EVERY: Duration = Duration::from_secs(1);

pub(crate) struct SenderStream {
    ssrc: u32,
    clock_rate: f64,

    /// Whether to always use the latest packet, even if out-of-order.
    use_latest_packet: bool,

    /// Track if first packet has been processed
    started: bool,

    /// Last sequence number seen (for out-of-order detection)
    last_rtp_sn: u16,

    /// data from rtp packets
    last_rtp_time_rtp: u32,
    last_rtp_time_time: Option<Instant>,
    time_baseline: Option<SystemInstant>,

    counters: Counters,
}

impl SenderStream {
    pub(crate) fn new(ssrc: u32, clock_rate: u32, use_latest_packet: bool) -> Self {
        SenderStream {
            ssrc,
            clock_rate: clock_rate as f64,

            use_latest_packet,

            started: false,
            last_rtp_sn: 0,
            last_rtp_time_rtp: 0,
            last_rtp_time_time: None,
            time_baseline: None,

            counters: Default::default(),
        }
    }

    pub(crate) fn process_rtp(&mut self, now: Instant, pkt: &rtp::packet::Packet) {
        let seq = pkt.header.sequence_number;

        // Check if this packet should update timestamp info
        // Use u16 arithmetic: diff > 0 && diff < (1<<15) means in-order
        let diff = seq.wrapping_sub(self.last_rtp_sn);
        let is_in_order = !self.started || (diff > 0 && diff < (1 << 15));

        // Update timestamp mapping if:
        // - use_latest_packet is enabled (always update), OR
        // - this is the first packet, OR
        // - packet is in-order
        if self.use_latest_packet || is_in_order {
            self.started = true;
            self.last_rtp_sn = seq;

            // Update time only on first packet of a frame (when timestamp changes)
            // This ensures sender report is not affected by processing delay
            // of pushing a large frame which could span multiple packets.
            // The first accepted packet always establishes the mapping, even when its RTP
            // timestamp happens to be the zero `last_rtp_time_rtp` starts at.
            if self.last_rtp_time_time.is_none() || pkt.header.timestamp != self.last_rtp_time_rtp {
                self.last_rtp_time_rtp = pkt.header.timestamp;
                self.last_rtp_time_time = Some(now);
                // The wall clock is read once in a while, not for every frame: a report extrapolates
                // from the baseline with the monotonic clock, which keeps time as well as the wall
                // clock does over a second, and reading it costs more than the rest of the packet's
                // bookkeeping.
                if self
                    .time_baseline
                    .is_none_or(|b| now.saturating_duration_since(b.captured_at()) >= REBASE_EVERY)
                {
                    self.time_baseline = Some(SystemInstant::now(now));
                }
            }
        }

        // Always count packets and octets regardless of order
        self.counters.increment_packets();
        self.counters.count_octets(pkt.payload.len());
    }

    pub(crate) fn generate_report(
        &mut self,
        now: Instant,
    ) -> Option<rtcp::sender_report::SenderReport> {
        if let (Some(last_rtp_time_time), Some(time_baseline)) =
            (self.last_rtp_time_time, self.time_baseline)
        {
            Some(rtcp::sender_report::SenderReport {
                ssrc: self.ssrc,
                ntp_time: time_baseline.ntp(now),
                rtp_time: self.last_rtp_time_rtp.wrapping_add(
                    (now.duration_since(last_rtp_time_time).as_secs_f64() * self.clock_rate) as u32,
                ),
                packet_count: self.counters.packet_count(),
                octet_count: self.counters.octet_count(),
                ..Default::default()
            })
        } else {
            None
        }
    }
}

#[derive(Default)]
pub(crate) struct Counters {
    packets: u32,
    octets: u32,
}

/// Wrapping counters used for generating [`rtcp::sender_report::SenderReport`]
impl Counters {
    pub(crate) fn increment_packets(&mut self) {
        self.packets = self.packets.wrapping_add(1);
    }

    pub(crate) fn count_octets(&mut self, octets: usize) {
        // account for a payload size of at most `u32::MAX`
        // and log a message if larger
        self.octets = self
            .octets
            .wrapping_add(octets.try_into().unwrap_or_else(|_| {
                warn!("packet payload larger than 32 bits");
                u32::MAX
            }));
    }

    pub(crate) fn packet_count(&self) -> u32 {
        self.packets
    }

    pub(crate) fn octet_count(&self) -> u32 {
        self.octets
    }

    #[cfg(test)]
    pub(crate) fn mock(packets: u32, octets: u32) -> Self {
        Self { packets, octets }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rtp_packet(seq: u16, timestamp: u32, payload_len: usize) -> rtp::packet::Packet {
        rtp::packet::Packet {
            header: rtp::header::Header {
                sequence_number: seq,
                timestamp,
                ..Default::default()
            },
            payload: vec![0u8; payload_len].into(),
            ..Default::default()
        }
    }

    /// The wall clock is not read for every frame: the baseline a report extrapolates from is kept
    /// for a second, and the report still tells the time of the instant it is made at.
    #[test]
    fn the_wall_clock_baseline_is_kept_for_a_second() {
        let mut stream = SenderStream::new(1, 48_000, false);
        let t0 = Instant::now();
        stream.process_rtp(t0, &make_rtp_packet(1, 0, 8));
        let baseline = stream.time_baseline.expect("the first frame takes one");
        assert_eq!(baseline.captured_at(), t0);

        // Frames within the second leave it alone...
        for n in 1..40u32 {
            let at = t0 + Duration::from_millis(20 * u64::from(n));
            stream.process_rtp(at, &make_rtp_packet(n as u16 + 1, 960 * n, 8));
        }
        assert_eq!(stream.time_baseline.unwrap().captured_at(), t0);

        // ...and the report at the last of them is still the baseline plus the time since.
        let at = t0 + Duration::from_millis(780);
        let sr = stream.generate_report(at).unwrap();
        assert_eq!(sr.ntp_time, baseline.ntp(at));
        assert_eq!(sr.rtp_time, 960 * 39);

        // A frame a second after the baseline takes a new one.
        let later = t0 + Duration::from_millis(1000);
        stream.process_rtp(later, &make_rtp_packet(41, 960 * 50, 8));
        assert_eq!(stream.time_baseline.unwrap().captured_at(), later);
    }

    #[test]
    fn test_sender_stream_before_any_packet() {
        // Test that sender stream works before any packets are sent
        let stream = SenderStream::new(123456, 90000, false);
        let now = Instant::now();

        // No RTP has been sent, so there is no RTP-to-wall-clock mapping to report yet.
        let mut stream = stream;
        assert!(stream.generate_report(now).is_none());
    }

    #[test]
    fn test_sender_stream_after_rtp_packets() {
        // Test sender stream after sending RTP packets
        let mut stream = SenderStream::new(123456, 90000, false);
        let now = Instant::now();

        // Send 10 packets with 2-byte payload each
        for i in 0..10 {
            let pkt = make_rtp_packet(i, 0, 2);
            stream.process_rtp(now, &pkt);
        }

        let sr = stream
            .generate_report(now)
            .expect("a report is available once RTP has been sent");

        assert_eq!(sr.ssrc, 123456);
        assert_eq!(sr.packet_count, 10);
        assert_eq!(sr.octet_count, 20);
    }

    #[test]
    fn test_sender_stream_out_of_order_packets() {
        // Test that out-of-order packets are counted but don't update RTP timestamp
        let mut stream = SenderStream::new(123456, 90000, false);
        let now = Instant::now();

        // Send 10 in-order packets
        for i in 0..10u16 {
            let pkt = make_rtp_packet(i, i as u32, 2);
            stream.process_rtp(now, &pkt);
        }

        // Skip packet 10, send packet 12 first
        let pkt = make_rtp_packet(12, 12, 2);
        stream.process_rtp(now, &pkt);

        // Now send the out-of-order packet 11
        let pkt = make_rtp_packet(11, 11, 2);
        stream.process_rtp(now, &pkt);

        let sr = stream
            .generate_report(now)
            .expect("a report is available once RTP has been sent");

        assert_eq!(sr.ssrc, 123456);
        // All 12 packets are counted
        assert_eq!(sr.packet_count, 12);
        assert_eq!(sr.octet_count, 24);
        // RTP timestamp should be from the last in-order packet (12), not the out-of-order (11)
        assert_eq!(sr.rtp_time, 12);
    }

    #[test]
    fn test_sender_stream_out_of_order_with_use_latest_packet() {
        // Test that with use_latest_packet, out-of-order packets DO update RTP timestamp
        let mut stream = SenderStream::new(123456, 90000, true); // use_latest_packet = true
        let now = Instant::now();

        // Send 10 in-order packets
        for i in 0..10u16 {
            let pkt = make_rtp_packet(i, i as u32, 2);
            stream.process_rtp(now, &pkt);
        }

        // Skip packet 10, send packet 12 first
        let pkt = make_rtp_packet(12, 12, 2);
        stream.process_rtp(now, &pkt);

        // Now send the out-of-order packet 11
        let pkt = make_rtp_packet(11, 11, 2);
        stream.process_rtp(now, &pkt);

        let sr = stream
            .generate_report(now)
            .expect("a report is available once RTP has been sent");

        assert_eq!(sr.ssrc, 123456);
        // All 12 packets are counted
        assert_eq!(sr.packet_count, 12);
        assert_eq!(sr.octet_count, 24);
        // RTP timestamp should be from the LATEST packet (11), since use_latest_packet is true
        assert_eq!(sr.rtp_time, 11);
    }

    #[test]
    fn test_sender_stream_frame_first_packet_optimization() {
        // Test that only the first packet of a frame updates the time mapping
        let mut stream = SenderStream::new(123456, 90000, false);
        let base_time = Instant::now();

        // First packet of frame with timestamp 1000
        let pkt1 = make_rtp_packet(0, 1000, 100);
        stream.process_rtp(base_time, &pkt1);

        // Second packet of same frame (same timestamp), arrives later
        let later_time = base_time + std::time::Duration::from_millis(10);
        let pkt2 = make_rtp_packet(1, 1000, 100);
        stream.process_rtp(later_time, &pkt2);

        // The time mapping should still be from the first packet
        // Generate report at base_time - RTP time should be 1000 (no extrapolation)
        let sr = stream
            .generate_report(base_time)
            .expect("a report is available once RTP has been sent");
        assert_eq!(sr.rtp_time, 1000);
    }

    #[test]
    fn test_sender_stream_sequence_wrap() {
        // Test sequence number wraparound
        let mut stream = SenderStream::new(123456, 90000, false);
        let now = Instant::now();

        // Send packet near the end of sequence space
        let pkt = make_rtp_packet(65534, 100, 10);
        stream.process_rtp(now, &pkt);

        // Send packet at 65535
        let pkt = make_rtp_packet(65535, 200, 10);
        stream.process_rtp(now, &pkt);

        // Wrap around to 0
        let pkt = make_rtp_packet(0, 300, 10);
        stream.process_rtp(now, &pkt);

        // Continue to 1
        let pkt = make_rtp_packet(1, 400, 10);
        stream.process_rtp(now, &pkt);

        let sr = stream
            .generate_report(now)
            .expect("a report is available once RTP has been sent");

        assert_eq!(sr.packet_count, 4);
        assert_eq!(sr.octet_count, 40);
        // RTP time should be from the last in-order packet
        assert_eq!(sr.rtp_time, 400);
    }

    #[test]
    fn test_counters_wrapping() {
        let mut counters = Counters::default();

        // Set to max - 1
        counters.packets = u32::MAX - 1;
        counters.octets = u32::MAX - 1;

        // Increment should wrap
        counters.increment_packets();
        assert_eq!(counters.packet_count(), u32::MAX);

        counters.increment_packets();
        assert_eq!(counters.packet_count(), 0);

        counters.count_octets(1);
        assert_eq!(counters.octet_count(), u32::MAX);

        counters.count_octets(1);
        assert_eq!(counters.octet_count(), 0);
    }
}

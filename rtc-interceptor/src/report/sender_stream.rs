use log::warn;
use shared::time::SystemInstant;
use std::time::Instant;

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
    last_rtp_time_time: Instant,
    time_baseline: SystemInstant,

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
            last_rtp_time_time: Instant::now(),
            time_baseline: SystemInstant::now(),

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
            // of pushing a large frame which could span multiple packets
            if pkt.header.timestamp != self.last_rtp_time_rtp {
                self.last_rtp_time_rtp = pkt.header.timestamp;
                self.last_rtp_time_time = now;
            }
        }

        // Always count packets and octets regardless of order
        self.counters.increment_packets();
        self.counters.count_octets(pkt.payload.len());
    }

    pub(crate) fn generate_report(&mut self, now: Instant) -> rtcp::sender_report::SenderReport {
        rtcp::sender_report::SenderReport {
            ssrc: self.ssrc,
            ntp_time: self.time_baseline.ntp(now),
            rtp_time: self.last_rtp_time_rtp.wrapping_add(
                (now.duration_since(self.last_rtp_time_time).as_secs_f64() * self.clock_rate)
                    as u32,
            ),
            packet_count: self.counters.packet_count(),
            octet_count: self.counters.octet_count(),
            ..Default::default()
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

    #[test]
    fn test_sender_stream_before_any_packet() {
        // Test that sender stream works before any packets are sent
        let stream = SenderStream::new(123456, 90000, false);
        let now = Instant::now();

        // Generate report before any packets
        let mut stream = stream;
        let sr = stream.generate_report(now);

        assert_eq!(sr.ssrc, 123456);
        assert_eq!(sr.packet_count, 0);
        assert_eq!(sr.octet_count, 0);
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

        let sr = stream.generate_report(now);

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

        let sr = stream.generate_report(now);

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

        let sr = stream.generate_report(now);

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
        let sr = stream.generate_report(base_time);
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

        let sr = stream.generate_report(now);

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

use std::time::Instant;

/// Number of packets tracked per u64 entry in the bitmap.
const PACKETS_PER_ENTRY: usize = 64;

pub(crate) struct ReceiverStream {
    ssrc: u32,
    receiver_ssrc: u32,
    clock_rate: f64,

    /// Bitmap for tracking received packets. Each u64 tracks 64 packets.
    /// With size=128, total capacity is 128 * 64 = 8192 packets.
    packets: Vec<u64>,
    size: usize,
    started: bool,
    seq_num_cycles: u16,
    last_seq_num: u16,
    last_report_seq_num: u16,
    last_rtp_time_rtp: u32,
    last_rtp_time_time: Instant,
    jitter: f64,
    last_sender_report: u32,
    last_sender_report_time: Option<Instant>,
    total_lost: u32,
}

impl ReceiverStream {
    pub(crate) fn new(ssrc: u32, clock_rate: u32) -> Self {
        const DEFAULT_SIZE: usize = 128;
        Self {
            ssrc,
            receiver_ssrc: rand::random::<u32>(),
            clock_rate: clock_rate as f64,

            packets: vec![0u64; DEFAULT_SIZE],
            size: DEFAULT_SIZE,
            started: false,
            seq_num_cycles: 0,
            last_seq_num: 0,
            last_report_seq_num: 0,
            last_rtp_time_rtp: 0,
            last_rtp_time_time: Instant::now(),
            jitter: 0.0,
            last_sender_report: 0,
            last_sender_report_time: None,
            total_lost: 0,
        }
    }

    fn set_received(&mut self, seq: u16) {
        let pos = (seq as usize) % (self.size * PACKETS_PER_ENTRY);
        self.packets[pos / PACKETS_PER_ENTRY] |= 1 << (pos % PACKETS_PER_ENTRY);
    }

    fn del_received(&mut self, seq: u16) {
        let pos = (seq as usize) % (self.size * PACKETS_PER_ENTRY);
        self.packets[pos / PACKETS_PER_ENTRY] &= !(1u64 << (pos % PACKETS_PER_ENTRY));
    }

    fn get_received(&self, seq: u16) -> bool {
        let pos = (seq as usize) % (self.size * PACKETS_PER_ENTRY);
        (self.packets[pos / PACKETS_PER_ENTRY] & (1 << (pos % PACKETS_PER_ENTRY))) != 0
    }

    pub(crate) fn process_rtp(&mut self, now: Instant, pkt: &rtp::packet::Packet) {
        let seq = pkt.header.sequence_number;

        if !self.started {
            // first frame
            self.started = true;
            self.set_received(seq);
            self.last_seq_num = seq;
            self.last_report_seq_num = seq.wrapping_sub(1);
            self.last_rtp_time_rtp = pkt.header.timestamp;
            self.last_rtp_time_time = now;
        } else {
            // following frames
            self.set_received(seq);

            // Use u16 arithmetic for proper wraparound handling (matching pion)
            // diff > 0 && diff < (1<<15) means packet is in-order
            let diff = seq.wrapping_sub(self.last_seq_num);
            if diff > 0 && diff < (1 << 15) {
                // wrap around detection: sequence number wrapped if new seq < old seq
                if seq < self.last_seq_num {
                    self.seq_num_cycles = self.seq_num_cycles.wrapping_add(1);
                }

                // set missing packets as not received
                let mut i = self.last_seq_num.wrapping_add(1);
                while i != seq {
                    self.del_received(i);
                    i = i.wrapping_add(1);
                }

                self.last_seq_num = seq;
            }

            // compute jitter
            // https://tools.ietf.org/html/rfc3550#page-39
            let d = now.duration_since(self.last_rtp_time_time).as_secs_f64() * self.clock_rate
                - (pkt.header.timestamp as f64 - self.last_rtp_time_rtp as f64);
            self.jitter += (d.abs() - self.jitter) / 16.0;

            self.last_rtp_time_rtp = pkt.header.timestamp;
            self.last_rtp_time_time = now;
        }
    }

    pub(crate) fn process_sender_report(
        &mut self,
        now: Instant,
        sr: &rtcp::sender_report::SenderReport,
    ) {
        self.last_sender_report = (sr.ntp_time >> 16) as u32;
        self.last_sender_report_time = Some(now);
    }

    pub(crate) fn generate_report(
        &mut self,
        now: Instant,
    ) -> rtcp::receiver_report::ReceiverReport {
        let total_since_report = self.last_seq_num.wrapping_sub(self.last_report_seq_num);
        let mut total_lost_since_report = {
            if self.last_seq_num == self.last_report_seq_num {
                0
            } else {
                let mut ret = 0u32;
                let mut i = self.last_report_seq_num.wrapping_add(1);
                while i != self.last_seq_num {
                    if !self.get_received(i) {
                        ret += 1;
                    }
                    i = i.wrapping_add(1);
                }
                ret
            }
        };

        self.total_lost += total_lost_since_report;

        // allow up to 24 bits
        if total_lost_since_report > 0xFFFFFF {
            total_lost_since_report = 0xFFFFFF;
        }
        if self.total_lost > 0xFFFFFF {
            self.total_lost = 0xFFFFFF
        }

        // Calculate DLSR (Delay Since Last SR) - RFC 3550
        // Return 0 if no SR has been received yet
        let delay = match self.last_sender_report_time {
            Some(sr_time) => (now.duration_since(sr_time).as_secs_f64() * 65536.0) as u32,
            None => 0,
        };

        // Calculate fraction lost, avoiding division by zero
        let fraction_lost = if total_since_report > 0 {
            ((total_lost_since_report * 256) as f64 / total_since_report as f64) as u8
        } else {
            0
        };

        let r = rtcp::receiver_report::ReceiverReport {
            ssrc: self.receiver_ssrc,
            reports: vec![rtcp::reception_report::ReceptionReport {
                ssrc: self.ssrc,
                last_sequence_number: (self.seq_num_cycles as u32) << 16
                    | (self.last_seq_num as u32 & 0xFFFF),
                last_sender_report: self.last_sender_report,
                fraction_lost,
                total_lost: self.total_lost,
                delay,
                jitter: self.jitter as u32,
            }],
            ..Default::default()
        };

        self.last_report_seq_num = self.last_seq_num;

        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_rtp_packet(seq: u16, timestamp: u32) -> rtp::packet::Packet {
        rtp::packet::Packet {
            header: rtp::header::Header {
                sequence_number: seq,
                timestamp,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_can_use_entire_history_size() {
        // Port of pion's TestReceiverStream/can use entire history size
        let mut stream = ReceiverStream::new(12345, 90000);
        let max_packets = stream.size * PACKETS_PER_ENTRY;

        // We shouldn't wrap around so long as we only try max_packets worth
        for seq in 0..max_packets as u16 {
            assert!(
                !stream.get_received(seq),
                "packet with SN {} shouldn't be received yet",
                seq
            );
            stream.set_received(seq);
            assert!(
                stream.get_received(seq),
                "packet with SN {} should now be received",
                seq
            );
        }

        // Delete should also work
        for seq in 0..max_packets as u16 {
            assert!(
                stream.get_received(seq),
                "packet with SN {} should still be marked as received",
                seq
            );
            stream.del_received(seq);
            assert!(
                !stream.get_received(seq),
                "packet with SN {} should no longer be received",
                seq
            );
        }
    }

    #[test]
    fn test_receiver_stream_before_any_packet() {
        // Port of pion's TestReceiverInterceptor/before any packet
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        let rr = stream.generate_report(now);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        assert_eq!(rr.reports[0].last_sequence_number, 0);
        assert_eq!(rr.reports[0].last_sender_report, 0);
        assert_eq!(rr.reports[0].fraction_lost, 0);
        assert_eq!(rr.reports[0].total_lost, 0);
        assert_eq!(rr.reports[0].delay, 0);
        assert_eq!(rr.reports[0].jitter, 0);
    }

    #[test]
    fn test_receiver_stream_after_rtp_packets() {
        // Port of pion's TestReceiverInterceptor/after RTP packets
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        for i in 0..10u16 {
            let pkt = make_rtp_packet(i, 0);
            stream.process_rtp(now, &pkt);
        }

        let rr = stream.generate_report(now);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        assert_eq!(rr.reports[0].last_sequence_number, 9);
        assert_eq!(rr.reports[0].last_sender_report, 0);
        assert_eq!(rr.reports[0].fraction_lost, 0);
        assert_eq!(rr.reports[0].total_lost, 0);
        assert_eq!(rr.reports[0].delay, 0);
        assert_eq!(rr.reports[0].jitter, 0);
    }

    #[test]
    fn test_receiver_stream_overflow() {
        // Port of pion's TestReceiverInterceptor/overflow
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        // Receive packet at 0xffff
        stream.process_rtp(now, &make_rtp_packet(0xffff, 0));

        // Wrap to 0x00
        stream.process_rtp(now, &make_rtp_packet(0x00, 0));

        // Out-of-order packet 0xfffe (should not update last_seq_num)
        stream.process_rtp(now, &make_rtp_packet(0xfffe, 0));

        let rr = stream.generate_report(now);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        // Extended sequence number should show 1 cycle (1 << 16)
        assert_eq!(rr.reports[0].last_sequence_number, 1 << 16);
        assert_eq!(rr.reports[0].fraction_lost, 0);
        assert_eq!(rr.reports[0].total_lost, 0);
    }

    #[test]
    fn test_receiver_stream_packet_loss() {
        // Port of pion's TestReceiverInterceptor/packet loss
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        // Receive packet 1
        stream.process_rtp(now, &make_rtp_packet(0x01, 0));

        // Skip packet 2, receive packet 3
        stream.process_rtp(now, &make_rtp_packet(0x03, 0));

        let rr = stream.generate_report(now);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        assert_eq!(rr.reports[0].last_sequence_number, 0x03);
        // fraction_lost = 256 * 1 / 3 = 85
        assert_eq!(rr.reports[0].fraction_lost, (256u32 * 1 / 3) as u8);
        assert_eq!(rr.reports[0].total_lost, 1);
    }

    #[test]
    fn test_receiver_stream_overflow_and_packet_loss() {
        // Port of pion's TestReceiverInterceptor/overflow and packet loss
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        // Receive packet 0xffff
        stream.process_rtp(now, &make_rtp_packet(0xffff, 0));

        // Skip 0x00, receive 0x01
        stream.process_rtp(now, &make_rtp_packet(0x01, 0));

        let rr = stream.generate_report(now);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        // Extended sequence number: 1 cycle + 0x01
        assert_eq!(rr.reports[0].last_sequence_number, (1 << 16) | 0x01);
        // fraction_lost = 256 * 1 / 3 = 85
        assert_eq!(rr.reports[0].fraction_lost, (256u32 * 1 / 3) as u8);
        assert_eq!(rr.reports[0].total_lost, 1);
    }

    #[test]
    fn test_receiver_stream_reordered_packets() {
        // Port of pion's TestReceiverInterceptor/reordered packets
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        // Receive packets in order: 1, 3, 2, 4
        for seq in [0x01u16, 0x03, 0x02, 0x04] {
            stream.process_rtp(now, &make_rtp_packet(seq, 0));
        }

        let rr = stream.generate_report(now);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        assert_eq!(rr.reports[0].last_sequence_number, 0x04);
        // No loss because packet 2 arrived (just out of order)
        assert_eq!(rr.reports[0].fraction_lost, 0);
        assert_eq!(rr.reports[0].total_lost, 0);
    }

    #[test]
    fn test_receiver_stream_jitter() {
        // Port of pion's TestReceiverInterceptor/jitter
        let mut stream = ReceiverStream::new(123456, 90000);
        let base_time = Instant::now();

        // First packet
        stream.process_rtp(base_time, &make_rtp_packet(0x01, 42378934));

        // Second packet arrives 1 second later, but RTP timestamp only advances by 60000
        // (should be 90000 for 1 second at 90kHz clock rate)
        // D = |arrival_diff * clock_rate - rtp_diff| = |1 * 90000 - 60000| = 30000
        let later_time = base_time + Duration::from_secs(1);
        stream.process_rtp(later_time, &make_rtp_packet(0x02, 42378934 + 60000));

        let rr = stream.generate_report(later_time);

        assert_eq!(rr.reports.len(), 1);
        assert_eq!(rr.reports[0].ssrc, 123456);
        assert_eq!(rr.reports[0].last_sequence_number, 0x02);
        // jitter = D / 16 = 30000 / 16 = 1875
        assert_eq!(rr.reports[0].jitter, 30000 / 16);
    }

    #[test]
    fn test_receiver_stream_delay() {
        // Port of pion's TestReceiverInterceptor/delay
        let mut stream = ReceiverStream::new(123456, 90000);
        let base_time = Instant::now();

        // Receive a sender report
        let sr = rtcp::sender_report::SenderReport {
            ssrc: 123456,
            ntp_time: 0x1234_5678_0000_0000, // Some NTP time
            rtp_time: 987654321,
            packet_count: 0,
            octet_count: 0,
            ..Default::default()
        };
        stream.process_sender_report(base_time, &sr);

        // Generate receiver report 1 second later
        let later_time = base_time + Duration::from_secs(1);
        let rr = stream.generate_report(later_time);

        assert_eq!(rr.reports.len(), 1);
        // DLSR in 1/65536 seconds units: 1 second = 65536
        assert_eq!(rr.reports[0].delay, 65536);
        // LSR is middle 32 bits of NTP time
        assert_eq!(rr.reports[0].last_sender_report, 0x5678_0000);
    }

    #[test]
    fn test_receiver_stream_delay_before_sender_report() {
        // Test that delay is 0 before receiving any sender report
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        // Receive some RTP packets
        for i in 0..5u16 {
            stream.process_rtp(now, &make_rtp_packet(i, 0));
        }

        // Generate report without having received any SR
        let rr = stream.generate_report(now);

        assert_eq!(rr.reports[0].delay, 0);
        assert_eq!(rr.reports[0].last_sender_report, 0);
    }

    #[test]
    fn test_receiver_stream_cumulative_loss() {
        // Test that total_lost accumulates across reports
        let mut stream = ReceiverStream::new(123456, 90000);
        let now = Instant::now();

        // First batch: receive 1, skip 2, receive 3
        stream.process_rtp(now, &make_rtp_packet(1, 0));
        stream.process_rtp(now, &make_rtp_packet(3, 0));

        let rr1 = stream.generate_report(now);
        assert_eq!(rr1.reports[0].total_lost, 1);

        // Second batch: receive 4, skip 5, receive 6
        stream.process_rtp(now, &make_rtp_packet(4, 0));
        stream.process_rtp(now, &make_rtp_packet(6, 0));

        let rr2 = stream.generate_report(now);
        // Total lost should now be 2 (1 from first batch + 1 from second)
        assert_eq!(rr2.reports[0].total_lost, 2);
    }

    #[test]
    fn test_receiver_stream_24bit_loss_clamping() {
        // Test that total_lost is clamped to 24 bits (0xFFFFFF)
        let mut stream = ReceiverStream::new(123456, 90000);
        stream.total_lost = 0xFFFFFE; // Almost at max

        let now = Instant::now();

        // Receive packets with a gap
        stream.process_rtp(now, &make_rtp_packet(1, 0));
        stream.process_rtp(now, &make_rtp_packet(10, 0)); // 8 packets lost

        let rr = stream.generate_report(now);

        // Should be clamped to 0xFFFFFF
        assert_eq!(rr.reports[0].total_lost, 0xFFFFFF);
    }
}

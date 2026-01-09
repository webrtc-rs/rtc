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

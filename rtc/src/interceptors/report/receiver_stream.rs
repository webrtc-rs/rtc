use std::time::Instant;

pub(crate) struct ReceiverStream {
    ssrc: u32,
    receiver_ssrc: u32,
    clock_rate: f64,

    packets: Vec<u64>,
    started: bool,
    seq_num_cycles: u16,
    last_seq_num: i32,
    last_report_seq_num: i32,
    last_rtp_time_rtp: u32,
    last_rtp_time_time: Instant,
    jitter: f64,
    last_sender_report: u32,
    last_sender_report_time: Instant,
    total_lost: u32,
}

impl ReceiverStream {
    pub(crate) fn new(ssrc: u32, clock_rate: u32) -> Self {
        Self {
            ssrc,
            receiver_ssrc: rand::random::<u32>(),
            clock_rate: clock_rate as f64,

            packets: vec![0u64; 128],
            started: false,
            seq_num_cycles: 0,
            last_seq_num: 0,
            last_report_seq_num: 0,
            last_rtp_time_rtp: 0,
            last_rtp_time_time: Instant::now(),
            jitter: 0.0,
            last_sender_report: 0,
            last_sender_report_time: Instant::now(),
            total_lost: 0,
        }
    }

    fn set_received(&mut self, seq: u16) {
        let pos = (seq as usize) % self.packets.len();
        self.packets[pos / 64] |= 1 << (pos % 64);
    }

    fn del_received(&mut self, seq: u16) {
        let pos = (seq as usize) % self.packets.len();
        self.packets[pos / 64] &= u64::MAX ^ (1u64 << (pos % 64));
    }

    fn get_received(&self, seq: u16) -> bool {
        let pos = (seq as usize) % self.packets.len();
        (self.packets[pos / 64] & (1 << (pos % 64))) != 0
    }

    pub(crate) fn process_rtp(&mut self, now: Instant, pkt: &rtp::packet::Packet) {
        if !self.started {
            // first frame
            self.started = true;
            self.set_received(pkt.header.sequence_number);
            self.last_seq_num = pkt.header.sequence_number as i32;
            self.last_report_seq_num = pkt.header.sequence_number as i32 - 1;
        } else {
            // following frames
            self.set_received(pkt.header.sequence_number);

            let diff = pkt.header.sequence_number as i32 - self.last_seq_num;
            if !(-0x0FFF..=0).contains(&diff) {
                // overflow
                if diff < -0x0FFF {
                    self.seq_num_cycles += 1;
                }

                // set missing packets as missing
                for i in self.last_seq_num + 1..pkt.header.sequence_number as i32 {
                    self.del_received(i as u16);
                }

                self.last_seq_num = pkt.header.sequence_number as i32;
            }

            // compute jitter
            // https://tools.ietf.org/html/rfc3550#page-39
            let d = now.duration_since(self.last_rtp_time_time).as_secs_f64() * self.clock_rate
                - (pkt.header.timestamp as f64 - self.last_rtp_time_rtp as f64);
            self.jitter += (d.abs() - self.jitter) / 16.0;
        }

        self.last_rtp_time_rtp = pkt.header.timestamp;
        self.last_rtp_time_time = now;
    }

    pub(crate) fn process_sender_report(
        &mut self,
        now: Instant,
        sr: &rtcp::sender_report::SenderReport,
    ) {
        self.last_sender_report = (sr.ntp_time >> 16) as u32;
        self.last_sender_report_time = now;
    }

    pub(crate) fn generate_report(
        &mut self,
        now: Instant,
    ) -> rtcp::receiver_report::ReceiverReport {
        let total_since_report = (self.last_seq_num - self.last_report_seq_num) as u16;
        let mut total_lost_since_report = {
            if self.last_seq_num == self.last_report_seq_num {
                0
            } else {
                let mut ret = 0u32;
                let mut i = (self.last_report_seq_num + 1) as u16;
                while i != self.last_seq_num as u16 {
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

        let r = rtcp::receiver_report::ReceiverReport {
            ssrc: self.receiver_ssrc,
            reports: vec![rtcp::reception_report::ReceptionReport {
                ssrc: self.ssrc,
                last_sequence_number: (self.seq_num_cycles as u32) << 16
                    | (self.last_seq_num as u32),
                last_sender_report: self.last_sender_report,
                fraction_lost: ((total_lost_since_report * 256) as f64 / total_since_report as f64)
                    as u8,
                total_lost: self.total_lost,
                delay: (now
                    .duration_since(self.last_sender_report_time)
                    .as_secs_f64()
                    * 65536.0) as u32,
                jitter: self.jitter as u32,
            }],
            ..Default::default()
        };

        self.last_report_seq_num = self.last_seq_num;

        r
    }
}

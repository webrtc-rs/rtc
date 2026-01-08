use log::warn;
use rtp::extension::abs_send_time_extension::unix2ntp;
use std::time::{Instant, SystemTime};

pub(crate) struct SenderStream {
    ssrc: u32,
    clock_rate: f64,

    /// data from rtp packets
    last_rtp_time_rtp: u32,
    last_rtp_time_time: Instant,
    counters: Counters,
}

impl SenderStream {
    pub(crate) fn new(ssrc: u32, clock_rate: u32) -> Self {
        SenderStream {
            ssrc,
            clock_rate: clock_rate as f64,
            last_rtp_time_rtp: 0,
            last_rtp_time_time: Instant::now(),
            counters: Default::default(),
        }
    }

    pub(crate) fn process_rtp(&mut self, now: Instant, pkt: &rtp::packet::Packet) {
        // always update time to minimize errors
        self.last_rtp_time_rtp = pkt.header.timestamp;
        self.last_rtp_time_time = now;

        self.counters.increment_packets();
        self.counters.count_octets(pkt.payload.len());
    }

    pub(crate) fn generate_report(&mut self, now: Instant) -> rtcp::sender_report::SenderReport {
        rtcp::sender_report::SenderReport {
            ssrc: self.ssrc,
            ntp_time: unix2ntp(SystemTime::now()),
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

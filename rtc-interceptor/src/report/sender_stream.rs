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

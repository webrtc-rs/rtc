#[cfg(test)]
mod packetizer_test;

use crate::{extension::abs_send_time_extension::*, header::*, packet::*, sequence::*};
use shared::{
    error::Result,
    marshal::{Marshal, MarshalSize},
    time::SystemInstant,
};

use bytes::{Bytes, BytesMut};
use std::fmt;
use std::time::Instant;

/// Payloader payloads a byte array for use as rtp.Packet payloads
pub trait Payloader: Send + Sync + fmt::Debug {
    /// Splits one encoded frame into payloads no larger than `mtu`.
    ///
    /// # Errors
    ///
    /// Fails if the frame is malformed for this codec, or `mtu` is too small to make progress.
    fn payload(&mut self, mtu: usize, b: &Bytes) -> Result<Vec<Bytes>>;
    /// Clones this payloader behind a trait object.
    fn clone_to(&self) -> Box<dyn Payloader>;
}

impl Clone for Box<dyn Payloader> {
    fn clone(&self) -> Box<dyn Payloader> {
        self.clone_to()
    }
}

/// Packetizer packetizes a payload
pub trait Packetizer: Send + Sync + fmt::Debug {
    /// Attaches the absolute-send-time header extension under id `value`.
    fn enable_abs_send_time(&mut self, value: u8);
    /// Packetizes one frame, advancing the timestamp by `samples`.
    ///
    /// Assigns sequence numbers, sets the marker bit on the final packet, and applies any
    /// enabled header extensions. `now` is the instant the frame is being sent at; it is what
    /// the absolute-send-time extension is derived from, so the caller supplies it rather than
    /// the packetizer sampling a clock of its own.
    ///
    /// # Errors
    ///
    /// Propagates payloader failures.
    fn packetize(&mut self, now: Instant, payload: &Bytes, samples: u32) -> Result<Vec<Packet>>;
    /// Advances the timestamp without sending anything, for dropped or silent frames.
    fn skip_samples(&mut self, skipped_samples: u32);
    /// Clones this packetizer behind a trait object.
    fn clone_to(&self) -> Box<dyn Packetizer>;
}

impl Clone for Box<dyn Packetizer> {
    fn clone(&self) -> Box<dyn Packetizer> {
        self.clone_to()
    }
}

/// Depacketizer depacketizes a RTP payload, removing any RTP specific data from the payload
pub trait Depacketizer {
    /// Reassembles a frame from one RTP payload, buffering fragments as needed.
    ///
    /// # Errors
    ///
    /// Fails if the payload is malformed for this codec.
    fn depacketize(&mut self, b: &Bytes) -> Result<Bytes>;

    /// Checks if the packet is at the beginning of a partition.  This
    /// should return false if the result could not be determined, in
    /// which case the caller will detect timestamp discontinuities.
    fn is_partition_head(&self, payload: &Bytes) -> bool;

    /// Checks if the packet is at the end of a partition.  This should
    /// return false if the result could not be determined.
    fn is_partition_tail(&self, marker: bool, payload: &Bytes) -> bool;
}

#[derive(Clone)]
pub(crate) struct PacketizerImpl {
    pub(crate) mtu: usize,
    pub(crate) payload_type: u8,
    pub(crate) ssrc: u32,
    pub(crate) payloader: Box<dyn Payloader>,
    pub(crate) sequencer: Box<dyn Sequencer>,
    pub(crate) timestamp: u32,
    pub(crate) clock_rate: u32,
    pub(crate) abs_send_time_ext_id: u8, //http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
    pub(crate) time_baseline: SystemInstant,
}

impl fmt::Debug for PacketizerImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketizerImpl")
            .field("mtu", &self.mtu)
            .field("payload_type", &self.payload_type)
            .field("ssrc", &self.ssrc)
            .field("timestamp", &self.timestamp)
            .field("clock_rate", &self.clock_rate)
            .field("abs_send_time_ext_id", &self.abs_send_time_ext_id)
            .finish()
    }
}

/// Builds a packetizer for one outbound stream.
///
/// Ties together the codec's payloader, a sequencer, and the SSRC, payload type, MTU and clock
/// rate the stream was negotiated with.
pub fn new_packetizer(
    now: Instant,
    mtu: usize,
    payload_type: u8,
    ssrc: u32,
    payloader: Box<dyn Payloader>,
    sequencer: Box<dyn Sequencer>,
    clock_rate: u32,
) -> impl Packetizer {
    PacketizerImpl {
        mtu,
        payload_type,
        ssrc,
        payloader,
        sequencer,
        timestamp: rand::random::<u32>(),
        clock_rate,
        abs_send_time_ext_id: 0,
        time_baseline: SystemInstant::now(now),
    }
}

impl Packetizer for PacketizerImpl {
    fn enable_abs_send_time(&mut self, id: u8) {
        self.abs_send_time_ext_id = id
    }

    fn packetize(&mut self, now: Instant, payload: &Bytes, samples: u32) -> Result<Vec<Packet>> {
        let payloads = self.payloader.payload(self.mtu - 12, payload)?;
        let payloads_len = payloads.len();
        let mut packets = Vec::with_capacity(payloads_len);
        for (i, payload) in payloads.into_iter().enumerate() {
            packets.push(Packet {
                header: Header {
                    version: 2,
                    padding: false,
                    extension: false,
                    marker: i == payloads_len - 1,
                    payload_type: self.payload_type,
                    sequence_number: self.sequencer.next_sequence_number(),
                    timestamp: self.timestamp, //TODO: Figure out how to do timestamps
                    ssrc: self.ssrc,
                    ..Default::default()
                },
                payload,
            });
        }

        self.timestamp = self.timestamp.wrapping_add(samples);

        if payloads_len != 0 && self.abs_send_time_ext_id != 0 {
            let send_time = AbsSendTimeExtension::new(self.time_baseline.ntp(now));
            //apply http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
            let mut raw = BytesMut::with_capacity(send_time.marshal_size());
            raw.resize(send_time.marshal_size(), 0);
            let _ = send_time.marshal_to(&mut raw)?;
            packets[payloads_len - 1]
                .header
                .set_extension(self.abs_send_time_ext_id, raw.freeze())?;
        }

        Ok(packets)
    }

    /// skip_samples causes a gap in sample count between Packetize requests so the
    /// RTP payloads produced have a gap in timestamps
    fn skip_samples(&mut self, skipped_samples: u32) {
        self.timestamp = self.timestamp.wrapping_add(skipped_samples);
    }

    fn clone_to(&self) -> Box<dyn Packetizer> {
        Box::new(self.clone())
    }
}

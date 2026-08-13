//! RTCP Congestion Control Feedback ([RFC 8888]).
//!
//! A receiver reports, per media stream, whether each packet in a sequence-number range arrived,
//! when it arrived, and what its ECN marking was. Congestion control on the sender uses that to
//! estimate available bandwidth.
//!
//! This is the feedback format RFC 8888 standardised; [`TransportLayerCc`] is the older
//! `draft-holmer-rmcat-transport-wide-cc` format that browsers ship today. They occupy the same
//! packet type (205) and are told apart by FMT — 11 here, 15 there.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P| FMT=11  |   PT = 205    |          length               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                 SSRC of RTCP packet sender                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   SSRC of 1st RTP Stream                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          begin_seq            |          num_reports          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |R|ECN|  Arrival time offset    | ...                           .
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! .                                                               .
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   SSRC of nth RTP Stream                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          begin_seq            |          num_reports          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |R|ECN|  Arrival time offset    | ...                           |
//! .                                                               .
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                 Report Timestamp (32 bits)                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! [RFC 8888]: https://www.rfc-editor.org/rfc/rfc8888.html
//! [`TransportLayerCc`]: crate::transport_feedbacks::transport_layer_cc::TransportLayerCc

#[cfg(test)]
mod cc_feedback_report_test;

use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut};
use std::any::Any;
use std::fmt;

/// Sender SSRC, then the report blocks: the offset of the first one.
const REPORT_BLOCK_OFFSET: usize = HEADER_LENGTH + SSRC_LENGTH;
/// The report timestamp trailing every report.
const REPORT_TIMESTAMP_LENGTH: usize = 4;
/// SSRC (4) + begin_seq (2) + num_reports (2), before the metric blocks.
const REPORT_BLOCK_HEADER_LENGTH: usize = 8;
/// Every metric block is exactly two bytes.
const METRIC_BLOCK_LENGTH: usize = 2;
/// `num_reports` is a `u16`, but a block may not describe more than this many packets.
const MAX_METRIC_BLOCKS: usize = 16384;

/// The two ECN bits of the IP header, as reported for a received packet ([RFC 3168] §5).
///
/// The numeric values are the on-the-wire codepoints, which is what makes the ECT pair look
/// transposed at a glance: `ECT(1)` is `01` and `ECT(0)` is `10`.
///
/// [RFC 3168]: https://www.rfc-editor.org/rfc/rfc3168#section-5
#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
#[repr(u8)]
pub enum Ecn {
    /// `00` — Not ECN-Capable Transport.
    #[default]
    NotEct = 0,
    /// `01` — ECN Capable Transport, ECT(1).
    Ect1 = 1,
    /// `10` — ECN Capable Transport, ECT(0).
    Ect0 = 2,
    /// `11` — Congestion Encountered.
    Ce = 3,
}

impl Ecn {
    /// The codepoint for the low two bits of `value`.
    ///
    /// Total over two bits, so this cannot fail — which is why there is no `TryFrom`.
    fn from_bits(value: u8) -> Self {
        match value & 0x03 {
            0 => Ecn::NotEct,
            1 => Ecn::Ect1,
            2 => Ecn::Ect0,
            _ => Ecn::Ce,
        }
    }
}

impl fmt::Display for Ecn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Ecn::NotEct => "Not-ECT (00)",
            Ecn::Ect1 => "ECT(1) (01)",
            Ecn::Ect0 => "ECT(0) (10)",
            Ecn::Ce => "CE (11)",
        };
        write!(f, "{s}")
    }
}

/// One packet's fate, in two bytes: whether it arrived, its ECN marking, and when.
///
/// A metric block has no sequence number of its own — it is positional. The *i*th block in a
/// report block describes sequence number `begin_sequence + i`.
#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub struct CcFeedbackMetricBlock {
    /// Whether the packet arrived. When `false` the remaining fields carry no information and
    /// are decoded as zero, per [RFC 8888] §3.1.
    ///
    /// [RFC 8888]: https://www.rfc-editor.org/rfc/rfc8888.html#section-3.1
    pub received: bool,
    /// The ECN marking the packet carried. Meaningful only when `received`.
    pub ecn: Ecn,
    /// Arrival time before the report timestamp, in units of 1/1024 s.
    ///
    /// Thirteen bits, so at most 8191 — about 8 s. Meaningful only when `received`.
    pub arrival_time_offset: u16,
}

impl CcFeedbackMetricBlock {
    /// Encode into the two-byte wire form.
    fn marshal_word(&self) -> Result<u16> {
        let received = u16::from(self.received);
        let word = set_nbits_of_uint16(0, 1, 0, received)?;
        let word = set_nbits_of_uint16(word, 2, 1, self.ecn as u16)?;
        set_nbits_of_uint16(word, 13, 3, self.arrival_time_offset)
    }

    /// Decode from the two-byte wire form.
    ///
    /// A not-received packet reports nothing else: the other 15 bits are ignored rather than
    /// decoded, so a peer that leaves stale bits there cannot make a lost packet look like it
    /// arrived with an ECN marking.
    fn unmarshal_word(word: u16) -> Self {
        let received = word & 0x8000 != 0;
        if !received {
            return Self::default();
        }
        Self {
            received,
            ecn: Ecn::from_bits((word >> 13) as u8),
            arrival_time_offset: word & 0x1FFF,
        }
    }
}

impl fmt::Display for CcFeedbackMetricBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.received {
            write!(f, "(rx, {}, {}/1024s)", self.ecn, self.arrival_time_offset)
        } else {
            write!(f, "(lost)")
        }
    }
}

/// The packets of one media stream that a report describes.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct CcFeedbackReportBlock {
    /// SSRC of the RTP stream this block reports on.
    pub media_ssrc: u32,
    /// Sequence number of the first packet described by `metric_blocks`.
    pub begin_sequence: u16,
    /// One entry per sequence number from `begin_sequence`, in order.
    pub metric_blocks: Vec<CcFeedbackMetricBlock>,
}

impl CcFeedbackReportBlock {
    /// Encoded length in bytes.
    ///
    /// Metric blocks are two bytes each, so an odd count is padded with one empty block to keep
    /// the next report block 32-bit aligned. `num_reports` still records the true count, so the
    /// padding is not mistaken for a reported packet.
    fn raw_size(&self) -> usize {
        REPORT_BLOCK_HEADER_LENGTH + METRIC_BLOCK_LENGTH * self.padded_metric_block_count()
    }

    fn padded_metric_block_count(&self) -> usize {
        let count = self.metric_blocks.len();
        if count.is_multiple_of(2) {
            count
        } else {
            count + 1
        }
    }

    fn marshal_to(&self, buf: &mut &mut [u8]) -> Result<()> {
        if self.metric_blocks.len() > MAX_METRIC_BLOCKS {
            return Err(Error::TooManyReports);
        }

        buf.put_u32(self.media_ssrc);
        buf.put_u16(self.begin_sequence);
        buf.put_u16(self.metric_blocks.len() as u16);

        for block in &self.metric_blocks {
            buf.put_u16(block.marshal_word()?);
        }
        // The alignment block, written explicitly: the caller's buffer is not guaranteed zeroed.
        for _ in self.metric_blocks.len()..self.padded_metric_block_count() {
            buf.put_u16(0);
        }

        Ok(())
    }

    /// Decode one report block, returning it with the number of bytes it consumed.
    ///
    /// `budget` is what remains of the report's block region; a `num_reports` claiming more than
    /// that is a truncated or malformed packet rather than a short read.
    fn unmarshal_from<B: Buf>(raw_packet: &mut B, budget: usize) -> Result<(Self, usize)> {
        if budget < REPORT_BLOCK_HEADER_LENGTH
            || raw_packet.remaining() < REPORT_BLOCK_HEADER_LENGTH
        {
            return Err(Error::PacketTooShort);
        }

        let media_ssrc = raw_packet.get_u32();
        let begin_sequence = raw_packet.get_u16();
        let num_reports = raw_packet.get_u16() as usize;

        let padded = if num_reports.is_multiple_of(2) {
            num_reports
        } else {
            num_reports + 1
        };
        let consumed = REPORT_BLOCK_HEADER_LENGTH + METRIC_BLOCK_LENGTH * padded;
        if budget < consumed || raw_packet.remaining() < METRIC_BLOCK_LENGTH * padded {
            return Err(Error::PacketTooShort);
        }

        let mut metric_blocks = Vec::with_capacity(num_reports);
        for _ in 0..num_reports {
            metric_blocks.push(CcFeedbackMetricBlock::unmarshal_word(raw_packet.get_u16()));
        }
        if padded != num_reports {
            raw_packet.advance(METRIC_BLOCK_LENGTH);
        }

        Ok((
            Self {
                media_ssrc,
                begin_sequence,
                metric_blocks,
            },
            consumed,
        ))
    }
}

impl fmt::Display for CcFeedbackReportBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\tssrc={:x} begin_seq={} reports={}\n\t\t",
            self.media_ssrc,
            self.begin_sequence,
            self.metric_blocks.len()
        )?;
        for block in &self.metric_blocks {
            write!(f, "{block} ")?;
        }
        writeln!(f)
    }
}

/// An RTCP Congestion Control Feedback report ([RFC 8888]).
///
/// [RFC 8888]: https://www.rfc-editor.org/rfc/rfc8888.html
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct CcFeedbackReport {
    /// SSRC of the sender of this report.
    pub sender_ssrc: u32,
    /// One block per media stream being reported on.
    pub report_blocks: Vec<CcFeedbackReportBlock>,
    /// The instant every `arrival_time_offset` is measured back from, in NTP-style 1/65536 s
    /// units truncated to 32 bits.
    pub report_timestamp: u32,
}

impl fmt::Display for CcFeedbackReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "CcFeedbackReport sender_ssrc={:x} report_timestamp={}",
            self.sender_ssrc, self.report_timestamp
        )?;
        for block in &self.report_blocks {
            write!(f, "{block}")?;
        }
        Ok(())
    }
}

impl Packet for CcFeedbackReport {
    fn header(&self) -> Header {
        Header {
            padding: get_padding_size(self.raw_size()) != 0,
            count: FORMAT_CCFB,
            packet_type: PacketType::TransportSpecificFeedback,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    /// Every media SSRC this report carries a block for.
    ///
    /// One report covers several streams, so unlike most feedback packets this returns more than
    /// one SSRC — which is what lets an SFU route a single report to several senders.
    fn destination_ssrc(&self) -> Vec<u32> {
        self.report_blocks
            .iter()
            .map(|block| block.media_ssrc)
            .collect()
    }

    fn raw_size(&self) -> usize {
        let blocks: usize = self.report_blocks.iter().map(|b| b.raw_size()).sum();
        REPORT_BLOCK_OFFSET + blocks + REPORT_TIMESTAMP_LENGTH
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<CcFeedbackReport>() == Some(self)
    }

    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for CcFeedbackReport {
    fn marshal_size(&self) -> usize {
        let l = self.raw_size();
        // Already 32-bit aligned by construction; the term keeps the invariant explicit.
        l + get_padding_size(l)
    }
}

impl Marshal for CcFeedbackReport {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }

        let h = self.header();
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];

        buf.put_u32(self.sender_ssrc);
        for block in &self.report_blocks {
            block.marshal_to(&mut buf)?;
        }
        buf.put_u32(self.report_timestamp);

        if h.padding {
            put_padding(buf, self.raw_size());
        }

        Ok(self.marshal_size())
    }
}

impl Unmarshal for CcFeedbackReport {
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let raw_packet_len = raw_packet.remaining();
        if raw_packet_len < REPORT_BLOCK_OFFSET + REPORT_TIMESTAMP_LENGTH {
            return Err(Error::PacketTooShort);
        }

        let h = Header::unmarshal(raw_packet)?;
        if h.packet_type != PacketType::TransportSpecificFeedback || h.count != FORMAT_CCFB {
            return Err(Error::WrongType);
        }

        // The header's length field, not the buffer's, delimits this packet: in a compound RTCP
        // datagram the buffer may hold more than this report.
        let packet_len = 4 * (h.length as usize + 1);
        if raw_packet_len < packet_len || packet_len < REPORT_BLOCK_OFFSET + REPORT_TIMESTAMP_LENGTH
        {
            return Err(Error::PacketTooShort);
        }

        let sender_ssrc = raw_packet.get_u32();

        let mut remaining_blocks_len = packet_len - REPORT_BLOCK_OFFSET - REPORT_TIMESTAMP_LENGTH;
        let mut report_blocks = Vec::new();
        while remaining_blocks_len > 0 {
            let (block, consumed) =
                CcFeedbackReportBlock::unmarshal_from(raw_packet, remaining_blocks_len)?;
            report_blocks.push(block);
            remaining_blocks_len -= consumed;
        }

        let report_timestamp = raw_packet.get_u32();

        Ok(CcFeedbackReport {
            sender_ssrc,
            report_blocks,
            report_timestamp,
        })
    }
}

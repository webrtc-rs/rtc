//! What a feedback report says happened to one packet.

use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
use std::time::{Duration, Instant};

/// One packet's fate, as reported by the receiver.
///
/// `arrival` is a [`Duration`] rather than an [`Instant`] because it is measured on the
/// **receiver's** clock, which this endpoint has no way to align with its own. Only differences
/// between arrivals are meaningful, and those are what congestion control actually reads: the
/// spread between send spacing and arrival spacing is the delay the path is imposing.
///
/// Each feedback format supplies its own epoch — TWCC's 24-bit reference time, RFC 8888's report
/// timestamp — and both advance monotonically, so arrivals stay comparable across successive
/// reports of the same format. They are *not* comparable between formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acknowledgement {
    /// The sequence number this refers to. TWCC numbers packets itself; RFC 8888 uses the RTP
    /// sequence number of the stream it names.
    pub sequence_number: u16,
    /// Whether the receiver got it.
    pub arrived: bool,
    /// When it arrived, on the receiver's clock. `None` for a packet that did not arrive, or one
    /// reported as received without a usable arrival time.
    pub arrival: Option<Duration>,
    /// The ECN marking the receiver observed. TWCC cannot carry this and always reports `NotEct`.
    pub ecn: Ecn,
}

impl Acknowledgement {
    /// A packet the receiver did not get.
    pub fn lost(sequence_number: u16) -> Self {
        Self {
            sequence_number,
            arrived: false,
            arrival: None,
            ecn: Ecn::NotEct,
        }
    }

    /// A packet the receiver got at `arrival` on its own clock.
    pub fn received(sequence_number: u16, arrival: Option<Duration>, ecn: Ecn) -> Self {
        Self {
            sequence_number,
            arrived: true,
            arrival,
            ecn,
        }
    }
}

/// One outgoing packet, joined with whatever the receiver later said about it.
///
/// This is the record congestion control consumes: what was sent, when it left here, and when it
/// turned up there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketReport {
    /// SSRC of the stream the packet belongs to.
    pub ssrc: u32,
    /// Monotonic identifier assigned when the packet was recorded, so reports stay in send order
    /// however the sequence numbers wrap.
    pub id: u64,
    /// The RTP sequence number the packet carried.
    pub rtp_sequence_number: u16,
    /// Whether this packet is tracked by its transport-wide sequence number rather than its RTP
    /// one — the two feedback formats identify packets differently.
    pub is_twcc: bool,
    /// The transport-wide sequence number, when `is_twcc`.
    pub twcc_sequence_number: u16,
    /// Size on the wire, in bytes.
    pub size: usize,
    /// Whether the receiver reported it as arrived.
    pub arrived: bool,
    /// When it left this endpoint. **The release instant**, not the instant the application
    /// enqueued it — see the chain contract's rule 3, since a pacer's queueing delay counted as
    /// network delay is exactly what corrupts a bandwidth estimate.
    pub departure: Instant,
    /// When it arrived, on the receiver's clock. See [`Acknowledgement::arrival`].
    pub arrival: Option<Duration>,
    /// The ECN marking the receiver observed.
    pub ecn: Ecn,
}

/// A batch of packet reports, with the round trip time they imply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// When the feedback that produced this batch was received here.
    pub arrival: Instant,
    /// Round trip time derived from the newest packet this feedback acknowledged.
    pub rtt: Option<Duration>,
    /// The packets being reported on, in send order.
    pub packet_reports: Vec<PacketReport>,
}

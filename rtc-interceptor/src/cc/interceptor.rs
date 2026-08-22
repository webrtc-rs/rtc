//! Records what left, ingests what the remote said about it, and drives an estimator.

use super::estimator::BandwidthEstimator;
use crate::Interceptor;
use crate::rtpfb::convert::{convert_ccfb, convert_twcc};
use crate::rtpfb::history::History;
use crate::stream_info::StreamInfo;
use crate::twcc::stream_supports_twcc;
use crate::{Attribute, Packet, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use shared::marshal::{MarshalSize, Unmarshal};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// How long an unacknowledged packet is kept before it is written off.
///
/// Bounds the send history on a path that has stopped reporting. Too short and late feedback names
/// packets there is no record of; too long and memory grows on a dead path. Two seconds is several
/// round trips on any path worth estimating for, and one report interval is measured in tens of
/// milliseconds.
pub const DEFAULT_PRUNE_HORIZON: Duration = Duration::from_secs(2);

/// Per-stream state: the header-extension id the transport-wide sequence number is written under.
struct LocalStream {
    hdr_ext_id: u8,
}

/// Builder for [`CongestionControlInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{CongestionControlBuilder, ConstantBitrate, Registry};
///
/// let chain = Registry::new()
///     .with(CongestionControlBuilder::new(ConstantBitrate::new(1_000_000.0)).build())
///     .build();
/// # let _ = chain;
/// ```
pub struct CongestionControlBuilder<E: BandwidthEstimator> {
    estimator: E,
    prune_horizon: Duration,
}

impl<E: BandwidthEstimator> CongestionControlBuilder<E> {
    /// A builder driving `estimator`.
    pub fn new(estimator: E) -> Self {
        Self {
            estimator,
            prune_horizon: DEFAULT_PRUNE_HORIZON,
        }
    }

    /// How long an unacknowledged packet is kept before it is written off.
    pub fn with_prune_horizon(mut self, prune_horizon: Duration) -> Self {
        self.prune_horizon = prune_horizon;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> CongestionControlInterceptor<E> {
        CongestionControlInterceptor {
            last_target: self.estimator.target_bitrate(),
            estimator: self.estimator,
            prune_horizon: self.prune_horizon,
            history: History::new(),
            streams: HashMap::new(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

/// Records every departing packet, resolves the remote's feedback against it, and drives a
/// [`BandwidthEstimator`].
///
/// # Where this belongs in the chain
///
/// **Wire-most.** It is the only position that sees every byte that leaves: nothing exits the chain
/// except through the interceptors ahead of it in the walk, so a retransmission emitted by the NACK
/// responder and a repair packet emitted by the FEC encoder both arrive here, already paced and
/// already numbered. An estimator reading a history that omits them sees fewer bytes than are on
/// the wire, infers headroom, and raises the target during loss — a positive feedback loop that is
/// hard to spot, because the estimator's own accounting stays internally consistent throughout.
///
/// It also has to be **below the pacer**, so `packet.now` is the instant the packet was *released*
/// rather than the instant the application enqueued it. A pacer can hold a packet for tens of
/// milliseconds; counting that as network delay is exactly the error that makes a delay-based
/// estimate collapse.
///
/// # How the estimate gets out
///
/// On the read leg, attached to the feedback packet that produced it, as
/// [`Attribute::TargetBitrateChanged`]. The pacer sits application-ward of this interceptor, so it
/// sees that packet *after* this one does and reads the attribute on its way past. That is the only
/// leg the estimate can cross on: on the write leg this interceptor is last, and anything it
/// attached would already have gone by everything that cares.
pub struct CongestionControlInterceptor<E: BandwidthEstimator> {
    estimator: E,
    history: History,
    streams: HashMap<u32, LocalStream>,
    prune_horizon: Duration,
    /// The last target handed onward, so an unchanged estimate does not re-announce itself.
    last_target: f64,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl<E: BandwidthEstimator> CongestionControlInterceptor<E> {
    /// The estimator, for reading its stats.
    pub fn estimator(&self) -> &E {
        &self.estimator
    }

    /// How many sent packets are still awaiting a verdict.
    pub fn outstanding(&self) -> usize {
        self.history.len()
    }

    /// The transport-wide sequence number the TWCC sender wrote, if this stream carries one.
    ///
    /// The sender sits between the pacer and here, so by the time a packet arrives the number is
    /// already in its header — which is the whole reason this interceptor is wire-most rather than
    /// the sender being.
    fn twcc_sequence_number(&self, rtp_packet: &rtp::Packet) -> Option<u16> {
        let stream = self.streams.get(&rtp_packet.header.ssrc)?;
        let mut extension = rtp_packet.header.get_extension(stream.hdr_ext_id)?;
        rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(&mut extension)
            .ok()
            .map(|extension| extension.transport_sequence)
    }

    /// Feed one inbound RTCP packet to the history. Returns whether it said anything.
    #[allow(clippy::borrowed_box)]
    fn ingest(&mut self, now: Instant, rtcp_packet: &Box<dyn rtcp::Packet>) -> bool {
        let payload = rtcp_packet.as_any();

        if let Some(feedback) = payload
            .downcast_ref::<rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc>(
        ) {
            for acknowledgement in convert_twcc(feedback) {
                self.history.on_twcc_feedback(now, acknowledgement);
            }
            return true;
        }

        if let Some(feedback) = payload
            .downcast_ref::<rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReport>(
        ) {
            let (_report_delay, per_stream) = convert_ccfb(feedback);
            for (ssrc, acknowledgements) in per_stream {
                for acknowledgement in acknowledgements {
                    self.history.on_ccfb_feedback(now, ssrc, acknowledgement);
                }
            }
            return true;
        }

        false
    }
}

impl<E: BandwidthEstimator> Protocol<TaggedPacket, TaggedPacket, ()>
    for CongestionControlInterceptor<E>
{
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        let mut reported = false;
        if let Packet::Rtcp(ref rtcp_packets) = msg.message.packet {
            // `for` over a borrow of `msg` while `self` is borrowed mutably: collect first.
            let feedback: Vec<_> = rtcp_packets.to_vec();
            for rtcp_packet in &feedback {
                reported |= self.ingest(msg.now, rtcp_packet);
            }
        }

        if reported {
            let reports = self.history.take_reports();
            self.estimator.on_reports(msg.now, &reports);

            let target = self.estimator.target_bitrate();
            if target != self.last_target {
                self.last_target = target;
                // Onto *this* packet: the pacer is application-ward of here, so it sees this
                // packet after this interceptor does and reads the attribute on its way past.
                msg.message.add(Attribute::TargetBitrateChanged {
                    bits_per_second: target,
                });
            }
        }

        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet {
            let twcc_sequence_number = self.twcc_sequence_number(rtp_packet);
            // Only a stream this endpoint is sending and that negotiated transport-wide CC is
            // tracked; anything else has no sequence space the remote will report against.
            if self.streams.contains_key(&rtp_packet.header.ssrc) {
                self.history.add_outgoing(
                    rtp_packet.header.ssrc,
                    rtp_packet.header.sequence_number,
                    twcc_sequence_number.is_some(),
                    twcc_sequence_number.unwrap_or_default(),
                    rtp_packet.marshal_size(),
                    // The release instant. The pacer has already run on this leg — recording the
                    // enqueue instant instead would charge its queueing delay to the network.
                    msg.now,
                );
            }
        }

        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        self.history
            .prune_before(now.checked_sub(self.prune_horizon).unwrap_or(now));
        self.estimator.handle_timeout(now);
        Ok(())
    }

    /// Whatever the estimator wants, and `None` when it wants nothing.
    ///
    /// This interceptor has no timer of its own: pruning is bounded work that can ride any wake-up,
    /// and asking for one on its own account would wake the whole chain on an idle connection.
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.estimator.poll_timeout()
    }
}

impl<E: BandwidthEstimator> Interceptor for CongestionControlInterceptor<E> {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        // Tracked whether or not it negotiated transport-wide CC: RFC 8888 reports against the RTP
        // sequence number and needs no extension, so a stream without one is still worth recording.
        let hdr_ext_id = stream_supports_twcc(info).unwrap_or_default();
        self.streams.insert(info.ssrc, LocalStream { hdr_ext_id });
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

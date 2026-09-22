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
/// use rtc_interceptor::{Slot, CongestionControlBuilder, ConstantBitrate, Registry};
///
/// let chain = Registry::new()
///     .with(Slot::CongestionControl, CongestionControlBuilder::new(ConstantBitrate::new(1_000_000.0)).build())
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
    fn ingest(&mut self, now: Instant, rtcp_packet: &dyn rtcp::Packet) -> bool {
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
            // Borrowed, not cloned: the packets belong to `msg`, not `self`, and cloning a boxed
            // packet deep-copies it — including the ones this interceptor has no use for.
            for rtcp_packet in rtcp_packets {
                reported |= self.ingest(msg.now, rtcp_packet.as_ref());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AttributedPacket;
    use crate::rtpfb::acknowledgement::PacketReport;
    use crate::stream_info::{RTCPFeedback, RTPHeaderExtension};
    use crate::twcc::TRANSPORT_CC_URI;
    use rtcp::transport_feedbacks::cc_feedback_report::{
        CcFeedbackMetricBlock, CcFeedbackReport, CcFeedbackReportBlock,
    };
    use rtcp::transport_feedbacks::transport_layer_cc::{
        PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
        TransportLayerCc,
    };
    use shared::TransportContext;
    use std::ops::Range;

    const SSRC: u32 = 0x0A0B_0C0D;
    const INITIAL_TARGET: f64 = 1_000_000.0;

    /// Records what it is told. Its target drops with every packet reported, so feedback that
    /// resolves something moves the estimate and feedback that resolves nothing does not.
    #[derive(Default)]
    struct Recorder {
        calls: usize,
        seen: Vec<PacketReport>,
    }

    impl BandwidthEstimator for Recorder {
        fn on_reports(&mut self, _now: Instant, reports: &[PacketReport]) {
            self.calls += 1;
            self.seen.extend_from_slice(reports);
        }

        fn target_bitrate(&self) -> f64 {
            INITIAL_TARGET - 1_000.0 * self.seen.len() as f64
        }
    }

    fn interceptor() -> CongestionControlInterceptor<Recorder> {
        let mut interceptor = CongestionControlBuilder::new(Recorder::default()).build();
        interceptor.bind_local_stream(&StreamInfo {
            ssrc: SSRC,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "transport-cc".to_owned(),
                parameter: String::new(),
            }],
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: TRANSPORT_CC_URI.to_owned(),
                id: 5,
            }],
            ..Default::default()
        });
        interceptor
    }

    /// Sends `sequence_numbers`, each also carrying it as its transport-wide sequence number.
    fn send(
        interceptor: &mut CongestionControlInterceptor<Recorder>,
        now: Instant,
        sequence_numbers: Range<u16>,
    ) {
        for sequence_number in sequence_numbers {
            let mut header = rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                ssrc: SSRC,
                ..Default::default()
            };
            header
                .set_extension(5, sequence_number.to_be_bytes().to_vec().into())
                .expect("extension");
            interceptor
                .handle_write(TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                        header,
                        payload: vec![0xAB; 1200].into(),
                    })),
                })
                .expect("write");
            while interceptor.poll_write().is_some() {}
        }
    }

    fn twcc(base: u16, count: u16) -> Box<dyn rtcp::Packet> {
        Box::new(TransportLayerCc {
            media_ssrc: SSRC,
            base_sequence_number: base,
            packet_status_count: count,
            reference_time: 1,
            packet_chunks: vec![PacketStatusChunk::RunLengthChunk(RunLengthChunk {
                type_tcc: StatusChunkTypeTcc::RunLengthChunk,
                packet_status_symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
                run_length: count,
            })],
            recv_deltas: (0..count)
                .map(|_| RecvDelta {
                    type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                    delta: 250,
                })
                .collect(),
            ..Default::default()
        })
    }

    fn ccfb(begin: u16, count: u16) -> Box<dyn rtcp::Packet> {
        Box::new(CcFeedbackReport {
            sender_ssrc: 1,
            report_blocks: vec![CcFeedbackReportBlock {
                media_ssrc: SSRC,
                begin_sequence: begin,
                metric_blocks: (0..count)
                    .map(|index| CcFeedbackMetricBlock {
                        received: true,
                        arrival_time_offset: 100 - index,
                        ..Default::default()
                    })
                    .collect(),
            }],
            report_timestamp: 0,
        })
    }

    fn receiver_report() -> Box<dyn rtcp::Packet> {
        Box::new(rtcp::receiver_report::ReceiverReport {
            ssrc: 1,
            reports: vec![rtcp::reception_report::ReceptionReport {
                ssrc: SSRC,
                ..Default::default()
            }],
            ..Default::default()
        })
    }

    fn pli() -> Box<dyn rtcp::Packet> {
        Box::new(
            rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication {
                sender_ssrc: 1,
                media_ssrc: SSRC,
            },
        )
    }

    fn target_attribute(packet: &TaggedPacket) -> Option<f64> {
        match packet.message.get(&Attribute::TargetBitrateChanged {
            bits_per_second: 0.0,
        }) {
            Some(Attribute::TargetBitrateChanged { bits_per_second }) => Some(*bits_per_second),
            _ => None,
        }
    }

    fn address(packet: &dyn rtcp::Packet) -> *const () {
        packet as *const dyn rtcp::Packet as *const ()
    }

    /// One step of a feedback exchange, and what it must leave behind.
    struct Round {
        /// Sent before the feedback arrives.
        send: Range<u16>,
        feedback: Vec<Box<dyn rtcp::Packet>>,
        /// Packets reported to the estimator so far.
        reported: usize,
        /// Calls the estimator has had so far.
        calls: usize,
        /// The target-bitrate attribute the feedback leaves with.
        attribute: Option<f64>,
    }

    /// Feedback is ingested from the packets `msg` owns rather than from copies of them.
    ///
    /// Each compound packet is read twice: as-is by one interceptor, and as deep copies (what the
    /// interceptor used to ingest) by another. The history, the estimator's input and output, the
    /// target-bitrate attribute and the forwarded packet must agree between the two — and the
    /// packet forwarded is the caller's original, not a copy.
    #[test]
    fn feedback_is_read_in_place_and_forwarded_untouched() {
        let epoch = Instant::now();
        let mut borrowed = interceptor();
        let mut copied = interceptor();

        let rounds = vec![
            // TWCC among unrelated reports: resolves 0..10.
            Round {
                send: 0..10,
                feedback: vec![twcc(0, 10), receiver_report(), pli()],
                reported: 10,
                calls: 1,
                attribute: Some(INITIAL_TARGET - 10_000.0),
            },
            // Nothing for congestion control: no estimator call, no attribute.
            Round {
                send: 10..20,
                feedback: vec![receiver_report(), pli()],
                reported: 10,
                calls: 1,
                attribute: None,
            },
            // RFC 8888 feedback for what the previous round sent.
            Round {
                send: 0..0,
                feedback: vec![ccfb(10, 10), receiver_report()],
                reported: 20,
                calls: 2,
                attribute: Some(INITIAL_TARGET - 20_000.0),
            },
            // Feedback naming only packets already reported: the estimator hears "no news".
            Round {
                send: 0..0,
                feedback: vec![twcc(0, 10), pli()],
                reported: 20,
                calls: 3,
                attribute: None,
            },
            // Both kinds in one compound packet.
            Round {
                send: 20..40,
                feedback: vec![pli(), twcc(20, 10), ccfb(30, 10)],
                reported: 40,
                calls: 4,
                attribute: Some(INITIAL_TARGET - 40_000.0),
            },
        ];

        for (round, step) in rounds.into_iter().enumerate() {
            let sent_at = epoch + Duration::from_millis(100 * round as u64);
            send(&mut borrowed, sent_at, step.send.clone());
            send(&mut copied, sent_at, step.send);

            let now = sent_at + Duration::from_millis(50);
            let originals: Vec<*const ()> = step
                .feedback
                .iter()
                .map(|packet| address(&**packet))
                .collect();
            let copies = step.feedback.to_vec();
            for (interceptor, packets) in [(&mut borrowed, step.feedback), (&mut copied, copies)] {
                interceptor
                    .handle_read(TaggedPacket {
                        now,
                        transport: TransportContext::default(),
                        message: AttributedPacket::new(Packet::Rtcp(packets)),
                    })
                    .expect("read");
            }

            let out = borrowed.poll_read().expect("the feedback is forwarded");
            let reference = copied.poll_read().expect("the feedback is forwarded");
            assert!(borrowed.poll_read().is_none());
            assert_eq!(out.now, now);

            let (Packet::Rtcp(forwarded), Packet::Rtcp(expected)) =
                (&out.message.packet, &reference.message.packet)
            else {
                panic!("round {round}: RTCP must be forwarded as RTCP");
            };
            assert_eq!(
                forwarded
                    .iter()
                    .map(|packet| address(&**packet))
                    .collect::<Vec<_>>(),
                originals,
                "round {round}: the caller's packets are forwarded, in order, not copies of them"
            );
            assert_eq!(forwarded.len(), expected.len());
            assert!(
                forwarded
                    .iter()
                    .zip(expected)
                    .all(|(forwarded, expected)| **forwarded == **expected),
                "round {round}: the forwarded packets must be unchanged"
            );

            assert_eq!(target_attribute(&out), step.attribute, "round {round}");
            assert_eq!(target_attribute(&out), target_attribute(&reference));

            assert_eq!(
                borrowed.estimator().seen.len(),
                step.reported,
                "round {round}"
            );
            assert_eq!(borrowed.estimator().seen, copied.estimator().seen);
            assert_eq!(borrowed.estimator().calls, step.calls, "round {round}");
            assert_eq!(borrowed.estimator().calls, copied.estimator().calls);
            assert_eq!(borrowed.outstanding(), copied.outstanding());
        }

        assert_eq!(borrowed.outstanding(), 0, "every packet sent was reported");
        let sequence_numbers: Vec<u16> = borrowed
            .estimator()
            .seen
            .iter()
            .map(|report| report.rtp_sequence_number)
            .collect();
        assert_eq!(sequence_numbers, (0..40).collect::<Vec<_>>());
    }
}

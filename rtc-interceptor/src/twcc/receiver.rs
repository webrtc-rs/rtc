//! TWCC Receiver Interceptor - tracks incoming packets and generates feedback.

use super::recorder::Recorder;
use super::stream_supports_twcc;
use crate::stream_info::StreamInfo;
use crate::{Interceptor, Packet, TaggedPacket};
use shared::error::Error;
use shared::marshal::Unmarshal;
use shared::TransportContext;
use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

/// Default interval for sending TWCC feedback.
const DEFAULT_INTERVAL: Duration = Duration::from_millis(100);

/// Builder for the TwccReceiverInterceptor.
///
/// # Example
///
/// ```ignore
/// use rtc_interceptor::{Registry, TwccReceiverBuilder};
/// use std::time::Duration;
///
/// let chain = Registry::new()
///     .with(TwccReceiverBuilder::new()
///         .with_interval(Duration::from_millis(100))
///         .build())
///     .build();
/// ```
pub struct TwccReceiverBuilder<P> {
    /// Interval between feedback reports.
    interval: Duration,
    _phantom: PhantomData<P>,
}

impl<P> Default for TwccReceiverBuilder<P> {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            _phantom: PhantomData,
        }
    }
}

impl<P> TwccReceiverBuilder<P> {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interval between feedback reports.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Build the interceptor factory function.
    pub fn build(self) -> impl FnOnce(P) -> TwccReceiverInterceptor<P> {
        move |inner| TwccReceiverInterceptor::new(inner, self.interval)
    }
}

/// Per-stream state for the receiver.
struct RemoteStream {
    /// Header extension ID for transport-wide CC.
    hdr_ext_id: u8,
}

/// Interceptor that tracks incoming RTP packets and generates TWCC feedback.
///
/// This interceptor examines incoming RTP packets for transport-wide CC sequence
/// numbers and periodically generates TransportLayerCC feedback packets.
pub struct TwccReceiverInterceptor<P> {
    inner: P,

    /// Configuration
    interval: Duration,

    /// Start time for calculating arrival times.
    start_time: Option<Instant>,

    /// TWCC recorder for building feedback.
    recorder: Option<Recorder>,

    /// Remote stream state per SSRC.
    streams: HashMap<u32, RemoteStream>,

    /// Queue for feedback packets.
    write_queue: VecDeque<TaggedPacket>,

    /// Next timeout for sending feedback.
    next_timeout: Option<Instant>,
}

impl<P> TwccReceiverInterceptor<P> {
    fn new(inner: P, interval: Duration) -> Self {
        Self {
            inner,
            interval,
            start_time: None,
            recorder: None,
            streams: HashMap::new(),
            write_queue: VecDeque::new(),
            next_timeout: None,
        }
    }

    fn generate_feedback(&mut self, now: Instant) {
        let Some(recorder) = self.recorder.as_mut() else {
            return;
        };

        let packets = recorder.build_feedback_packet();
        for pkt in packets {
            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: Packet::Rtcp(vec![pkt]),
            });
        }
    }
}

impl<P: Interceptor> sansio::Protocol<TaggedPacket, TaggedPacket, ()>
    for TwccReceiverInterceptor<P>
{
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // Process incoming RTP packets with TWCC extension
        if let Packet::Rtp(ref rtp_packet) = msg.message {
            if let Some(stream) = self.streams.get(&rtp_packet.header.ssrc) {
                // Initialize recorder on first packet
                if self.recorder.is_none() {
                    // Use a random sender SSRC for feedback
                    self.recorder = Some(Recorder::new(rand::random()));
                    self.start_time = Some(msg.now);
                    self.next_timeout = Some(msg.now + self.interval);
                }

                // Extract transport CC sequence number
                if let Some(ext_data) = rtp_packet.header.get_extension(stream.hdr_ext_id) {
                    if let Ok(tcc) =
                        rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(
                            &mut ext_data.as_ref(),
                        )
                    {
                        // Calculate arrival time in microseconds since start
                        let arrival_time = self
                            .start_time
                            .map(|start| msg.now.duration_since(start).as_micros() as i64)
                            .unwrap_or(0);

                        if let Some(recorder) = self.recorder.as_mut() {
                            recorder.record(
                                rtp_packet.header.ssrc,
                                tcc.transport_sequence,
                                arrival_time,
                            );
                        }
                    }
                }
            }
        }

        self.inner.handle_read(msg)
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.inner.poll_read()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.inner.handle_write(msg)
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        // First drain feedback packets
        if let Some(pkt) = self.write_queue.pop_front() {
            return Some(pkt);
        }
        self.inner.poll_write()
    }

    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        // Check if we need to send feedback
        if let Some(timeout) = self.next_timeout {
            if now >= timeout {
                self.generate_feedback(now);
                self.next_timeout = Some(now + self.interval);
            }
        }
        self.inner.handle_timeout(now)
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        let inner_timeout = self.inner.poll_timeout();

        match (self.next_timeout, inner_timeout) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }
}

impl<P: Interceptor> Interceptor for TwccReceiverInterceptor<P> {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        self.inner.bind_local_stream(info);
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.inner.unbind_local_stream(info);
    }

    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        if let Some(hdr_ext_id) = stream_supports_twcc(info) {
            // Don't track if ID is 0 (invalid)
            if hdr_ext_id != 0 {
                self.streams.insert(info.ssrc, RemoteStream { hdr_ext_id });
            }
        }
        self.inner.bind_remote_stream(info);
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
        self.inner.unbind_remote_stream(info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_info::RTPHeaderExtension;
    use crate::Registry;
    use sansio::Protocol;
    use shared::marshal::Marshal;

    fn make_rtp_packet_with_twcc(ssrc: u32, seq: u16, twcc_seq: u16, hdr_ext_id: u8) -> rtp::Packet {
        let mut pkt = rtp::Packet {
            header: rtp::header::Header {
                ssrc,
                sequence_number: seq,
                ..Default::default()
            },
            payload: vec![].into(),
            ..Default::default()
        };

        let tcc_ext = rtp::extension::transport_cc_extension::TransportCcExtension {
            transport_sequence: twcc_seq,
        };
        if let Ok(ext_data) = tcc_ext.marshal() {
            let _ = pkt.header.set_extension(hdr_ext_id, ext_data.freeze());
        }

        pkt
    }

    #[test]
    fn test_twcc_receiver_builder_defaults() {
        let chain = Registry::new()
            .with(TwccReceiverBuilder::default().build())
            .build();

        assert_eq!(chain.interval, DEFAULT_INTERVAL);
        assert!(chain.recorder.is_none());
    }

    #[test]
    fn test_twcc_receiver_builder_custom_interval() {
        let chain = Registry::new()
            .with(
                TwccReceiverBuilder::new()
                    .with_interval(Duration::from_millis(50))
                    .build(),
            )
            .build();

        assert_eq!(chain.interval, Duration::from_millis(50));
    }

    #[test]
    fn test_twcc_receiver_records_packets() {
        let mut chain = Registry::new()
            .with(TwccReceiverBuilder::new().build())
            .build();

        // Bind remote stream with TWCC support
        let info = StreamInfo {
            ssrc: 12345,
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: super::super::TRANSPORT_CC_URI.to_string(),
                id: 5,
            }],
            ..Default::default()
        };
        chain.bind_remote_stream(&info);

        let now = Instant::now();

        // Receive RTP packet with TWCC extension
        let rtp = make_rtp_packet_with_twcc(12345, 1, 0, 5);
        let pkt = TaggedPacket {
            now,
            transport: Default::default(),
            message: Packet::Rtp(rtp),
        };
        chain.handle_read(pkt).unwrap();

        // Recorder should be initialized
        assert!(chain.recorder.is_some());
        assert!(chain.next_timeout.is_some());
    }

    #[test]
    fn test_twcc_receiver_generates_feedback_on_timeout() {
        let mut chain = Registry::new()
            .with(
                TwccReceiverBuilder::new()
                    .with_interval(Duration::from_millis(100))
                    .build(),
            )
            .build();

        let info = StreamInfo {
            ssrc: 12345,
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: super::super::TRANSPORT_CC_URI.to_string(),
                id: 5,
            }],
            ..Default::default()
        };
        chain.bind_remote_stream(&info);

        let start = Instant::now();

        // Receive some packets
        for i in 0..5u16 {
            let rtp = make_rtp_packet_with_twcc(12345, i, i, 5);
            let pkt = TaggedPacket {
                now: start + Duration::from_millis(i as u64 * 10),
                transport: Default::default(),
                message: Packet::Rtp(rtp),
            };
            chain.handle_read(pkt).unwrap();
        }

        // Trigger timeout
        let timeout_time = start + Duration::from_millis(150);
        chain.handle_timeout(timeout_time).unwrap();

        // Should have feedback packet
        let feedback = chain.poll_write();
        assert!(feedback.is_some());

        if let Some(tagged) = feedback {
            if let Packet::Rtcp(rtcp_packets) = tagged.message {
                assert!(!rtcp_packets.is_empty());
            } else {
                panic!("Expected RTCP packet");
            }
        }
    }

    #[test]
    fn test_twcc_receiver_no_feedback_without_binding() {
        let mut chain = Registry::new()
            .with(TwccReceiverBuilder::new().build())
            .build();

        let now = Instant::now();

        // Receive packet without binding (no TWCC tracking)
        let rtp = make_rtp_packet_with_twcc(12345, 1, 0, 5);
        let pkt = TaggedPacket {
            now,
            transport: Default::default(),
            message: Packet::Rtp(rtp),
        };
        chain.handle_read(pkt).unwrap();

        // Recorder should not be initialized
        assert!(chain.recorder.is_none());
    }

    #[test]
    fn test_twcc_receiver_unbind_removes_stream() {
        let mut chain = Registry::new()
            .with(TwccReceiverBuilder::new().build())
            .build();

        let info = StreamInfo {
            ssrc: 12345,
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: super::super::TRANSPORT_CC_URI.to_string(),
                id: 5,
            }],
            ..Default::default()
        };

        chain.bind_remote_stream(&info);
        assert!(chain.streams.contains_key(&12345));

        chain.unbind_remote_stream(&info);
        assert!(!chain.streams.contains_key(&12345));
    }

    #[test]
    fn test_twcc_receiver_poll_timeout() {
        let mut chain = Registry::new()
            .with(TwccReceiverBuilder::new().build())
            .build();

        // No timeout initially
        assert!(chain.poll_timeout().is_none());

        let info = StreamInfo {
            ssrc: 12345,
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: super::super::TRANSPORT_CC_URI.to_string(),
                id: 5,
            }],
            ..Default::default()
        };
        chain.bind_remote_stream(&info);

        let now = Instant::now();

        // Receive a packet to initialize recorder
        let rtp = make_rtp_packet_with_twcc(12345, 1, 0, 5);
        let pkt = TaggedPacket {
            now,
            transport: Default::default(),
            message: Packet::Rtp(rtp),
        };
        chain.handle_read(pkt).unwrap();

        // Should have timeout now
        let timeout = chain.poll_timeout();
        assert!(timeout.is_some());
    }
}

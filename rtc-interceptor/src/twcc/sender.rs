//! Tags outgoing RTP packets with transport-wide sequence numbers.

use super::stream_supports_twcc;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Packet, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use shared::marshal::Marshal;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::Instant;

/// Builder for the [`TwccSenderInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Registry, TwccSenderBuilder};
///
/// let chain = Registry::new()
///     .with(TwccSenderBuilder::new().build())
///     .build();
/// ```
#[derive(Default)]
pub struct TwccSenderBuilder {
    /// The first transport-wide sequence number to hand out.
    initial_sequence_number: u16,
}

impl TwccSenderBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the first transport-wide sequence number to hand out.
    ///
    /// Defaults to zero. The counter is shared across every local stream and wraps, so the
    /// starting point only matters to a test that wants to pin the numbers it asserts on, or to
    /// a session resuming a numbering it had already begun.
    pub fn with_initial_sequence_number(mut self, sequence_number: u16) -> Self {
        self.initial_sequence_number = sequence_number;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> TwccSenderInterceptor {
        TwccSenderInterceptor::new(self.initial_sequence_number)
    }
}

/// Per-stream state.
struct LocalStream {
    /// Header extension ID for transport-wide CC.
    hdr_ext_id: u8,
}

/// Numbers every departing RTP packet so the remote can report on it
/// ([`draft-holmer-rmcat-transport-wide-cc-extensions-01`]).
///
/// # Where this belongs in the chain
///
/// **Between the pacer and the send history**, near the wire. Numbering identifies a
/// *transmission*, not a packet, so it has to happen after the pacer has decided what actually
/// leaves and before the history records it — a retransmission is a separate transmission and gets
/// its own number.
///
/// Under the nested chain this could not hold: a retransmission left from the NACK responder's own
/// queue and never reached the tagger at all.
///
/// [`draft-holmer-rmcat-transport-wide-cc-extensions-01`]: http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
#[derive(Default)]
pub struct TwccSenderInterceptor {
    /// Transport-wide sequence number counter, shared across all streams.
    next_sequence_number: u16,
    streams: HashMap<u32, LocalStream>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
    /// Outbound packets ready for the next interceptor: what passed through, plus
    /// anything this one generated.
    write_queue: VecDeque<TaggedPacket>,
}

impl TwccSenderInterceptor {
    /// A tagger with no streams bound yet.
    fn new(initial_sequence_number: u16) -> Self {
        Self {
            next_sequence_number: initial_sequence_number,
            ..Default::default()
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for TwccSenderInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(ref mut rtp_packet) = msg.message.packet
            && let Some(stream) = self.streams.get(&rtp_packet.header.ssrc)
        {
            let seq = self.next_sequence_number;
            self.next_sequence_number = self.next_sequence_number.wrapping_add(1);

            let tcc_ext = rtp::extension::transport_cc_extension::TransportCcExtension {
                transport_sequence: seq,
            };
            if let Ok(ext_data) = tcc_ext.marshal() {
                let _ = rtp_packet
                    .header
                    .set_extension(stream.hdr_ext_id, ext_data.freeze());
            }
        }
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for TwccSenderInterceptor {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if let Some(hdr_ext_id) = stream_supports_twcc(info)
            && hdr_ext_id != 0
        {
            self.streams.insert(info.ssrc, LocalStream { hdr_ext_id });
        }
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
    use crate::chain::Chain;
    use crate::stream_info::RTPHeaderExtension;
    use sansio::Protocol;
    use shared::TransportContext;
    use shared::marshal::Unmarshal;
    use std::time::Instant;

    const TWCC_URI: &str =
        "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

    fn stream_info(ssrc: u32, ext_id: u16) -> StreamInfo {
        StreamInfo {
            ssrc,
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: TWCC_URI.to_owned(),
                id: ext_id,
            }],
            ..Default::default()
        }
    }

    fn packet(sequence_number: u16, ssrc: u32) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    sequence_number,
                    ssrc,
                    ..Default::default()
                },
                payload: vec![0u8; 4].into(),
            })),
        }
    }

    fn tag_of(msg: &TaggedPacket, ext_id: u8) -> Option<u16> {
        let Packet::Rtp(rtp) = &msg.message.packet else {
            return None;
        };
        let data = rtp.header.get_extension(ext_id)?;
        rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(&mut data.as_ref())
            .ok()
            .map(|e| e.transport_sequence)
    }

    fn chain() -> Chain {
        let mut chain = Chain::new(vec![Box::new(TwccSenderBuilder::new().build())]);
        chain.bind_local_stream(&stream_info(1, 5));
        chain
    }

    #[test]
    fn a_bound_stream_is_numbered_consecutively() {
        let mut chain = chain();
        let mut tags = Vec::new();
        for sequence_number in 0..3 {
            chain.handle_write(packet(sequence_number, 1)).unwrap();
            while let Some(out) = chain.poll_write() {
                tags.push(tag_of(&out, 5));
            }
        }
        assert_eq!(vec![Some(0), Some(1), Some(2)], tags);
    }

    #[test]
    fn an_unbound_stream_is_left_alone() {
        let mut chain = chain();
        chain.handle_write(packet(0, 999)).unwrap();
        let out = chain.poll_write().expect("passes through");
        assert_eq!(None, tag_of(&out, 5), "no extension added");
    }

    #[test]
    fn unbinding_stops_the_numbering() {
        let mut chain = chain();
        chain.unbind_local_stream(&stream_info(1, 5));
        chain.handle_write(packet(0, 1)).unwrap();
        let out = chain.poll_write().expect("passes through");
        assert_eq!(None, tag_of(&out, 5));
    }

    /// The counter is transport-wide: one sequence across every stream, not one per SSRC.
    #[test]
    fn the_counter_is_shared_across_streams() {
        let mut chain = chain();
        chain.bind_local_stream(&stream_info(2, 5));

        let mut tags = Vec::new();
        for ssrc in [1, 2, 1] {
            chain.handle_write(packet(0, ssrc)).unwrap();
            while let Some(out) = chain.poll_write() {
                tags.push(tag_of(&out, 5));
            }
        }
        assert_eq!(vec![Some(0), Some(1), Some(2)], tags);
    }

    /// An interceptor wireward of the tagger sees the number, which is what lets a send history key on it.
    #[test]
    fn a_stage_closer_to_the_wire_sees_the_tag() {
        #[derive(Default)]
        struct Recorder {
            seen: Vec<Option<u16>>,
            write_queue: VecDeque<TaggedPacket>,
        }
        impl Protocol<TaggedPacket, TaggedPacket, ()> for Recorder {
            type Rout = TaggedPacket;
            type Wout = TaggedPacket;
            type Eout = ();
            type Error = Error;
            type Time = Instant;

            fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
                self.seen.push(tag_of(&msg, 5));
                self.write_queue.push_back(msg);
                Ok(())
            }

            fn poll_write(&mut self) -> Option<Self::Wout> {
                self.write_queue.pop_front()
            }

            fn handle_read(&mut self, _msg: TaggedPacket) -> Result<(), Self::Error> {
                Ok(())
            }

            fn poll_read(&mut self) -> Option<Self::Rout> {
                None
            }

            fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
                Ok(())
            }

            fn poll_timeout(&mut self) -> Option<Self::Time> {
                None
            }
        }
        impl Interceptor for Recorder {
            fn bind_local_stream(&mut self, _info: &StreamInfo) {}
            fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
            fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
            fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
        }
        // index 0 = wireward of the tagger at index 1, so it acts *after* on the write walk.
        let mut chain = Chain::new(vec![
            Box::new(Recorder::default()),
            Box::new(TwccSenderBuilder::new().build()),
        ]);
        chain.bind_local_stream(&stream_info(1, 5));

        chain.handle_write(packet(0, 1)).unwrap();
        let out = chain.poll_write().expect("reaches the driver");
        assert_eq!(Some(0), tag_of(&out, 5), "the packet leaves tagged");
    }
}

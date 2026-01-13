//! TWCC Sender Interceptor - adds transport-wide sequence numbers to outgoing packets.

use super::stream_supports_twcc;
use crate::stream_info::StreamInfo;
use crate::{Interceptor, Packet, TaggedPacket, interceptor};
use shared::error::Error;
use shared::marshal::Marshal;
use std::collections::HashMap;
use std::marker::PhantomData;

/// Builder for the TwccSenderInterceptor.
///
/// # Example
///
/// ```ignore
/// use rtc_interceptor::{Registry, TwccSenderBuilder};
///
/// let chain = Registry::new()
///     .with(TwccSenderBuilder::new().build())
///     .build();
/// ```
pub struct TwccSenderBuilder<P> {
    _phantom: PhantomData<P>,
}

impl<P> Default for TwccSenderBuilder<P> {
    fn default() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<P> TwccSenderBuilder<P> {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the interceptor factory function.
    pub fn build(self) -> impl FnOnce(P) -> TwccSenderInterceptor<P> {
        move |inner| TwccSenderInterceptor::new(inner)
    }
}

/// Per-stream state for the sender.
struct LocalStream {
    /// Header extension ID for transport-wide CC.
    hdr_ext_id: u8,
}

/// Interceptor that adds transport-wide sequence numbers to outgoing RTP packets.
///
/// This interceptor examines the stream's RTP header extensions for the transport-wide
/// CC extension URI and adds sequence numbers to each outgoing packet.
#[derive(Interceptor)]
pub struct TwccSenderInterceptor<P> {
    #[next]
    inner: P,
    /// Transport-wide sequence number counter (shared across all streams).
    next_sequence_number: u16,
    /// Local stream state per SSRC.
    streams: HashMap<u32, LocalStream>,
}

impl<P> TwccSenderInterceptor<P> {
    fn new(inner: P) -> Self {
        Self {
            inner,
            next_sequence_number: 0,
            streams: HashMap::new(),
        }
    }
}

#[interceptor]
impl<P: Interceptor> TwccSenderInterceptor<P> {
    #[overrides]
    fn handle_write(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        // Add transport-wide CC sequence number to outgoing RTP packets
        if let Packet::Rtp(ref mut rtp_packet) = msg.message
            && let Some(stream) = self.streams.get(&rtp_packet.header.ssrc)
        {
            // Create transport CC extension
            let seq = self.next_sequence_number;
            self.next_sequence_number = self.next_sequence_number.wrapping_add(1);

            let tcc_ext = rtp::extension::transport_cc_extension::TransportCcExtension {
                transport_sequence: seq,
            };

            // Marshal the extension
            if let Ok(ext_data) = tcc_ext.marshal() {
                // Set the extension on the packet
                let _ = rtp_packet
                    .header
                    .set_extension(stream.hdr_ext_id, ext_data.freeze());
            }
        }

        self.inner.handle_write(msg)
    }

    #[overrides]
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if let Some(hdr_ext_id) = stream_supports_twcc(info) {
            // Don't add header extension if ID is 0 (invalid)
            if hdr_ext_id != 0 {
                self.streams.insert(info.ssrc, LocalStream { hdr_ext_id });
            }
        }
        self.inner.bind_local_stream(info);
    }

    #[overrides]
    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
        self.inner.unbind_local_stream(info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Registry;
    use crate::stream_info::RTPHeaderExtension;
    use sansio::Protocol;
    use shared::marshal::Unmarshal;
    use std::time::Instant;

    fn make_rtp_packet(ssrc: u32, seq: u16) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: Default::default(),
            message: Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    ssrc,
                    sequence_number: seq,
                    ..Default::default()
                },
                payload: vec![].into(),
            }),
        }
    }

    #[test]
    fn test_twcc_sender_builder_defaults() {
        let chain = Registry::new()
            .with(TwccSenderBuilder::default().build())
            .build();

        assert!(chain.streams.is_empty());
    }

    #[test]
    fn test_twcc_sender_adds_extension() {
        let mut chain = Registry::new()
            .with(TwccSenderBuilder::new().build())
            .build();

        // Bind stream with TWCC support
        let info = StreamInfo {
            ssrc: 12345,
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: super::super::TRANSPORT_CC_URI.to_string(),
                id: 5,
            }],
            ..Default::default()
        };
        chain.bind_local_stream(&info);

        // Send packets
        let pkt1 = make_rtp_packet(12345, 1);
        chain.handle_write(pkt1).unwrap();
        let out1 = chain.poll_write().unwrap();

        let pkt2 = make_rtp_packet(12345, 2);
        chain.handle_write(pkt2).unwrap();
        let out2 = chain.poll_write().unwrap();

        // Verify extensions were added with incrementing sequence numbers
        if let Packet::Rtp(rtp1) = out1.message {
            let ext = rtp1.header.get_extension(5);
            assert!(ext.is_some());
            let tcc = rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(
                &mut ext.unwrap().as_ref(),
            )
            .unwrap();
            assert_eq!(tcc.transport_sequence, 0);
        } else {
            panic!("Expected RTP packet");
        }

        if let Packet::Rtp(rtp2) = out2.message {
            let ext = rtp2.header.get_extension(5);
            assert!(ext.is_some());
            let tcc = rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(
                &mut ext.unwrap().as_ref(),
            )
            .unwrap();
            assert_eq!(tcc.transport_sequence, 1);
        } else {
            panic!("Expected RTP packet");
        }
    }

    #[test]
    fn test_twcc_sender_no_extension_without_binding() {
        let mut chain = Registry::new()
            .with(TwccSenderBuilder::new().build())
            .build();

        // Send packet without binding (no TWCC)
        let pkt = make_rtp_packet(12345, 1);
        chain.handle_write(pkt).unwrap();
        let out = chain.poll_write().unwrap();

        // Verify no extension was added
        if let Packet::Rtp(rtp) = out.message {
            assert!(rtp.header.get_extension(5).is_none());
        } else {
            panic!("Expected RTP packet");
        }
    }

    #[test]
    fn test_twcc_sender_unbind_removes_stream() {
        let mut chain = Registry::new()
            .with(TwccSenderBuilder::new().build())
            .build();

        let info = StreamInfo {
            ssrc: 12345,
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: super::super::TRANSPORT_CC_URI.to_string(),
                id: 5,
            }],
            ..Default::default()
        };

        chain.bind_local_stream(&info);
        assert!(chain.streams.contains_key(&12345));

        chain.unbind_local_stream(&info);
        assert!(!chain.streams.contains_key(&12345));
    }

    #[test]
    fn test_twcc_sender_sequence_wraparound() {
        let mut chain = Registry::new()
            .with(TwccSenderBuilder::new().build())
            .build();

        let info = StreamInfo {
            ssrc: 12345,
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: super::super::TRANSPORT_CC_URI.to_string(),
                id: 5,
            }],
            ..Default::default()
        };
        chain.bind_local_stream(&info);

        // Set sequence number near wraparound
        chain.next_sequence_number = 65534;

        for expected_seq in [65534u16, 65535, 0, 1] {
            let pkt = make_rtp_packet(12345, 1);
            chain.handle_write(pkt).unwrap();
            let out = chain.poll_write().unwrap();

            if let Packet::Rtp(rtp) = out.message {
                let ext = rtp.header.get_extension(5).unwrap();
                let tcc = rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(
                    &mut ext.as_ref(),
                )
                .unwrap();
                assert_eq!(tcc.transport_sequence, expected_seq);
            }
        }
    }

    #[test]
    fn test_twcc_sender_multiple_streams_share_counter() {
        let mut chain = Registry::new()
            .with(TwccSenderBuilder::new().build())
            .build();

        // Bind two streams
        let info1 = StreamInfo {
            ssrc: 1111,
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: super::super::TRANSPORT_CC_URI.to_string(),
                id: 5,
            }],
            ..Default::default()
        };
        let info2 = StreamInfo {
            ssrc: 2222,
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: super::super::TRANSPORT_CC_URI.to_string(),
                id: 5,
            }],
            ..Default::default()
        };
        chain.bind_local_stream(&info1);
        chain.bind_local_stream(&info2);

        // Send packets alternating between streams
        for (i, ssrc) in [1111u32, 2222, 1111, 2222].iter().enumerate() {
            let pkt = make_rtp_packet(*ssrc, 1);
            chain.handle_write(pkt).unwrap();
            let out = chain.poll_write().unwrap();

            if let Packet::Rtp(rtp) = out.message {
                let ext = rtp.header.get_extension(5).unwrap();
                let tcc = rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(
                    &mut ext.as_ref(),
                )
                .unwrap();
                assert_eq!(tcc.transport_sequence, i as u16);
            }
        }
    }
}

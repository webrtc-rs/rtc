use crate::{
    application_defined::*, goodbye::*, header::*, payload_feedbacks::full_intra_request::*,
    payload_feedbacks::picture_loss_indication::*,
    payload_feedbacks::receiver_estimated_maximum_bitrate::*,
    payload_feedbacks::slice_loss_indication::*, raw_packet::*, receiver_report::*,
    sender_report::*, source_description::*, transport_feedbacks::cc_feedback_report::*,
    transport_feedbacks::rapid_resynchronization_request::*,
    transport_feedbacks::transport_layer_cc::*, transport_feedbacks::transport_layer_nack::*,
};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, Unmarshal},
};

use crate::extended_report::ExtendedReport;
use bytes::{Buf, BytesMut};
use std::any::Any;
use std::fmt;

/// Packet represents an RTCP packet, a protocol used for out-of-band statistics and
/// control information for an RTP session
pub trait Packet: Send + Sync + Marshal + Unmarshal + fmt::Display + fmt::Debug {
    /// This packet's RTCP header.
    fn header(&self) -> Header;
    /// The SSRCs this packet is about.
    ///
    /// Used to route feedback: a report's destination SSRCs identify the streams it concerns,
    /// which is how an SFU decides where to forward it.
    fn destination_ssrc(&self) -> Vec<u32>;
    /// The encoded size in bytes, header and padding included.
    fn raw_size(&self) -> usize;
    /// Downcasting hook, so a caller holding `Box<dyn Packet>` can recover the concrete type.
    fn as_any(&self) -> &dyn Any;
    /// Compares against another packet, since `PartialEq` is not object safe.
    fn equal(&self, other: &dyn Packet) -> bool;
    /// Clones this packet behind a trait object, since `Clone` is not object safe.
    fn cloned(&self) -> Box<dyn Packet>;
}

impl PartialEq for dyn Packet {
    fn eq(&self, other: &Self) -> bool {
        self.equal(other)
    }
}

impl Clone for Box<dyn Packet> {
    fn clone(&self) -> Box<dyn Packet> {
        self.cloned()
    }
}

/// marshal takes an array of Packets and serializes them to a single buffer
pub fn marshal(packets: &[Box<dyn Packet>]) -> Result<BytesMut> {
    // Size the compound packet up front and marshal each sub-packet straight
    // into it, instead of allocating a fresh BytesMut per sub-packet
    // (p.marshal()) and copying it in.
    let total: usize = packets.iter().map(|p| p.marshal_size()).sum();
    let mut out = BytesMut::new();
    out.resize(total, 0);
    let mut offset = 0;
    for p in packets {
        offset += p.marshal_to(&mut out[offset..])?;
    }
    Ok(out)
}

/// Unmarshal takes an entire udp datagram (which may consist of multiple RTCP packets) and
/// returns the unmarshaled packets it contains.
///
/// If this is a reduced-size RTCP packet a feedback packet (Goodbye, SliceLossIndication, etc)
/// will be returned. Otherwise, the underlying type of the returned packet will be
/// CompoundPacket.
pub fn unmarshal<B>(raw_data: &mut B) -> Result<Vec<Box<dyn Packet>>>
where
    B: Buf,
{
    let mut packets = vec![];

    while raw_data.has_remaining() {
        let p = unmarshaller(raw_data)?;
        packets.push(p);
    }

    match packets.len() {
        // Empty Packet
        0 => Err(Error::InvalidHeader),

        // Multiple Packet
        _ => Ok(packets),
    }
}

/// unmarshaller is a factory which pulls the first RTCP packet from a bytestream,
/// and returns it's parsed representation, and the amount of data that was processed.
pub(crate) fn unmarshaller<B>(raw_data: &mut B) -> Result<Box<dyn Packet>>
where
    B: Buf,
{
    // Fast path: the whole packet is in the buffer's first chunk (always so for `&[u8]`, `Bytes`
    // and `BytesMut`), so the packet is parsed straight from that slice. Reading through a
    // `chain` of header and body instead costs a bounds check and a branch per field.
    let chunk = raw_data.chunk();
    if chunk.len() >= HEADER_LENGTH {
        let h = Header::unmarshal(&mut &chunk[..HEADER_LENGTH])?;
        let total = HEADER_LENGTH + (h.length as usize) * 4;
        if chunk.len() >= total {
            let p = parse_packet(&h, &mut &chunk[..total])?;
            raw_data.advance(total);
            return Ok(p);
        }
    }

    // Keep the header's wire bytes: a packet type this crate does not model must survive as a
    // RawPacket byte for byte, and `PacketType` cannot represent it.
    if raw_data.remaining() < HEADER_LENGTH {
        return Err(Error::PacketTooShort);
    }
    let mut header_buf = [0u8; HEADER_LENGTH];
    raw_data.copy_to_slice(&mut header_buf);
    let h = Header::unmarshal(&mut header_buf.as_slice())?;

    let length = (h.length as usize) * 4;
    if length > raw_data.remaining() {
        return Err(Error::PacketTooShort);
    }

    let mut in_packet = header_buf.as_slice().chain(raw_data.take(length));
    parse_packet(&h, &mut in_packet)
}

/// Parses one packet of the type `h` announces from `in_packet`, which holds the whole packet
/// header included.
fn parse_packet<B: Buf>(h: &Header, in_packet: &mut B) -> Result<Box<dyn Packet>> {
    let p: Box<dyn Packet> = match h.packet_type {
        PacketType::SenderReport => Box::new(SenderReport::unmarshal(in_packet)?),
        PacketType::ReceiverReport => Box::new(ReceiverReport::unmarshal(in_packet)?),
        PacketType::SourceDescription => Box::new(SourceDescription::unmarshal(in_packet)?),
        PacketType::Goodbye => Box::new(Goodbye::unmarshal(in_packet)?),

        PacketType::TransportSpecificFeedback => match h.count {
            FORMAT_TLN => Box::new(TransportLayerNack::unmarshal(in_packet)?),
            FORMAT_RRR => Box::new(RapidResynchronizationRequest::unmarshal(in_packet)?),
            FORMAT_TCC => Box::new(TransportLayerCc::unmarshal(in_packet)?),
            FORMAT_CCFB => Box::new(CcFeedbackReport::unmarshal(in_packet)?),
            _ => Box::new(RawPacket::unmarshal(in_packet)?),
        },
        PacketType::PayloadSpecificFeedback => match h.count {
            FORMAT_PLI => Box::new(PictureLossIndication::unmarshal(in_packet)?),
            FORMAT_SLI => Box::new(SliceLossIndication::unmarshal(in_packet)?),
            FORMAT_REMB => Box::new(ReceiverEstimatedMaximumBitrate::unmarshal(in_packet)?),
            FORMAT_FIR => Box::new(FullIntraRequest::unmarshal(in_packet)?),
            _ => Box::new(RawPacket::unmarshal(in_packet)?),
        },
        PacketType::ExtendedReport => Box::new(ExtendedReport::unmarshal(in_packet)?),
        PacketType::ApplicationDefined => Box::new(ApplicationDefined::unmarshal(in_packet)?),
        _ => Box::new(RawPacket::unmarshal(in_packet)?),
    };

    Ok(p)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::reception_report::*;
    use bytes::Bytes;

    /// A packet split across two buffers takes the slower path that cannot borrow the whole
    /// packet from one slice; it must produce exactly what the contiguous fast path does, for
    /// every place the split can fall.
    #[test]
    fn test_unmarshal_is_the_same_for_split_and_contiguous_buffers() -> Result<()> {
        let packets: Vec<Box<dyn Packet>> = vec![
            Box::new(ReceiverReport {
                ssrc: 0x902f9e2e,
                reports: vec![ReceptionReport {
                    ssrc: 0xbc5e9a40,
                    last_sequence_number: 0x46e1,
                    jitter: 273,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            Box::new(SourceDescription {
                chunks: vec![SourceDescriptionChunk {
                    source: 0x902f9e2e,
                    items: vec![SourceDescriptionItem {
                        sdes_type: SdesType::SdesCname,
                        text: Bytes::from_static(b"{9c00eb92-1afb-9d49}"),
                    }],
                }],
            }),
            Box::new(Goodbye {
                sources: vec![0x902f9e2e],
                reason: Bytes::from_static(b"bye"),
            }),
            Box::new(PictureLossIndication {
                sender_ssrc: 1,
                media_ssrc: 2,
            }),
        ];
        let raw = marshal(&packets)?.freeze();

        let expected = unmarshal(&mut raw.clone())?;
        assert_eq!(expected.len(), packets.len());
        for split in 0..=raw.len() {
            let mut chained = raw.slice(..split).chain(raw.slice(split..));
            let got = unmarshal(&mut chained)?;
            assert_eq!(got.len(), expected.len(), "split at {split}");
            for (a, b) in got.iter().zip(&expected) {
                assert!(a.equal(b.as_ref()), "split at {split}: {a:?} != {b:?}");
            }
        }
        Ok(())
    }

    #[test]
    fn test_packet_unmarshal() {
        let mut data = Bytes::from_static(&[
            // Receiver Report (offset=0)
            0x81, 0xc9, 0x0, 0x7, // v=2, p=0, count=1, RR, len=7
            0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
            0xbc, 0x5e, 0x9a, 0x40, // ssrc=0xbc5e9a40
            0x0, 0x0, 0x0, 0x0, // fracLost=0, totalLost=0
            0x0, 0x0, 0x46, 0xe1, // lastSeq=0x46e1
            0x0, 0x0, 0x1, 0x11, // jitter=273
            0x9, 0xf3, 0x64, 0x32, // lsr=0x9f36432
            0x0, 0x2, 0x4a, 0x79, // delay=150137
            // Source Description (offset=32)
            0x81, 0xca, 0x0, 0xc, // v=2, p=0, count=1, SDES, len=12
            0x90, 0x2f, 0x9e, 0x2e, // ssrc=0x902f9e2e
            0x1, 0x26, // CNAME, len=38
            0x7b, 0x39, 0x63, 0x30, 0x30, 0x65, 0x62, 0x39, 0x32, 0x2d, 0x31, 0x61, 0x66, 0x62,
            0x2d, 0x39, 0x64, 0x34, 0x39, 0x2d, 0x61, 0x34, 0x37, 0x64, 0x2d, 0x39, 0x31, 0x66,
            0x36, 0x34, 0x65, 0x65, 0x65, 0x36, 0x39, 0x66, 0x35,
            0x7d, // text="{9c00eb92-1afb-9d49-a47d-91f64eee69f5}"
            0x0, 0x0, 0x0, 0x0, // END + padding
            // Goodbye (offset=84)
            0x81, 0xcb, 0x0, 0x1, // v=2, p=0, count=1, BYE, len=1
            0x90, 0x2f, 0x9e, 0x2e, // source=0x902f9e2e
            0x81, 0xce, 0x0, 0x2, // Picture Loss Indication (offset=92)
            0x90, 0x2f, 0x9e, 0x2e, // sender=0x902f9e2e
            0x90, 0x2f, 0x9e, 0x2e, // media=0x902f9e2e
            0x85, 0xcd, 0x0, 0x2, // RapidResynchronizationRequest (offset=104)
            0x90, 0x2f, 0x9e, 0x2e, // sender=0x902f9e2e
            0x90, 0x2f, 0x9e, 0x2e, // media=0x902f9e2e
        ]);

        let packet = unmarshal(&mut data).expect("Error unmarshalling packets");

        let a = ReceiverReport {
            ssrc: 0x902f9e2e,
            reports: vec![ReceptionReport {
                ssrc: 0xbc5e9a40,
                fraction_lost: 0,
                total_lost: 0,
                last_sequence_number: 0x46e1,
                jitter: 273,
                last_sender_report: 0x9f36432,
                delay: 150137,
            }],
            ..Default::default()
        };

        let b = SourceDescription {
            chunks: vec![SourceDescriptionChunk {
                source: 0x902f9e2e,
                items: vec![SourceDescriptionItem {
                    sdes_type: SdesType::SdesCname,
                    text: Bytes::from_static(b"{9c00eb92-1afb-9d49-a47d-91f64eee69f5}"),
                }],
            }],
        };

        let c = Goodbye {
            sources: vec![0x902f9e2e],
            ..Default::default()
        };

        let d = PictureLossIndication {
            sender_ssrc: 0x902f9e2e,
            media_ssrc: 0x902f9e2e,
        };

        let e = RapidResynchronizationRequest {
            sender_ssrc: 0x902f9e2e,
            media_ssrc: 0x902f9e2e,
        };

        let expected: Vec<Box<dyn Packet>> = vec![
            Box::new(a),
            Box::new(b),
            Box::new(c),
            Box::new(d),
            Box::new(e),
        ];

        assert!(packet == expected, "Invalid packets");
    }

    #[test]
    fn test_packet_unmarshal_empty() -> Result<()> {
        let result = unmarshal(&mut Bytes::new());
        if let Err(got) = result {
            let want = Error::InvalidHeader;
            assert_eq!(got, want, "Unmarshal(nil) err = {got}, want {want}");
        } else {
            panic!("want error");
        }

        Ok(())
    }

    #[test]
    fn test_packet_invalid_header_length() -> Result<()> {
        let mut data = Bytes::from_static(&[
            // Goodbye (offset=84)
            // v=2, p=0, count=1, BYE, len=100
            0x81, 0xcb, 0x0, 0x64,
        ]);

        let result = unmarshal(&mut data);
        if let Err(got) = result {
            let want = Error::PacketTooShort;
            assert_eq!(
                got, want,
                "Unmarshal(invalid_header_length) err = {got}, want {want}"
            );
        } else {
            panic!("want error");
        }

        Ok(())
    }
    #[test]
    fn test_packet_unmarshal_firefox() -> Result<()> {
        // issue report from https://github.com/webrtc-rs/srtp/issues/7
        let tests = vec![
            Bytes::from_static(&[
                143, 205, 0, 6, 65, 227, 184, 49, 118, 243, 78, 96, 42, 63, 0, 5, 12, 162, 166, 0,
                32, 5, 200, 4, 0, 4, 0, 0,
            ]),
            Bytes::from_static(&[
                143, 205, 0, 9, 65, 227, 184, 49, 118, 243, 78, 96, 42, 68, 0, 17, 12, 162, 167, 1,
                32, 17, 88, 0, 4, 0, 4, 8, 108, 0, 4, 0, 4, 12, 0, 4, 0, 4, 4, 0,
            ]),
            Bytes::from_static(&[
                143, 205, 0, 8, 65, 227, 184, 49, 118, 243, 78, 96, 42, 91, 0, 12, 12, 162, 168, 3,
                32, 12, 220, 4, 0, 4, 0, 8, 128, 4, 0, 4, 0, 8, 0, 0,
            ]),
            Bytes::from_static(&[
                143, 205, 0, 7, 65, 227, 184, 49, 118, 243, 78, 96, 42, 103, 0, 8, 12, 162, 169, 4,
                32, 8, 232, 4, 0, 4, 0, 4, 4, 0, 0, 0,
            ]),
        ];

        for mut test in tests {
            unmarshal(&mut test)?;
        }

        Ok(())
    }

    // Round-trips a compound through packet::marshal -> packet::unmarshal ->
    // packet::marshal and asserts byte-stability, covering the in-place compound
    // marshal and the sub-packet unmarshaller.
    #[test]
    fn test_marshal_compound_roundtrip() -> Result<()> {
        use crate::reception_report::ReceptionReport;

        let rr = ReceiverReport {
            ssrc: 0x902f9e2e,
            reports: vec![ReceptionReport {
                ssrc: 0xbc5e9a40,
                fraction_lost: 0,
                total_lost: 0,
                last_sequence_number: 0x46e1,
                jitter: 273,
                last_sender_report: 0x9f36432,
                delay: 150137,
            }],
            ..Default::default()
        };
        let pli = PictureLossIndication {
            sender_ssrc: 0x902f9e2e,
            media_ssrc: 0x902f9e2e,
        };
        let packets: Vec<Box<dyn Packet>> = vec![Box::new(rr), Box::new(pli)];

        let raw1 = marshal(&packets)?;
        let out = unmarshal(&mut raw1.clone().freeze())?;
        assert_eq!(out.len(), 2, "expected two sub-packets");
        let raw2 = marshal(&out)?;
        assert_eq!(raw1, raw2, "compound marshal/unmarshal round-trip mismatch");

        Ok(())
    }
}

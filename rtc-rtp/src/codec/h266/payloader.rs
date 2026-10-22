//! The H.266 payloader: Annex B access units in, RFC 9328 payloads out.
//!
//! NAL units that fit the MTU are buffered and leave in aggregation packets of up to the MTU;
//! NAL units that do not fit are fragmented. NAL units that are themselves RFC 9328 packets
//! (an aggregation packet or a fragmentation unit) are dropped, as pion drops them.

use bytes::{Bytes, BytesMut};

use super::{
    AGGREGATION_UNIT_LENGTH_SIZE, H266Packet, NAL_HEADER_SIZE, SingleNalUnitPacket,
    emit_h266_nalus, new_aggregation_packet, new_fragmentation_packets, parse_h266_packet,
};
use crate::packetizer::Payloader;
use shared::error::Result;

/// Whether this NAL unit could still fit inside an aggregation packet with another one.
fn can_aggregate(mtu: usize, packet: &SingleNalUnitPacket) -> bool {
    // Leave room for the aggregation header, two size fields and a second unit's header.
    packet.wire_size() + 2 * AGGREGATION_UNIT_LENGTH_SIZE + NAL_HEADER_SIZE <= mtu
}

/// Whether adding `new` to the buffered NAL units would push the aggregation packet past the
/// MTU.
fn should_aggregate_now(
    mtu: usize,
    buffered: &[SingleNalUnitPacket],
    new: &SingleNalUnitPacket,
) -> bool {
    if buffered.is_empty() {
        return false;
    }
    // Aggregation header plus every unit's size field.
    let mut total = NAL_HEADER_SIZE + (buffered.len() + 1) * AGGREGATION_UNIT_LENGTH_SIZE;
    let has_donl = buffered[0].donl.is_some();
    if has_donl {
        // The aggregate's own DONL.
        total += super::DONL_SIZE;
    }
    for packet in buffered {
        total += packet.wire_size();
        // A unit's DONL is not carried inside the aggregate.
        if has_donl {
            total -= super::DONL_SIZE;
        }
    }
    total += new.wire_size();
    if has_donl {
        total -= super::DONL_SIZE;
    }
    total > mtu
}

/// Packetizes H.266/VVC access units into RTP payloads, aggregating small NAL units and
/// fragmenting large ones.
///
/// NAL units held for aggregation that never get a partner leave in a single NAL unit packet;
/// NAL units too large to aggregate are fragmented on their own.
#[derive(Default, Debug, Clone)]
pub struct H266Payloader {
    nalu_buffer: Vec<SingleNalUnitPacket>,
}

impl Payloader for H266Payloader {
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        let mut payloads: Vec<Bytes> = vec![];
        let nalu_buffer = &mut self.nalu_buffer;

        fn flush(nalu_buffer: &mut Vec<SingleNalUnitPacket>, payloads: &mut Vec<Bytes>) {
            match nalu_buffer.len() {
                0 => {}
                1 => {
                    let mut out = BytesMut::with_capacity(nalu_buffer[0].wire_size());
                    nalu_buffer[0].packetize_into(&mut out);
                    payloads.push(out.freeze());
                }
                _ => {
                    if let Ok(aggregation) = new_aggregation_packet(nalu_buffer) {
                        let mut out =
                            BytesMut::with_capacity(NAL_HEADER_SIZE + aggregation.payload.len());
                        aggregation.packetize_into(&mut out);
                        payloads.push(out.freeze());
                    }
                }
            }
            nalu_buffer.clear();
        }

        emit_h266_nalus(payload, |nalu| {
            if nalu.len() < NAL_HEADER_SIZE {
                return;
            }
            let packet = match parse_h266_packet(&nalu, false) {
                Ok(H266Packet::Single(packet)) => packet,
                _ => return,
            };

            if nalu.len() > mtu {
                flush(nalu_buffer, &mut payloads);
                if let Ok(fragments) = new_fragmentation_packets(mtu, &packet) {
                    for fragment in fragments {
                        let mut out =
                            BytesMut::with_capacity(NAL_HEADER_SIZE + 1 + fragment.payload.len());
                        fragment.packetize_into(&mut out);
                        payloads.push(out.freeze());
                    }
                }
            } else if nalu_buffer.is_empty() {
                if can_aggregate(mtu, &packet) {
                    nalu_buffer.push(packet);
                } else {
                    payloads.push(nalu);
                }
            } else {
                if should_aggregate_now(mtu, nalu_buffer, &packet) {
                    flush(nalu_buffer, &mut payloads);
                }
                nalu_buffer.push(packet);
            }
        });

        flush(nalu_buffer, &mut payloads);
        Ok(payloads)
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(self.clone())
    }
}

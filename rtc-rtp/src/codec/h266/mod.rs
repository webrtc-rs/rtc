//! H.266/VVC RTP payload format ([RFC 9328]).
//!
//! VVC inherits H.265's two-byte NAL header and its three packet shapes — single NAL unit,
//! aggregation packet (type 28) and fragmentation unit (type 29) — but drops PACI and moves the
//! layer id ahead of the NAL type. This module provides
//! [`H266Payloader`](crate::codec::h266::H266Payloader), which picks between the shapes based on
//! the MTU, and [`H266Depacketizer`](crate::codec::h266::H266Depacketizer), which reverses the
//! choice.
//!
//! [RFC 9328]: https://datatracker.ietf.org/doc/html/rfc9328

use bytes::{BufMut, Bytes, BytesMut};

use shared::error::{Error, Result};

#[cfg(test)]
mod h266_test;

mod depacketizer;
mod payloader;

pub use depacketizer::H266Depacketizer;
pub use payloader::H266Payloader;

/// Bytes in an H.266 NAL unit header — two, like H.265's.
pub const NAL_HEADER_SIZE: usize = 2;
/// Bytes of a DONL field, when the stream carries one.
pub const DONL_SIZE: usize = 2;

/// <https://datatracker.ietf.org/doc/html/rfc9328#section-4.3.2>
const AGGREGATION_PACKET_TYPE: u8 = 28;
/// <https://datatracker.ietf.org/doc/html/rfc9328#section-4.3.3>
const FRAGMENTATION_UNIT_TYPE: u8 = 29;
/// The largest aggregation unit the 16-bit size field can describe.
const MAX_PACKET_SIZE: usize = u16::MAX as usize;
/// Bytes of each aggregation unit's size field.
const AGGREGATION_UNIT_LENGTH_SIZE: usize = 2;

/// An H.266 NAL unit header.
///
/// ```text
/// +---------------+---------------+
/// |0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |F|Z| LayerID   |  Type   | TID |
/// +---------------+---------------+
/// ```
///
/// ## Specifications
///
/// * [RFC 9328 §1.1.4]
///
/// [RFC 9328 §1.1.4]: https://datatracker.ietf.org/doc/html/rfc9328#section-1.1.4
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct H266NALUHeader(pub u16);

impl H266NALUHeader {
    /// Parses an H.266 NAL header from its two bytes.
    pub fn new(high_byte: u8, low_byte: u8) -> Self {
        H266NALUHeader((u16::from(high_byte) << 8) | u16::from(low_byte))
    }

    /// The forbidden bit, should always be 0.
    pub fn f(&self) -> bool {
        (self.0 >> 15) != 0
    }

    /// A reserved bit, should always be 0.
    pub fn z(&self) -> bool {
        const MASK: u16 = 0b01000000 << 8;
        (self.0 & MASK) != 0
    }

    /// The NAL unit type.
    pub fn nalu_type(&self) -> u8 {
        const MASK: u16 = 0b11111000;
        ((self.0 & MASK) >> 3) as u8
    }

    /// Whether the NAL unit type is a VCL NAL unit (section 7.4.2.2 of H.266).
    pub fn is_type_vcl_unit(&self) -> bool {
        self.nalu_type() <= 11
    }

    /// The layer id, which should be 0 unless the stream is layered.
    pub fn layer_id(&self) -> u8 {
        const MASK: u16 = 0b00111111 << 8;
        ((self.0 & MASK) >> 8) as u8
    }

    /// The temporal id plus one.
    pub fn tid(&self) -> u8 {
        const MASK: u16 = 0b00000111;
        (self.0 & MASK) as u8
    }

    /// Whether the packet is an aggregation packet.
    pub fn is_aggregation_packet(&self) -> bool {
        self.nalu_type() == AGGREGATION_PACKET_TYPE
    }

    /// Whether the packet is a fragmentation unit.
    pub fn is_fragmentation_unit(&self) -> bool {
        self.nalu_type() == FRAGMENTATION_UNIT_TYPE
    }
}

/// One NAL unit in a single NAL unit packet: its header, an optional DONL, and its payload.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(super) struct SingleNalUnitPacket {
    header: u16,
    donl: Option<u16>,
    payload: Bytes,
}

impl SingleNalUnitPacket {
    /// Size of the packet on the wire, DONL included when present.
    fn wire_size(&self) -> usize {
        NAL_HEADER_SIZE + self.donl.map_or(0, |_| DONL_SIZE) + self.payload.len()
    }

    /// Appends the packet in its wire form, DONL included when present.
    fn packetize_into(&self, out: &mut BytesMut) {
        out.put_u16(self.header);
        if let Some(donl) = self.donl {
            out.put_u16(donl);
        }
        out.put_slice(&self.payload);
    }
}

/// An aggregation packet: one header, an optional DONL, and a run of length-prefixed NAL units.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(super) struct AggregationPacket {
    header: u16,
    donl: Option<u16>,
    payload: Bytes,
}

impl AggregationPacket {
    /// Appends the packet in its wire form, DONL included when present.
    fn packetize_into(&self, out: &mut BytesMut) {
        out.put_u16(self.header);
        if let Some(donl) = self.donl {
            out.put_u16(donl);
        }
        out.put_slice(&self.payload);
    }
}

/// One fragmentation unit of a larger NAL unit.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(super) struct FragmentationPacket {
    header: u16,
    fu_header: u8,
    donl: Option<u16>,
    payload: Bytes,
}

impl FragmentationPacket {
    /// Appends the packet in its wire form, DONL included when present.
    fn packetize_into(&self, out: &mut BytesMut) {
        out.put_u16(self.header);
        out.put_u8(self.fu_header);
        if let Some(donl) = self.donl {
            out.put_u16(donl);
        }
        out.put_slice(&self.payload);
    }
}

/// The four-byte Annex B start code.
const ANNEXB_START_CODE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// The start (S) bit of a fragmentation unit header.
fn fu_start(fu_header: u8) -> bool {
    fu_header & 0x80 != 0
}

/// The end (E) bit of a fragmentation unit header.
fn fu_end(fu_header: u8) -> bool {
    fu_header & 0x40 != 0
}

/// The NAL unit type carried in the low five bits of a fragmentation unit header.
fn fu_type(fu_header: u8) -> u8 {
    fu_header & 0x1f
}

/// A parsed H.266 RTP payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum H266Packet {
    /// Exactly one NAL unit.
    Single(SingleNalUnitPacket),
    /// Two or more length-prefixed NAL units.
    Aggregation(AggregationPacket),
    /// One fragment of a larger NAL unit.
    Fragmentation(FragmentationPacket),
}

/// Parses an H.266 RTP payload of the shape announced by its header.
///
/// `has_donl` says whether the stream carries DONL fields; a fragmentation unit only carries
/// one after its FU header when it is the first fragment of a NAL unit, which the caller decides
/// from the fragments it has seen so far.
pub(super) fn parse_h266_packet(buf: &Bytes, has_donl: bool) -> Result<H266Packet> {
    let mut min_length = NAL_HEADER_SIZE;
    let mut payload_start = NAL_HEADER_SIZE;
    let mut donl_start = NAL_HEADER_SIZE;
    if has_donl {
        payload_start += DONL_SIZE;
        min_length += DONL_SIZE;
    }
    if buf.len() < min_length {
        return Err(Error::ErrShortPacket);
    }

    let header = H266NALUHeader::new(buf[0], buf[1]);

    // A fragmentation unit carries one more header byte before its optional DONL.
    if header.is_fragmentation_unit() {
        payload_start += 1;
        donl_start += 1;
        min_length += 1;
    }
    if buf.len() < min_length {
        return Err(Error::ErrShortPacket);
    }

    let donl = has_donl.then(|| u16::from_be_bytes([buf[donl_start], buf[donl_start + 1]]));

    if header.is_aggregation_packet() {
        Ok(H266Packet::Aggregation(AggregationPacket {
            header: header.0,
            donl,
            payload: buf.slice(payload_start..),
        }))
    } else if header.is_fragmentation_unit() {
        Ok(H266Packet::Fragmentation(FragmentationPacket {
            header: header.0,
            fu_header: buf[NAL_HEADER_SIZE],
            donl,
            payload: buf.slice(payload_start..),
        }))
    } else {
        Ok(H266Packet::Single(SingleNalUnitPacket {
            header: header.0,
            donl,
            payload: buf.slice(payload_start..),
        }))
    }
}

/// Calls `emit` with each NAL unit of an Annex B buffer, or with the whole buffer when it holds
/// no start code. Emitted NAL units carry no start code.
pub(super) fn emit_h266_nalus(nals: &Bytes, mut emit: impl FnMut(Bytes)) {
    let finder = memchr::memmem::Finder::new(&[0u8, 0, 1]);
    let Some(mut start) = finder.find(nals) else {
        emit(nals.clone());
        return;
    };
    let mut offset = 3;

    while start < nals.len() {
        let from = (start + offset).min(nals.len());
        match finder.find(&nals[from..]) {
            None => {
                emit(nals.slice(from..));
                break;
            }
            Some(end) => {
                let mut next_start = from + end;
                let end_is_4_byte = next_start > 0 && nals[next_start - 1] == 0;
                if end_is_4_byte {
                    next_start -= 1;
                }
                emit(nals.slice(from..next_start));
                start = next_start;
                offset = if end_is_4_byte { 4 } else { 3 };
            }
        }
    }
}

/// Builds one aggregation packet from `packets`.
///
/// The aggregation header carries the F bit when any NAL unit has it, and the lowest layer id
/// and temporal id of the aggregated units. Each unit's DONL is dropped from the wire: decoding
/// order is derived from the aggregate's own DONL instead.
pub(super) fn new_aggregation_packet(packets: &[SingleNalUnitPacket]) -> Result<AggregationPacket> {
    if packets.len() < 2 {
        return Err(Error::ErrH266NotEnoughPackets);
    }

    let mut header = u16::from(AGGREGATION_PACKET_TYPE) << 3;
    let first = &packets[0];
    if first.wire_size() > MAX_PACKET_SIZE {
        return Err(Error::ErrH266PacketTooLarge);
    }

    let mut f_bit = H266NALUHeader(first.header).f();
    let mut layer_id = H266NALUHeader(first.header).layer_id();
    let mut tid = H266NALUHeader(first.header).tid();

    let mut payload = BytesMut::new();
    for packet in packets {
        // Aggregated units never carry their own DONL.
        let wire_size = NAL_HEADER_SIZE + packet.payload.len();
        if wire_size > MAX_PACKET_SIZE {
            return Err(Error::ErrH266PacketTooLarge);
        }
        if H266NALUHeader(packet.header).f() {
            f_bit = true;
        }
        layer_id = layer_id.min(H266NALUHeader(packet.header).layer_id());
        tid = tid.min(H266NALUHeader(packet.header).tid());
        payload.put_u16(wire_size as u16);
        payload.put_u16(packet.header);
        payload.put_slice(&packet.payload);
    }

    header |= u16::from(tid) | (u16::from(layer_id) << 8);
    if f_bit {
        header |= 1 << 15;
    }

    Ok(AggregationPacket {
        header,
        donl: first.donl,
        payload: payload.freeze(),
    })
}

/// Splits an aggregation packet into its NAL units.
///
/// When the aggregate carries a DONL, unit `i` gets `donl + i`, wrapping like a 16-bit
/// decoding order number does.
pub(super) fn split_aggregation_packet(
    packet: &AggregationPacket,
) -> Result<Vec<SingleNalUnitPacket>> {
    let mut cur_donl = packet.donl;
    let mut packets = vec![];
    let mut payload = packet.payload.clone();
    while !payload.is_empty() {
        if payload.len() < NAL_HEADER_SIZE {
            return Err(Error::ErrShortPacket);
        }
        let cur_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        if payload.len() - AGGREGATION_UNIT_LENGTH_SIZE < cur_len {
            return Err(Error::ErrShortPacket);
        }
        let unit =
            payload.slice(AGGREGATION_UNIT_LENGTH_SIZE..AGGREGATION_UNIT_LENGTH_SIZE + cur_len);
        let parsed = parse_h266_packet(&unit, false)?;
        let H266Packet::Single(mut p) = parsed else {
            return Err(Error::ErrInvalidH266PacketType);
        };
        if let Some(donl) = cur_donl {
            p.donl = Some(donl);
            cur_donl = Some(donl.wrapping_add(1));
        }
        packets.push(p);
        payload = payload.slice(AGGREGATION_UNIT_LENGTH_SIZE + cur_len..);
    }
    if packets.len() < 2 {
        return Err(Error::ErrH266NotEnoughPackets);
    }
    Ok(packets)
}

/// Replaces a NAL unit header's type with the fragmentation unit type, keeping its other fields.
fn fragmentation_packet_header(payload_header: u16) -> u16 {
    const TYPE_MASK: u16 = !0b11111000;
    (payload_header & TYPE_MASK) | (u16::from(FRAGMENTATION_UNIT_TYPE) << 3)
}

/// Restores a fragmented NAL unit's header type from its fragmentation unit header.
fn rebuild_fragmentation_packet_header(payload_header: u16, fu_header: u8) -> u16 {
    const TYPE_MASK: u16 = !0b11111000;
    (payload_header & TYPE_MASK) | (u16::from(fu_type(fu_header)) << 3)
}

/// Splits one NAL unit into fragmentation units of at most `mtu` bytes.
///
/// Fails when `mtu` leaves no room for a payload byte, or when the NAL unit already fits in a
/// single fragmentation unit. The P bit is never set.
pub(super) fn new_fragmentation_packets(
    mtu: usize,
    packet: &SingleNalUnitPacket,
) -> Result<Vec<FragmentationPacket>> {
    // Payload header, FU header, and optionally the first fragment's DONL.
    let overhead = NAL_HEADER_SIZE + 1 + packet.donl.map_or(0, |_| DONL_SIZE);
    let Some(slice_size) = mtu.checked_sub(overhead).filter(|s| *s > 0) else {
        return Err(Error::ErrShortPacket);
    };
    if packet.payload.len() <= slice_size {
        return Err(Error::ErrShortPacket);
    }

    let mut packets = vec![];
    let header = fragmentation_packet_header(packet.header);
    let nal_type = H266NALUHeader(packet.header).nalu_type();

    let mut rest = packet.payload.clone();
    packets.push(FragmentationPacket {
        header,
        fu_header: nal_type | 0x80,
        donl: packet.donl,
        payload: rest.slice(..slice_size),
    });
    rest = rest.slice(slice_size..);

    while rest.len() > slice_size {
        packets.push(FragmentationPacket {
            header,
            fu_header: nal_type,
            donl: None,
            payload: rest.slice(..slice_size),
        });
        rest = rest.slice(slice_size..);
    }

    packets.push(FragmentationPacket {
        header,
        fu_header: nal_type | 0x40,
        donl: None,
        payload: rest,
    });
    Ok(packets)
}

/// Rejoins the fragmentation units of one NAL unit.
pub(super) fn rebuild_fragmentation_packets(
    packets: &[FragmentationPacket],
) -> Result<SingleNalUnitPacket> {
    if packets.len() < 2 {
        return Err(Error::ErrH266NotEnoughPackets);
    }
    if !fu_start(packets[0].fu_header) {
        return Err(Error::ErrH266FirstFragmentationUnitMissing);
    }
    if !fu_end(packets[packets.len() - 1].fu_header) {
        return Err(Error::ErrH266LastFragmentationUnitMissing);
    }

    let mut payload = BytesMut::new();
    for fu in packets {
        payload.put_slice(&fu.payload);
    }

    Ok(SingleNalUnitPacket {
        header: rebuild_fragmentation_packet_header(packets[0].header, packets[0].fu_header),
        donl: packets[0].donl,
        payload: payload.freeze(),
    })
}

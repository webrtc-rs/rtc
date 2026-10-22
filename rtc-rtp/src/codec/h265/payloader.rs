//! The H.265 payloader: Annex B access units in, RFC 7798 payloads out.
//!
//! Parameter sets (VPS/SPS/PPS) are held back and sent together with the next VCL NAL unit, in an
//! aggregation packet where they fit, so a receiver joining mid-stream gets what it needs to
//! start decoding with the very next frame. Each parameter set is remembered by its id; a
//! re-sent set replaces the earlier one and moves to the back.

use bytes::{BufMut, Bytes, BytesMut};

use super::{H265NALUHeader, NAL_HEADER_SIZE};
use crate::packetizer::Payloader;
use shared::error::Result;

const NALU_AGGREGATION_PACKET_TYPE: u8 = 48;
const NALU_FRAGMENTATION_UNIT_TYPE: u8 = 49;
const NALU_VPS_TYPE: u8 = 32;
const NALU_SPS_TYPE: u8 = 33;
const NALU_PPS_TYPE: u8 = 34;
const NALU_AUD_TYPE: u8 = 35;
const NALU_FILLER_TYPE: u8 = 38;

const MAX_VPS_COUNT: u32 = 16;
const MAX_SPS_COUNT: u32 = 16;
const MAX_PPS_COUNT: u32 = 64;

/// A single NAL unit: its two-byte header and everything after it.
#[derive(Debug, Clone)]
struct Nal {
    header: u16,
    payload: Bytes,
}

impl Nal {
    fn header(&self) -> H265NALUHeader {
        H265NALUHeader(self.header)
    }

    fn wire_size(&self) -> usize {
        NAL_HEADER_SIZE + self.payload.len()
    }

    fn serialize(&self, out: &mut BytesMut) {
        out.put_u16(self.header);
        out.put_slice(&self.payload);
    }
}

#[derive(Debug, Clone)]
struct ParamSetEntry {
    typ: u8,
    id: u32,
    nal: Nal,
}

/// Packetizes H.265/HEVC access units into RTP payloads, aggregating small NAL units and
/// fragmenting large ones.
#[derive(Default, Debug, Clone)]
pub struct HevcPayloader {
    /// Send every NAL unit on its own, without aggregation or parameter-set handling.
    pub skip_aggregation: bool,
    cache: Vec<ParamSetEntry>,
}

impl HevcPayloader {
    /// Locates the NAL unit boundaries in an Annex B buffer.
    ///
    /// Returns the offset of each start code and the length of the code that was matched.
    pub fn parse(nalu: &Bytes) -> (Vec<usize>, usize) {
        let finder = memchr::memmem::Finder::new(&crate::codec::h264::ANNEXB_NALUSTART_CODE);
        let nals = finder.find_iter(nalu).collect::<Vec<usize>>();
        if nals.is_empty() {
            let finder = memchr::memmem::Finder::new(&super::ANNEXB_3_NALUSTART_CODE);
            return (finder.find_iter(nalu).collect::<Vec<usize>>(), 3);
        }
        (nals, 4)
    }
}

/// Calls `emit` with each NAL unit of an Annex B buffer (or the whole buffer when it holds no
/// start code).
fn emit_nalus(nals: &Bytes, mut emit: impl FnMut(Bytes)) {
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

fn can_aggregate(mtu: usize, nal: &Nal) -> bool {
    nal.wire_size() + 2 * 2 + NAL_HEADER_SIZE < mtu
}

fn should_aggregate_now(mtu: usize, buffered: &[Nal], new: &Nal) -> bool {
    if buffered.is_empty() {
        return false;
    }
    let total = NAL_HEADER_SIZE
        + (buffered.len() + 1) * 2
        + buffered.iter().map(Nal::wire_size).sum::<usize>()
        + new.wire_size();
    total > mtu
}

/// One aggregation packet holding all of `nals`, or `None` when they cannot be aggregated.
fn aggregate(nals: &[Nal]) -> Option<Bytes> {
    if nals.len() < 2 {
        return None;
    }
    let mut f = false;
    let mut layer_id = nals[0].header().layer_id();
    let mut tid = nals[0].header().tid();
    let mut body = BytesMut::new();
    for nal in nals {
        if nal.wire_size() > u16::MAX as usize {
            return None;
        }
        f |= nal.header().f();
        layer_id = layer_id.min(nal.header().layer_id());
        tid = tid.min(nal.header().tid());
        body.put_u16(nal.wire_size() as u16);
        nal.serialize(&mut body);
    }

    let mut header =
        (NALU_AGGREGATION_PACKET_TYPE as u16) << 9 | tid as u16 | (layer_id as u16) << 3;
    if f {
        header |= 1 << 15;
    }
    let mut out = BytesMut::with_capacity(2 + body.len());
    out.put_u16(header);
    out.put_slice(&body);
    Some(out.freeze())
}

/// The fragmentation units of one NAL unit, or `None` when `mtu` leaves no room for a payload
/// byte or the NAL unit already fits in one packet.
fn fragment(mtu: usize, nal: &Nal) -> Option<Vec<Bytes>> {
    const OVERHEAD: usize = 3; // payload header + FU header
    let slice_size = mtu.checked_sub(OVERHEAD).filter(|s| *s > 0)?;
    if nal.payload.len() <= slice_size {
        return None;
    }

    let nal_type = nal.header().nalu_type();
    let header = (nal.header & !(0x3f << 9)) | (NALU_FRAGMENTATION_UNIT_TYPE as u16) << 9;

    let mut packets = vec![];
    let mut rest = &nal.payload[..];
    let mut first = true;
    while !rest.is_empty() {
        let take = slice_size.min(rest.len());
        let last = take == rest.len();
        let mut fu_header = nal_type;
        if first {
            fu_header |= 0x80;
        } else if last {
            fu_header |= 0x40;
        }
        let mut out = BytesMut::with_capacity(OVERHEAD + take);
        out.put_u16(header);
        out.put_u8(fu_header);
        out.put_slice(&rest[..take]);
        packets.push(out.freeze());
        rest = &rest[take..];
        first = false;
    }
    Some(packets)
}

impl Payloader for HevcPayloader {
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        let mut payloads: Vec<Bytes> = vec![];
        let mut buffer: Vec<Nal> = vec![];
        let cache = &mut self.cache;
        let skip_aggregation = self.skip_aggregation;

        fn flush(buffer: &mut Vec<Nal>, payloads: &mut Vec<Bytes>) {
            match buffer.len() {
                0 => {}
                1 => {
                    let mut out = BytesMut::with_capacity(buffer[0].wire_size());
                    buffer[0].serialize(&mut out);
                    payloads.push(out.freeze());
                }
                _ => {
                    if let Some(p) = aggregate(buffer) {
                        payloads.push(p);
                    }
                }
            }
            buffer.clear();
        }

        fn fragment_and_append(mtu: usize, nal: &Nal, payloads: &mut Vec<Bytes>) {
            if let Some(frags) = fragment(mtu, nal) {
                payloads.extend(frags);
            }
        }

        emit_nalus(payload, |nalu| {
            if nalu.len() < NAL_HEADER_SIZE {
                return;
            }
            let header = H265NALUHeader::new(nalu[0], nalu[1]);
            if header.is_aggregation_packet()
                || header.is_fragmentation_unit()
                || header.is_paci_packet()
            {
                return;
            }
            let nal = Nal {
                header: u16::from_be_bytes([nalu[0], nalu[1]]),
                payload: nalu.slice(NAL_HEADER_SIZE..),
            };

            if skip_aggregation {
                cache.clear();
                if nalu.len() > mtu {
                    flush(&mut buffer, &mut payloads);
                    fragment_and_append(mtu, &nal, &mut payloads);
                } else {
                    payloads.push(nalu);
                }
                return;
            }

            // Parameter sets wait for the next VCL NAL unit.
            let nal_type = header.nalu_type();
            let (id, max) = match nal_type {
                NALU_VPS_TYPE => (vps_id(&nal.payload), MAX_VPS_COUNT),
                NALU_SPS_TYPE => (sps_id(header.layer_id(), &nal.payload), MAX_SPS_COUNT),
                NALU_PPS_TYPE => (pps_id(&nal.payload), MAX_PPS_COUNT),
                NALU_AUD_TYPE | NALU_FILLER_TYPE => return,
                _ => (None, 0),
            };
            if let Some(id) = id.filter(|id| *id < max) {
                cache.retain(|e| !(e.typ == nal_type && e.id == id));
                cache.push(ParamSetEntry {
                    typ: nal_type,
                    id,
                    nal,
                });
                return;
            }

            let mut pending: Vec<Nal> = cache.drain(..).map(|e| e.nal).collect();
            pending.push(nal);

            for pending in pending {
                if pending.wire_size() > mtu {
                    flush(&mut buffer, &mut payloads);
                    fragment_and_append(mtu, &pending, &mut payloads);
                    continue;
                }
                if pending.wire_size() <= NAL_HEADER_SIZE {
                    flush(&mut buffer, &mut payloads);
                    let mut out = BytesMut::with_capacity(pending.wire_size());
                    pending.serialize(&mut out);
                    payloads.push(out.freeze());
                    continue;
                }
                if buffer.is_empty() {
                    if can_aggregate(mtu, &pending) {
                        buffer.push(pending);
                    } else {
                        let mut out = BytesMut::with_capacity(pending.wire_size());
                        pending.serialize(&mut out);
                        payloads.push(out.freeze());
                    }
                } else {
                    if should_aggregate_now(mtu, &buffer, &pending) {
                        flush(&mut buffer, &mut payloads);
                    }
                    buffer.push(pending);
                }
            }
        });

        flush(&mut buffer, &mut payloads);
        Ok(payloads)
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(self.clone())
    }
}

// --- parameter-set ids ------------------------------------------------------------------------

/// A bit reader over an RBSP, with the Exp-Golomb code H.265 parameter sets use.
struct ParamBits {
    data: Vec<u8>,
    pos: usize,
}

impl ParamBits {
    fn u(&mut self, n: usize) -> Option<u32> {
        let bit_len = self.data.len() * 8;
        if self.pos > bit_len || n > bit_len - self.pos || n > 32 {
            return None;
        }
        let mut v: u32 = 0;
        for _ in 0..n {
            v = (v << 1) | u32::from((self.data[self.pos >> 3] >> (7 - (self.pos & 7))) & 1);
            self.pos += 1;
        }
        Some(v)
    }

    fn ue(&mut self) -> Option<u32> {
        let mut zeros = 0;
        loop {
            if self.u(1)? == 1 {
                break;
            }
            zeros += 1;
            if zeros > 31 {
                return None;
            }
        }
        let suffix = self.u(zeros)?;
        Some(((1u64 << zeros) - 1 + u64::from(suffix)) as u32)
    }
}

/// Removes emulation-prevention bytes (`00 00 03` → `00 00`).
fn strip_emulation(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut zeros = 0;
    for &x in b {
        if zeros >= 2 && x == 0x03 {
            zeros = 0;
            continue;
        }
        out.push(x);
        zeros = if x == 0 { zeros + 1 } else { 0 };
    }
    out
}

fn vps_id(rbsp: &[u8]) -> Option<u32> {
    rbsp.first().map(|b| u32::from(b >> 4) & 0x0f)
}

fn pps_id(rbsp: &[u8]) -> Option<u32> {
    ParamBits {
        data: strip_emulation(rbsp),
        pos: 0,
    }
    .ue()
}

fn sps_id(layer_id: u8, rbsp: &[u8]) -> Option<u32> {
    let mut r = ParamBits {
        data: strip_emulation(rbsp),
        pos: 0,
    };
    r.u(4)?; // sps_video_parameter_set_id
    let ext_or_max_sub_layers_minus1 = r.u(3)?;
    if layer_id != 0 && ext_or_max_sub_layers_minus1 == 7 {
        return r.ue();
    }
    if ext_or_max_sub_layers_minus1 > 6 {
        return None;
    }
    r.u(1)?; // sps_temporal_id_nesting_flag
    skip_profile_tier_level(&mut r, ext_or_max_sub_layers_minus1 as usize)?;
    r.ue()
}

fn skip_profile_tier_level(r: &mut ParamBits, max_sub_layers_minus1: usize) -> Option<()> {
    r.u(32)?;
    r.u(32)?;
    r.u(24)?;
    r.u(8)?; // general_level_idc
    if max_sub_layers_minus1 == 0 {
        return Some(());
    }

    let mut sub_profile_present = [false; 7];
    let mut sub_level_present = [false; 7];
    for i in 0..max_sub_layers_minus1 {
        sub_profile_present[i] = r.u(1)? == 1;
        sub_level_present[i] = r.u(1)? == 1;
    }
    for _ in max_sub_layers_minus1..8 {
        r.u(2)?; // reserved_zero_2bits
    }
    for i in 0..max_sub_layers_minus1 {
        if sub_profile_present[i] {
            r.u(32)?;
            r.u(32)?;
            r.u(24)?;
        }
        if sub_level_present[i] {
            r.u(8)?;
        }
    }
    Some(())
}

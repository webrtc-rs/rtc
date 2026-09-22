//! Randomised media blocks for the encoder and decoder equivalence tests.
//!
//! The blocks aim at what the recovery representation has to carry byte for byte: unequal
//! payload lengths (0–1,500 bytes, weighted towards the 8/16/32/64-byte vector boundaries),
//! CSRC lists, every header-extension profile, RTP padding, and headers whose
//! `extensions_padding` claims more bytes than `marshal_to` writes. A few packets are made
//! deliberately unserialisable, so the paths that give up are compared too.

use bytes::Bytes;

pub(crate) const MEDIA_SSRC: u32 = 0x1B63_FA42;

/// A small deterministic generator (xorshift64*), so a failure reproduces from its seed.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `0..=max`.
    pub(crate) fn upto(&mut self, max: usize) -> usize {
        (self.next() % (max as u64 + 1)) as usize
    }

    pub(crate) fn chance(&mut self, one_in: u64) -> bool {
        self.next().is_multiple_of(one_in)
    }

    fn bytes(&mut self, len: usize) -> Bytes {
        (0..len)
            .map(|_| self.next() as u8)
            .collect::<Vec<_>>()
            .into()
    }
}

/// Payload lengths either side of the vector widths `xor_into` works in.
const BOUNDARY_LENGTHS: &[usize] = &[
    0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129, 1199, 1200, 1201,
    1500,
];

fn payload_length(rng: &mut Rng) -> usize {
    match rng.upto(3) {
        0 => BOUNDARY_LENGTHS[rng.upto(BOUNDARY_LENGTHS.len() - 1)],
        1 => rng.upto(1500),
        2 => 1100 + rng.upto(100),
        _ => rng.upto(80),
    }
}

/// Header extensions in one of the three profiles, all of which `marshal_to` accepts.
fn add_extensions(rng: &mut Rng, header: &mut rtp::header::Header) {
    match rng.upto(3) {
        0 => {}
        1 => {
            header.extension = true;
            header.extension_profile = 0xBEDE;
            for _ in 0..1 + rng.upto(3) {
                let id = 1 + rng.upto(13) as u8;
                let len = 1 + rng.upto(15);
                header.extensions.push(rtp::header::Extension {
                    id,
                    payload: rng.bytes(len),
                });
            }
        }
        2 => {
            header.extension = true;
            header.extension_profile = 0x1000;
            for _ in 0..1 + rng.upto(2) {
                let id = 1 + rng.upto(254) as u8;
                let len = rng.upto(40);
                header.extensions.push(rtp::header::Extension {
                    id,
                    payload: rng.bytes(len),
                });
            }
        }
        _ => {
            header.extension = true;
            header.extension_profile = 0x1234;
            let len = 4 * rng.upto(5);
            header.extensions.push(rtp::header::Extension {
                id: 0,
                payload: rng.bytes(len),
            });
        }
    }
    if header.extension && rng.chance(8) {
        // More than `marshal_to` writes: the serialised packet ends in bytes it leaves unwritten.
        header.extensions_padding = 1 + rng.upto(6);
    }
}

/// One media packet. With `exotic` false it is an ordinary packet that survives a round trip
/// through the wire unchanged; with it true it may also carry RTP padding, over-long
/// `extensions_padding`, or be impossible to serialise at all.
pub(crate) fn media_packet(rng: &mut Rng, sequence_number: u16, exotic: bool) -> rtp::Packet {
    let mut header = rtp::header::Header {
        version: 2,
        marker: rng.chance(2),
        payload_type: rng.upto(127) as u8,
        sequence_number,
        timestamp: rng.next() as u32,
        ssrc: MEDIA_SSRC,
        ..Default::default()
    };
    if rng.chance(4) {
        header.csrc = (0..rng.upto(15)).map(|_| rng.next() as u32).collect();
    }
    add_extensions(rng, &mut header);

    if exotic {
        if rng.chance(6) {
            header.padding = true;
        }
        if rng.chance(25) {
            // Two extensions under the RFC 3550 profile: `marshal_to` refuses it.
            header.extension = true;
            header.extension_profile = 0x1234;
            header.extensions = vec![
                rtp::header::Extension {
                    id: 0,
                    payload: rng.bytes(4),
                },
                rtp::header::Extension {
                    id: 0,
                    payload: rng.bytes(4),
                },
            ];
        }
    } else {
        header.extensions_padding = 0;
    }

    let len = payload_length(rng);
    rtp::Packet {
        header,
        payload: rng.bytes(len),
    }
}

/// `count` consecutive media packets starting at a random sequence number, wrapping included.
pub(crate) fn media_block(rng: &mut Rng, count: usize, exotic: bool) -> Vec<rtp::Packet> {
    let base = if rng.chance(4) {
        u16::MAX - rng.upto(4) as u16
    } else {
        rng.next() as u16
    };
    (0..count)
        .map(|offset| media_packet(rng, base.wrapping_add(offset as u16), exotic))
        .collect()
}

/// Block sizes around the packet-mask boundaries (15, 46, 109) and the format's limit (110).
pub(crate) const BLOCK_SIZES: &[usize] = &[1, 2, 3, 5, 10, 15, 16, 17, 46, 47, 48, 109, 110];

/// Repair-packet counts, including more than there are media packets.
pub(crate) const FEC_COUNTS: &[u32] = &[1, 2, 3, 4, 7, 10, 48, 120];

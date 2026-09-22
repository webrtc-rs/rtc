#[cfg(test)]
mod fingerprint_test;

use crate::attributes::ATTR_FINGERPRINT;
use crate::checks::*;
use crate::message::*;
use shared::error::*;

use crc_fast::CrcAlgorithm;

/// FINGERPRINT attribute.
///
/// RFC 5389 Section 15.5.
pub struct FingerprintAttr;

/// Shorthand for FingerprintAttr.
///
/// Example:
///
///  m := New()
///  FINGERPRINT.add_to(m).
pub const FINGERPRINT: FingerprintAttr = FingerprintAttr {};

/// The value the CRC-32 is XORed with, `0x5354554e` — ASCII `STUN`.
pub const FINGERPRINT_XOR_VALUE: u32 = 0x5354554e;
/// The attribute's value length in bytes.
pub const FINGERPRINT_SIZE: usize = 4; // 32 bit

// FingerprintValue returns CRC-32 of b XOR-ed by 0x5354554e.
//
// The value of the attribute is computed as the CRC-32 of the STUN message
// up to (but excluding) the FINGERPRINT attribute itself, XOR'ed with
// the 32-bit value 0x5354554e (the XOR helps in cases where an
// application packet is also using CRC-32 in it).
/// Computes the `FINGERPRINT` value over `b`: CRC-32 XORed with [`FINGERPRINT_XOR_VALUE`].
///
/// The CRC-32 (ISO-HDLC, the IEEE polynomial RFC 5389 names) comes from `crc-fast`, which folds
/// with carry-less multiplication on x86/x86_64 (PCLMULQDQ) and aarch64 (PMULL), selected at
/// runtime, and falls back to slice-by-16 tables elsewhere. At ~100 bytes — one fingerprint per
/// connectivity check or consent probe — that measured ~3.5x faster than the slice-by-16 `crc`
/// table it replaced on Apple M1; see `rtc-stun/benches/README.md`.
pub fn fingerprint_value(b: &[u8]) -> u32 {
    let checksum = crc_fast::checksum(CrcAlgorithm::Crc32IsoHdlc, b) as u32;
    checksum ^ FINGERPRINT_XOR_VALUE // XOR
}

impl Setter for FingerprintAttr {
    // add_to adds fingerprint to message.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        let l = m.length;
        // length in header should include size of fingerprint attribute
        m.length += (FINGERPRINT_SIZE + ATTRIBUTE_HEADER_SIZE) as u32; // increasing length
        m.write_length(); // writing Length to Raw
        let val = fingerprint_value(&m.raw);
        let b = val.to_be_bytes();
        m.length = l;
        m.add(ATTR_FINGERPRINT, &b);
        Ok(())
    }
}

impl FingerprintAttr {
    /// Check reads fingerprint value from m and checks it, returning error if any.
    /// Can return *AttrLengthErr, ErrAttributeNotFound, and *CRCMismatch.
    pub fn check(&self, m: &Message) -> Result<()> {
        let b = m.get(ATTR_FINGERPRINT)?;
        check_size(ATTR_FINGERPRINT, b.len(), FINGERPRINT_SIZE)?;
        let val = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let attr_start = m.raw.len() - (FINGERPRINT_SIZE + ATTRIBUTE_HEADER_SIZE);
        let expected = fingerprint_value(&m.raw[..attr_start]);
        check_fingerprint(val, expected)
    }
}

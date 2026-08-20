//! SMPTE ST 336 (KLV) RTP payload format ([RFC 6597]).
//!
//! The format defines no header of its own: a KLV unit that fits the MTU is sent as-is,
//! and a larger one is simply split into consecutive chunks. The marker bit (set by the
//! payloader on the last chunk) is the only signal that a unit is complete.
//!
//! [RFC 6597]: https://datatracker.ietf.org/doc/html/rfc6597
#[cfg(test)]
mod smpte336m_test;

use crate::packetizer::{Depacketizer, Payloader};
use shared::error::Result;

use bytes::Bytes;

/// Smpte336mPayloader payloads SMPTE ST 336 (KLV) metadata units
#[derive(Default, Debug, Copy, Clone)]
pub struct Smpte336mPayloader;

impl Payloader for Smpte336mPayloader {
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        let mut remaining = payload.len();
        let mut index = 0;
        let mut payloads = Vec::with_capacity(remaining.div_ceil(mtu));
        while remaining > 0 {
            let chunk_size = std::cmp::min(mtu, remaining);
            payloads.push(payload.slice(index..index + chunk_size));
            remaining -= chunk_size;
            index += chunk_size;
        }

        Ok(payloads)
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(*self)
    }
}

/// Smpte336mDepacketizer depacketizes SMPTE ST 336 (KLV) metadata units
#[derive(Default, Debug, Copy, Clone)]
pub struct Smpte336mDepacketizer;

impl Depacketizer for Smpte336mDepacketizer {
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes> {
        Ok(packet.clone())
    }

    fn is_partition_head(&self, _payload: &Bytes) -> bool {
        true
    }

    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }
}

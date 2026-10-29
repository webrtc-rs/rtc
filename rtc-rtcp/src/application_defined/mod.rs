#[cfg(test)]
mod application_defined_test;

use crate::{header::*, packet::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut, Bytes};
use std::any::Any;
use std::fmt;

const APP_FIXED_LENGTH: usize = HEADER_LENGTH + SSRC_LENGTH + 4;

/// An application-defined packet ([RFC 3550] §6.7): experimental extensions that carry a
/// four-character name and opaque data for the application that defined the name.
///
/// [RFC 3550]: https://datatracker.ietf.org/doc/html/rfc3550#section-6.7
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct ApplicationDefined {
    /// The application-defined subtype, carried in the header's 5-bit count field.
    pub sub_type: u8,
    /// The SSRC or CSRC of the source this packet is about.
    pub ssrc: u32,
    /// The four-character ASCII name that picks the application.
    pub name: [u8; 4],
    /// The application-dependent data, without padding.
    pub data: Bytes,
}

impl fmt::Display for ApplicationDefined {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ApplicationDefined {} {:x} {} {:?}",
            self.sub_type,
            self.ssrc,
            String::from_utf8_lossy(&self.name),
            self.data
        )
    }
}

impl ApplicationDefined {
    fn padding_size(&self) -> usize {
        (4 - self.data.len() % 4) % 4
    }
}

impl Packet for ApplicationDefined {
    fn header(&self) -> Header {
        Header {
            padding: self.padding_size() != 0,
            count: self.sub_type,
            packet_type: PacketType::ApplicationDefined,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    fn destination_ssrc(&self) -> Vec<u32> {
        vec![self.ssrc]
    }

    fn raw_size(&self) -> usize {
        APP_FIXED_LENGTH + self.data.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<ApplicationDefined>() == Some(self)
    }

    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for ApplicationDefined {
    fn marshal_size(&self) -> usize {
        APP_FIXED_LENGTH + self.data.len() + self.padding_size()
    }
}

impl Marshal for ApplicationDefined {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if self.data.len() > 0xFFFF - 12 {
            return Err(Error::AppDefinedDataTooLarge);
        }
        crate::header::length_field(self.marshal_size())?;
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }

        /*
         *   0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |V=2|P| subtype |   PT=APP=204  |             length            |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                           SSRC/CSRC                           |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                          name (ASCII)                         |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                   application-dependent data                ...
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        let n = self.header().marshal_to(buf)?;
        buf = &mut buf[n..];
        buf.put_u32(self.ssrc);
        buf.put_slice(&self.name);
        buf.put_slice(&self.data);

        // Padding bytes each carry the padding count, as the P bit promises.
        let padding = self.padding_size();
        for _ in 0..padding {
            buf.put_u8(padding as u8);
        }

        Ok(self.marshal_size())
    }
}

impl Unmarshal for ApplicationDefined {
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let raw_packet_len = raw_packet.remaining();
        let header = Header::unmarshal(raw_packet)?;
        if raw_packet_len < APP_FIXED_LENGTH {
            return Err(Error::PacketTooShort);
        }
        if (header.length as usize + 1) * 4 != raw_packet_len {
            return Err(Error::AppDefinedInvalidLength);
        }

        let ssrc = raw_packet.get_u32();
        let mut name = [0u8; 4];
        raw_packet.copy_to_slice(&mut name);
        let mut data = raw_packet.copy_to_bytes(raw_packet.remaining());

        if header.padding {
            // The last byte of the packet holds the padding count, bounded by the data region.
            // With no data that byte is the last one of the name.
            let padding = data.last().copied().unwrap_or(name[3]) as usize;
            if padding > data.len() {
                return Err(Error::WrongPadding);
            }
            data.truncate(data.len() - padding);
        }

        Ok(ApplicationDefined {
            sub_type: header.count,
            ssrc,
            name,
            data,
        })
    }
}

use crate::header::{
    CC_MASK, CSRC_LENGTH, CSRC_OFFSET, EXTENSION_MASK, EXTENSION_PROFILE_ONE_BYTE,
    EXTENSION_PROFILE_TWO_BYTE, EXTENSION_SHIFT, Header, HeaderSummary, PADDING_MASK,
    PADDING_SHIFT, VERSION_MASK, VERSION_SHIFT, step_extension,
};
use shared::error::{Error, Result};

/// A borrowed, allocation-free parse of an RTP packet.
///
/// [`Packet::unmarshal`](super::Packet) builds an owned packet: a CSRC list, a table of
/// reference-counted extension payloads, a reference-counted payload. That is the right shape
/// for a packet that is queued or handed to another task, and the wrong one for a packet that is
/// looked at and forwarded, where the reference counts alone cost more than the parsing. A
/// `PacketView` is the other shape — the parsed fields plus slices of the datagram it was parsed
/// from, as a parser that fills a struct of subslices would produce — so it costs a few loads and
/// touches no allocator and no atomic.
///
/// `parse` accepts and rejects exactly what [`Packet::unmarshal`](super::Packet) does. The CSRC
/// list and the extension elements are not copied out; [`csrc`](Self::csrc) and
/// [`extensions`](Self::extensions) read them from the datagram as they are asked for.
///
/// ```
/// use rtc_rtp::packet::PacketView;
///
/// let datagram = [
///     0x90, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x07, // fixed header
///     0xBE, 0xDE, 0x00, 0x01, 0x10, 0xAA, 0x00, 0x00,                         // one extension
///     0xDE, 0xAD,                                                             // payload
/// ];
/// let view = PacketView::parse(&datagram)?;
/// assert_eq!(view.ssrc(), 7);
/// assert_eq!(view.extension(1), Some(&[0xAA][..]));
/// assert_eq!(view.payload(), &[0xDE, 0xAD]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy)]
pub struct PacketView<'a> {
    first: u8,
    summary: HeaderSummary,
    csrc: &'a [u8],
    extension_profile: u16,
    extension_region: &'a [u8],
    payload: &'a [u8],
    padding_size: u8,
}

impl<'a> PacketView<'a> {
    /// Parses the RTP packet in `buf`.
    ///
    /// # Errors
    ///
    /// Exactly those of [`Packet::unmarshal`](super::Packet): a datagram too short for the header
    /// it announces, an extension element that overruns its block, or invalid trailing padding.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        let summary = Header::peek(buf)?;
        let first = buf[0];
        let csrc_end = CSRC_OFFSET + (first & CC_MASK) as usize * CSRC_LENGTH;

        let (extension_profile, extension_region) =
            if (first >> EXTENSION_SHIFT & EXTENSION_MASK) > 0 {
                (
                    u16::from_be_bytes([buf[csrc_end], buf[csrc_end + 1]]),
                    &buf[csrc_end + 4..summary.header_len],
                )
            } else {
                (0, &buf[..0])
            };

        let mut payload = &buf[summary.header_len..];
        let mut padding_size = 0;
        if (first >> PADDING_SHIFT & PADDING_MASK) > 0 {
            padding_size = *payload.last().ok_or(Error::ErrShortPacket)?;
            if padding_size == 0 {
                return Err(Error::ErrInvalidRtpPadding);
            }
            if padding_size as usize > payload.len() {
                return Err(Error::ErrShortPacket);
            }
            payload = &payload[..payload.len() - padding_size as usize];
        }

        Ok(Self {
            first,
            summary,
            csrc: &buf[CSRC_OFFSET..csrc_end],
            extension_profile,
            extension_region,
            payload,
            padding_size,
        })
    }

    /// The RTP version field.
    pub fn version(&self) -> u8 {
        self.first >> VERSION_SHIFT & VERSION_MASK
    }

    /// The marker bit.
    pub fn marker(&self) -> bool {
        self.summary.marker
    }

    /// The payload type.
    pub fn payload_type(&self) -> u8 {
        self.summary.payload_type
    }

    /// The sequence number.
    pub fn sequence_number(&self) -> u16 {
        self.summary.sequence_number
    }

    /// The RTP timestamp.
    pub fn timestamp(&self) -> u32 {
        self.summary.timestamp
    }

    /// The synchronization source.
    pub fn ssrc(&self) -> u32 {
        self.summary.ssrc
    }

    /// The contributing sources.
    pub fn csrc(&self) -> impl ExactSizeIterator<Item = u32> + 'a {
        let (words, _) = self.csrc.as_chunks::<CSRC_LENGTH>();
        words.iter().map(|word| u32::from_be_bytes(*word))
    }

    /// Whether the packet carries a header-extension block.
    pub fn has_extension(&self) -> bool {
        (self.first >> EXTENSION_SHIFT & EXTENSION_MASK) > 0
    }

    /// The header-extension profile, or `0` when there is no extension block.
    pub fn extension_profile(&self) -> u16 {
        self.extension_profile
    }

    /// The header extensions, in packet order, as `(id, payload)` pairs.
    ///
    /// A one-byte or two-byte (RFC 8285) block yields its elements; any other profile yields the
    /// whole block as a single element with id `0`, as [`Header`] stores it.
    pub fn extensions(&self) -> Extensions<'a> {
        let rfc8285 = matches!(
            self.extension_profile,
            EXTENSION_PROFILE_ONE_BYTE | EXTENSION_PROFILE_TWO_BYTE
        );
        Extensions {
            region: self.extension_region,
            position: 0,
            profile: self.extension_profile,
            rfc8285,
            pending_generic: self.has_extension() && !rfc8285,
        }
    }

    /// The payload of the first extension element with `id`.
    pub fn extension(&self, id: u8) -> Option<&'a [u8]> {
        self.extensions()
            .find_map(|(found, payload)| (found == id).then_some(payload))
    }

    /// The header's size on the wire, extension block included: the offset of the payload.
    pub fn header_len(&self) -> usize {
        self.summary.header_len
    }

    /// The payload, with any trailing padding removed.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// The number of padding octets that followed the payload, or `0` when there were none.
    pub fn padding_size(&self) -> u8 {
        self.padding_size
    }
}

/// The header extensions of a [`PacketView`], in packet order.
#[derive(Debug, Clone)]
pub struct Extensions<'a> {
    region: &'a [u8],
    position: usize,
    profile: u16,
    rfc8285: bool,
    pending_generic: bool,
}

impl<'a> Iterator for Extensions<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pending_generic {
            self.pending_generic = false;
            return Some((0, self.region));
        }
        if !self.rfc8285 {
            return None;
        }
        // `PacketView::parse` already walked the whole block, so this cannot meet an overrun.
        let mut padding = 0;
        let element = step_extension(
            self.region,
            self.position,
            self.region.len(),
            self.profile,
            &mut padding,
        )
        .ok()??;
        self.position = element.next;
        Some((
            element.id,
            &self.region[element.at..element.at + element.len],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;
    use bytes::Bytes;
    use shared::marshal::Unmarshal;

    fn owned(buf: &[u8]) -> Result<Packet> {
        Packet::unmarshal(&mut Bytes::copy_from_slice(buf))
    }

    /// Everything the view reports, set against the owned packet parsed from the same bytes.
    fn assert_same(buf: &[u8]) {
        let view = PacketView::parse(buf);
        let packet = owned(buf);
        let (Ok(view), Ok(packet)) = (&view, &packet) else {
            assert_eq!(
                view.is_ok(),
                packet.is_ok(),
                "verdicts differ on {buf:02x?}: view {:?}, owned {:?}",
                view.as_ref().err(),
                packet.as_ref().err()
            );
            return;
        };
        let header = &packet.header;
        assert_eq!(view.version(), header.version);
        assert_eq!(view.marker(), header.marker);
        assert_eq!(view.payload_type(), header.payload_type);
        assert_eq!(view.sequence_number(), header.sequence_number);
        assert_eq!(view.timestamp(), header.timestamp);
        assert_eq!(view.ssrc(), header.ssrc);
        assert_eq!(view.csrc().collect::<Vec<_>>(), header.csrc);
        assert_eq!(view.has_extension(), header.extension);
        assert_eq!(view.extension_profile(), header.extension_profile);
        assert_eq!(view.padding_size(), header.padding_size);
        assert_eq!(view.payload(), &packet.payload[..]);
        let extensions: Vec<(u8, Vec<u8>)> = view
            .extensions()
            .map(|(id, payload)| (id, payload.to_vec()))
            .collect();
        let expected: Vec<(u8, Vec<u8>)> = header
            .extensions
            .iter()
            .map(|e| (e.id, e.payload.to_vec()))
            .collect();
        assert_eq!(extensions, expected, "extensions differ on {buf:02x?}");
    }

    #[test]
    fn plain_packet() {
        let buf = [
            0x80, 0x60, 0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 2, 0xde, 0xad, 0xbe, 0xef,
        ];
        assert_same(&buf);
        let view = PacketView::parse(&buf).unwrap();
        assert_eq!(view.payload(), &[0xde, 0xad, 0xbe, 0xef]);
        assert!(view.extensions().next().is_none());
    }

    #[test]
    fn csrc_extensions_and_padding() {
        let buf = [
            0xb2, 0xe0, 0x00, 0x09, 0, 0, 0, 3, 0, 0, 0, 4, // V=2 P X CC=2, marker
            0, 0, 0, 10, 0, 0, 0, 11, // csrc
            0xBE, 0xDE, 0, 2, 0x12, 1, 2, 3, 0x00, 0x00, 0x30, 9, // elements, padding
            7, 7, 7, 0, 0, 0, 3, // payload and 3 octets of padding
        ];
        assert_same(&buf);
        let view = PacketView::parse(&buf).unwrap();
        assert_eq!(view.csrc().collect::<Vec<_>>(), [10, 11]);
        assert_eq!(view.extension(1), Some(&[1, 2, 3][..]));
        assert_eq!(view.extension(3), Some(&[9][..]));
        assert_eq!(view.extension(2), None);
        assert_eq!(view.padding_size(), 3);
    }

    #[test]
    fn two_byte_and_generic_extensions() {
        let two = [
            0x90, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0x10, 0x00, 0, 2, 5, 2, 0xaa, 0xbb, 6, 0, 0,
            0, 1,
        ];
        assert_same(&two);
        let generic = [
            0x90, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0x12, 0x34, 0, 1, 1, 2, 3, 4, 9,
        ];
        assert_same(&generic);
        let view = PacketView::parse(&generic).unwrap();
        assert_eq!(
            view.extensions().collect::<Vec<_>>(),
            [(0, &[1, 2, 3, 4][..])]
        );
    }

    #[test]
    fn malformed_packets_are_rejected_like_the_owned_parser() {
        // Too short, extension overrun, zero padding, padding longer than the payload.
        for buf in [
            &[0x80, 0x60][..],
            &[
                0x90, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0xBE, 0xDE, 0, 1, 0x1f,
            ][..],
            &[0xa0, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 1, 2, 0][..],
            &[0xa0, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 9][..],
            &[0xa0, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2][..],
        ] {
            assert_same(buf);
        }
    }

    #[test]
    fn agrees_with_the_owned_parser_on_arbitrary_bytes() {
        // A deterministic xorshift stream, biased toward the header bits that steer the parser.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = (next() % 48) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if let Some(first) = buf.first_mut() {
                *first = 0x80 | (*first & 0x3f);
            }
            if buf.len() > 16 && next() % 2 == 0 {
                let at = 12 + (buf[0] & 0x0f) as usize * 4;
                if at + 1 < buf.len() {
                    buf[at] = if next() % 2 == 0 { 0xBE } else { 0x10 };
                    buf[at + 1] = if buf[at] == 0xBE { 0xDE } else { 0x00 };
                }
            }
            assert_same(&buf);
        }
    }
}

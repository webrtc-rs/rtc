//! The RTP header and its extensions.
//!
//! [`Header`](crate::header::Header) is the fixed 12-byte header plus the optional CSRC list and header-extension
//! block. The `*_SHIFT`/`*_MASK` constants describe how the flag fields pack into the first two
//! octets, and the `*_OFFSET`/`*_LENGTH` constants give the byte positions a caller can patch in
//! place without re-encoding.
//!
//! Header extensions ([RFC 8285]) come in two forms, selected by
//! [`Header::extension_profile`](crate::header::Header::extension_profile): one-byte ids ([`EXTENSION_PROFILE_ONE_BYTE`](crate::header::EXTENSION_PROFILE_ONE_BYTE)) or two-byte ids
//! ([`EXTENSION_PROFILE_TWO_BYTE`](crate::header::EXTENSION_PROFILE_TWO_BYTE)) when an id above 14 is needed. Use
//! [`Header::set_extension`](crate::header::Header::set_extension) and [`Header::get_extension`](crate::header::Header::get_extension) rather than touching
//! [`Header::extensions`](crate::header::Header::extensions) directly — they keep [`Header::extensions_padding`](crate::header::Header::extensions_padding) and the extension
//! flag consistent, which marshalling depends on.
//!
//! [RFC 8285]: https://datatracker.ietf.org/doc/html/rfc8285

use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

#[cfg(test)]
mod header_extension_test;

use bytes::{Buf, BufMut, Bytes};

/// The length of the extension-profile and length fields that precede header extensions.
pub const HEADER_LENGTH: usize = 4;
/// Bit offset of the version field in the first header octet.
pub const VERSION_SHIFT: u8 = 6;
/// Bit mask of the version field once shifted.
pub const VERSION_MASK: u8 = 0x3;
/// Bit offset of the padding flag.
pub const PADDING_SHIFT: u8 = 5;
/// Bit mask of the padding flag once shifted.
pub const PADDING_MASK: u8 = 0x1;
/// Bit offset of the extension flag.
pub const EXTENSION_SHIFT: u8 = 4;
/// Bit mask of the extension flag once shifted.
pub const EXTENSION_MASK: u8 = 0x1;
/// Extension profile `0xBEDE`, which selects one-byte header extension ids ([RFC 8285]).
pub const EXTENSION_PROFILE_ONE_BYTE: u16 = 0xBEDE;
/// Extension profile `0xC0DE`: a one-byte-id header extension block that has been encrypted
/// together with the CSRCs ([RFC 9335], "Cryptex"). Only ever seen on the wire.
///
/// [RFC 9335]: https://www.rfc-editor.org/rfc/rfc9335
pub const CRYPTEX_PROFILE_ONE_BYTE: u16 = 0xC0DE;
/// Extension profile `0xC2DE`: the two-byte-id form of [`CRYPTEX_PROFILE_ONE_BYTE`].
pub const CRYPTEX_PROFILE_TWO_BYTE: u16 = 0xC2DE;
/// Extension profile `0x1000`, which selects two-byte header extension ids, allowing ids
/// above 14.
pub const EXTENSION_PROFILE_TWO_BYTE: u16 = 0x1000;
/// Extension id 15, reserved by the RFC and never assigned.
pub const EXTENSION_ID_RESERVED: u8 = 0xF;
/// Bit mask of the CSRC count field.
pub const CC_MASK: u8 = 0xF;
/// Bit offset of the marker bit.
pub const MARKER_SHIFT: u8 = 7;
/// Bit mask of the marker bit once shifted.
pub const MARKER_MASK: u8 = 0x1;
/// Bit mask of the payload-type field.
pub const PT_MASK: u8 = 0x7F;
/// Byte offset of the sequence number within the header.
pub const SEQ_NUM_OFFSET: usize = 2;
/// Length of the sequence number in bytes.
pub const SEQ_NUM_LENGTH: usize = 2;
/// Byte offset of the timestamp within the header.
pub const TIMESTAMP_OFFSET: usize = 4;
/// Length of the timestamp in bytes.
pub const TIMESTAMP_LENGTH: usize = 4;
/// Byte offset of the SSRC within the header.
pub const SSRC_OFFSET: usize = 8;
/// Length of the SSRC in bytes.
pub const SSRC_LENGTH: usize = 4;
/// Byte offset of the first CSRC within the header.
pub const CSRC_OFFSET: usize = 12;
/// Length of each CSRC in bytes.
pub const CSRC_LENGTH: usize = 4;

#[derive(Debug, Eq, PartialEq, Default, Clone)]
/// One RTP header extension: an id and its payload bytes.
pub struct Extension {
    /// The extension id, as negotiated by `a=extmap`.
    pub id: u8,
    /// The extension's value.
    pub payload: Bytes,
}

/// Header represents an RTP packet header
/// NOTE: PayloadOffset is populated by Marshal/Unmarshal and should not be modified
#[derive(Debug, Eq, PartialEq, Default, Clone)]
pub struct Header {
    /// The RTP version, always 2.
    pub version: u8,
    /// Whether the payload is followed by padding octets, the last giving the padding length.
    pub padding: bool,
    /// Whether a header-extension block follows the fixed header.
    pub extension: bool,
    /// The marker bit: the last packet of a video frame, or the start of a talk spurt for audio.
    pub marker: bool,
    /// The payload type, which identifies the codec as negotiated in SDP.
    pub payload_type: u8,
    /// Increments by one per packet sent; used to detect loss and restore order.
    pub sequence_number: u16,
    /// The sampling instant of the first octet, in the codec's clock rate.
    pub timestamp: u32,
    /// The synchronization source — the identifier of the stream this packet belongs to.
    pub ssrc: u32,
    /// The contributing sources, listed when a mixer combined several streams.
    pub csrc: Vec<u32>,
    /// Which header-extension form is in use: [`EXTENSION_PROFILE_ONE_BYTE`] or
    /// [`EXTENSION_PROFILE_TWO_BYTE`].
    pub extension_profile: u16,
    /// The header extensions present on this packet.
    pub extensions: Vec<Extension>,
    /// Padding bytes appended to the extension block so it ends on a 32-bit boundary.
    pub extensions_padding: usize,
    /// The number of padding octets that follow the payload, the last of which holds this count.
    ///
    /// Set when a packet is parsed so it marshals back to the same size. Zero means "pad to a
    /// 32-bit boundary" when [`Header::padding`] is set.
    pub padding_size: u8,
}

impl Unmarshal for Header {
    /// Unmarshal parses the passed byte slice and stores the result in the Header this method is called upon
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        // The header is parsed in place from the buffer's first chunk, so extension payloads can
        // share the caller's allocation instead of being copied out.
        let header_bytes = {
            let chunk = raw_packet.chunk();
            let end = Self::wire_len(chunk)?;
            raw_packet.copy_to_bytes(end)
        };
        Self::parse(&header_bytes)
    }
}

impl Header {
    /// The number of bytes the header occupies at the front of `buf`, extension block included.
    ///
    /// This is the true size on the wire, which can exceed [`MarshalSize::marshal_size`] when a
    /// sender padded the extension block; anything that treats the header as a unit (SRTP
    /// encryption starts after it and authenticates it) must use this, not the re-computed size.
    ///
    /// # Errors
    ///
    /// Fails if `buf` is too short for the header it announces.
    pub fn wire_len(buf: &[u8]) -> Result<usize> {
        if buf.len() < HEADER_LENGTH {
            return Err(Error::ErrHeaderSizeInsufficient);
        }
        let cc = (buf[0] & CC_MASK) as usize;
        let mut n = CSRC_OFFSET + cc * CSRC_LENGTH;
        if buf.len() < n {
            return Err(Error::ErrHeaderSizeInsufficient);
        }
        if (buf[0] >> EXTENSION_SHIFT & EXTENSION_MASK) > 0 {
            if buf.len() < n + 4 {
                return Err(Error::ErrHeaderSizeInsufficientForExtension);
            }
            let extension_length = u16::from_be_bytes([buf[n + 2], buf[n + 3]]) as usize * 4;
            n += 4 + extension_length;
            if buf.len() < n {
                return Err(Error::ErrHeaderSizeInsufficientForExtension);
            }
        }
        Ok(n)
    }

    /// Parses a header from `data`, whose first [`Header::wire_len`] bytes are the header.
    pub(crate) fn parse(data: &Bytes) -> Result<Header> {
        let mut header = Header::default();
        header.parse_into(data)?;
        Ok(header)
    }

    /// Parses the header at the front of `data` into `self`, reusing the allocations its CSRC list
    /// and extension table already hold.
    ///
    /// Extension payloads share `data`'s buffer rather than copying out of it.
    pub(crate) fn parse_into(&mut self, data: &Bytes) -> Result<()> {
        let buf: &[u8] = data;
        // One bounds check for the twelve fixed bytes; the reads below are then constant-offset.
        let fixed: &[u8; CSRC_OFFSET] =
            buf.first_chunk().ok_or(Error::ErrHeaderSizeInsufficient)?;
        let b0 = fixed[0];
        let cc = (b0 & CC_MASK) as usize;

        self.csrc.clear();
        self.extensions.clear();

        let mut n = CSRC_OFFSET;
        self.csrc.reserve_exact(cc);
        for _ in 0..cc {
            let word = buf
                .get(n..n + CSRC_LENGTH)
                .ok_or(Error::ErrHeaderSizeInsufficient)?;
            self.csrc
                .push(u32::from_be_bytes([word[0], word[1], word[2], word[3]]));
            n += CSRC_LENGTH;
        }

        let extension = (b0 >> EXTENSION_SHIFT & EXTENSION_MASK) > 0;
        let mut extensions_padding: usize = 0;
        let mut extension_profile = 0;
        if extension {
            let block = buf
                .get(n..n + 4)
                .ok_or(Error::ErrHeaderSizeInsufficientForExtension)?;
            extension_profile = u16::from_be_bytes([block[0], block[1]]);
            let extension_length = u16::from_be_bytes([block[2], block[3]]) as usize * 4;
            n += 4;
            let extension_end = n + extension_length;

            match extension_profile {
                // RFC 8285 one-byte and two-byte header extensions
                EXTENSION_PROFILE_ONE_BYTE | EXTENSION_PROFILE_TWO_BYTE => {
                    // A header that already owns a table has room for the next packet's elements
                    // (the same few extensions ride on every packet of a stream), so it fills in
                    // one pass. A fresh one counts first, so its table is a single exact
                    // allocation.
                    if self.extensions.capacity() == 0 {
                        let mut count = 0;
                        walk_extensions(buf, n, extension_end, extension_profile, |_, _, _| {
                            count += 1;
                        })?;
                        self.extensions.reserve_exact(count);
                    }
                    let extensions = &mut self.extensions;
                    extensions_padding = walk_extensions(
                        buf,
                        n,
                        extension_end,
                        extension_profile,
                        |id, at, len| {
                            extensions.push(Extension {
                                id,
                                payload: data.slice(at..at + len),
                            });
                        },
                    )?;
                }
                // RFC3550 Extension
                _ => self.extensions.push(Extension {
                    id: 0,
                    payload: data.slice(n..extension_end),
                }),
            };
        }

        self.version = b0 >> VERSION_SHIFT & VERSION_MASK;
        self.padding = (b0 >> PADDING_SHIFT & PADDING_MASK) > 0;
        self.extension = extension;
        self.marker = (fixed[1] >> MARKER_SHIFT & MARKER_MASK) > 0;
        self.payload_type = fixed[1] & PT_MASK;
        self.sequence_number = u16::from_be_bytes([fixed[2], fixed[3]]);
        self.timestamp = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        self.ssrc = u32::from_be_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]);
        self.extension_profile = extension_profile;
        self.extensions_padding = extensions_padding;
        self.padding_size = 0;
        Ok(())
    }
}

/// One element of an RFC 8285 extension block: where its payload starts, how long it is, and
/// where the next element begins.
pub(crate) struct ExtensionElement {
    pub(crate) id: u8,
    pub(crate) at: usize,
    pub(crate) len: usize,
    pub(crate) next: usize,
}

/// Reads the element at or after `start` in an RFC 8285 one-byte or two-byte extension block that
/// ends at `end`, skipping padding bytes (and counting them in `padding`).
///
/// `Ok(None)` marks the end of the block: its last byte was reached, or the reserved id (15) or an
/// id of 0 that carries a non-zero length ended the extensions early.
pub(crate) fn step_extension(
    buf: &[u8],
    start: usize,
    end: usize,
    profile: u16,
    padding: &mut usize,
) -> Result<Option<ExtensionElement>> {
    let mut n = start;
    while n < end {
        if buf[n] == 0x00 {
            n += 1;
            *padding += 1;
            continue;
        }

        let (id, len);
        if profile == EXTENSION_PROFILE_ONE_BYTE {
            id = buf[n] >> 4;
            len = ((buf[n] & 0x0F) + 1) as usize;
            n += 1;
            if id == EXTENSION_ID_RESERVED || id == 0 {
                return Ok(None);
            }
        } else {
            id = buf[n];
            n += 1;
            if end <= n {
                return Err(Error::ErrHeaderSizeInsufficientForExtension);
            }
            len = buf[n] as usize;
            n += 1;
        }

        if end < n + len {
            return Err(Error::ErrHeaderSizeInsufficientForExtension);
        }

        return Ok(Some(ExtensionElement {
            id,
            at: n,
            len,
            next: n + len,
        }));
    }
    Ok(None)
}

/// Walks an RFC 8285 one-byte or two-byte extension block, calling `visit(id, offset, len)` for
/// each element and returning how many padding bytes it skipped.
///
/// Both parsing and [`Header::peek`] go through this, so the two accept and reject exactly the
/// same blocks.
pub(crate) fn walk_extensions(
    buf: &[u8],
    start: usize,
    end: usize,
    profile: u16,
    mut visit: impl FnMut(u8, usize, usize),
) -> Result<usize> {
    let mut n = start;
    let mut padding = 0;
    while let Some(element) = step_extension(buf, n, end, profile, &mut padding)? {
        visit(element.id, element.at, element.len);
        n = element.next;
    }
    Ok(padding)
}

/// The fixed fields of an RTP header, read without allocating.
///
/// What an SRTP context, a router or a jitter buffer needs to decide what to do with a packet;
/// see [`Header::peek`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderSummary {
    /// The marker bit.
    pub marker: bool,
    /// The payload type.
    pub payload_type: u8,
    /// The sequence number.
    pub sequence_number: u16,
    /// The RTP timestamp.
    pub timestamp: u32,
    /// The synchronization source.
    pub ssrc: u32,
    /// The header's size on the wire, extension block included: the offset of the payload.
    pub header_len: usize,
}

/// Whether an RFC 8285 one-byte extension block is well formed: every element fits in the block.
///
/// The same verdict as walking it with [`step_extension`], without building a `Result` and an
/// element per step; the datagrams that matter (media with a handful of extensions) go through
/// here, and a block this rejects is handed to the general walk to produce the error.
#[inline]
pub(crate) fn one_byte_block_is_valid(block: &[u8]) -> bool {
    let end = block.len();
    let mut n = 0;
    while n < end {
        let b = block[n];
        if b == 0x00 {
            n += 1;
            continue;
        }
        let id = b >> 4;
        if id == EXTENSION_ID_RESERVED || id == 0 {
            // Ends the block early; whatever follows is not looked at.
            return true;
        }
        n += 1 + ((b & 0x0F) as usize + 1);
        if n > end {
            return false;
        }
    }
    true
}

/// Where the pieces of a validated header sit in a datagram.
pub(crate) struct Located {
    pub(crate) summary: HeaderSummary,
    /// The end of the CSRC list: the offset of the extension block header, if there is one.
    pub(crate) csrc_end: usize,
    /// The extension profile, or 0 when there is no extension block.
    pub(crate) profile: u16,
}

/// Validates the header at the front of `buf` and says where its parts are.
///
/// The one implementation behind [`Header::peek`] and `PacketView::parse`, written so the
/// compiler sees one bounds check for the twelve fixed bytes and plain loads after it.
#[inline]
pub(crate) fn locate(buf: &[u8]) -> Result<Located> {
    let Some(fixed) = buf.first_chunk::<CSRC_OFFSET>() else {
        return Err(Error::ErrHeaderSizeInsufficient);
    };
    let first = fixed[0];
    let csrc_end = CSRC_OFFSET + (first & CC_MASK) as usize * CSRC_LENGTH;
    if buf.len() < csrc_end {
        return Err(Error::ErrHeaderSizeInsufficient);
    }

    let mut header_len = csrc_end;
    let mut profile = 0;
    if (first >> EXTENSION_SHIFT & EXTENSION_MASK) > 0 {
        let Some(block) = buf.get(csrc_end..csrc_end + 4) else {
            return Err(Error::ErrHeaderSizeInsufficientForExtension);
        };
        profile = u16::from_be_bytes([block[0], block[1]]);
        header_len = csrc_end + 4 + u16::from_be_bytes([block[2], block[3]]) as usize * 4;
        if buf.len() < header_len {
            return Err(Error::ErrHeaderSizeInsufficientForExtension);
        }
        let elements = &buf[csrc_end + 4..header_len];
        match profile {
            EXTENSION_PROFILE_ONE_BYTE => {
                if !one_byte_block_is_valid(elements) {
                    walk_extensions(buf, csrc_end + 4, header_len, profile, |_, _, _| {})?;
                }
            }
            EXTENSION_PROFILE_TWO_BYTE => {
                walk_extensions(buf, csrc_end + 4, header_len, profile, |_, _, _| {})?;
            }
            _ => {}
        }
    }

    Ok(Located {
        summary: HeaderSummary {
            marker: (fixed[1] >> MARKER_SHIFT & MARKER_MASK) > 0,
            payload_type: fixed[1] & PT_MASK,
            sequence_number: u16::from_be_bytes([fixed[2], fixed[3]]),
            timestamp: u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]),
            ssrc: u32::from_be_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]),
            header_len,
        },
        csrc_end,
        profile,
    })
}

impl Header {
    /// Reads and validates the header at the front of `buf` without allocating.
    ///
    /// Accepts and rejects exactly what [`Header::unmarshal`] does, but skips building the CSRC
    /// list and extension table, so it costs a few loads instead of two allocations. Use it
    /// where only the routing fields matter.
    ///
    /// # Errors
    ///
    /// Fails if `buf` is too short for the header it announces, or if a one-byte or two-byte
    /// extension element overruns its block.
    pub fn peek(buf: &[u8]) -> Result<HeaderSummary> {
        locate(buf).map(|located| located.summary)
    }
}

impl Header {
    /// Marshaled header size given an already-computed extension payload length
    /// (see [`Header::get_extension_payload_len`]). Lets `marshal_to` size the
    /// buffer and write the extension length field from a single scan of the
    /// extensions instead of walking them via `marshal_size` and again directly.
    fn marshal_size_for(&self, extension_payload_len: usize) -> usize {
        let mut head_size = 12 + (self.csrc.len() * CSRC_LENGTH);
        if self.extension {
            head_size += 4 + (extension_payload_len + self.extensions_padding).div_ceil(4) * 4;
        }
        head_size
    }
}

impl MarshalSize for Header {
    /// MarshalSize returns the size of the packet once marshaled.
    fn marshal_size(&self) -> usize {
        let extension_payload_len = if self.extension {
            self.get_extension_payload_len()
        } else {
            0
        };
        self.marshal_size_for(extension_payload_len)
    }
}

impl Marshal for Header {
    /// Marshal serializes the header and writes to the buffer.
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        /*
         *  0                   1                   2                   3
         *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |V=2|P|X|  CC   |M|     PT      |       sequence number         |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |                           timestamp                           |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |           synchronization source (SSRC) identifier            |
         * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         * |            contributing source (CSRC) identifiers             |
         * |                             ....                              |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        let remaining_before = buf.remaining_mut();
        // Scan the extensions once here; reused for the bounds check, the
        // extension length field, and the trailing padding below (previously
        // walked three times: marshal_size() here plus twice in the body).
        let extension_payload_len = if self.extension {
            self.get_extension_payload_len()
        } else {
            0
        };
        if remaining_before < self.marshal_size_for(extension_payload_len) {
            return Err(Error::ErrBufferTooSmall);
        }

        // The first byte contains the version, padding bit, extension bit, and csrc size
        let mut b0 = (self.version << VERSION_SHIFT) | self.csrc.len() as u8;
        if self.padding {
            b0 |= 1 << PADDING_SHIFT;
        }

        if self.extension {
            b0 |= 1 << EXTENSION_SHIFT;
        }
        buf.put_u8(b0);

        // The second byte contains the marker bit and payload type.
        let mut b1 = self.payload_type;
        if self.marker {
            b1 |= 1 << MARKER_SHIFT;
        }
        buf.put_u8(b1);

        buf.put_u16(self.sequence_number);
        buf.put_u32(self.timestamp);
        buf.put_u32(self.ssrc);

        for csrc in &self.csrc {
            buf.put_u32(*csrc);
        }

        if self.extension {
            buf.put_u16(self.extension_profile);

            // extension_payload_len computed once at the top of this function.
            if self.extension_profile != EXTENSION_PROFILE_ONE_BYTE
                && self.extension_profile != EXTENSION_PROFILE_TWO_BYTE
                && !extension_payload_len.is_multiple_of(4)
            {
                //the payload must be in 32-bit words.
                return Err(Error::HeaderExtensionPayloadNot32BitWords);
            }
            let extension_payload_size =
                ((extension_payload_len + self.extensions_padding) as u16).div_ceil(4);
            buf.put_u16(extension_payload_size);

            match self.extension_profile {
                // RFC 8285 RTP One Byte Header Extension
                EXTENSION_PROFILE_ONE_BYTE => {
                    for extension in &self.extensions {
                        buf.put_u8((extension.id << 4) | (extension.payload.len() as u8 - 1));
                        buf.put(&*extension.payload);
                    }
                }
                // RFC 8285 RTP Two Byte Header Extension
                EXTENSION_PROFILE_TWO_BYTE => {
                    for extension in &self.extensions {
                        buf.put_u8(extension.id);
                        buf.put_u8(extension.payload.len() as u8);
                        buf.put(&*extension.payload);
                    }
                }
                // RFC3550 Extension: the single raw payload block, or nothing
                // at all when the header was built with the extension flag set
                // but no extension attached (pion marshals that as an empty
                // block; erroring broke round-trips of freshly built headers).
                _ => {
                    if self.extensions.len() > 1 {
                        return Err(Error::ErrRfc3550headerIdrange);
                    }

                    if let Some(extension) = self.extensions.first() {
                        let ext_len = extension.payload.len();
                        if ext_len % 4 != 0 {
                            return Err(Error::HeaderExtensionPayloadNot32BitWords);
                        }
                        buf.put(&*extension.payload);
                    }
                }
            };

            // add padding to reach 4 bytes boundaries
            for _ in extension_payload_len..extension_payload_size as usize * 4 {
                buf.put_u8(0);
            }
        }

        let remaining_after = buf.remaining_mut();
        Ok(remaining_before - remaining_after)
    }
}

impl Header {
    /// The total encoded length of the extension payloads, padding excluded.
    pub fn get_extension_payload_len(&self) -> usize {
        let payload_len: usize = self
            .extensions
            .iter()
            .map(|extension| extension.payload.len())
            .sum();

        let profile_len = self.extensions.len()
            * match self.extension_profile {
                EXTENSION_PROFILE_ONE_BYTE => 1,
                EXTENSION_PROFILE_TWO_BYTE => 2,
                _ => 0,
            };

        payload_len + profile_len
    }

    /// SetExtension sets an RTP header extension
    pub fn set_extension(&mut self, id: u8, payload: Bytes) -> Result<()> {
        let payload_len = payload.len() as isize;
        if self.extension {
            match self.extension_profile {
                EXTENSION_PROFILE_ONE_BYTE => {
                    if !(1..=14).contains(&id) {
                        return Err(Error::ErrRfc8285oneByteHeaderIdrange);
                    }
                    if payload_len > 16 {
                        return Err(Error::ErrRfc8285oneByteHeaderSize);
                    }
                }
                EXTENSION_PROFILE_TWO_BYTE => {
                    if id < 1 {
                        return Err(Error::ErrRfc8285twoByteHeaderIdrange);
                    }
                    if payload_len > 255 {
                        return Err(Error::ErrRfc8285twoByteHeaderSize);
                    }
                }
                _ => {
                    if id != 0 {
                        return Err(Error::ErrRfc3550headerIdrange);
                    }
                }
            }

            // Update existing if it exists else add new extension
            if let Some(extension) = self
                .extensions
                .iter_mut()
                .find(|extension| extension.id == id)
            {
                extension.payload = payload;
            } else {
                self.extensions.push(Extension { id, payload });
            }
            // Pion pads to the next word boundary and nothing more; padding
            // preserved from a parsed header no longer applies once it is edited.
            self.extensions_padding = 0;
        } else {
            // No existing header extensions
            self.extension = true;
            self.extension_profile = match payload_len {
                0..=16 => EXTENSION_PROFILE_ONE_BYTE,
                17..=255 => EXTENSION_PROFILE_TWO_BYTE,
                _ => self.extension_profile,
            };
            self.extensions_padding = 0;
            self.extensions.push(Extension { id, payload });
        }
        Ok(())
    }

    /// returns an extension id array
    pub fn get_extension_ids(&self) -> Vec<u8> {
        if self.extension {
            self.extensions.iter().map(|e| e.id).collect()
        } else {
            vec![]
        }
    }

    /// returns an RTP header extension
    pub fn get_extension(&self, id: u8) -> Option<Bytes> {
        if self.extension {
            self.extensions
                .iter()
                .find(|extension| extension.id == id)
                .map(|extension| extension.payload.clone())
        } else {
            None
        }
    }

    /// The payload of an RTP header extension, borrowed rather than cloned.
    ///
    /// [`Header::get_extension`](Self::get_extension) hands out an owned [`Bytes`], and cloning
    /// a payload that was never shared before costs an allocation — the `bytes` crate promotes
    /// a freshly-frozen payload to its shared form on the first clone. In the per-packet path
    /// (a congestion controller reading the transport-cc sequence on every packet) that is one
    /// heap allocation per packet for what is a two-byte read, so this borrowed form exists.
    pub fn get_extension_payload(&self, id: u8) -> Option<&[u8]> {
        if self.extension {
            self.extensions
                .iter()
                .find(|extension| extension.id == id)
                .map(|extension| extension.payload.as_ref())
        } else {
            None
        }
    }

    /// Removes an RTP Header extension
    ///
    /// Removing the last extension also clears the extension flag and profile,
    /// as pion does: a header with no extensions left marshals as if extensions
    /// were never enabled.
    pub fn del_extension(&mut self, id: u8) -> Result<()> {
        if self.extension {
            if let Some(index) = self
                .extensions
                .iter()
                .position(|extension| extension.id == id)
            {
                self.extensions.remove(index);

                if self.extensions.is_empty() {
                    self.extension = false;
                    self.extension_profile = 0;
                    self.extensions_padding = 0;
                    return Ok(());
                }

                self.extensions_padding = 0;

                Ok(())
            } else {
                Err(Error::ErrHeaderExtensionNotFound)
            }
        } else {
            Err(Error::ErrHeaderExtensionsNotEnabled)
        }
    }

    /// Removes all RTP header extensions (pion's `ClearExtensions`): the table
    /// is emptied and the extension flag and profile are reset.
    pub fn clear_extensions(&mut self) {
        self.extensions.clear();
        self.extension = false;
        self.extension_profile = 0;
        self.extensions_padding = 0;
    }

    /// Sets an RTP header extension, switching the extension profile when the
    /// header already carries one of a different kind (pion's
    /// `SetExtensionWithProfile`).
    ///
    /// Upgrading (for example to two-byte ids for an id above 14 or a payload
    /// above 16 bytes) re-encodes every existing extension under the new
    /// profile; downgrading to one-byte ids fails if any existing extension
    /// does not fit the one-byte element format (an id above 14 or a payload
    /// above 16 bytes).
    pub fn set_extension_with_profile(
        &mut self,
        id: u8,
        payload: Bytes,
        intended_profile: u16,
    ) -> Result<()> {
        if !self.extension || self.extension_profile == intended_profile {
            return self.set_extension(id, payload);
        }

        // Don't mutate the header if the set is invalid anyway.
        check_extension(intended_profile, id, &payload)?;

        // If downgrading, assert the existing extensions will still fit.
        if intended_profile == EXTENSION_PROFILE_ONE_BYTE {
            for extension in &self.extensions {
                check_extension(intended_profile, extension.id, &extension.payload)?;
            }
        }

        self.extension_profile = intended_profile;
        self.set_extension(id, payload)
    }
}

/// pion's `headerExtensionCheck`: the id/payload rules per profile.
fn check_extension(extension_profile: u16, id: u8, payload: &[u8]) -> Result<()> {
    match extension_profile {
        EXTENSION_PROFILE_ONE_BYTE => {
            if !(1..=14).contains(&id) {
                return Err(Error::ErrRfc8285oneByteHeaderIdrange);
            }
            if payload.len() > 16 {
                return Err(Error::ErrRfc8285oneByteHeaderSize);
            }
        }
        EXTENSION_PROFILE_TWO_BYTE => {
            if id < 1 {
                return Err(Error::ErrRfc8285twoByteHeaderIdrange);
            }
            if payload.len() > 255 {
                return Err(Error::ErrRfc8285twoByteHeaderSize);
            }
        }
        _ => {
            if id != 0 {
                return Err(Error::ErrRfc3550headerIdrange);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod peek_test {
    use super::*;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    fn sample(rng: &mut StdRng) -> Vec<u8> {
        let mut header = Header {
            version: 2,
            marker: rng.random(),
            payload_type: rng.random_range(0..128),
            sequence_number: rng.random(),
            timestamp: rng.random(),
            ssrc: rng.random(),
            csrc: (0..rng.random_range(0..4)).map(|_| rng.random()).collect(),
            ..Default::default()
        };
        if rng.random_bool(0.7) {
            header.extension = true;
            header.extension_profile = if rng.random_bool(0.5) {
                EXTENSION_PROFILE_ONE_BYTE
            } else {
                EXTENSION_PROFILE_TWO_BYTE
            };
            for id in 1..=rng.random_range(1..4u8) {
                let len = rng.random_range(1..=8);
                let _ = header.set_extension(id, Bytes::from((0..len).collect::<Vec<u8>>()));
            }
        }
        let mut raw = header.marshal().unwrap().to_vec();
        raw.extend_from_slice(&[0xAB; 32]);
        raw
    }

    /// `peek` must accept and reject exactly what `unmarshal` does, and report the same fields:
    /// SRTP relies on it in place of a full parse.
    #[test]
    fn peek_agrees_with_unmarshal_on_valid_and_mutated_headers() {
        let mut rng = StdRng::seed_from_u64(0x5eed);
        let mut disagreements = 0;
        for _ in 0..20_000 {
            let mut raw = sample(&mut rng);
            // Flip a few bytes and truncate some inputs so rejects are well represented.
            for _ in 0..rng.random_range(0..3) {
                let i = rng.random_range(0..raw.len());
                raw[i] = rng.random();
            }
            if rng.random_bool(0.2) {
                raw.truncate(rng.random_range(0..raw.len()));
            }

            let parsed = Header::unmarshal(&mut &raw[..]);
            let peeked = Header::peek(&raw);
            match (&parsed, &peeked) {
                (Ok(h), Ok(s)) => {
                    assert_eq!(h.marker, s.marker, "{raw:02x?}");
                    assert_eq!(h.payload_type, s.payload_type, "{raw:02x?}");
                    assert_eq!(h.sequence_number, s.sequence_number, "{raw:02x?}");
                    assert_eq!(h.timestamp, s.timestamp, "{raw:02x?}");
                    assert_eq!(h.ssrc, s.ssrc, "{raw:02x?}");
                    assert_eq!(Header::wire_len(&raw).unwrap(), s.header_len, "{raw:02x?}");
                }
                (Err(a), Err(b)) => assert_eq!(a, b, "{raw:02x?}"),
                _ => disagreements += 1,
            }
        }
        assert_eq!(disagreements, 0, "peek and unmarshal disagreed");
    }
}

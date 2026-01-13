#[cfg(test)]
mod ogg_reader_test;

use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};
use bytes::BytesMut;

use crate::io::ResetFn;
use shared::error::{Error, Result};

pub const PAGE_HEADER_TYPE_CONTINUATION_OF_STREAM: u8 = 0x00;
pub const PAGE_HEADER_TYPE_BEGINNING_OF_STREAM: u8 = 0x02;
pub const PAGE_HEADER_TYPE_END_OF_STREAM: u8 = 0x04;
pub const DEFAULT_PRE_SKIP: u16 = 3840; // 3840 recommended in the RFC
pub const PAGE_HEADER_SIGNATURE: &[u8] = b"OggS";
pub const ID_PAGE_SIGNATURE: &[u8] = b"OpusHead";
pub const COMMENT_PAGE_SIGNATURE: &[u8] = b"OpusTags";
pub const PAGE_HEADER_SIZE: usize = 27;
pub const ID_PAGE_PAYLOAD_SIZE: usize = 19;

/// Header type classification for Opus pages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OggHeaderType {
    /// OpusHead - Opus ID page
    OpusHead,
    /// OpusTags - Opus comment/metadata page
    OpusTags,
}

/// OggReader is used to read Ogg files and return page payloads
pub struct OggReader<R: Read> {
    reader: R,
    bytes_read: usize,
    checksum_table: [u32; 256],
    do_checksum: bool,
}

/// OggHeader is the metadata from the first two pages
/// in the file (ID and Comment)
/// <https://tools.ietf.org/html/rfc7845.html#section-3>
#[derive(Debug, Clone)]
pub struct OggHeader {
    pub channel_map: u8,
    pub channels: u8,
    pub output_gain: u16,
    pub pre_skip: u16,
    pub sample_rate: u32,
    pub version: u8,
    pub stream_count: u8,
    pub coupled_count: u8,
    pub channel_mapping: Vec<u8>,
}

/// OpusTags contains Vorbis comment metadata from an OpusTags page
/// <https://www.xiph.org/vorbis/doc/v-comment.html>
#[derive(Debug, Clone, Default)]
pub struct OpusTags {
    pub vendor: String,
    pub user_comments: Vec<UserComment>,
}

/// A key-value pair from Vorbis comments
#[derive(Debug, Clone)]
pub struct UserComment {
    pub comment: String,
    pub value: String,
}

/// OggPageHeader is the metadata for a Page
/// Pages are the fundamental unit of multiplexing in an Ogg stream
/// <https://tools.ietf.org/html/rfc7845.html#section-1>
#[derive(Debug, Clone)]
pub struct OggPageHeader {
    pub granule_position: u64,
    /// Serial number of the logical bitstream (track)
    pub serial: u32,
    /// Page header type flags
    pub header_type: u8,

    sig: [u8; 4],
    version: u8,
    index: u32,
    segments_count: u8,
}

impl OggPageHeader {
    /// Classify the page payload as OpusHead or OpusTags header
    pub fn opus_header_type(&self, payload: &[u8]) -> Option<OggHeaderType> {
        if payload.len() < 8 {
            return None;
        }

        let sig = &payload[..8];
        if sig == ID_PAGE_SIGNATURE {
            // OpusHead must be beginning of stream
            if self.header_type == PAGE_HEADER_TYPE_BEGINNING_OF_STREAM {
                return Some(OggHeaderType::OpusHead);
            }
            return None;
        }
        if sig == COMMENT_PAGE_SIGNATURE {
            return Some(OggHeaderType::OpusTags);
        }

        None
    }

    /// Check if this is the beginning of a stream
    pub fn is_beginning_of_stream(&self) -> bool {
        self.header_type == PAGE_HEADER_TYPE_BEGINNING_OF_STREAM
    }

    /// Check if this is the end of a stream
    pub fn is_end_of_stream(&self) -> bool {
        self.header_type == PAGE_HEADER_TYPE_END_OF_STREAM
    }
}

/// Parse an OpusHead from a page payload
/// <https://tools.ietf.org/html/rfc7845.html#section-5.1>
pub fn parse_opus_head(payload: &[u8]) -> Result<OggHeader> {
    if payload.len() < ID_PAGE_PAYLOAD_SIZE {
        return Err(Error::ErrBadIDPageLength);
    }

    if &payload[..8] != ID_PAGE_SIGNATURE {
        return Err(Error::ErrBadIDPagePayloadSignature);
    }

    let mut reader = Cursor::new(&payload[8..]);
    let version = reader.read_u8()?;
    let channels = reader.read_u8()?;
    let pre_skip = reader.read_u16::<LittleEndian>()?;
    let sample_rate = reader.read_u32::<LittleEndian>()?;
    let output_gain = reader.read_u16::<LittleEndian>()?;
    let channel_map = reader.read_u8()?;

    let (stream_count, coupled_count, channel_mapping) = match channel_map {
        0 => {
            // Family 0: mono or stereo, no mapping table
            if payload.len() != ID_PAGE_PAYLOAD_SIZE {
                return Err(Error::ErrBadIDPageLength);
            }
            (0, 0, vec![])
        }
        1 | 2 | 255 => {
            // Extended channel mapping
            let expected_len = 21 + channels as usize;
            if payload.len() < expected_len {
                return Err(Error::ErrBadIDPageLength);
            }
            let stream_count = payload[19];
            let coupled_count = payload[20];
            let channel_mapping = payload[21..expected_len].to_vec();
            (stream_count, coupled_count, channel_mapping)
        }
        3 => {
            return Err(Error::ErrUnsupportedChannelMappingFamily);
        }
        _ => {
            return Err(Error::ErrUnsupportedChannelMappingFamily);
        }
    };

    Ok(OggHeader {
        channel_map,
        channels,
        output_gain,
        pre_skip,
        sample_rate,
        version,
        stream_count,
        coupled_count,
        channel_mapping,
    })
}

/// Parse OpusTags from a page payload
/// <https://tools.ietf.org/html/rfc7845.html#section-5.2>
pub fn parse_opus_tags(payload: &[u8]) -> Result<OpusTags> {
    const HEADER_MAGIC_LEN: usize = 8;
    const U32_SIZE: usize = 4;
    const MIN_HEADER_LEN: usize = HEADER_MAGIC_LEN + U32_SIZE + U32_SIZE;

    if payload.len() < MIN_HEADER_LEN {
        return Err(Error::ErrBadOpusTagsSignature);
    }

    if &payload[..8] != COMMENT_PAGE_SIGNATURE {
        return Err(Error::ErrBadOpusTagsSignature);
    }

    // Parse vendor string
    let vendor_len = u32::from_le_bytes([
        payload[HEADER_MAGIC_LEN],
        payload[HEADER_MAGIC_LEN + 1],
        payload[HEADER_MAGIC_LEN + 2],
        payload[HEADER_MAGIC_LEN + 3],
    ]) as usize;

    let vendor_start = HEADER_MAGIC_LEN + U32_SIZE;
    let vendor_end = vendor_start + vendor_len;

    if vendor_end + U32_SIZE > payload.len() {
        return Err(Error::ErrBadOpusTagsSignature);
    }

    let vendor = String::from_utf8_lossy(&payload[vendor_start..vendor_end]).to_string();

    // Parse user comments
    let comment_count = u32::from_le_bytes([
        payload[vendor_end],
        payload[vendor_end + 1],
        payload[vendor_end + 2],
        payload[vendor_end + 3],
    ]) as usize;

    let mut pos = vendor_end + U32_SIZE;
    let mut user_comments = Vec::with_capacity(comment_count);

    for _ in 0..comment_count {
        if pos + U32_SIZE > payload.len() {
            return Err(Error::ErrBadOpusTagsSignature);
        }

        let comment_len = u32::from_le_bytes([
            payload[pos],
            payload[pos + 1],
            payload[pos + 2],
            payload[pos + 3],
        ]) as usize;
        pos += U32_SIZE;

        if pos + comment_len > payload.len() {
            return Err(Error::ErrBadOpusTagsSignature);
        }

        let comment_str = String::from_utf8_lossy(&payload[pos..pos + comment_len]).to_string();
        pos += comment_len;

        // Split on first '=' to get key=value pair
        if let Some(eq_pos) = comment_str.find('=') {
            user_comments.push(UserComment {
                comment: comment_str[..eq_pos].to_string(),
                value: comment_str[eq_pos + 1..].to_string(),
            });
        }
    }

    Ok(OpusTags {
        vendor,
        user_comments,
    })
}

impl<R: Read> OggReader<R> {
    /// new returns a new Ogg reader and Ogg header
    /// with an io.Reader input
    ///
    /// Warning: This only parses the first OpusHead (a single logical bitstream/track)
    /// and returns a single OggHeader. If you need to handle Ogg containers with multiple
    /// Opus headers/tracks, use new_with_options and scan pages via parse_next_page
    /// to find and parse each OpusHead.
    pub fn new(reader: R, do_checksum: bool) -> Result<(OggReader<R>, OggHeader)> {
        let mut r = OggReader {
            reader,
            bytes_read: 0,
            checksum_table: generate_checksum_table(),
            do_checksum,
        };

        let header = r.read_headers()?;

        Ok((r, header))
    }

    /// Create a new OggReader without consuming headers
    ///
    /// Use this when you need to handle Ogg containers with multiple
    /// logical bitstreams (tracks). You can then use parse_next_page
    /// to iterate through pages and parse_opus_head/parse_opus_tags
    /// to parse the header pages for each track.
    pub fn new_with_options(reader: R, do_checksum: bool) -> OggReader<R> {
        OggReader {
            reader,
            bytes_read: 0,
            checksum_table: generate_checksum_table(),
            do_checksum,
        }
    }

    fn read_headers(&mut self) -> Result<OggHeader> {
        let (payload, page_header) = self.parse_next_page()?;

        if page_header.sig != PAGE_HEADER_SIGNATURE {
            return Err(Error::ErrBadIDPageSignature);
        }

        if page_header.header_type != PAGE_HEADER_TYPE_BEGINNING_OF_STREAM {
            return Err(Error::ErrBadIDPageType);
        }

        parse_opus_head(&payload)
    }

    // parse_next_page reads from stream and returns Ogg page payload, header,
    // and an error if there is incomplete page data.
    pub fn parse_next_page(&mut self) -> Result<(BytesMut, OggPageHeader)> {
        let mut h = [0u8; PAGE_HEADER_SIZE];
        self.reader.read_exact(&mut h)?;

        let mut head_reader = Cursor::new(h);
        let mut sig = [0u8; 4]; //0-3
        head_reader.read_exact(&mut sig)?;
        let version = head_reader.read_u8()?; //4
        let header_type = head_reader.read_u8()?; //5
        let granule_position = head_reader.read_u64::<LittleEndian>()?; //6-13
        let serial = head_reader.read_u32::<LittleEndian>()?; //14-17
        let index = head_reader.read_u32::<LittleEndian>()?; //18-21
        let checksum = head_reader.read_u32::<LittleEndian>()?; //22-25
        let segments_count = head_reader.read_u8()?; //26

        let mut size_buffer = vec![0u8; segments_count as usize];
        self.reader.read_exact(&mut size_buffer)?;

        let mut payload_size = 0usize;
        for s in &size_buffer {
            payload_size += *s as usize;
        }

        let mut payload = BytesMut::with_capacity(payload_size);
        payload.resize(payload_size, 0);
        self.reader.read_exact(&mut payload)?;

        if self.do_checksum {
            let mut sum = 0;

            for (index, v) in h.iter().enumerate() {
                // Don't include expected checksum in our generation
                if index > 21 && index < 26 {
                    sum = self.update_checksum(0, sum);
                    continue;
                }
                sum = self.update_checksum(*v, sum);
            }

            for v in &size_buffer {
                sum = self.update_checksum(*v, sum);
            }
            for v in &payload[..] {
                sum = self.update_checksum(*v, sum);
            }

            if sum != checksum {
                return Err(Error::ErrChecksumMismatch);
            }
        }

        let page_header = OggPageHeader {
            granule_position,
            sig,
            version,
            header_type,
            serial,
            index,
            segments_count,
        };

        Ok((payload, page_header))
    }

    /// reset_reader resets the internal stream of OggReader. This is useful
    /// for live streams, where the end of the file might be read without the
    /// data being finished.
    pub fn reset_reader(&mut self, mut reset: ResetFn<R>) {
        self.reader = reset(self.bytes_read);
    }

    fn update_checksum(&self, v: u8, sum: u32) -> u32 {
        (sum << 8) ^ self.checksum_table[(((sum >> 24) as u8) ^ v) as usize]
    }
}

pub(crate) fn generate_checksum_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    const POLY: u32 = 0x04c11db7;

    for (i, t) in table.iter_mut().enumerate() {
        let mut r = (i as u32) << 24;
        for _ in 0..8 {
            if (r & 0x80000000) != 0 {
                r = (r << 1) ^ POLY;
            } else {
                r <<= 1;
            }
        }
        *t = r;
    }
    table
}

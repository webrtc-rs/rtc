#[cfg(test)]
mod fragment_buffer_test;

use crate::content::*;
use crate::handshake::HandshakeType;
use crate::handshake::handshake_header::*;
use crate::record_layer::record_layer_header::*;
use shared::error::*;

use std::collections::HashMap;
use std::io::Cursor;

// 2 mb max buffer size
const FRAGMENT_BUFFER_MAX_SIZE: usize = 2_000_000;
// The most handshake fragments held at once, empty ones included: retaining them costs memory
// even though they carry no bytes.
const FRAGMENT_BUFFER_MAX_COUNT: usize = 1000;

/// The payload of one handshake fragment.
struct FragmentRange {
    offset: u32,
    data: Vec<u8>,
}

impl FragmentRange {
    fn end(&self) -> u32 {
        // Fragment offsets and lengths are 24-bit, so this cannot overflow.
        self.offset + self.data.len() as u32
    }
}

/// What has been received of one handshake message.
///
/// A peer may fragment a retransmitted message differently from the original transmission
/// (RFC 6347 §4.2.3), so fragments can overlap. `ranges` is sorted by offset and never holds a
/// fragment that another one fully covers, which makes its ends increase as well; `covered` is
/// the length of the contiguous prefix of the message received so far and advances as fragments
/// arrive, so completeness is known without scanning.
struct Fragments {
    ranges: Vec<FragmentRange>,
    covered: u32,
    handshake_type: HandshakeType,
    handshake_length: u32,
    // From the first fragment received at offset 0.
    handshake_header: Option<HandshakeHeader>,
    epoch: u16,
}

impl Fragments {
    /// Stores a fragment if the growth in fragment count fits within `available`, returning the
    /// change in stored fragment count and bytes. Replacing smaller fragments can decrease both.
    fn add(&mut self, offset: u32, data: &[u8], available: usize) -> Result<(isize, isize)> {
        let frag = FragmentRange {
            offset,
            data: data.to_vec(),
        };

        // First fragment starting at or after `offset`.
        let i = self.ranges.partition_point(|r| r.offset < offset);
        if self.covers(i, &frag) {
            return Ok((0, 0));
        }

        // ranges[i..j] start inside the new fragment and end inside it: covered.
        let mut j = i;
        let (mut fragment_delta, mut byte_delta) = (0isize, 0isize);
        while j < self.ranges.len() && self.ranges[j].end() <= frag.end() {
            fragment_delta -= 1;
            byte_delta -= self.ranges[j].data.len() as isize;
            j += 1;
        }
        fragment_delta += 1;
        if fragment_delta > available as isize {
            return Err(Error::ErrFragmentBufferOverflow {
                new_size: FRAGMENT_BUFFER_MAX_COUNT + 1,
                max_size: FRAGMENT_BUFFER_MAX_COUNT,
            });
        }

        byte_delta += frag.data.len() as isize;
        self.ranges.splice(i..j, [frag]);
        self.advance_covered(i);
        Ok((fragment_delta, byte_delta))
    }

    /// Whether a stored fragment already carries every byte of `frag`, whose insertion index is
    /// `i`. Since ends increase with offsets, only the fragment before `i` and one starting at
    /// the same offset can.
    fn covers(&self, i: usize, frag: &FragmentRange) -> bool {
        if i > 0 && self.ranges[i - 1].end() >= frag.end() {
            return true;
        }
        self.ranges
            .get(i)
            .is_some_and(|r| r.offset == frag.offset && r.end() >= frag.end())
    }

    /// Extends the covered prefix after inserting `ranges[i]`. Only a fragment touching the
    /// prefix can extend it, possibly through fragments received earlier that start within its
    /// reach.
    fn advance_covered(&mut self, i: usize) {
        if self.ranges[i].offset > self.covered {
            return;
        }
        for r in &self.ranges[i..] {
            if r.offset > self.covered {
                break;
            }
            self.covered = self.covered.max(r.end());
        }
    }
}

pub(crate) struct FragmentBuffer {
    // map of MessageSequenceNumbers that hold slices of fragments
    cache: HashMap<u16, Fragments>,

    current_message_sequence_number: u16,

    total_buffer_size: usize,
    total_fragment_count: usize,
}

impl FragmentBuffer {
    pub fn new() -> Self {
        FragmentBuffer {
            cache: HashMap::new(),
            current_message_sequence_number: 0,
            total_buffer_size: 0,
            total_fragment_count: 0,
        }
    }

    // Attempts to push a DTLS packet to the FragmentBuffer
    // when it returns true it means the FragmentBuffer has inserted and the buffer shouldn't be handled
    // when an error returns it is fatal, and the DTLS connection should be stopped
    pub fn push(&mut self, mut buf: &[u8]) -> Result<bool> {
        let current_size = self.size();
        if current_size + buf.len() >= FRAGMENT_BUFFER_MAX_SIZE {
            return Err(Error::ErrFragmentBufferOverflow {
                new_size: current_size + buf.len(),
                max_size: FRAGMENT_BUFFER_MAX_SIZE,
            });
        }

        let mut reader = Cursor::new(buf);
        let record_layer_header = RecordLayerHeader::unmarshal(&mut reader)?;

        // Fragment isn't a handshake, we don't need to handle it
        if record_layer_header.content_type != ContentType::Handshake {
            return Ok(false);
        }

        buf = &buf[RECORD_LAYER_HEADER_SIZE..];
        while !buf.is_empty() {
            let mut reader = Cursor::new(buf);
            let header = HandshakeHeader::unmarshal(&mut reader)?;

            let end = HANDSHAKE_HEADER_LENGTH + header.fragment_length as usize;
            if end > buf.len() {
                return Err(Error::ErrBufferTooSmall);
            }
            let data = &buf[HANDSHAKE_HEADER_LENGTH..end];
            buf = &buf[end..];

            // Already assembled, or claims bytes outside the message: ignore it, and keep
            // reading the rest of the record.
            if self.message_assembled(header.message_sequence)
                || header.fragment_offset > header.length
                || header.fragment_length > header.length - header.fragment_offset
            {
                continue;
            }

            let is_new = !self.cache.contains_key(&header.message_sequence);
            if let Some(f) = self.cache.get(&header.message_sequence)
                && (header.handshake_type != f.handshake_type
                    || header.length != f.handshake_length)
            {
                // Disagrees with the message's earlier fragments; admitting it would break the
                // bounds `pop` relies on.
                continue;
            }

            let available = FRAGMENT_BUFFER_MAX_COUNT.saturating_sub(self.total_fragment_count);
            let message_fragments =
                self.cache
                    .entry(header.message_sequence)
                    .or_insert_with(|| Fragments {
                        ranges: vec![],
                        covered: 0,
                        handshake_type: header.handshake_type,
                        handshake_length: header.length,
                        handshake_header: None,
                        epoch: 0,
                    });

            // empty fragments also count because retaining them consumes memory.
            let (fragment_delta, byte_delta) =
                match message_fragments.add(header.fragment_offset, data, available) {
                    Ok(deltas) => deltas,
                    Err(e) => {
                        if is_new {
                            self.cache.remove(&header.message_sequence);
                        }
                        return Err(e);
                    }
                };
            if header.fragment_offset == 0 && message_fragments.handshake_header.is_none() {
                message_fragments.handshake_header = Some(header);
                message_fragments.epoch = record_layer_header.epoch;
            }

            self.total_fragment_count = self
                .total_fragment_count
                .saturating_add_signed(fragment_delta);
            self.total_buffer_size = self.total_buffer_size.saturating_add_signed(byte_delta);
        }

        Ok(true)
    }

    /// Whether the message numbered `seq` is already behind the one being assembled
    /// (serial-number comparison on the 16-bit sequence space).
    fn message_assembled(&self, seq: u16) -> bool {
        seq != self.current_message_sequence_number
            && self.current_message_sequence_number.wrapping_sub(seq) < 0x8000
    }

    pub fn pop(&mut self) -> Result<(Vec<u8>, u16)> {
        let seq_num = self.current_message_sequence_number;
        let Some(frags) = self.cache.get(&seq_num) else {
            return Err(Error::ErrEmptyFragment);
        };
        if frags.covered < frags.handshake_length {
            return Err(Error::ErrEmptyFragment);
        }
        let Some(mut first_header) = frags.handshake_header else {
            return Err(Error::ErrEmptyFragment);
        };
        first_header.fragment_offset = 0;
        first_header.fragment_length = first_header.length;

        let mut content = vec![];
        {
            let mut writer = &mut content;
            if first_header.marshal(&mut writer).is_err() {
                return Err(Error::ErrEmptyFragment);
            }
        }
        content.reserve(frags.handshake_length as usize);

        // The message is contiguous, so each fragment continues at or before where the previous
        // one ended.
        let mut cursor = 0u32;
        for frag in &frags.ranges {
            content.extend_from_slice(&frag.data[(cursor - frag.offset) as usize..]);
            cursor = frag.end();
        }
        let epoch = frags.epoch;
        self.total_buffer_size -= frags.ranges.iter().map(|r| r.data.len()).sum::<usize>();
        self.total_fragment_count -= frags.ranges.len();

        self.cache.remove(&seq_num);
        self.current_message_sequence_number = self.current_message_sequence_number.wrapping_add(1);

        Ok((content, epoch))
    }

    fn size(&self) -> usize {
        self.total_buffer_size
    }
}

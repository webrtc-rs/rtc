#[cfg(test)]
mod fragment_buffer_test;

use crate::content::*;
use crate::handshake::handshake_header::*;
use crate::record_layer::record_layer_header::*;
use shared::error::*;

use std::collections::HashMap;
use std::collections::hash_map::Entry;

// 2 mb max buffer size, counting each buffered message's storage and bookkeeping
const FRAGMENT_BUFFER_MAX_SIZE: usize = 2_000_000;

// Largest handshake message body that will be reassembled. Certificate chains are the only
// messages that get anywhere near this; OpenSSL's default limit for them is 100 KiB.
const FRAGMENT_BUFFER_MAX_MESSAGE_LENGTH: usize = 128 * 1024;

// How far past the next expected message_sequence a message may be buffered. A flight carries
// at most a handful of messages, so anything further ahead cannot be part of it.
const FRAGMENT_BUFFER_MAX_MESSAGES_AHEAD: u16 = 16;

// Fixed bookkeeping charged per buffered message on top of its byte buffers.
const PENDING_MESSAGE_OVERHEAD: usize = size_of::<PendingMessage>() + size_of::<u16>();

// One handshake message being reassembled.
//
// Fragments are copied straight into `raw` at their offset, so a message's storage is sized by
// its advertised length rather than by how many fragments it arrives in. Overlapping bytes are
// taken from the latest fragment until the message is complete; after that, fragments are
// ignored. Zero-length fragments carry no bytes and change nothing.
struct PendingMessage {
    handshake_header: HandshakeHeader,
    epoch: u16,
    // The rebuilt message: an unfragmented handshake header followed by the body.
    raw: Vec<u8>,
    // One bit per body byte received so far. Left empty when the first fragment carried the
    // whole message.
    received: Vec<u8>,
    received_len: usize,
    // What this message counts against FRAGMENT_BUFFER_MAX_SIZE.
    size: usize,
}

impl PendingMessage {
    // What a message started by `first` counts against FRAGMENT_BUFFER_MAX_SIZE.
    fn size_for(first: &HandshakeHeader) -> usize {
        let length = first.length as usize;
        let received = if Self::is_unfragmented(first) {
            0
        } else {
            length.div_ceil(8)
        };
        HANDSHAKE_HEADER_LENGTH + length + received + PENDING_MESSAGE_OVERHEAD
    }

    fn is_unfragmented(first: &HandshakeHeader) -> bool {
        first.fragment_offset == 0 && first.fragment_length == first.length
    }

    fn new(epoch: u16, first: &HandshakeHeader) -> Self {
        let length = first.length as usize;

        let handshake_header = HandshakeHeader {
            fragment_offset: 0,
            fragment_length: first.length,
            ..*first
        };
        let mut raw = Vec::with_capacity(HANDSHAKE_HEADER_LENGTH + length);
        // A Vec never fails to accept a write, and every field was decoded from the same widths.
        let _ = handshake_header.marshal(&mut raw);
        raw.resize(HANDSHAKE_HEADER_LENGTH + length, 0);

        let received = if Self::is_unfragmented(first) {
            vec![]
        } else {
            vec![0; length.div_ceil(8)]
        };

        PendingMessage {
            handshake_header,
            epoch,
            raw,
            received,
            received_len: 0,
            size: Self::size_for(first),
        }
    }

    fn is_complete(&self) -> bool {
        self.received_len == self.handshake_header.length as usize
    }

    fn write(&mut self, offset: usize, payload: &[u8]) {
        if payload.is_empty() || self.is_complete() {
            return;
        }

        let start = HANDSHAKE_HEADER_LENGTH + offset;
        self.raw[start..start + payload.len()].copy_from_slice(payload);
        if self.received.is_empty() {
            // Only the first fragment of an unfragmented message gets here.
            self.received_len = payload.len();
        } else {
            self.received_len += mark_received(&mut self.received, offset, offset + payload.len());
        }
    }
}

// Sets the bits for body bytes `start..end`, returning how many were not already set.
fn mark_received(bits: &mut [u8], start: usize, end: usize) -> usize {
    let mut added = 0;
    let mut i = start;
    while i < end {
        let bit = i % 8;
        let n = (8 - bit).min(end - i);
        let mask = (((1u16 << n) - 1) as u8) << bit;
        let byte = &mut bits[i / 8];
        added += (mask & !*byte).count_ones() as usize;
        *byte |= mask;
        i += n;
    }
    added
}

pub(crate) struct FragmentBuffer {
    // map of MessageSequenceNumbers to the messages being reassembled
    cache: HashMap<u16, PendingMessage>,

    current_message_sequence_number: u16,

    // Sum of the buffered messages' sizes, kept up to date on insert and removal.
    size: usize,
}

impl FragmentBuffer {
    pub fn new() -> Self {
        FragmentBuffer {
            cache: HashMap::new(),
            current_message_sequence_number: 0,
            size: 0,
        }
    }

    // Attempts to push a DTLS packet to the FragmentBuffer
    // when it returns true it means the FragmentBuffer has inserted and the buffer shouldn't be handled
    // when an error returns it is fatal, and the DTLS connection should be stopped
    //
    // Fragments of messages that were already popped (retransmissions) or that lie beyond
    // FRAGMENT_BUFFER_MAX_MESSAGES_AHEAD are dropped, but still reported as handshake data.
    pub fn push(&mut self, buf: &[u8]) -> Result<bool> {
        let record_layer_header = RecordLayerHeader::unmarshal(&mut &buf[..])?;

        // Fragment isn't a handshake, we don't need to handle it
        if record_layer_header.content_type != ContentType::Handshake {
            return Ok(false);
        }

        // Check the framing of every fragment before buffering any, so a malformed record is
        // rejected as a whole.
        let body = &buf[RECORD_LAYER_HEADER_SIZE..];
        let mut rest = body;
        while !rest.is_empty() {
            rest = split_fragment(rest)?.2;
        }

        let mut rest = body;
        while !rest.is_empty() {
            let (handshake_header, payload, next) = split_fragment(rest)?;
            self.insert(record_layer_header.epoch, &handshake_header, payload)?;
            rest = next;
        }

        Ok(true)
    }

    fn insert(&mut self, epoch: u16, header: &HandshakeHeader, payload: &[u8]) -> Result<()> {
        let ahead = header
            .message_sequence
            .wrapping_sub(self.current_message_sequence_number);
        if ahead >= FRAGMENT_BUFFER_MAX_MESSAGES_AHEAD {
            return Ok(());
        }

        let message = match self.cache.entry(header.message_sequence) {
            Entry::Occupied(entry) => {
                let message = entry.into_mut();
                if message.epoch != epoch
                    || message.handshake_header.handshake_type != header.handshake_type
                    || message.handshake_header.length != header.length
                {
                    // A fragment that disagrees with the rest of its message.
                    return Err(Error::ErrLengthMismatch);
                }
                message
            }
            Entry::Vacant(entry) => {
                if header.length as usize > FRAGMENT_BUFFER_MAX_MESSAGE_LENGTH {
                    return Err(Error::ErrFragmentBufferOverflow {
                        new_size: header.length as usize,
                        max_size: FRAGMENT_BUFFER_MAX_MESSAGE_LENGTH,
                    });
                }
                let new_size = self.size + PendingMessage::size_for(header);
                if new_size >= FRAGMENT_BUFFER_MAX_SIZE {
                    return Err(Error::ErrFragmentBufferOverflow {
                        new_size,
                        max_size: FRAGMENT_BUFFER_MAX_SIZE,
                    });
                }
                self.size = new_size;
                entry.insert(PendingMessage::new(epoch, header))
            }
        };

        message.write(header.fragment_offset as usize, payload);
        Ok(())
    }

    pub fn pop(&mut self) -> Result<(Vec<u8>, u16)> {
        let seq_num = self.current_message_sequence_number;
        if !self.cache.get(&seq_num).is_some_and(|m| m.is_complete()) {
            return Err(Error::ErrEmptyFragment);
        }

        let message = self.cache.remove(&seq_num).ok_or(Error::ErrEmptyFragment)?;
        self.size -= message.size;
        self.current_message_sequence_number = seq_num.wrapping_add(1);

        Ok((message.raw, message.epoch))
    }

    // Drops every buffered message, for a handshake that can no longer complete.
    pub fn release(&mut self) {
        self.cache = HashMap::new();
        self.size = 0;
    }

    #[cfg(test)]
    pub(crate) fn size(&self) -> usize {
        self.size
    }
}

// Splits the handshake fragment at the start of `buf` into its header, its payload, and the
// bytes after it. The payload is `fragment_length` bytes, which must lie within both the record
// and the message the header describes.
fn split_fragment(buf: &[u8]) -> Result<(HandshakeHeader, &[u8], &[u8])> {
    let handshake_header = HandshakeHeader::unmarshal(&mut &buf[..])?;

    let end = HANDSHAKE_HEADER_LENGTH + handshake_header.fragment_length as usize;
    let message_end =
        handshake_header.fragment_offset as usize + handshake_header.fragment_length as usize;
    if end > buf.len() || message_end > handshake_header.length as usize {
        return Err(Error::ErrLengthMismatch);
    }

    Ok((
        handshake_header,
        &buf[HANDSHAKE_HEADER_LENGTH..end],
        &buf[end..],
    ))
}

//! TCP framing utilities for ICE over TCP (RFC 4571/RFC 6544).
//!
//! When using ICE over TCP, all messages must be framed with a 2-byte
//! big-endian length prefix. This module provides helper functions for
//! encoding and decoding framed packets without performing any I/O.
//!
//! # Protocol Format (RFC 4571 Section 2)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! -----------------------------------------------------------------
//! |             LENGTH            |  STUN/DTLS/RTP packet ...     |
//! -----------------------------------------------------------------
//! ```
//!
//! # Example Usage
//!
//! ```rust
//! use rtc_shared::tcp_framing::{frame_packet, TcpFrameDecoder};
//!
//! // Encoding: add framing header to outbound packet
//! let packet = b"STUN message data";
//! let framed = frame_packet(packet);
//! // Send `framed` over TCP...
//!
//! // Decoding: parse framed packets from inbound TCP data
//! let mut decoder = TcpFrameDecoder::new();
//! // Feed data as it arrives from TCP...
//! decoder.extend_from_slice(&framed);
//! while let Some(packet) = decoder.next_packet() {
//!     // Process complete packet
//!     assert_eq!(packet, b"STUN message data");
//! }
//! ```

/// Length of the framing header (2 bytes for length prefix).
pub const FRAMING_HEADER_LEN: usize = 2;

/// Maximum packet size that can be framed (u16::MAX = 65535 bytes).
pub const MAX_FRAMED_PACKET_SIZE: usize = u16::MAX as usize;

/// Adds RFC 4571 framing header to a packet.
///
/// Returns a new `Vec<u8>` containing the 2-byte big-endian length prefix
/// followed by the packet data.
///
/// # Panics
///
/// Panics if `buf.len() > 65535` (maximum u16 value).
///
/// # Example
///
/// ```rust
/// use rtc_shared::tcp_framing::frame_packet;
///
/// let packet = b"Hello, WebRTC!";
/// let framed = frame_packet(packet);
///
/// assert_eq!(framed.len(), 2 + packet.len());
/// assert_eq!(&framed[0..2], &[0, 14]); // Length = 14 in big-endian
/// assert_eq!(&framed[2..], packet);
/// ```
pub fn frame_packet(buf: &[u8]) -> Vec<u8> {
    assert!(
        buf.len() <= MAX_FRAMED_PACKET_SIZE,
        "packet length {} exceeds maximum {}",
        buf.len(),
        MAX_FRAMED_PACKET_SIZE
    );

    let mut framed = Vec::with_capacity(FRAMING_HEADER_LEN + buf.len());
    let header = (buf.len() as u16).to_be_bytes();
    framed.extend_from_slice(&header);
    framed.extend_from_slice(buf);
    framed
}

/// Adds RFC 4571 framing header to a packet, writing into a provided buffer.
///
/// Returns the total number of bytes written (header + payload).
///
/// # Arguments
///
/// * `buf` - The packet data to frame
/// * `out` - Output buffer (must be at least `buf.len() + 2` bytes)
///
/// # Returns
///
/// * `Some(n)` - Total bytes written to `out`
/// * `None` - If `out` is too small or `buf` exceeds max size
///
/// # Example
///
/// ```rust
/// use rtc_shared::tcp_framing::frame_packet_to;
///
/// let packet = b"Hello";
/// let mut out = [0u8; 100];
///
/// let n = frame_packet_to(packet, &mut out).unwrap();
/// assert_eq!(n, 7); // 2 byte header + 5 byte payload
/// ```
pub fn frame_packet_to(buf: &[u8], out: &mut [u8]) -> Option<usize> {
    if buf.len() > MAX_FRAMED_PACKET_SIZE {
        return None;
    }

    let total_len = FRAMING_HEADER_LEN + buf.len();
    if out.len() < total_len {
        return None;
    }

    let header = (buf.len() as u16).to_be_bytes();
    out[..FRAMING_HEADER_LEN].copy_from_slice(&header);
    out[FRAMING_HEADER_LEN..total_len].copy_from_slice(buf);

    Some(total_len)
}

/// A stateful decoder for RFC 4571 framed TCP packets.
///
/// This decoder buffers incoming TCP data and extracts complete framed packets.
/// It handles partial reads gracefully - you can feed it data in any chunk size.
///
/// # Example
///
/// ```rust
/// use rtc_shared::tcp_framing::TcpFrameDecoder;
///
/// let mut decoder = TcpFrameDecoder::new();
///
/// // Simulate receiving data in chunks
/// let chunk1 = &[0, 5, b'H', b'e']; // Partial: header + 2 bytes
/// let chunk2 = &[b'l', b'l', b'o']; // Remaining 3 bytes
///
/// decoder.extend_from_slice(chunk1);
/// assert!(decoder.next_packet().is_none()); // Not complete yet
///
/// decoder.extend_from_slice(chunk2);
/// assert_eq!(decoder.next_packet(), Some(b"Hello".to_vec()));
/// ```
#[derive(Debug, Default)]
pub struct TcpFrameDecoder {
    buffer: Vec<u8>,
}

impl TcpFrameDecoder {
    /// Creates a new decoder with an empty buffer.
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Creates a new decoder with pre-allocated buffer capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    /// Appends data to the internal buffer.
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Attempts to extract the next complete packet from the buffer.
    ///
    /// Returns `Some(packet)` if a complete packet is available,
    /// or `None` if more data is needed.
    ///
    /// The returned packet does not include the 2-byte length header.
    pub fn next_packet(&mut self) -> Option<Vec<u8>> {
        // Need at least the header
        if self.buffer.len() < FRAMING_HEADER_LEN {
            return None;
        }

        // Parse the length
        let length = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
        let total_len = FRAMING_HEADER_LEN + length;

        // Check if we have the complete packet
        if self.buffer.len() < total_len {
            return None;
        }

        // Extract the packet (skip header)
        let packet = self.buffer[FRAMING_HEADER_LEN..total_len].to_vec();

        // Remove processed data from buffer
        self.buffer.drain(..total_len);

        Some(packet)
    }

    /// Returns the number of buffered bytes.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clears the internal buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_packet() {
        let packet = b"Hello, WebRTC!";
        let framed = frame_packet(packet);

        assert_eq!(framed.len(), FRAMING_HEADER_LEN + packet.len());

        // Check header (big-endian length)
        let length = u16::from_be_bytes([framed[0], framed[1]]) as usize;
        assert_eq!(length, packet.len());

        // Check payload
        assert_eq!(&framed[FRAMING_HEADER_LEN..], packet);
    }

    #[test]
    fn test_frame_packet_to() {
        let packet = b"Hello";
        let mut out = [0u8; 100];

        let n = frame_packet_to(packet, &mut out).unwrap();
        assert_eq!(n, 7);
        assert_eq!(&out[..n], &frame_packet(packet)[..]);
    }

    #[test]
    fn test_frame_packet_to_buffer_too_small() {
        let packet = b"Hello";
        let mut out = [0u8; 3]; // Too small

        assert!(frame_packet_to(packet, &mut out).is_none());
    }

    #[test]
    fn test_decoder_complete_packet() {
        let mut decoder = TcpFrameDecoder::new();
        let framed = frame_packet(b"Test");

        decoder.extend_from_slice(&framed);

        let packet = decoder.next_packet().unwrap();
        assert_eq!(packet, b"Test");
        assert!(decoder.is_empty());
    }

    #[test]
    fn test_decoder_partial_header() {
        let mut decoder = TcpFrameDecoder::new();

        // Only first byte of header
        decoder.extend_from_slice(&[0]);
        assert!(decoder.next_packet().is_none());

        // Complete header + payload
        decoder.extend_from_slice(&[5, b'H', b'e', b'l', b'l', b'o']);
        assert_eq!(decoder.next_packet(), Some(b"Hello".to_vec()));
    }

    #[test]
    fn test_decoder_partial_payload() {
        let mut decoder = TcpFrameDecoder::new();

        // Header says 5 bytes, but only 2 bytes of payload
        decoder.extend_from_slice(&[0, 5, b'H', b'e']);
        assert!(decoder.next_packet().is_none());
        assert_eq!(decoder.buffered_len(), 4);

        // Rest of payload
        decoder.extend_from_slice(&[b'l', b'l', b'o']);
        assert_eq!(decoder.next_packet(), Some(b"Hello".to_vec()));
    }

    #[test]
    fn test_decoder_multiple_packets() {
        let mut decoder = TcpFrameDecoder::new();

        let framed1 = frame_packet(b"First");
        let framed2 = frame_packet(b"Second");
        let framed3 = frame_packet(b"Third");

        // Feed all at once
        decoder.extend_from_slice(&framed1);
        decoder.extend_from_slice(&framed2);
        decoder.extend_from_slice(&framed3);

        assert_eq!(decoder.next_packet(), Some(b"First".to_vec()));
        assert_eq!(decoder.next_packet(), Some(b"Second".to_vec()));
        assert_eq!(decoder.next_packet(), Some(b"Third".to_vec()));
        assert!(decoder.next_packet().is_none());
    }

    #[test]
    fn test_decoder_multiple_packets_interleaved() {
        let mut decoder = TcpFrameDecoder::new();

        let mut combined = frame_packet(b"First");
        combined.extend_from_slice(&frame_packet(b"Second"));

        // Feed first 5 bytes (partial first packet)
        decoder.extend_from_slice(&combined[..5]);
        assert!(decoder.next_packet().is_none());

        // Feed rest
        decoder.extend_from_slice(&combined[5..]);
        assert_eq!(decoder.next_packet(), Some(b"First".to_vec()));
        assert_eq!(decoder.next_packet(), Some(b"Second".to_vec()));
    }

    #[test]
    fn test_empty_packet() {
        let framed = frame_packet(b"");
        assert_eq!(framed.len(), FRAMING_HEADER_LEN);
        assert_eq!(framed, vec![0, 0]);

        let mut decoder = TcpFrameDecoder::new();
        decoder.extend_from_slice(&framed);
        assert_eq!(decoder.next_packet(), Some(vec![]));
    }

    #[test]
    #[should_panic(expected = "packet length")]
    fn test_frame_packet_too_large() {
        let huge = vec![0u8; MAX_FRAMED_PACKET_SIZE + 1];
        frame_packet(&huge);
    }

    #[test]
    fn test_decoder_clear() {
        let mut decoder = TcpFrameDecoder::new();
        decoder.extend_from_slice(&[0, 5, b'H']);

        assert_eq!(decoder.buffered_len(), 3);
        decoder.clear();
        assert!(decoder.is_empty());
    }
}

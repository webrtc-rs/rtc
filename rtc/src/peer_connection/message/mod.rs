//! WebRTC message types for media and data transport.
//!
//! This module defines the message types used to send and receive data through
//! WebRTC peer connections. In this sans-I/O library, messages represent the
//! application-level data that flows between peers, including media packets,
//! control information, and application data.
//!
//! # Message Types
//!
//! The primary type is [`RTCMessage`], which represents three kinds of data:
//!
//! - **RTP Packets** - Encoded media frames (audio/video)
//! - **RTCP Packets** - Media control and statistics
//! - **Data Channel Messages** - Application-defined data
//!
//! # Sans-I/O Architecture
//!
//! In a sans-I/O design, the library separates protocol logic from I/O operations:
//!
//! ```text
//! ┌──────────────────────────────────────┐
//! │      Application Logic               │
//! └────────────┬────────────┬────────────┘
//!              │            │
//!         Send │            │ Receive
//!    RTCMessage│            │RTCMessage
//!              ↓            ↑
//! ┌────────────────────────────────────┐
//! │   Peer Connection (sans-I/O)       │
//! │   - Protocol processing            │
//! │   - State management               │
//! └────────────┬────────────┬──────────┘
//!              │            │
//!      Network │            │ Network
//!        bytes │            │ bytes
//!              ↓            ↑
//! ┌────────────────────────────────────┐
//! │   I/O Layer (application-provided) │
//! │   - Sockets                        │
//! │   - Event loop                     │
//! └────────────────────────────────────┘
//! ```
//!
//! # Usage Pattern
//!
//! ## Sending Messages
//!
//! Applications create [`RTCMessage`] instances and pass them to the peer
//! connection for processing and transmission:
//!
//! ```no_run
//! use rtc::peer_connection::message::RTCMessage;
//! use rtc::media_stream::track::MediaStreamTrackId;
//!
//! # fn send_media(track_id: MediaStreamTrackId, rtp_packet: rtp::Packet) {
//! // Create a message
//! let message = RTCMessage::RtpPacket(track_id, rtp_packet);
//!
//! // Send through peer connection
//! // peer_connection.send_message(message)?;
//! # }
//! ```
//!
//! ## Receiving Messages
//!
//! Applications poll the peer connection for incoming messages and process
//! them based on type:
//!
//! ```no_run
//! use rtc::peer_connection::message::RTCMessage;
//!
//! # fn receive_messages(message: RTCMessage) {
//! match message {
//!     RTCMessage::RtpPacket(track_id, packet) => {
//!         // Decode and render media
//!         println!("Received media for track {:?}", track_id);
//!     }
//!     RTCMessage::RtcpPacket(track_id, packets) => {
//!         // Process statistics and feedback
//!         println!("Received {} RTCP packets", packets.len());
//!     }
//!     RTCMessage::DataChannelMessage(channel_id, msg) => {
//!         // Handle application data
//!         if msg.is_string {
//!             println!("Text message");
//!         } else {
//!             println!("Binary message");
//!         }
//!     }
//! }
//! # }
//! ```
//!
//! # Message Flow Examples
//!
//! ## Media Streaming
//!
//! ```no_run
//! use rtc::peer_connection::message::RTCMessage;
//! use rtc::media_stream::track::MediaStreamTrackId;
//!
//! # fn stream_media(track_id: MediaStreamTrackId) {
//! // Capture and encode media frame
//! // let encoded_frame = encode_audio_frame(...);
//! # let encoded_frame = vec![0u8; 100];
//!
//! // Create RTP packet
//! let rtp_packet = rtp::Packet {
//!     header: rtp::Header {
//!         version: 2,
//!         payload_type: 111,
//!         sequence_number: 1234,
//!         timestamp: 48000,
//!         ssrc: 0x12345678,
//!         ..Default::default()
//!     },
//!     payload: encoded_frame.into(),
//! };
//!
//! // Send media
//! let message = RTCMessage::RtpPacket(track_id, rtp_packet);
//! // peer_connection.send_message(message)?;
//! # }
//! ```
//!
//! ## Quality Monitoring
//!
//! ```no_run
//! use rtc::peer_connection::message::RTCMessage;
//!
//! # fn monitor_quality(message: RTCMessage) {
//! if let RTCMessage::RtcpPacket(track_id, packets) = message {
//!     for packet in packets {
//!         // Extract quality metrics from RTCP
//!         println!("RTCP packet type: {:?}", packet.header());
//!         // Process sender reports, receiver reports, etc.
//!     }
//! }
//! # }
//! ```
//!
//! ## Data Channel Communication
//!
//! ```no_run
//! use rtc::peer_connection::message::RTCMessage;
//! use rtc::data_channel::{RTCDataChannelId, RTCDataChannelMessage};
//! use bytes::BytesMut;
//!
//! # fn send_data(channel_id: RTCDataChannelId) {
//! // Send text
//! let text = RTCDataChannelMessage {
//!     is_string: true,
//!     data: BytesMut::from("Hello, peer!"),
//! };
//! let msg1 = RTCMessage::DataChannelMessage(channel_id, text);
//!
//! // Send binary
//! let binary = RTCDataChannelMessage {
//!     is_string: false,
//!     data: BytesMut::from(&[0xFF, 0xD8, 0xFF, 0xE0][..]), // JPEG header
//! };
//! let msg2 = RTCMessage::DataChannelMessage(channel_id, binary);
//! # }
//! ```
//!
//! # Message Processing
//!
//! ## Filtering Messages by Type
//!
//! ```no_run
//! use rtc::peer_connection::message::RTCMessage;
//!
//! fn process_messages(messages: Vec<RTCMessage>) {
//!     // Process only media messages
//!     for msg in messages.iter() {
//!         if matches!(msg, RTCMessage::RtpPacket(_, _)) {
//!             println!("Processing media packet");
//!         }
//!     }
//!
//!     // Process only data channel messages
//!     for msg in messages.iter() {
//!         if let RTCMessage::DataChannelMessage(id, data) = msg {
//!             println!("Data on channel {}: {} bytes", id, data.data.len());
//!         }
//!     }
//! }
//! ```
//!
//! ## Batching Messages
//!
//! ```no_run
//! use rtc::peer_connection::message::RTCMessage;
//! use rtc::media_stream::track::MediaStreamTrackId;
//!
//! # fn batch_send(track_id: MediaStreamTrackId, packets: Vec<rtp::Packet>) {
//! // Send multiple packets efficiently
//! let messages: Vec<RTCMessage> = packets
//!     .into_iter()
//!     .map(|packet| RTCMessage::RtpPacket(track_id.clone(), packet))
//!     .collect();
//!
//! // for msg in messages {
//! //     peer_connection.send_message(msg)?;
//! // }
//! # }
//! ```
//!
//! # Performance Considerations
//!
//! - **Zero-copy**: Messages use `BytesMut` for efficient memory handling
//! - **Batching**: Send multiple messages together to reduce overhead
//! - **Prioritization**: Applications can prioritize data channel messages over media
//!
//! # Specifications
//!
//! - [RFC 3550] - RTP: Real-time Transport Protocol
//! - [RFC 3551] - RTP Profile for Audio and Video
//! - [RFC 3711] - SRTP: Secure Real-time Transport Protocol
//! - [RFC 8831] - WebRTC Data Channels
//! - [W3C WebRTC] - Web Real-Time Communications
//!
//! [RFC 3550]: https://datatracker.ietf.org/doc/html/rfc3550
//! [RFC 3551]: https://datatracker.ietf.org/doc/html/rfc3551
//! [RFC 3711]: https://datatracker.ietf.org/doc/html/rfc3711
//! [RFC 8831]: https://datatracker.ietf.org/doc/html/rfc8831
//! [W3C WebRTC]: https://w3c.github.io/webrtc-pc/

use crate::data_channel::RTCDataChannelId;
use crate::data_channel::message::RTCDataChannelMessage;
use crate::media_stream::track::MediaStreamTrackId;

pub(crate) mod internal;

/// Messages that can be sent or received through a peer connection.
///
/// `RTCMessage` represents the different types of messages that flow through
/// a WebRTC connection in this sans-I/O library. Applications use these messages
/// to send and receive media data (RTP), control information (RTCP), and
/// application data (data channels).
///
/// # Message Types
///
/// - **RTP Packets** - Media data (audio/video frames)
/// - **RTCP Packets** - Control information (statistics, feedback)
/// - **Data Channel Messages** - Application data (text, binary)
///
/// # Usage Pattern
///
/// In a sans-I/O architecture, messages are:
///
/// 1. **Outgoing**: Created by the application and passed to the peer connection
/// 2. **Incoming**: Retrieved from the peer connection after processing network data
///
/// # Examples
///
/// ## Sending RTP Media
///
/// ```no_run
/// use rtc::peer_connection::message::RTCMessage;
/// use rtc::media_stream::track::MediaStreamTrackId;
///
/// # fn example(track_id: MediaStreamTrackId, rtp_packet: rtp::Packet) {
/// // Create an RTP message for a specific track
/// let message = RTCMessage::RtpPacket(track_id, rtp_packet);
///
/// // Send through peer connection (sans-I/O)
/// // peer_connection.send_message(message)?;
/// # }
/// ```
///
/// ## Sending RTCP Feedback
///
/// ```no_run
/// use rtc::peer_connection::message::RTCMessage;
/// use rtc::media_stream::track::MediaStreamTrackId;
///
/// # fn example(track_id: MediaStreamTrackId, rtcp_packets: Vec<Box<dyn rtcp::Packet>>) {
/// // Create an RTCP message with control packets
/// let message = RTCMessage::RtcpPacket(track_id, rtcp_packets);
///
/// // Send through peer connection
/// // peer_connection.send_message(message)?;
/// # }
/// ```
///
/// ## Sending Data Channel Message
///
/// ```no_run
/// use rtc::peer_connection::message::RTCMessage;
/// use rtc::data_channel::{RTCDataChannelId, RTCDataChannelMessage};
/// use bytes::BytesMut;
///
/// # fn example(channel_id: RTCDataChannelId) -> Result<(), Box<dyn std::error::Error>> {
/// // Create a text message
/// let text_msg = RTCDataChannelMessage {
///     is_string: true,
///     data: BytesMut::from("Hello, WebRTC!"),
/// };
/// let message = RTCMessage::DataChannelMessage(channel_id, text_msg);
///
/// // Or create a binary message
/// let binary_msg = RTCDataChannelMessage {
///     is_string: false,
///     data: BytesMut::from(&[0x01, 0x02, 0x03, 0x04][..]),
/// };
/// let message2 = RTCMessage::DataChannelMessage(channel_id, binary_msg);
/// # Ok(())
/// # }
/// ```
///
/// ## Processing Incoming Messages
///
/// ```no_run
/// use rtc::peer_connection::message::RTCMessage;
///
/// # fn handle_message(message: RTCMessage) {
/// match message {
///     RTCMessage::RtpPacket(track_id, rtp_packet) => {
///         println!("Received RTP for track {:?}", track_id);
///         // Process media packet (decode, render, etc.)
///     }
///     RTCMessage::RtcpPacket(track_id, rtcp_packets) => {
///         println!("Received {} RTCP packet(s) for track {:?}",
///                  rtcp_packets.len(), track_id);
///         // Process control information
///     }
///     RTCMessage::DataChannelMessage(channel_id, data) => {
///         println!("Received data on channel {}", channel_id);
///         // Process application data
///     }
/// }
/// # }
/// ```
///
/// ## Filtering by Message Type
///
/// ```no_run
/// use rtc::peer_connection::message::RTCMessage;
///
/// fn is_media_message(message: &RTCMessage) -> bool {
///     matches!(message, RTCMessage::RtpPacket(_, _) | RTCMessage::RtcpPacket(_, _))
/// }
///
/// fn is_data_message(message: &RTCMessage) -> bool {
///     matches!(message, RTCMessage::DataChannelMessage(_, _))
/// }
///
/// # fn example(message: RTCMessage) {
/// if is_media_message(&message) {
///     // Handle media
/// } else if is_data_message(&message) {
///     // Handle data
/// }
/// # }
/// ```
///
/// ## Extracting Message Content
///
/// ```no_run
/// use rtc::peer_connection::message::RTCMessage;
/// use rtc::media_stream::track::MediaStreamTrackId;
///
/// # fn example(message: RTCMessage) {
/// match message {
///     RTCMessage::RtpPacket(track_id, packet) => {
///         println!("RTP sequence: {}, timestamp: {}",
///                  packet.header.sequence_number,
///                  packet.header.timestamp);
///     }
///     RTCMessage::RtcpPacket(track_id, packets) => {
///         for packet in packets {
///             println!("RTCP packet type: {:?}", packet.header());
///         }
///     }
///     RTCMessage::DataChannelMessage(channel_id, msg) => {
///         if msg.is_string {
///             let text = String::from_utf8_lossy(&msg.data);
///             println!("Text: {}", text);
///         } else {
///             println!("Binary: {} bytes", msg.data.len());
///         }
///     }
/// }
/// # }
/// ```
///
/// # Message Flow
///
/// ```text
/// Application Layer
///       ↓ (send)          ↑ (receive)
/// RTCMessage variants
///       ↓                 ↑
/// Peer Connection (sans-I/O processing)
///       ↓                 ↑
/// Network Layer
/// ```
///
/// # Specifications
///
/// - [RFC 3550] - RTP: Real-time Transport Protocol
/// - [RFC 3551] - RTP Profile for Audio and Video
/// - [RFC 3711] - SRTP: Secure Real-time Transport Protocol
/// - [RFC 8831] - WebRTC Data Channels
///
/// [RFC 3550]: https://datatracker.ietf.org/doc/html/rfc3550
/// [RFC 3551]: https://datatracker.ietf.org/doc/html/rfc3551
/// [RFC 3711]: https://datatracker.ietf.org/doc/html/rfc3711
/// [RFC 8831]: https://datatracker.ietf.org/doc/html/rfc8831
#[derive(Debug, Clone)]
pub enum RTCMessage {
    /// RTP packet for a specific media track.
    ///
    /// Contains media data (encoded audio or video). Each RTP packet includes:
    ///
    /// - **Track ID**: Identifies which media track this packet belongs to
    /// - **RTP Packet**: Contains sequence number, timestamp, payload type, and encoded media data
    ///
    /// # Fields
    ///
    /// - `MediaStreamTrackId` - The track this packet belongs to
    /// - `rtp::Packet` - The RTP packet with header and payload
    ///
    /// # Use Cases
    ///
    /// - **Sending**: Encode media frames and send as RTP packets
    /// - **Receiving**: Decode RTP packets and render media
    /// - **Processing**: Analyze sequence numbers for packet loss detection
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rtc::peer_connection::message::RTCMessage;
    /// use rtc::media_stream::track::MediaStreamTrackId;
    ///
    /// # fn example(track_id: MediaStreamTrackId, rtp_packet: rtp::Packet) {
    /// let message = RTCMessage::RtpPacket(track_id, rtp_packet);
    ///
    /// if let RTCMessage::RtpPacket(tid, packet) = message {
    ///     println!("Track: {:?}, Sequence: {}", tid, packet.header.sequence_number);
    /// }
    /// # }
    /// ```
    RtpPacket(MediaStreamTrackId, rtp::Packet),

    /// RTCP packet(s) for a specific media track.
    ///
    /// Contains control information about media transmission. RTCP packets include:
    ///
    /// - **Sender Reports (SR)**: Statistics from media senders
    /// - **Receiver Reports (RR)**: Statistics from media receivers
    /// - **Source Description (SDES)**: Additional source information
    /// - **Bye**: Indicates participant is leaving
    /// - **Application-defined**: Custom RTCP packets
    ///
    /// # Fields
    ///
    /// - `MediaStreamTrackId` - The track these packets relate to
    /// - `Vec<Box<dyn rtcp::Packet>>` - One or more RTCP packets
    ///
    /// # Use Cases
    ///
    /// - **Monitoring**: Track quality metrics (packet loss, jitter)
    /// - **Feedback**: Send NACK/PLI for lost/corrupted packets
    /// - **Statistics**: Report transmission statistics
    ///
    /// # Note
    ///
    /// Multiple RTCP packets can be combined into a single compound RTCP message
    /// for efficiency.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rtc::peer_connection::message::RTCMessage;
    /// use rtc::media_stream::track::MediaStreamTrackId;
    ///
    /// # fn example(track_id: MediaStreamTrackId, rtcp_packets: Vec<Box<dyn rtcp::Packet>>) {
    /// let message = RTCMessage::RtcpPacket(track_id, rtcp_packets);
    ///
    /// if let RTCMessage::RtcpPacket(tid, packets) = message {
    ///     println!("Track: {:?}, RTCP packets: {}", tid, packets.len());
    /// }
    /// # }
    /// ```
    RtcpPacket(MediaStreamTrackId, Vec<Box<dyn rtcp::Packet>>),

    /// Data channel message.
    ///
    /// Contains application-defined data sent over a data channel. Messages can be:
    ///
    /// - **Text**: UTF-8 encoded strings
    /// - **Binary**: Arbitrary byte arrays
    ///
    /// # Fields
    ///
    /// - `RTCDataChannelId` - The data channel this message belongs to
    /// - `RTCDataChannelMessage` - The message content (text or binary)
    ///
    /// # Use Cases
    ///
    /// - **Signaling**: Send application-level control messages
    /// - **File Transfer**: Send file data in chunks
    /// - **Game State**: Send game updates in real-time
    /// - **Chat**: Send text messages between peers
    ///
    /// # Message Ordering and Reliability
    ///
    /// Depends on data channel configuration:
    ///
    /// - **Reliable & Ordered**: Messages arrive in order, guaranteed
    /// - **Unreliable & Unordered**: Like UDP, may arrive out of order or not at all
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rtc::peer_connection::message::RTCMessage;
    /// use rtc::data_channel::{RTCDataChannelId, RTCDataChannelMessage};
    /// use bytes::BytesMut;
    ///
    /// # fn example(channel_id: RTCDataChannelId) {
    /// // Text message
    /// let text_msg = RTCDataChannelMessage {
    ///     is_string: true,
    ///     data: BytesMut::from("Hello!"),
    /// };
    /// let message = RTCMessage::DataChannelMessage(channel_id, text_msg);
    ///
    /// // Binary message
    /// let binary_msg = RTCDataChannelMessage {
    ///     is_string: false,
    ///     data: BytesMut::from(&[1, 2, 3, 4][..]),
    /// };
    /// let message2 = RTCMessage::DataChannelMessage(channel_id, binary_msg);
    /// # }
    /// ```
    DataChannelMessage(RTCDataChannelId, RTCDataChannelMessage),
}

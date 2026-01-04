//! # RTC - Sans-I/O WebRTC Implementation
//!
//! A Rust implementation of the [WebRTC specification](https://www.w3.org/TR/webrtc/) using a
//! **sans-I/O architecture**. This crate provides full WebRTC functionality while giving you
//! complete control over networking, threading, and async runtime integration.
//!
//! ## What is Sans-I/O?
//!
//! Sans-I/O (without I/O) is a design pattern that separates protocol logic from I/O operations.
//! Instead of the library performing network reads and writes directly, **you** provide the
//! network data and handle the output. This gives you:
//!
//! - **Runtime Independence**: Works with tokio, async-std, smol, or blocking I/O
//! - **Full Control**: You control threading, scheduling, and I/O multiplexing
//! - **Testability**: Protocol logic can be tested without real network I/O
//! - **Flexibility**: Easy integration with existing networking code
//!
//! ## Quick Start
//!
//! ```no_run
//! use rtc::peer_connection::RTCPeerConnection;
//! use rtc::peer_connection::configuration::RTCConfigurationBuilder;
//! use rtc::peer_connection::transport::RTCIceServer;
//! use rtc::peer_connection::sdp::RTCSessionDescription;
//! use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Create a peer connection with ICE servers
//! let config = RTCConfigurationBuilder::new()
//!     .with_ice_servers(vec![RTCIceServer {
//!         urls: vec!["stun:stun.l.google.com:19302".to_string()],
//!         ..Default::default()
//!     }])
//!     .build();
//!
//! let mut pc = RTCPeerConnection::new(config)?;
//!
//! // 2. Create an offer
//! let offer = pc.create_offer(None)?;
//! pc.set_local_description(offer.clone())?;
//!
//! // Send offer to remote peer via your signaling channel
//! // signaling.send(offer.sdp)?;
//!
//! // 3. Receive answer from remote peer
//! // let answer_sdp = signaling.receive()?;
//! # let answer_sdp = String::new();
//! let answer = RTCSessionDescription::answer(answer_sdp)?;
//! pc.set_remote_description(answer)?;
//!
//! // 4. Add local ICE candidate
//! # use std::net::{IpAddr, Ipv4Addr};
//! let candidate = CandidateHostConfig {
//!     base_config: CandidateConfig {
//!         network: "udp".to_owned(),
//!         address: "192.168.1.100".to_string(),
//!         port: 8080,
//!         component: 1,
//!         ..Default::default()
//!     },
//!     ..Default::default()
//! }
//! .new_candidate_host()?;
//! let local_candidate_init = RTCIceCandidate::from(&candidate).to_json()?;
//! pc.add_local_candidate(local_candidate_init)?;
//!
//! // 5. Event loop - see complete example below
//! # Ok(())
//! # }
//! ```
//!
//! ## Complete Event Loop with All API Calls
//!
//! This example demonstrates the full sans-I/O event loop pattern with all key API methods:
//!
//! ```no_run
//! use rtc::peer_connection::RTCPeerConnection;
//! use rtc::peer_connection::configuration::{RTCConfigurationBuilder, media_engine::MediaEngine};
//! use rtc::peer_connection::transport::RTCIceServer;
//! use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
//! use rtc::peer_connection::state::{RTCPeerConnectionState, RTCIceConnectionState};
//! use rtc::peer_connection::message::RTCMessage;
//! use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
//! use rtc::sansio::Protocol;
//! use std::time::{Duration, Instant};
//! use tokio::net::UdpSocket;
//! use bytes::BytesMut;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure media codecs
//! let media_engine = MediaEngine::default();
//!
//! // Create peer connection configuration
//! let config = RTCConfigurationBuilder::new()
//!     .with_ice_servers(vec![RTCIceServer {
//!         urls: vec!["stun:stun.l.google.com:19302".to_string()],
//!         ..Default::default()
//!     }])
//!     .with_media_engine(media_engine)
//!     .build();
//!
//! let mut pc = RTCPeerConnection::new(config)?;
//!
//! // Bind UDP socket for network I/O
//! let socket = UdpSocket::bind("0.0.0.0:0").await?;
//! let local_addr = socket.local_addr()?;
//!
//! let mut buf = vec![0u8; 2000];
//! const DEFAULT_TIMEOUT: Duration = Duration::from_secs(86400);
//!
//! // Main event loop
//! loop {
//!     // 1. poll_write() - Get outgoing network packets
//!     while let Some(msg) = pc.poll_write() {
//!         socket.send_to(&msg.message, msg.transport.peer_addr).await?;
//!     }
//!
//!     // 2. poll_event() - Process connection state changes and events
//!     while let Some(event) = pc.poll_event() {
//!         match event {
//!             RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
//!                 println!("ICE Connection State: {state}");
//!                 if state == RTCIceConnectionState::Failed {
//!                     break;
//!                 }
//!             }
//!             RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
//!                 println!("Connection State: {state}");
//!                 if state == RTCPeerConnectionState::Failed {
//!                     return Ok(());
//!                 }
//!             }
//!             RTCPeerConnectionEvent::OnDataChannel(dc_event) => {
//!                 println!("Data channel event: {:?}", dc_event);
//!             }
//!             RTCPeerConnectionEvent::OnTrack(track_event) => {
//!                 match track_event {
//!                     RTCTrackEvent::OnOpen(init) => {
//!                         println!("Track opened: track_id={}, receiver_id={:?}",
//!                             init.track_id, init.receiver_id);
//!                     }
//!                     RTCTrackEvent::OnClose(track_id) => {
//!                         println!("Track closed: {track_id}");
//!                     }
//!                     _ => {}
//!                 }
//!             }
//!             _ => {}
//!         }
//!     }
//!
//!     // 3. poll_read() - Get incoming application messages (RTP/RTCP/data)
//!     while let Some(message) = pc.poll_read() {
//!         match message {
//!             RTCMessage::RtpPacket(track_id, rtp_packet) => {
//!                 println!("Received RTP packet on track {track_id}");
//!                 // Process RTP packet
//!             }
//!             RTCMessage::RtcpPacket(receiver_id, rtcp_packets) => {
//!                 println!("Received RTCP packets on receiver {:?}", receiver_id);
//!                 // Process RTCP packets
//!             }
//!             RTCMessage::DataChannelMessage(channel_id, message) => {
//!                 println!("Received data channel message on channel {:?}", channel_id);
//!                 // Process data channel message
//!             }
//!         }
//!     }
//!
//!     // 4. poll_timeout() - Get next timer deadline
//!     let timeout = pc.poll_timeout()
//!         .unwrap_or(Instant::now() + DEFAULT_TIMEOUT);
//!     let delay = timeout.saturating_duration_since(Instant::now());
//!
//!     // Handle immediate timeout
//!     if delay.is_zero() {
//!         // 6. handle_timeout() - Notify about timer expiration
//!         pc.handle_timeout(Instant::now())?;
//!         continue;
//!     }
//!
//!     // Wait for events using tokio::select!
//!     let timer = tokio::time::sleep(delay);
//!     tokio::pin!(timer);
//!
//!     tokio::select! {
//!         biased;
//!
//!         // Timer expired
//!         _ = timer => {
//!             pc.handle_timeout(Instant::now())?;
//!         }
//!         // Received network packet
//!         Ok((n, peer_addr)) = socket.recv_from(&mut buf) => {
//!             // 5. handle_read() - Feed incoming network packets
//!             pc.handle_read(TaggedBytesMut {
//!                 now: Instant::now(),
//!                 transport: TransportContext {
//!                     local_addr,
//!                     peer_addr,
//!                     ecn: None,
//!                     transport_protocol: TransportProtocol::UDP,
//!                 },
//!                 message: BytesMut::from(&buf[..n]),
//!             })?;
//!         }
//!         // Ctrl-C to exit
//!         _ = tokio::signal::ctrl_c() => {
//!             break;
//!         }
//!     }
//! }
//!
//! pc.close()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Core API Methods
//!
//! ### Sans-I/O Event Loop Methods
//!
//! The event loop uses these six core methods:
//!
//! 1. **`poll_write()`** - Get outgoing network packets to send via UDP
//! 2. **`poll_event()`** - Process connection state changes and notifications
//! 3. **`poll_read()`** - Get incoming application messages (RTP, RTCP, data)
//! 4. **`poll_timeout()`** - Get next timer deadline for retransmissions/keepalives
//! 5. **`handle_read()`** - Feed incoming network packets into the connection
//! 6. **`handle_timeout()`** - Notify about timer expiration
//!
//! Additional methods for external control:
//!
//! - **`handle_write()`** - Queue application messages (RTP/RTCP/data) for sending
//! - **`handle_event()`** - Inject external events into the connection
//!
//! ### Signaling with Complete Example
//!
//! WebRTC requires an external signaling channel to exchange offers, answers, and ICE
//! candidates. This example shows the complete offer/answer flow:
//!
//! ```no_run
//! use rtc::peer_connection::RTCPeerConnection;
//! use rtc::peer_connection::configuration::RTCConfigurationBuilder;
//! use rtc::peer_connection::transport::RTCIceServer;
//! use rtc::peer_connection::sdp::RTCSessionDescription;
//! use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
//!
//! # fn send_to_remote_peer(_: &str) {}
//! # fn receive_from_remote_peer() -> String { String::new() }
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Offerer side - creates the offer
//! let config = RTCConfigurationBuilder::new()
//!     .with_ice_servers(vec![RTCIceServer {
//!         urls: vec!["stun:stun.l.google.com:19302".to_string()],
//!         ..Default::default()
//!     }])
//!     .build();
//!
//! let mut offerer = RTCPeerConnection::new(config.clone())?;
//!
//! // 1. Create offer
//! let offer = offerer.create_offer(None)?;
//!
//! // 2. Set local description
//! offerer.set_local_description(offer.clone())?;
//!
//! // 3. Add local ICE candidate
//! let candidate = CandidateHostConfig {
//!     base_config: CandidateConfig {
//!         network: "udp".to_owned(),
//!         address: "192.168.1.100".to_string(),
//!         port: 8080,
//!         component: 1,
//!         ..Default::default()
//!     },
//!     ..Default::default()
//! }
//! .new_candidate_host()?;
//! offerer.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;
//!
//! // 4. Send offer to remote peer (your signaling channel)
//! send_to_remote_peer(&serde_json::to_string(&offer)?);
//!
//! // --- On answerer side ---
//! let mut answerer = RTCPeerConnection::new(config)?;
//!
//! // 5. Receive and set remote description
//! let offer_json = receive_from_remote_peer();
//! let remote_offer: RTCSessionDescription = serde_json::from_str(&offer_json)?;
//! answerer.set_remote_description(remote_offer)?;
//!
//! // 6. Create answer
//! let answer = answerer.create_answer(None)?;
//!
//! // 7. Set local description
//! answerer.set_local_description(answer.clone())?;
//!
//! // 8. Send answer back to offerer
//! send_to_remote_peer(&serde_json::to_string(&answer)?);
//!
//! // --- Back on offerer side ---
//! // 9. Receive and set remote description
//! let answer_json = receive_from_remote_peer();
//! let remote_answer: RTCSessionDescription = serde_json::from_str(&answer_json)?;
//! offerer.set_remote_description(remote_answer)?;
//!
//! // Now both peers are connected!
//! # Ok(())
//! # }
//! ```
//!
//! ## Module Organization
//!
//! ### [`peer_connection`]
//!
//! Core WebRTC peer connection implementation:
//!
//! - **[`RTCPeerConnection`](peer_connection::RTCPeerConnection)** - Peer connection interface
//! - **[`certificate`](peer_connection::certificate)** - Peer connection certficiate
//! - **[`configuration`](peer_connection::configuration)** - Peer connection configuration
//! - **[`event`](peer_connection::event)** - Peer connection events
//! - **[`message`](peer_connection::message)** - RTP/RTCP Packets and Application messages
//! - **[`sdp`](peer_connection::sdp)** - SDP offer/answer types
//! - **[`state`](peer_connection::state)** - Peer connection state types
//! - **[`transport`](peer_connection::transport)** - ICE, DTLS, SCTP transport types
//!
//! ### [`data_channel`]
//!
//! WebRTC data channels for arbitrary data transfer:
//!
//! - **[`RTCDataChannel`](data_channel::RTCDataChannel)** - Data channel interface
//! - **[`RTCDataChannelInit`](data_channel::RTCDataChannelInit)** - Channel configuration
//! - **[`RTCDataChannelMessage`](data_channel::RTCDataChannelMessage)** - Data channel messages
//!
//! ### [`rtp_transceiver`]
//!
//! RTP media transmission and reception:
//!
//! - **[`RTCRtpSender`](rtp_transceiver::rtp_sender::RTCRtpSender)** - Media sender
//! - **[`RTCRtpReceiver`](rtp_transceiver::rtp_receiver::RTCRtpReceiver)** - Media receiver
//!
//! ### [`media_stream`]
//!
//! Media track management:
//!
//! - **[`MediaStreamTrack`](media_stream::track::MediaStreamTrack)** - Audio/video track
//!
//! ## Features
//!
//! - ✅ **ICE (Interactive Connectivity Establishment)** - NAT traversal with STUN/TURN
//! - ✅ **DTLS (Datagram Transport Layer Security)** - Encryption for media and data
//! - ✅ **SCTP (Stream Control Transmission Protocol)** - Reliable data channels
//! - ✅ **RTP/RTCP** - Real-time media transport and control
//! - ✅ **SDP (Session Description Protocol)** - Offer/answer negotiation
//! - ✅ **Data Channels** - Bidirectional peer-to-peer data transfer
//! - ✅ **Media Tracks** - Audio/video transmission
//! - ✅ **Trickle ICE** - Progressive candidate gathering
//! - ✅ **ICE Restart** - Connection recovery
//! - ✅ **Simulcast & SVC** - Scalable video coding
//!
//! ## Working Examples
//!
//! The crate includes comprehensive examples in the `examples/` directory:
//!
//! - **data-channels-offer-answer** - Complete data channel setup with signaling
//! - **save-to-disk-vpx** - Receive and save VP8/VP9 video to disk
//! - **play-from-disk-vpx** - Send VP8/VP9 video from disk
//! - **rtp-forwarder** - Forward RTP streams between peers
//! - **simulcast** - Multiple quality streams
//! - **trickle-ice** - Progressive ICE candidate exchange
//!
//! See the `examples/` directory for complete, runnable code.
//!
//! ## Common Patterns
//!
//! ### Creating and Using Data Channels
//!
//! ```no_run
//! use rtc::peer_connection::RTCPeerConnection;
//! use rtc::peer_connection::configuration::RTCConfiguration;
//! use rtc::data_channel::RTCDataChannelInit;
//! use rtc::peer_connection::event::RTCPeerConnectionEvent;
//! use rtc::peer_connection::message::RTCMessage;
//! use rtc::sansio::Protocol;
//! use bytes::BytesMut;
//!
//! # fn example(mut pc: RTCPeerConnection) -> Result<(), Box<dyn std::error::Error>> {
//! // Create data channel with ordered, reliable delivery
//! let init = RTCDataChannelInit {
//!     ordered: true,
//!     max_retransmits: None,
//!     ..Default::default()
//! };
//!
//! let mut dc = pc.create_data_channel("my-channel", Some(init))?;
//! let channel_id = dc.id();
//!
//! // Send text message
//! dc.send_text("Hello, WebRTC!")?;
//!
//! // Send binary message
//! dc.send(BytesMut::from(&[0x01, 0x02, 0x03, 0x04][..]))?;
//!
//! // Later, retrieve the data channel by ID
//! if let Some(mut dc) = pc.data_channel(channel_id) {
//!     dc.send_text("Another message")?;
//! }
//!
//! // Receive messages in event loop
//! while let Some(message) = pc.poll_read() {
//!     if let RTCMessage::DataChannelMessage(channel_id, msg) = message {
//!         if msg.is_string {
//!             let text = String::from_utf8_lossy(&msg.data);
//!             println!("Received text: {text}");
//!         } else {
//!             println!("Received binary: {} bytes", msg.data.len());
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Adding Media Tracks with Codecs
//!
//! ```no_run
//! use rtc::peer_connection::RTCPeerConnection;
//! use rtc::media_stream::MediaStreamTrack;
//! use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};
//! use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MIME_TYPE_OPUS};
//!
//! # fn example(mut pc: RTCPeerConnection) -> Result<(), Box<dyn std::error::Error>> {
//! // Configure VP8 video codec
//! let video_codec = RTCRtpCodecParameters {
//!     rtp_codec: RTCRtpCodec {
//!         mime_type: MIME_TYPE_VP8.to_owned(),
//!         clock_rate: 90000,
//!         channels: 0,
//!         sdp_fmtp_line: "".to_owned(),
//!         rtcp_feedback: vec![],
//!     },
//!     payload_type: 96,
//!     ..Default::default()
//! };
//!
//! // Create video track
//! let video_track = MediaStreamTrack::new(
//!     "stream-id".to_string(),
//!     "video-track-id".to_string(),
//!     "video-label".to_string(),
//!     RtpCodecKind::Video,
//!     None,                  // rid (for simulcast)
//!     rand::random::<u32>(), // ssrc
//!     video_codec.rtp_codec.clone(),
//! );
//!
//! // Add track to peer connection
//! let sender_id = pc.add_track(video_track)?;
//!
//! // Send RTP packets
//! if let Some(mut sender) = pc.rtp_sender(sender_id) {
//!     // sender.write_rtp(rtp_packet)?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Receiving Media Tracks
//!
//! ```no_run
//! use rtc::peer_connection::RTCPeerConnection;
//! use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
//! use rtc::peer_connection::message::RTCMessage;
//! use rtc::sansio::Protocol;
//! use std::collections::HashMap;
//!
//! # fn example(mut pc: RTCPeerConnection) -> Result<(), Box<dyn std::error::Error>> {
//! // Track mapping for received tracks
//! let mut track_to_receiver = HashMap::new();
//!
//! // Handle track events
//! while let Some(event) = pc.poll_event() {
//!     if let RTCPeerConnectionEvent::OnTrack(track_event) = event {
//!         match track_event {
//!             RTCTrackEvent::OnOpen(init) => {
//!                 println!("New track: track_id={}, receiver_id={:?}",
//!                     init.track_id, init.receiver_id);
//!                 track_to_receiver.insert(init.track_id.clone(), init.receiver_id);
//!             }
//!             RTCTrackEvent::OnClose(track_id) => {
//!                 println!("Track closed: {track_id}");
//!                 track_to_receiver.remove(&track_id);
//!             }
//!             _ => {}
//!         }
//!     }
//! }
//!
//! // Receive RTP packets
//! while let Some(message) = pc.poll_read() {
//!     if let RTCMessage::RtpPacket(track_id, rtp_packet) = message {
//!         println!("RTP packet on track {}: {} bytes",
//!             track_id, rtp_packet.payload.len());
//!         
//!         // Access receiver to get track metadata
//!         if let Some(&receiver_id) = track_to_receiver.get(&track_id) {
//!             if let Some(receiver) = pc.rtp_receiver(receiver_id) {
//!                 if let Ok(Some(track)) = receiver.track(&track_id) {
//!                     println!("  SSRC: {}, Kind: {:?}", track.ssrc(), track.kind());
//!                 }
//!             }
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Sending RTCP Packets (e.g., PLI for keyframes)
//!
//! ```no_run
//! use rtc::peer_connection::RTCPeerConnection;
//! use rtc::rtp_transceiver::RTCRtpReceiverId;
//! use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
//!
//! # fn example(mut pc: RTCPeerConnection, receiver_id: RTCRtpReceiverId, media_ssrc: u32)
//! #     -> Result<(), Box<dyn std::error::Error>> {
//! // Request keyframe by sending Picture Loss Indication (PLI)
//! if let Some(mut receiver) = pc.rtp_receiver(receiver_id) {
//!     receiver.write_rtcp(vec![Box::new(PictureLossIndication {
//!         sender_ssrc: 0,
//!         media_ssrc,
//!     })])?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Specification Compliance
//!
//! This implementation follows these specifications:
//!
//! - [W3C WebRTC 1.0] - Main WebRTC API specification
//! - [RFC 8829] - JSEP: JavaScript Session Establishment Protocol  
//! - [RFC 8866] - SDP: Session Description Protocol
//! - [RFC 8445] - ICE: Interactive Connectivity Establishment
//! - [RFC 6347] - DTLS: Datagram Transport Layer Security
//! - [RFC 8831] - WebRTC Data Channels
//! - [RFC 3550] - RTP: Real-time Transport Protocol
//!
//! [W3C WebRTC 1.0]: https://www.w3.org/TR/webrtc/
//! [RFC 8829]: https://datatracker.ietf.org/doc/html/rfc8829
//! [RFC 8866]: https://datatracker.ietf.org/doc/html/rfc8866
//! [RFC 8445]: https://datatracker.ietf.org/doc/html/rfc8445
//! [RFC 6347]: https://datatracker.ietf.org/doc/html/rfc6347
//! [RFC 8831]: https://datatracker.ietf.org/doc/html/rfc8831
//! [RFC 3550]: https://datatracker.ietf.org/doc/html/rfc3550
//!
//! ## Further Reading
//!
//! - [Sans-I/O Approach](https://sans-io.readthedocs.io/) - Detailed explanation of sans-I/O design
//! - [WebRTC for the Curious](https://webrtcforthecurious.com/) - Comprehensive WebRTC guide
//! - [MDN WebRTC API](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API) - Browser WebRTC documentation

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/rtc.png"
)]
#![warn(rust_2018_idioms)]
#![allow(dead_code)]

pub use {
    datachannel, dtls, ice, interceptor, mdns, media, rtcp, rtp, sansio, sctp, sdp, shared, srtp,
    stun, turn,
};

pub mod data_channel;
pub mod media_stream;
pub mod peer_connection;
pub mod rtp_transceiver;
pub mod statistics;

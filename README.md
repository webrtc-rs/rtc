<h1 align="center">
 <a href="https://webrtc.rs"><img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/rtc.png" alt="WebRTC.rs"></a>
 <br>
</h1>
<p align="center">
 <a href="https://github.com/webrtc-rs/rtc/actions">
  <img src="https://github.com/webrtc-rs/rtc/workflows/cargo/badge.svg">
 </a>
 <a href="https://deps.rs/repo/github/webrtc-rs/rtc">
  <img src="https://deps.rs/repo/github/webrtc-rs/rtc/status.svg">
 </a>
 <a href="https://crates.io/crates/rtc">
  <img src="https://img.shields.io/crates/v/rtc.svg">
 </a>
 <a href="https://docs.rs/rtc">
  <img src="https://docs.rs/rtc/badge.svg">
 </a>
 <a href="https://doc.rust-lang.org/1.6.0/complement-project-faq.html#why-dual-mitasl2-license">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
 </a>
 <a href="https://discord.gg/4Ju8UHdXMs">
  <img src="https://img.shields.io/discord/800204819540869120?logo=discord" alt="Discord">
 </a>
</p>
<p align="center">
 <strong>Sans-I/O WebRTC implementation in Rust</strong>
</p>

## Overview

**RTC** is a pure Rust implementation of [WebRTC](https://www.w3.org/TR/webrtc/) using a **sans-I/O architecture**.
Unlike traditional WebRTC libraries, RTC separates protocol logic from I/O operations, giving you complete control over
networking, threading, and async runtime integration.

### What is Sans-I/O?

Sans-I/O (without I/O) is a design pattern where the library handles protocol logic but **you** control all I/O
operations. Instead of the library performing network reads and writes directly, you feed it network data and it tells
you what to send.

**Benefits:**

- 🚀 **Runtime Independent** - Works with tokio, async-std, smol, or blocking I/O
- 🎯 **Full Control** - You control threading, scheduling, and I/O multiplexing
- 🧪 **Testable** - Protocol logic can be tested without real network I/O
- 🔌 **Flexible** - Easy integration with existing networking code

## Sans-I/O Event Loop Pattern

The sans-I/O architecture uses a simple event loop with eight core methods:

### Core API Methods

1. **`poll_write()`** - Get outgoing network packets to send via UDP
2. **`poll_event()`** - Process connection state changes and notifications
3. **`poll_read()`** - Get incoming application messages (RTP, RTCP, data)
4. **`poll_timeout()`** - Get next timer deadline for retransmissions/keepalives
5. **`handle_timeout()`** - Handle timeout event
6. **`handle_write()`** - Handle application messages (RTP, RTCP, data)
7. **`handle_event()`** - Handle user events
8. **`handle_read()`** - Handle incoming network packets

### Event Loop Example

```rust
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::sansio::Protocol;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use bytes::BytesMut;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup peer connection
    let config = RTCConfigurationBuilder::new().build();
    let mut pc = RTCPeerConnection::new(config)?;

    // Signaling: Create offer and set local description
    let offer = pc.create_offer(None)?;
    pc.set_local_description(offer.clone())?;

    // TODO: Send offer.sdp to remote peer via your signaling channel
    // signaling_channel.send_offer(&offer.sdp).await?;

    // TODO: Receive answer from remote peer via your signaling channel
    // let answer_sdp = signaling_channel.receive_answer().await?;
    // let answer = RTCSessionDescription::answer(answer_sdp)?;
    // pc.set_remote_description(answer)?;

    // Bind UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_addr = socket.local_addr()?;
    let mut buf = vec![0u8; 2000];

    'EventLoop: loop {
        // 1. Send outgoing packets
        while let Some(msg) = pc.poll_write() {
            socket.send_to(&msg.message, msg.transport.peer_addr).await?;
        }

        // 2. Handle events
        while let Some(event) = pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    println!("Connection state: {state}");
                    if state == RTCPeerConnectionState::Failed {
                        return Ok(());
                    }
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    println!("New track: {}", init.track_id);
                }
                _ => {}
            }
        }

        // 3. Handle incoming messages
        while let Some(message) = pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(track_id, packet) => {
                    println!("RTP packet on track {track_id}");
                }
                RTCMessage::DataChannelMessage(channel_id, msg) => {
                    println!("Data channel message");
                }
                _ => {}
            }
        }

        // 4. Handle timeouts
        let timeout = pc.poll_timeout()
            .unwrap_or(Instant::now() + Duration::from_secs(86400));
        let delay = timeout.saturating_duration_since(Instant::now());

        if delay.is_zero() {
            pc.handle_timeout(Instant::now())?;
            continue;
        }

        // 5. Multiplex I/O
        tokio::select! {
            _ = stop_rx.recv() => {
                break 'EventLoop,
            } 
            _ = tokio::time::sleep(delay) => {
                pc.handle_timeout(Instant::now())?;
            }
            Ok(message) = message_rx.recv() => {
                pc.handle_write(message)?;
            }
            Ok(event) = event_rx.recv() => {
                pc.handle_event(event)?;
            }
            Ok((n, peer_addr)) = socket.recv_from(&mut buf) => {
                pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&buf[..n]),
                })?;
            }
        }
    }

    pc.close()?;

    Ok(())
}
```

## Features

- ✅ **ICE** (Interactive Connectivity Establishment) - NAT traversal with STUN/TURN
- ✅ **DTLS** (Datagram Transport Layer Security) - Encryption for media and data
- ✅ **SCTP** (Stream Control Transmission Protocol) - Reliable data channels
- ✅ **RTP/RTCP** - Real-time media transport and control
- ✅ **SDP** (Session Description Protocol) - Offer/answer negotiation
- ✅ **Data Channels** - Bidirectional peer-to-peer data transfer
- ✅ **Media Tracks** - Audio/video transmission
- ✅ **Trickle ICE** - Progressive candidate gathering
- ✅ **Simulcast & SVC** - Scalable video coding

## More Examples

The repository includes comprehensive examples demonstrating various use cases:

- **[data-channels-offer-answer](examples/examples/data-channels-offer-answer/)** - Complete data channel setup with
  signaling
- **[reflect](examples/examples/reflect/)** - Echo server that reflects media back to sender
- **[save-to-disk-vpx](examples/examples/save-to-disk-vpx/)** - Receive and save VP8/VP9 video
- **[play-from-disk-vpx](examples/examples/play-from-disk-vpx/)** - Send VP8/VP9 video from disk

Run an example:

```bash
cargo run --example data-channels-offer --features examples
```

## Architecture

RTC is built from composable crates, each implementing a specific protocol:

## RTC Crates

<p align="center">
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/uncheck.png">RTC<a href="https://crates.io/crates/rtc"><img src="https://img.shields.io/crates/v/rtc.svg"></a>
    <br>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/uncheck.png">Media<a href="https://crates.io/crates/rtc-media"><img src="https://img.shields.io/crates/v/rtc-media.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/uncheck.png">Interceptor<a href="https://crates.io/crates/rtc-interceptor"><img src="https://img.shields.io/crates/v/rtc-interceptor.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/check.png">DataChannel<a href="https://crates.io/crates/rtc-datachannel"><img src="https://img.shields.io/crates/v/rtc-datachannel.svg"></a>
    <br>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/check.png">RTP<a href="https://crates.io/crates/rtc-rtp"><img src="https://img.shields.io/crates/v/rtc-rtp.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/check.png">RTCP<a href="https://crates.io/crates/rtc-rtcp"><img src="https://img.shields.io/crates/v/rtc-rtcp.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/check.png">SRTP<a href="https://crates.io/crates/rtc-srtp"><img src="https://img.shields.io/crates/v/rtc-srtp.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/check.png">SCTP<a href="https://crates.io/crates/rtc-sctp"><img src="https://img.shields.io/crates/v/rtc-sctp.svg"></a>
    <br>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/check.png">DTLS<a href="https://crates.io/crates/rtc-dtls"><img src="https://img.shields.io/crates/v/rtc-dtls.svg"></a>
    <br>
    <!--img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/uncheck.png">mDNS<a href="https://crates.io/crates/rtc-mdns"><img src="https://img.shields.io/crates/v/rtc-mdns.svg"></a-->
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/check.png">STUN<a href="https://crates.io/crates/rtc-stun"><img src="https://img.shields.io/crates/v/rtc-stun.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/check.png">TURN<a href="https://crates.io/crates/rtc-turn"><img src="https://img.shields.io/crates/v/rtc-turn.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/check.png">ICE<a href="https://crates.io/crates/rtc-ice"><img src="https://img.shields.io/crates/v/rtc-ice.svg"></a>
    <br>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/check.png">SDP<a href="https://crates.io/crates/rtc-sdp"><img src="https://img.shields.io/crates/v/rtc-sdp.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc/master/doc/check.png">Shared<a href="https://crates.io/crates/rtc-shared"><img src="https://img.shields.io/crates/v/rtc-shared.svg"></a>
</p>

### Dependency Graph

<p align="center">
 <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/rtc_crates_dep_graph.png" alt="RTC Crates Dependency Graph">
</p>

### Protocol Stack

<p align="center">
 <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/rtc_stack.png" alt="RTC Protocols Stack">
</p>

## Common Use Cases

### Data Channels

```rust
use rtc::data_channel::RTCDataChannelInit;

fn example(mut pc: RTCPeerConnection) -> Result<(), Box<dyn std::error::Error>> {
    // Create a data channel
    let init = RTCDataChannelInit {
        ordered: true,
        max_retransmits: None,
        ..Default::default()
    };
    let mut dc = pc.create_data_channel("my-channel", Some(init))?;

    // Send data
    dc.send_text("Hello, WebRTC!")?;
    Ok(())
}
```

### Media Tracks

```rust
use rtc::media_stream::MediaStreamTrack;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};

fn example(mut pc: RTCPeerConnection) -> Result<(), Box<dyn std::error::Error>> {
    // Create a video track
    let track = MediaStreamTrack::new(
        "stream-id".to_string(),
        "track-id".to_string(),
        "Camera".to_string(),
        RtpCodecKind::Video,
        None,
        12345, // SSRC
        RTCRtpCodec::default(),
    );

    // Add to peer connection
    let sender_id = pc.add_track(track)?;
    Ok(())
}
```

### Signaling

WebRTC requires an external signaling channel (e.g., WebSocket, HTTP) to exchange offers and answers:

```rust
fn example(mut pc: RTCPeerConnection) -> Result<(), Box<dyn std::error::Error>> {
    // Create and send offer
    let offer = pc.create_offer(None)?;
    pc.set_local_description(offer.clone())?;
    // Send offer.sdp via your signaling channel

    // Receive and apply answer
    // let answer = receive_answer_from_signaling()?;
    // pc.set_remote_description(answer)?;
    Ok(())
}
```

## Specification Compliance

This implementation follows these specifications:

- [W3C WebRTC 1.0](https://www.w3.org/TR/webrtc/) - Main WebRTC API specification
- [RFC 8829](https://datatracker.ietf.org/doc/html/rfc8829) - JSEP: JavaScript Session Establishment Protocol
- [RFC 8866](https://datatracker.ietf.org/doc/html/rfc8866) - SDP: Session Description Protocol
- [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445) - ICE: Interactive Connectivity Establishment
- [RFC 6347](https://datatracker.ietf.org/doc/html/rfc6347) - DTLS: Datagram Transport Layer Security
- [RFC 8831](https://datatracker.ietf.org/doc/html/rfc8831) - WebRTC Data Channels
- [RFC 3550](https://datatracker.ietf.org/doc/html/rfc3550) - RTP: Real-time Transport Protocol

## Documentation

- [API Documentation](https://docs.rs/rtc) - Complete API reference
- [Examples](examples/) - Working code examples
- [Sans-I/O Pattern](https://sans-io.readthedocs.io/) - Detailed explanation of the sans-I/O design
- [WebRTC for the Curious](https://webrtcforthecurious.com/) - Comprehensive WebRTC guide

## Building and Testing

```bash
# Build the library
cargo build

# Run tests
cargo test

# Build documentation
cargo doc --open

# Run examples
cargo run --example data-channels-offer --features examples
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

## Acknowledgments

Special thanks to all contributors and the WebRTC-rs community for making this project possible.

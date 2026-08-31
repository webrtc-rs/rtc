<h1 align="center">
 <a href="https://webrtc.rs"><img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/rtc.png" alt="WebRTC.rs"></a>
 <br>
</h1>
<p align="center">
 <a href="https://github.com/webrtc-rs/rtc/actions">
  <img src="https://github.com/webrtc-rs/rtc/workflows/cargo/badge.svg">
 </a>
 <a href="https://codecov.io/gh/webrtc-rs/rtc">
  <img src="https://codecov.io/gh/webrtc-rs/rtc/branch/master/graph/badge.svg">
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
 <a href="https://twitter.com/WebRTCrs">
  <img src="https://img.shields.io/twitter/url/https/twitter.com/webrtcrs.svg?style=social&label=%40WebRTCrs" alt="Twitter">
 </a>
</p>
<p align="center">
 <strong>Sans-I/O WebRTC implementation in Rust</strong>
</p>

<p align="center">
<strong>Sponsored with 💖 by</strong><br>
</p>
<p align="center">
<strong>Gold Sponsors:</strong><br>
<a href="https://www.recall.ai" target="_blank">
<img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/recall_md.svg"
alt="Recall.ai">
</a><br>
<p align="center">
<strong>Silver Sponsors:</strong><br>
<a href="https://getstream.io/video/voice-calling/?utm_source=https://github.com/webrtc-rs/webrtc&utm_medium=sponsorship&utm_content=&utm_campaign=webrtcRepo_July2023_video_klmh22" target="_blank">
<img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/stream-logo.png" height="50" alt="Stream Chat">
</a><br>
<a href="https://channel.io/" target="_blank">
<img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/ChannelTalk_logo_md.png" alt="ChannelTalk">
</a><br>
<strong>Bronze Sponsors:</strong><br>
<a href="https://github.com/AdrianEddy" target="_blank">AdrianEddy</a><br>
</p>


<details>
<summary><b>Table of Content</b></summary>

- [Overview](#overview)
- [Installation](#installation)
- [Sans-I/O Event Loop Pattern](#sans-io-event-loop-pattern)
- [Feeding ICE Candidates](#feeding-ice-candidates)
- [Back-Pressure](#back-pressure)
- [Features](#features)
- [What's New in 0.21](#whats-new-in-021)
- [Examples](#examples)
- [Architecture](#architecture)
- [Common Use Cases](#common-use-cases)
- [Specification Compliance](#specification-compliance)
- [Documentation](#documentation)
- [Building and Testing](#building-and-testing)
- [Semantic Versioning](#semantic-versioning)
- [Contributing](#contributing)
- [License](#license)

</details>

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

There is no ambient clock, either: every method that needs the time takes an `Instant` from you. That is what makes a
whole session reproducible in a test without a socket or a sleep.

## Installation

```toml
[dependencies]
rtc = "0.21"
```

RTC requires Rust edition 2024.

### Crypto Providers

All cryptography goes through a pluggable [`RTCCryptoProvider`]. Two built-in providers ship with the crate and the
Cargo features are **additive** — enabling both builds successfully, and `ring` is preferred when both are on:

```toml
# Default: the ring provider, no C toolchain required.
rtc = "0.21"

# aws-lc-rs instead (pulls in the aws-lc-sys C toolchain).
rtc = { version = "0.21", default-features = false, features = ["crypto-aws-lc-rs"] }
```

There is **no process-global provider to install**. The provider is selected per peer connection through
`SettingEngine::set_crypto_provider`, so two peer connections in one process may use different ones. Applications
needing OpenSSL, a FIPS-validated module, an HSM, or a platform backend can implement the public traits themselves and
validate the result against the bundled conformance suite (`rtc_crypto::conformance::assert_provider`, behind the
`test-support` feature).

[`RTCCryptoProvider`]: https://docs.rs/rtc-crypto

## Sans-I/O Event Loop Pattern

The event loop is the [`sansio::Protocol`] trait implemented by `RTCPeerConnection` — **bring the trait into scope with
`use rtc::sansio::Protocol;` or none of these methods will resolve.**

| Method | Direction | What it does |
| --- | --- | --- |
| `handle_read(TaggedBytesMut)` | in | Feed one received UDP/TCP datagram, tagged with its 5-tuple and arrival instant |
| `poll_write() -> Option<TaggedBytesMut>` | out | Take the next packet to put on the wire; drain until `None` |
| `poll_read() -> Option<TaggedRTCMessage>` | out | Take the next inbound RTP/RTCP/data-channel message for the application |
| `poll_event() -> Option<RTCPeerConnectionEvent>` | out | Take the next state change or notification |
| `poll_timeout() -> Option<Instant>` | out | Next deadline for retransmissions, keepalives and ICE checks |
| `handle_timeout(Instant)` | in | Tell the connection a deadline has passed |
| `handle_write(TaggedRTCMessage)` | in | Queue an outbound RTP/RTCP/data-channel message |
| `close()` | in | Shut the connection down |

`handle_event` is also part of the trait, but `RTCEvent` is currently uninhabited: no value of it can be constructed,
so there is nothing to call it with. It exists so the signature is already right when the first inbound event variant
is added.

Order matters only in that `poll_write` should be drained after anything that could have produced output —
`handle_read`, `handle_timeout`, `handle_write`, and the negotiation calls all queue packets rather than sending them.

[`sansio::Protocol`]: https://docs.rs/sansio/latest/sansio/trait.Protocol.html

### Event Loop Example

```rust,no_run
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc::sansio::Protocol;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use bytes::BytesMut;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build the peer connection. `build` takes the instant the session starts.
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_servers(vec![RTCIceServer {
                    urls: vec!["stun:stun.l.google.com:19302".to_string()],
                    ..Default::default()
                }])
                .build(),
        )
        .build(Instant::now())?;

    // 2. Signaling: every description call also takes the current instant.
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer.clone())?;
    // send `offer.sdp` over your signaling channel, then:
    //   let answer = RTCSessionDescription::answer(answer_sdp)?;
    //   pc.set_remote_description(Instant::now(), answer)?;

    // 3. You own the socket.
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_addr = socket.local_addr()?;
    let mut buf = vec![0u8; 2000];
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(86400);

    loop {
        // Drain everything the connection wants to send.
        while let Some(msg) = pc.poll_write() {
            socket.send_to(&msg.message, msg.transport.peer_addr).await?;
        }

        // Drain state changes and notifications.
        while let Some(event) = pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    println!("connection state: {state}");
                    if state == RTCPeerConnectionState::Failed {
                        return Ok(());
                    }
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    println!("new track: {}", init.track_id);
                }
                // RTCPeerConnectionEvent is #[non_exhaustive].
                _ => {}
            }
        }

        // Drain inbound application messages. `poll_read` yields a *tagged* message:
        // `now` is when the packet was observed at the socket, not when you drained it.
        while let Some(TaggedRTCMessage { now, message }) = pc.poll_read() {
            match message {
                RTCMessage::RtpPacket(track_id, _packet) => {
                    println!("RTP on track {track_id} at {now:?}");
                }
                RTCMessage::RtcpPacket(receiver_id, _packets) => {
                    println!("RTCP for receiver {receiver_id:?}");
                }
                RTCMessage::DataChannelMessage(channel_id, _msg) => {
                    println!("data-channel message on {channel_id:?}");
                }
                // RTCMessage is #[non_exhaustive].
                _ => {}
            }
        }

        // Wait for whichever comes first: a packet or the next protocol deadline.
        let timeout = pc.poll_timeout().unwrap_or(Instant::now() + DEFAULT_TIMEOUT);
        let delay = timeout.saturating_duration_since(Instant::now());
        if delay.is_zero() {
            pc.handle_timeout(Instant::now())?;
            continue;
        }

        tokio::select! {
            biased;

            _ = tokio::time::sleep(delay) => {
                pc.handle_timeout(Instant::now())?;
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
}
```

## Feeding ICE Candidates

Because RTC does no I/O, it also does no candidate gathering: **you** bind the sockets, so **you** tell the connection
which local candidates exist. Build them with the `rtc-ice` candidate constructors and hand each one to
`add_local_candidate`:

```rust,no_run
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use std::time::Instant;

fn gather(pc: &mut rtc::peer_connection::RTCPeerConnection) -> Result<(), Box<dyn std::error::Error>> {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.100".to_string(),
            port: 8080,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

    // An EMPTY candidate string is the end-of-gathering sentinel: it moves the ICE gathering
    // state to `Complete` and emits `OnIceGatheringStateChangeEvent(Complete)`. Nothing else
    // reaches that state, so send it once you have added every local candidate.
    pc.add_local_candidate(RTCIceCandidateInit::default())?;
    Ok(())
}
```

Remote candidates arrive over your signaling channel and go in through `add_remote_candidate`, which requires a remote
description to have been set first. For `srflx` and `relay` candidates, set `RTCIceCandidateInit::url` to the
STUN/TURN server the candidate was gathered from so it is attributed correctly in `getStats`.

## Back-Pressure

`poll_read` is the throttle. Undrained data-channel messages leave bytes in SCTP's reassembly queue, which lowers the
receiver-window credit advertised in every SACK, which tells the peer to slow down. **Declining to call `poll_read` is
how you apply back-pressure**; resume when the application catches up. Media is never throttled this way — RTP arrives
over SRTP and is subject to none of SCTP's flow control.

## Features

- ✅ **ICE** (Interactive Connectivity Establishment) - NAT traversal with STUN/TURN, plus mDNS candidates
- ✅ **DTLS** (Datagram Transport Layer Security) - Encryption for media and data
- ✅ **SCTP** (Stream Control Transmission Protocol) - Reliable data channels
- ✅ **RTP/RTCP** - Real-time media transport and control
- ✅ **SDP** (Session Description Protocol) - Offer/answer negotiation, Unified Plan
- ✅ **Data Channels** - Bidirectional peer-to-peer data transfer, in-band (DCEP) and out-of-band
- ✅ **Media Tracks** - Audio/video transmission
- ✅ **Trickle ICE** - Progressive candidate gathering, and ICE restart
- ✅ **ICE over TCP** - Active and passive
- ✅ **Simulcast & SVC** - Simulcast and scalable video coding
- ✅ **RTX & FEC** - Retransmission and forward error correction
- ✅ **Statistics** - `getStats` per the W3C WebRTC Statistics API
- ✅ **Interceptors** - Composable RTP/RTCP pipeline (NACK, TWCC, reports, bandwidth estimation)
- ✅ **Pluggable crypto** - `ring` or `aws-lc-rs` built in, or bring your own provider

## What's New in 0.21

**A provider-neutral cryptographic API.** Every cryptographic operation in the stack now goes through the new
`rtc-crypto` crate rather than a hard-wired backend:

- `RTCCryptoProvider` bundles an `RTCCrypto` operations trait and an `RTCRandom` CSPRNG. `RingProvider` and
  `AwsLcRsProvider` ship built in, and an application can supply its own — OpenSSL, a FIPS-validated module, an HSM, a
  platform backend — by implementing the public traits.
- **No library code resolves a default provider.** `crypto::default_provider()` is called in exactly one place, at
  peer-connection construction, where the application either supplied one via `SettingEngine::set_crypto_provider` or
  gets the feature-selected built-in. A `--no-default-features` build now fails at configuration time instead of deep
  inside a handshake.
- **`crypto-ring` and `crypto-aws-lc-rs` are additive.** Enabling both builds and is covered in CI; previously the
  combination was a `compile_error!`, which broke otherwise valid builds whenever Cargo feature unification pulled in
  both.
- A reusable conformance suite (`rtc_crypto::conformance::assert_provider`) validates any implementation against the
  same RFC vectors the built-ins pass.
- Certificates are provider-neutral: `RTCCertificate::generate`, `generate_from_signing_key` and `from_pkcs8`.
  Non-exportable HSM/KMS keys are supported.

**Performance.** Key schedules moved off the per-packet path: SRTP keys its MACs once per context (~40% faster per
RTCP packet), DTLS CBC keys its record MACs at epoch setup (~4-7% faster), AES-CTR is batched (~9-10% faster on a
1200-byte payload), and the built-in `RTCRandom` no longer reads the OS per record (DTLS GCM record encryption went
from 1.015 µs to 262 ns). Every per-packet benchmark is at parity with or faster than the pre-migration baseline.

**Behaviour change.** `MediaEngine::register_default_codecs` no longer registers `video/ulpfec`, because the receive
path does not recover media from ULPFEC packets. **This changes the default offer's SDP**: payload type 116 is gone.
Register it explicitly with `MIME_TYPE_ULP_FEC` if you need it.

See [CHANGELOG.md](CHANGELOG.md) for the full list, and
[docs/crypto-provider-migration.md](docs/crypto-provider-migration.md) for before/after migration examples.

## Examples

The repository includes examples demonstrating various use cases:

- [data-channels-offer-answer](https://github.com/webrtc-rs/rtc/tree/master/examples/data-channels-offer-answer/) -
  Complete data channel setup with signaling
- [data-channels-flow-control](https://github.com/webrtc-rs/rtc/tree/master/examples/data-channels-flow-control/) -
  Applying back-pressure to a fast sender
- [trickle-ice](https://github.com/webrtc-rs/rtc/tree/master/examples/trickle-ice/) - Progressive candidate exchange
- [ice-restart](https://github.com/webrtc-rs/rtc/tree/master/examples/ice-restart/) - Recovering a connection after a
  network change
- [perfect-negotiation](https://github.com/webrtc-rs/rtc/tree/master/examples/perfect-negotiation/) - Glare-free
  renegotiation with rollback
- [reflect](https://github.com/webrtc-rs/rtc/tree/master/examples/reflect/) - Echo server that reflects media back to
  the sender
- [save-to-disk-vpx](https://github.com/webrtc-rs/rtc/tree/master/examples/save-to-disk-vpx/) - Receive and save VP8/VP9
  video
- [play-from-disk-vpx](https://github.com/webrtc-rs/rtc/tree/master/examples/play-from-disk-vpx/) - Send VP8/VP9 video
  from disk
- [simulcast](https://github.com/webrtc-rs/rtc/tree/master/examples/simulcast) - Receive 3 simulcast encodings in one
  track
- [broadcast](https://github.com/webrtc-rs/rtc/tree/master/examples/broadcast) - Broadcast a video to multiple peers
- [stats](https://github.com/webrtc-rs/rtc/tree/master/examples/stats) - Statistical information about a
  PeerConnection

Run one with its registered example name:

```bash
cargo run --example data-channels-offer
cargo run --example data-channels-answer
```

## Architecture

RTC is built from composable crates, each implementing a specific protocol:

## RTC Crates

<p align="center">
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">RTC<a href="https://crates.io/crates/rtc"><img src="https://img.shields.io/crates/v/rtc.svg"></a>
    <br>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">Media<a href="https://crates.io/crates/rtc-media"><img src="https://img.shields.io/crates/v/rtc-media.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">Interceptor<a href="https://crates.io/crates/rtc-interceptor"><img src="https://img.shields.io/crates/v/rtc-interceptor.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">DataChannel<a href="https://crates.io/crates/rtc-datachannel"><img src="https://img.shields.io/crates/v/rtc-datachannel.svg"></a>
    <br>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">RTP<a href="https://crates.io/crates/rtc-rtp"><img src="https://img.shields.io/crates/v/rtc-rtp.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">RTCP<a href="https://crates.io/crates/rtc-rtcp"><img src="https://img.shields.io/crates/v/rtc-rtcp.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">SRTP<a href="https://crates.io/crates/rtc-srtp"><img src="https://img.shields.io/crates/v/rtc-srtp.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">SCTP<a href="https://crates.io/crates/rtc-sctp"><img src="https://img.shields.io/crates/v/rtc-sctp.svg"></a>
    <br>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">DTLS<a href="https://crates.io/crates/rtc-dtls"><img src="https://img.shields.io/crates/v/rtc-dtls.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">Crypto<a href="https://crates.io/crates/rtc-crypto"><img src="https://img.shields.io/crates/v/rtc-crypto.svg"></a>
    <br>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">mDNS<a href="https://crates.io/crates/rtc-mdns"><img src="https://img.shields.io/crates/v/rtc-mdns.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">STUN<a href="https://crates.io/crates/rtc-stun"><img src="https://img.shields.io/crates/v/rtc-stun.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">TURN<a href="https://crates.io/crates/rtc-turn"><img src="https://img.shields.io/crates/v/rtc-turn.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">ICE<a href="https://crates.io/crates/rtc-ice"><img src="https://img.shields.io/crates/v/rtc-ice.svg"></a>
    <br>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">SDP<a href="https://crates.io/crates/rtc-sdp"><img src="https://img.shields.io/crates/v/rtc-sdp.svg"></a>
    <img src="https://raw.githubusercontent.com/webrtc-rs/webrtc-rs.github.io/master/res/check.png">Shared<a href="https://crates.io/crates/rtc-shared"><img src="https://img.shields.io/crates/v/rtc-shared.svg"></a>
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

```rust,no_run
use rtc::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::sansio::Protocol;
use std::time::Instant;

fn open(pc: &mut RTCPeerConnection) -> Result<RTCDataChannelId, Box<dyn std::error::Error>> {
    let init = RTCDataChannelInit {
        ordered: true,
        max_retransmits: None,
        ..Default::default()
    };
    // The handle borrows `pc`, so keep the id to reach the channel again later.
    let id = pc.create_data_channel("my-channel", Some(init))?.id();
    Ok(id)
}

fn on_open(pc: &mut RTCPeerConnection, id: RTCDataChannelId) -> Result<(), Box<dyn std::error::Error>> {
    // Only send once the channel is open: an in-band channel's SCTP stream is
    // established by the DCEP handshake, and sending before then is rejected.
    if let Some(mut dc) = pc.data_channel(id) {
        dc.send_text(Instant::now(), "Hello, WebRTC!")?;
    }
    Ok(())
}

fn drive(pc: &mut RTCPeerConnection) -> Result<(), Box<dyn std::error::Error>> {
    while let Some(event) = pc.poll_event() {
        if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) = event {
            on_open(pc, id)?;
        }
    }
    Ok(())
}
```

### Media Tracks

```rust,no_run
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnection;
use rtc::rtp_transceiver::RTCRtpSenderId;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};

fn add_video(
    pc: &mut RTCPeerConnection,
    ssrc: u32,
) -> Result<RTCRtpSenderId, Box<dyn std::error::Error>> {
    let track = MediaStreamTrack::new(
        "stream-id".to_string(),
        "track-id".to_string(),
        "Camera".to_string(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec::default(),
            ..Default::default()
        }],
    );

    Ok(pc.add_track(track)?)
}
```

### Statistics

```rust,no_run
use rtc::peer_connection::RTCPeerConnection;
use rtc::statistics::StatsSelector;
use std::time::Instant;

fn report(pc: &mut RTCPeerConnection) {
    // The instant is passed in rather than read from the clock, so a stats
    // snapshot is as reproducible as the rest of the session.
    let report = pc.get_stats(Instant::now(), StatsSelector::None);

    if let Some(stats) = report.peer_connection() {
        println!("data channels opened: {}", stats.data_channels_opened);
    }
    for stream in report.inbound_rtp_streams() {
        println!(
            "ssrc {}: {} packets received",
            stream.received_rtp_stream_stats.rtp_stream_stats.ssrc,
            stream.received_rtp_stream_stats.packets_received
        );
    }
}
```

### Signaling

WebRTC requires an external signaling channel (e.g. WebSocket, HTTP) to exchange offers and answers. Note that every
description call takes the current instant:

```rust,no_run
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::sdp::RTCSessionDescription;
use std::time::Instant;

fn negotiate(
    pc: &mut RTCPeerConnection,
    answer_sdp: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let offer = pc.create_offer(None)?;
    pc.set_local_description(Instant::now(), offer.clone())?;
    // send `offer.sdp` over your signaling channel, receive the answer, then:
    let answer = RTCSessionDescription::answer(answer_sdp)?;
    pc.set_remote_description(Instant::now(), answer)?;
    Ok(())
}
```

## Specification Compliance

This implementation follows these specifications:

| Layer | Specification |
| --- | --- |
| API | [W3C WebRTC 1.0](https://www.w3.org/TR/webrtc/), [W3C WebRTC Statistics](https://www.w3.org/TR/webrtc-stats/) |
| Signaling | [RFC 9429](https://datatracker.ietf.org/doc/html/rfc9429) (JSEP), [RFC 8866](https://datatracker.ietf.org/doc/html/rfc8866) (SDP), [RFC 8843](https://datatracker.ietf.org/doc/html/rfc8843) (BUNDLE), [RFC 8853](https://datatracker.ietf.org/doc/html/rfc8853) (Simulcast) |
| Connectivity | [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445) (ICE), [RFC 8838](https://datatracker.ietf.org/doc/html/rfc8838) (Trickle ICE), [RFC 8839](https://datatracker.ietf.org/doc/html/rfc8839) (SDP for ICE), [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489) (STUN), [RFC 8656](https://datatracker.ietf.org/doc/html/rfc8656) (TURN) |
| Security | [RFC 6347](https://datatracker.ietf.org/doc/html/rfc6347) (DTLS 1.2), [RFC 5764](https://datatracker.ietf.org/doc/html/rfc5764) (DTLS-SRTP), [RFC 3711](https://datatracker.ietf.org/doc/html/rfc3711) (SRTP) |
| Data | [RFC 9260](https://datatracker.ietf.org/doc/html/rfc9260) (SCTP), [RFC 8261](https://datatracker.ietf.org/doc/html/rfc8261) (SCTP over DTLS), [RFC 8831](https://datatracker.ietf.org/doc/html/rfc8831) (Data Channels), [RFC 8832](https://datatracker.ietf.org/doc/html/rfc8832) (DCEP) |
| Media | [RFC 3550](https://datatracker.ietf.org/doc/html/rfc3550) (RTP/RTCP), [RFC 4588](https://datatracker.ietf.org/doc/html/rfc4588) (RTX), [RFC 8285](https://datatracker.ietf.org/doc/html/rfc8285) (Header Extensions), [RFC 5761](https://datatracker.ietf.org/doc/html/rfc5761) (RTP/RTCP Mux) |

## Documentation

- [API Documentation](https://docs.rs/rtc) - Complete API reference
- [Examples](https://github.com/webrtc-rs/rtc/tree/master/examples) - Working code examples
- [Sans-I/O Pattern](https://sans-io.readthedocs.io/) - Detailed explanation of the sans-I/O design
- [WebRTC for the Curious](https://webrtcforthecurious.com/) - Comprehensive WebRTC guide

## Building and Testing

```bash
# Build the library
cargo build

# Run tests
cargo test

# Build with the aws-lc-rs crypto provider instead of ring
cargo build --no-default-features --features crypto-aws-lc-rs

# Build documentation
cargo doc --open

# Run an example
cargo run --example data-channels-answer
```

## Semantic Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **Patch** (`0.x.Y`): Bug fixes and internal improvements with no public API changes.
- **Minor** (`0.X.0`): Backwards-compatible additions or deprecations to the public API.
- **Major** (`X.0.0`): Breaking changes to the public API.

While the version is `0.x`, the minor version acts as the major — i.e., a minor bump may include breaking changes. Once
`1.0.0` is released, full semver stability guarantees apply.

Pre-release versions are published with the following suffixes, in order of increasing stability:

- **`-alpha.N`**: Early preview. API is unstable and may change significantly.
- **`-beta.N`**: Feature-complete for the release. API may still have minor changes.
- **`-rc.N`**: Release candidate. No further API changes are expected unless critical issues are found.

For example: `1.0.0-alpha.1` → `1.0.0-beta.1` → `1.0.0-rc.1` → `1.0.0`.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

## Acknowledgments

Special thanks to all contributors and the WebRTC-rs community for making this project possible.

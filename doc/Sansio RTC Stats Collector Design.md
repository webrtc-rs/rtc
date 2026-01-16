# Sansio RTC Stats Collector Design

> **Version:** 1.0
> **Status:** Draft
> **References:
** [W3C WebRTC Stats](https://www.w3.org/TR/webrtc-stats/), [W3C WebRTC](https://www.w3.org/TR/webrtc/#sec.stats-model)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Core Design Principles](#3-core-design-principles)
4. [File Structure](#4-file-structure)
5. [Accumulator Types](#5-accumulator-types)
6. [Coverage Analysis](#6-coverage-analysis)
7. [Handler Integration](#7-handler-integration)
8. [Public API](#8-public-api)
9. [Application Integration APIs](#9-application-integration-apis)
10. [Implementation Roadmap](#10-implementation-roadmap)

---

## 1. Executive Summary

### 1.1 Comparison with Other Implementations

| Aspect          | Pion (Go)              | Async WebRTC-RS       | Sansio RTC                           |
|-----------------|------------------------|-----------------------|--------------------------------------|
| Collection      | WaitGroup + goroutines | tokio::join! async    | Synchronous accumulation             |
| Timing          | On-demand fetch        | On-demand async fetch | Continuous accumulation + snapshot   |
| I/O             | Direct network access  | Async network         | No I/O, application-driven           |
| Threading       | Multi-threaded         | Async tasks           | Single-threaded, event-loop friendly |
| Synchronization | Mutex + WaitGroup      | Mutex + async         | None needed                          |

### 1.2 Coverage Summary

| Category              | Stats Types                        | Coverage    |
|-----------------------|------------------------------------|-------------|
| **Network/Transport** | ICE, Transport, Certificate        | 95%+ ✅      |
| **RTP Core**          | Packet counts, RTCP feedback       | 90%+ ✅      |
| **Codec/DataChannel** | Codec, DataChannel, PeerConnection | 100% ✅      |
| **Media Source**      | Audio/Video source capture         | Via App API |
| **Encoder/Decoder**   | Frame encode/decode stats          | Via App API |
| **Audio Playout**     | Jitter buffer, concealment         | Via App API |

---

## 2. Architecture Overview

### 2.1 High-Level Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          RTCPeerConnection                                 │
│  ┌────────────────────────────────────────────────────────────────────────┐│
│  │                        RTCStatsAccumulator                             ││
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   ││
│  │  │ ICE Stats    │ │ Transport    │ │ RTP Stream   │ │ DataChannel  │   ││
│  │  │ Accumulators │ │ Accumulator  │ │ Accumulators │ │ Accumulators │   ││
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘   ││
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   ││
│  │  │ Codec        │ │ Certificate  │ │ PeerConn     │ │ MediaSource  │   ││
│  │  │ Accumulators │ │ Accumulators │ │ Accumulator  │ │ Accumulators │   ││
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘   ││
│  └────────────────────────────────────────────────────────────────────────┘│
│                                                                            │
│  pub fn get_stats(&self, now: Instant) -> RTCStatsReport                   │
│      └─> Collects snapshots from all accumulators, builds report           │
└────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow Diagram

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│                                RTCPeerConnection                                   │
│                                                                                    │
│   handle_read(packet)                                                              │
│        │                                                                           │
│        ▼                                                                           │
│   ┌─────────────────────────────────────────────────────────────────────────────┐  │
│   │                            Handler Pipeline                                 │  │
│   │                                                                             │  │
│   │   ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐   │  │
│   │   │Demuxer  │───▶│  ICE    │───▶│  DTLS   │───▶│  SCTP   │───▶│DataChan │   │  │
│   │   │Handler  │    │Handler  │    │Handler  │    │Handler  │    │Handler  │   │  │
│   │   └────┬────┘    └────┬────┘    └────┬────┘    └────┬────┘    └────┬────┘   │  │
│   │        │              │              │              │              │        │  │
│   │        ▼              ▼              ▼              ▼              ▼        │  │
│   │   ┌─────────────────────────────────────────────────────────────────────┐   │  │
│   │   │                      RTCStatsAccumulator                            │   │  │
│   │   │  Updates stats as packets flow through the pipeline                 │   │  │
│   │   └─────────────────────────────────────────────────────────────────────┘   │  │
│   │                                                                             │  │
│   │   ┌─────────┐    ┌─────────┐    ┌─────────┐                                 │  │
│   │   │  SRTP   │───▶│Intercep │───▶│Endpoint │                                 │  │
│   │   │Handler  │    │Handler  │    │Handler  │                                 │  │
│   │   └────┬────┘    └────┬────┘    └────┬────┘                                 │  │
│   │        │              │              │                                      │  │
│   │        ▼              ▼              ▼                                      │  │
│   │   Update SRTP    Update RTP      Update Track                               │  │
│   │   Stats          Stream Stats    Stats                                      │  │
│   └─────────────────────────────────────────────────────────────────────────────┘  │
│        │                                                                           │
│        ▼                                                                           │
│   poll_read() -> RTCMessage                                                        │
│                                                                                    │
│   ──────────────────────────────────────────────────────────────────────────────── │
│                                                                                    │
│   get_stats(now: Instant) -> RTCStatsReport                                        │
│        │                                                                           │
│        ▼                                                                           │
│   RTCStatsAccumulator.snapshot(now) ──► RTCStatsReport                             │
└────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Design Principles

### 3.1 Incremental Accumulation

Stats are accumulated incrementally during normal `handle_read/handle_write/handle_event/handle_timeout` processing,
then returned as a snapshot when `get_stats()` is called.

**Benefits:**

- Zero-cost stats collection (no extra queries)
- Always up-to-date counters
- Instant snapshot without waiting

### 3.2 No Async, No Locks

The sansio design is inherently single-threaded. Stats accumulation happens synchronously during packet processing,
eliminating the need for mutexes or async coordination.

### 3.3 Centralized Stats Storage

A single `RTCStatsAccumulator` in `PipelineContext` holds all stats. This:

- Simplifies access from any handler
- Enables efficient snapshot generation
- Avoids scattered stats across components

### 3.4 Explicit Timestamp Parameter

The `get_stats(now: Instant)` API takes an explicit timestamp rather than using `Instant::now()` internally. This:

- Enables deterministic testing
- Follows sansio principle of no hidden I/O
- Allows batch stats with consistent timestamps

### 3.5 Application Integration for Media Stats

Since sansio doesn't handle media encoding/decoding, the application provides these stats via dedicated APIs. This is
consistent with the sansio philosophy: the library handles **protocol**, the application handles **I/O and media
processing**.

---

## 4. File Structure

```
src/statistics/
├── mod.rs                     # Module exports (accumulator, report, stats)
├── report.rs                  # RTCStatsReport and RTCStatsReportEntry
├── accumulator/               # Stats accumulation layer
│   ├── mod.rs                 # RTCStatsAccumulator (master accumulator)
│   ├── ice.rs                 # IceCandidateAccumulator, IceCandidatePairAccumulator
│   ├── transport.rs           # TransportStatsAccumulator
│   ├── certificate.rs         # CertificateStatsAccumulator
│   ├── rtp_stream.rs          # InboundRtpStreamAccumulator, OutboundRtpStreamAccumulator
│   ├── data_channel.rs        # DataChannelStatsAccumulator
│   ├── codec.rs               # CodecStatsAccumulator
│   ├── peer_connection.rs     # PeerConnectionStatsAccumulator
│   ├── media_source.rs        # MediaSourceStatsAccumulator
│   ├── audio_playout.rs       # AudioPlayoutStatsAccumulator
│   └── app_provided.rs        # Application-provided stats update types
└── stats/                     # W3C WebRTC Stats API types
    ├── mod.rs                 # RTCStatsType, RTCStats, RTCStatsId, RTCQualityLimitationReason
    ├── audio_playout.rs       # RTCAudioPlayoutStats
    ├── certificate.rs         # RTCCertificateStats
    ├── codec.rs               # RTCCodecStats
    ├── data_channel.rs        # RTCDataChannelStats
    ├── ice_candidate.rs       # RTCIceCandidateStats
    ├── ice_candidate_pair.rs  # RTCIceCandidatePairStats
    ├── peer_connection.rs     # RTCPeerConnectionStats
    ├── transport.rs           # RTCTransportStats
    ├── rtp_stream/            # RTP stream stats
    │   ├── mod.rs             # RTCRtpStreamStats
    │   ├── inbound.rs         # RTCInboundRtpStreamStats
    │   ├── outbound.rs        # RTCOutboundRtpStreamStats
    │   ├── received.rs        # RTCReceivedRtpStreamStats
    │   ├── sent.rs            # RTCSentRtpStreamStats
    │   ├── remote_inbound.rs  # RTCRemoteInboundRtpStreamStats
    │   └── remote_outbound.rs # RTCRemoteOutboundRtpStreamStats
    └── source/                # Media source stats
        ├── mod.rs
        ├── media.rs           # RTCMediaSourceStats
        ├── audio.rs           # RTCAudioSourceStats
        └── video.rs           # RTCVideoSourceStats
```

---

## 5. Accumulator Types

### 5.1 StatsAccumulator Trait

```rust
/// Trait for components that accumulate statistics incrementally.
pub trait StatsAccumulator {
    /// The stats type this accumulator produces
    type Stats;

    /// Create a snapshot of current stats at the given timestamp
    fn snapshot(&self, now: Instant) -> Self::Stats;

    /// Reset accumulated counters (optional, for delta stats)
    fn reset(&mut self) {}
}
```

### 5.2 ICE Candidate Accumulator

```rust
/// Accumulated ICE candidate statistics (no counters, snapshot from ice::Candidate)
#[derive(Debug, Default, Clone)]
pub struct IceCandidateAccumulator {
    pub transport_id: String,
    pub address: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub candidate_type: RTCIceCandidateType,
    pub priority: u16,
    pub url: String,
    pub relay_protocol: RTCIceServerTransportProtocol,
    pub foundation: String,
    pub related_address: String,
    pub related_port: u16,
    pub username_fragment: String,
    pub tcp_type: RTCIceTcpCandidateType,
}
```

**Source:** ICE Agent - populated when candidates are gathered/received

### 5.3 ICE Candidate Pair Accumulator

```rust
/// Accumulated ICE candidate pair statistics
#[derive(Debug, Default)]
pub struct IceCandidatePairAccumulator {
    pub local_candidate_id: String,
    pub remote_candidate_id: String,

    // Packet/byte counters - incremented during handle_read/handle_write
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,

    // Timestamps for last activity
    pub last_packet_sent_timestamp: Option<Instant>,
    pub last_packet_received_timestamp: Option<Instant>,

    // RTT tracking (updated from STUN responses)
    pub total_round_trip_time: f64,
    pub current_round_trip_time: f64,
    pub rtt_measurements: u32,

    // Request/response counters
    pub requests_sent: u64,
    pub requests_received: u64,
    pub responses_sent: u64,
    pub responses_received: u64,
    pub consent_requests_sent: u64,

    // Discard counters
    pub packets_discarded_on_send: u32,
    pub bytes_discarded_on_send: u32,

    // Bitrate estimation (from TWCC/congestion control)
    pub available_outgoing_bitrate: f64,
    pub available_incoming_bitrate: f64,

    // State
    pub state: RTCStatsIceCandidatePairState,
    pub nominated: bool,
}

impl IceCandidatePairAccumulator {
    pub fn on_packet_sent(&mut self, bytes: usize, now: Instant) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
        self.last_packet_sent_timestamp = Some(now);
    }

    pub fn on_packet_received(&mut self, bytes: usize, now: Instant) {
        self.packets_received += 1;
        self.bytes_received += bytes as u64;
        self.last_packet_received_timestamp = Some(now);
    }

    pub fn on_rtt_measured(&mut self, rtt_seconds: f64) {
        self.current_round_trip_time = rtt_seconds;
        self.total_round_trip_time += rtt_seconds;
        self.rtt_measurements += 1;
    }

    pub fn on_stun_request_sent(&mut self) {
        self.requests_sent += 1;
    }

    pub fn on_stun_request_received(&mut self) {
        self.requests_received += 1;
    }

    pub fn on_stun_response_sent(&mut self) {
        self.responses_sent += 1;
    }

    pub fn on_stun_response_received(&mut self) {
        self.responses_received += 1;
    }
}
```

**Source:** ICE Handler + ICE Agent events

### 5.4 Transport Stats Accumulator

```rust
/// Accumulated transport-level statistics
#[derive(Debug, Default)]
pub struct TransportStatsAccumulator {
    pub transport_id: String,

    // Packet/byte counters
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,

    // ICE state
    pub ice_role: RTCIceRole,
    pub ice_local_username_fragment: String,
    pub ice_state: RTCIceTransportState,

    // DTLS state
    pub dtls_state: RTCDtlsTransportState,
    pub dtls_role: RTCDtlsRole,
    pub tls_version: String,
    pub dtls_cipher: String,

    // SRTP
    pub srtp_cipher: String,

    // Selected candidate pair
    pub selected_candidate_pair_id: String,
    pub selected_candidate_pair_changes: u32,

    // Certificate references
    pub local_certificate_id: String,
    pub remote_certificate_id: String,

    // Congestion control feedback
    pub ccfb_messages_sent: u32,
    pub ccfb_messages_received: u32,
}
```

**Source:** ICE, DTLS, SRTP Handlers

### 5.5 Certificate Stats Accumulator

```rust
/// Accumulated certificate statistics (static after DTLS handshake)
#[derive(Debug, Default, Clone)]
pub struct CertificateStatsAccumulator {
    pub fingerprint: String,
    pub fingerprint_algorithm: String,
    pub base64_certificate: String,
    pub issuer_certificate_id: String,
}
```

**Source:** DTLS Transport - static after handshake

### 5.6 Inbound RTP Stream Accumulator

```rust
/// Accumulated statistics for an inbound RTP stream
#[derive(Debug, Default)]
pub struct InboundRtpStreamAccumulator {
    // Base identification
    pub ssrc: SSRC,
    pub kind: RtpCodecKind,
    pub transport_id: String,
    pub codec_id: String,
    pub track_identifier: String,
    pub mid: String,

    // Packet counters
    pub packets_received: u64,
    pub bytes_received: u64,
    pub header_bytes_received: u64,
    pub packets_lost: i64,
    pub jitter: f64,
    pub packets_discarded: u64,
    pub last_packet_received_timestamp: Option<Instant>,

    // ECN support (partial)
    pub packets_received_with_ect1: u64,
    pub packets_received_with_ce: u64,
    pub packets_reported_as_lost: u64,
    pub packets_reported_as_lost_but_recovered: u64,

    // RTCP feedback sent
    pub nack_count: u32,
    pub fir_count: u32,
    pub pli_count: u32,

    // FEC stats
    pub fec_packets_received: u64,
    pub fec_bytes_received: u64,
    pub fec_packets_discarded: u64,

    // Retransmission
    pub retransmitted_packets_received: u64,
    pub retransmitted_bytes_received: u64,
    pub rtx_ssrc: Option<u32>,
    pub fec_ssrc: Option<u32>,

    // Video frame tracking (RTP-level)
    pub frames_received: u32,
    pub frames_dropped: u32,
    pub frames_per_second: f64,

    // Pause/freeze detection (RTP-level)
    pub pause_count: u32,
    pub total_pauses_duration: f64,
    pub freeze_count: u32,
    pub total_freezes_duration: f64,

    // Frame assembly
    pub frames_assembled_from_multiple_packets: u32,
    pub total_assembly_time: f64,

    // Remote sender info (from RTCP SR)
    pub remote_packets_sent: u64,
    pub remote_bytes_sent: u64,
    pub remote_timestamp: Option<Instant>,
    pub reports_received: u64,

    // Application-provided stats (decoder/audio)
    pub decoder_stats: Option<DecoderStatsUpdate>,
    pub audio_receiver_stats: Option<AudioReceiverStatsUpdate>,
}

impl InboundRtpStreamAccumulator {
    pub fn on_rtp_received(&mut self, payload_bytes: usize, header_bytes: usize, now: Instant) {
        self.packets_received += 1;
        self.bytes_received += payload_bytes as u64;
        self.header_bytes_received += header_bytes as u64;
        self.last_packet_received_timestamp = Some(now);
    }

    pub fn on_rtcp_rr_generated(&mut self, packets_lost: i64, jitter: f64) {
        self.packets_lost = packets_lost;
        self.jitter = jitter;
    }

    pub fn on_nack_sent(&mut self) { self.nack_count += 1; }
    pub fn on_fir_sent(&mut self) { self.fir_count += 1; }
    pub fn on_pli_sent(&mut self) { self.pli_count += 1; }

    pub fn on_rtcp_sr_received(&mut self, packets_sent: u64, bytes_sent: u64, now: Instant) {
        self.remote_packets_sent = packets_sent;
        self.remote_bytes_sent = bytes_sent;
        self.remote_timestamp = Some(now);
        self.reports_received += 1;
    }

    pub fn on_frame_received(&mut self) { self.frames_received += 1; }
    pub fn on_frame_dropped(&mut self) { self.frames_dropped += 1; }
    pub fn on_rtx_received(&mut self, bytes: usize) {
        self.retransmitted_packets_received += 1;
        self.retransmitted_bytes_received += bytes as u64;
    }
}
```

### 5.7 Outbound RTP Stream Accumulator

```rust
/// Accumulated statistics for an outbound RTP stream
#[derive(Debug, Default)]
pub struct OutboundRtpStreamAccumulator {
    // Base identification
    pub ssrc: SSRC,
    pub kind: RtpCodecKind,
    pub transport_id: String,
    pub codec_id: String,
    pub mid: String,
    pub rid: String,
    pub encoding_index: u32,
    pub media_source_id: String,

    // Packet counters
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub header_bytes_sent: u64,
    pub last_packet_sent_timestamp: Option<Instant>,

    // Retransmission
    pub retransmitted_packets_sent: u64,
    pub retransmitted_bytes_sent: u64,
    pub rtx_ssrc: Option<u32>,

    // Frame tracking (RTP-level)
    pub frames_sent: u32,
    pub huge_frames_sent: u32,
    pub frames_per_second: f64,

    // RTCP feedback received
    pub nack_count: u32,
    pub fir_count: u32,
    pub pli_count: u32,

    // Timing
    pub total_packet_send_delay: f64,

    // State
    pub active: bool,

    // Quality limitation (from BWE/interceptor)
    pub quality_limitation_reason: RTCQualityLimitationReason,
    pub quality_limitation_resolution_changes: u32,
    pub target_bitrate: f64,

    // Remote receiver info (from RTCP RR)
    pub remote_packets_received: u64,
    pub remote_packets_lost: u64,
    pub remote_jitter: f64,
    pub remote_fraction_lost: f64,
    pub remote_round_trip_time: f64,
    pub rtt_measurements: u64,

    // Application-provided stats (encoder)
    pub encoder_stats: Option<EncoderStatsUpdate>,
}

impl OutboundRtpStreamAccumulator {
    pub fn on_rtp_sent(&mut self, payload_bytes: usize, header_bytes: usize, is_retransmit: bool, now: Instant) {
        self.packets_sent += 1;
        self.bytes_sent += payload_bytes as u64;
        self.header_bytes_sent += header_bytes as u64;
        self.last_packet_sent_timestamp = Some(now);

        if is_retransmit {
            self.retransmitted_packets_sent += 1;
            self.retransmitted_bytes_sent += payload_bytes as u64;
        }
    }

    pub fn on_nack_received(&mut self) { self.nack_count += 1; }
    pub fn on_fir_received(&mut self) { self.fir_count += 1; }
    pub fn on_pli_received(&mut self) { self.pli_count += 1; }

    pub fn on_rtcp_rr_received(&mut self, packets_received: u64, packets_lost: u64, jitter: f64, fraction_lost: f64, rtt: f64) {
        self.remote_packets_received = packets_received;
        self.remote_packets_lost = packets_lost;
        self.remote_jitter = jitter;
        self.remote_fraction_lost = fraction_lost;
        self.remote_round_trip_time = rtt;
        self.rtt_measurements += 1;
    }

    pub fn on_frame_sent(&mut self, is_huge: bool) {
        self.frames_sent += 1;
        if is_huge { self.huge_frames_sent += 1; }
    }
}
```

### 5.8 Data Channel Stats Accumulator

```rust
/// Accumulated data channel statistics
#[derive(Debug, Default)]
pub struct DataChannelStatsAccumulator {
    pub id: u16,
    pub label: String,
    pub protocol: String,
    pub state: RTCDataChannelState,

    // Message/byte counters
    pub messages_sent: u32,
    pub bytes_sent: u64,
    pub messages_received: u32,
    pub bytes_received: u64,
}

impl DataChannelStatsAccumulator {
    pub fn on_message_sent(&mut self, bytes: usize) {
        self.messages_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    pub fn on_message_received(&mut self, bytes: usize) {
        self.messages_received += 1;
        self.bytes_received += bytes as u64;
    }

    pub fn on_state_changed(&mut self, state: RTCDataChannelState) {
        self.state = state;
    }
}
```

### 5.9 Codec Stats Accumulator

```rust
/// Accumulated codec statistics (static after SDP negotiation)
#[derive(Debug, Default, Clone)]
pub struct CodecStatsAccumulator {
    pub payload_type: PayloadType,
    pub mime_type: String,
    pub channels: u16,
    pub clock_rate: u32,
    pub sdp_fmtp_line: String,
}
```

**Source:** MediaEngine - static after SDP negotiation

### 5.10 Peer Connection Stats Accumulator

```rust
/// Accumulated peer connection level statistics
#[derive(Debug, Default)]
pub struct PeerConnectionStatsAccumulator {
    pub data_channels_opened: u32,
    pub data_channels_closed: u32,
}

impl PeerConnectionStatsAccumulator {
    pub fn on_data_channel_opened(&mut self) { self.data_channels_opened += 1; }
    pub fn on_data_channel_closed(&mut self) { self.data_channels_closed += 1; }
}
```

### 5.11 Media Source Stats Accumulator

```rust
/// Accumulated media source statistics (application-provided)
#[derive(Debug, Default)]
pub struct MediaSourceStatsAccumulator {
    pub track_id: String,
    pub kind: RtpCodecKind,

    // Audio-specific (from application)
    pub audio_level: Option<f64>,
    pub total_audio_energy: Option<f64>,
    pub total_samples_duration: Option<f64>,
    pub echo_return_loss: Option<f64>,
    pub echo_return_loss_enhancement: Option<f64>,

    // Video-specific (from application)
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub frames: Option<u32>,
    pub frames_per_second: Option<f64>,
}
```

### 5.12 Audio Playout Stats Accumulator

```rust
/// Accumulated audio playout statistics (application-provided)
#[derive(Debug, Default)]
pub struct AudioPlayoutStatsAccumulator {
    pub kind: RtpCodecKind,
    pub synthesized_samples_duration: f64,
    pub synthesized_samples_events: u32,
    pub total_samples_duration: f64,
    pub total_playout_delay: f64,
    pub total_samples_count: u64,
}
```

### 5.13 Master Stats Accumulator

```rust
/// Master stats accumulator that aggregates stats from all components
#[derive(Debug, Default)]
pub struct RTCStatsAccumulator {
    /// ICE candidate pair stats (keyed by pair ID: "{local_id}-{remote_id}")
    pub ice_candidate_pairs: HashMap<String, IceCandidatePairAccumulator>,

    /// ICE candidate stats (keyed by candidate ID)
    pub local_candidates: HashMap<String, IceCandidateAccumulator>,
    pub remote_candidates: HashMap<String, IceCandidateAccumulator>,

    /// Transport stats
    pub transport: TransportStatsAccumulator,

    /// RTP stream stats (keyed by SSRC)
    pub rtp_streams: RtpStreamStatsCollection,

    /// Data channel stats (keyed by channel ID)
    pub data_channels: HashMap<RTCDataChannelId, DataChannelStatsAccumulator>,

    /// Peer connection level stats
    pub peer_connection: PeerConnectionStatsAccumulator,

    /// Codec stats (keyed by codec ID: "{direction}_{payload_type}")
    pub codecs: HashMap<String, CodecStatsAccumulator>,

    /// Certificate stats (keyed by certificate ID)
    pub certificates: HashMap<String, CertificateStatsAccumulator>,

    /// Media source stats (keyed by track ID)
    pub media_sources: HashMap<String, MediaSourceStatsAccumulator>,

    /// Audio playout stats (keyed by track ID)
    pub audio_playout: HashMap<String, AudioPlayoutStatsAccumulator>,
}

/// Collection of RTP stream accumulators indexed by SSRC
#[derive(Debug, Default)]
pub struct RtpStreamStatsCollection {
    pub inbound: HashMap<SSRC, InboundRtpStreamAccumulator>,
    pub outbound: HashMap<SSRC, OutboundRtpStreamAccumulator>,
}

impl RTCStatsAccumulator {
    /// Create a snapshot of all stats at the given timestamp
    pub fn snapshot(&self, now: Instant) -> RTCStatsReport {
        let mut reports = HashMap::new();

        // ICE candidate pairs
        for (id, acc) in &self.ice_candidate_pairs {
            reports.insert(id.clone(), RTCStatsReportType::CandidatePair(acc.snapshot(now)));
        }

        // Local candidates
        for (id, acc) in &self.local_candidates {
            reports.insert(id.clone(), RTCStatsReportType::LocalCandidate(acc.snapshot(now)));
        }

        // Remote candidates
        for (id, acc) in &self.remote_candidates {
            reports.insert(id.clone(), RTCStatsReportType::RemoteCandidate(acc.snapshot(now)));
        }

        // Transport
        reports.insert(
            self.transport.transport_id.clone(),
            RTCStatsReportType::Transport(self.transport.snapshot(now)),
        );

        // Inbound RTP streams + Remote Outbound
        for (ssrc, acc) in &self.rtp_streams.inbound {
            let id = format!("RTCInboundRTPStream_{}_{}", acc.kind, ssrc);
            reports.insert(id.clone(), RTCStatsReportType::InboundRTP(acc.snapshot(now)));

            if acc.remote_timestamp.is_some() {
                let remote_id = format!("RTCRemoteOutboundRTPStream_{}_{}", acc.kind, ssrc);
                reports.insert(remote_id, RTCStatsReportType::RemoteOutboundRTP(acc.snapshot_remote(now)));
            }
        }

        // Outbound RTP streams + Remote Inbound
        for (ssrc, acc) in &self.rtp_streams.outbound {
            let id = format!("RTCOutboundRTPStream_{}_{}", acc.kind, ssrc);
            reports.insert(id.clone(), RTCStatsReportType::OutboundRTP(acc.snapshot(now)));

            if acc.remote_packets_received > 0 {
                let remote_id = format!("RTCRemoteInboundRTPStream_{}_{}", acc.kind, ssrc);
                reports.insert(remote_id, RTCStatsReportType::RemoteInboundRTP(acc.snapshot_remote(now)));
            }
        }

        // Data channels
        for (id, acc) in &self.data_channels {
            let stats_id = format!("RTCDataChannel_{}", id);
            reports.insert(stats_id, RTCStatsReportType::DataChannel(acc.snapshot(now)));
        }

        // Peer connection
        reports.insert(
            "RTCPeerConnection".to_string(),
            RTCStatsReportType::PeerConnection(self.peer_connection.snapshot(now)),
        );

        // Codecs
        for (id, acc) in &self.codecs {
            reports.insert(id.clone(), RTCStatsReportType::Codec(acc.snapshot(now)));
        }

        // Certificates
        for (id, acc) in &self.certificates {
            reports.insert(id.clone(), RTCStatsReportType::Certificate(acc.snapshot(now)));
        }

        // Media sources
        for (id, acc) in &self.media_sources {
            reports.insert(id.clone(), RTCStatsReportType::MediaSource(acc.snapshot(now)));
        }

        // Audio playout
        for (id, acc) in &self.audio_playout {
            reports.insert(id.clone(), RTCStatsReportType::MediaPlayout(acc.snapshot(now)));
        }

        RTCStatsReport { reports }
    }
}
```

---

## 6. Coverage Analysis

### 6.1 Coverage Summary Table

| Stats Type                      | Fields | Covered | Partial | Missing | Coverage        |
|---------------------------------|--------|---------|---------|---------|-----------------|
| RTCCodecStats                   | 5      | 5       | 0       | 0       | 100% ✅          |
| RTCDataChannelStats             | 7      | 7       | 0       | 0       | 100% ✅          |
| RTCIceCandidateStats            | 13     | 13      | 0       | 0       | 100% ✅          |
| RTCIceCandidatePairStats        | 20     | 18      | 2       | 0       | 90% ✅           |
| RTCPeerConnectionStats          | 2      | 2       | 0       | 0       | 100% ✅          |
| RTCTransportStats               | 17     | 17      | 0       | 0       | 100% ✅          |
| RTCCertificateStats             | 4      | 4       | 0       | 0       | 100% ✅          |
| RTCAudioPlayoutStats            | 5      | 5       | 0       | 0       | 100% (via API)  |
| RTCRtpStreamStats (base)        | 4      | 4       | 0       | 0       | 100% ✅          |
| RTCReceivedRtpStreamStats       | 7      | 5       | 2       | 0       | 71% ⚠️          |
| RTCSentRtpStreamStats           | 2      | 2       | 0       | 0       | 100% ✅          |
| RTCInboundRtpStreamStats        | 57     | 25      | 10      | 22      | 44% (+ app API) |
| RTCOutboundRtpStreamStats       | 35     | 20      | 5       | 10      | 57% (+ app API) |
| RTCRemoteInboundRtpStreamStats  | 6      | 5       | 0       | 1       | 83% ✅           |
| RTCRemoteOutboundRtpStreamStats | 6      | 5       | 0       | 1       | 83% ✅           |
| RTCMediaSourceStats             | 2      | 2       | 0       | 0       | 100% ✅          |
| RTCAudioSourceStats             | 5      | 5       | 0       | 0       | 100% (via API)  |
| RTCVideoSourceStats             | 4      | 4       | 0       | 0       | 100% (via API)  |

### 6.2 Fields Requiring Application Input

The following fields cannot be tracked by sansio RTC and require application input:

**Decoder Stats (video inbound):**

- `frames_decoded`, `key_frames_decoded`, `frames_rendered`
- `frame_width`, `frame_height`, `qp_sum`
- `total_decode_time`, `total_inter_frame_delay`
- `decoder_implementation`, `power_efficient_decoder`

**Encoder Stats (video outbound):**

- `frames_encoded`, `key_frames_encoded`
- `frame_width`, `frame_height`, `qp_sum`
- `total_encode_time`, `encoder_implementation`
- `power_efficient_encoder`, `scalability_mode`

**Audio Processing Stats:**

- `audio_level`, `total_audio_energy`, `total_samples_duration`
- `concealed_samples`, `concealment_events`
- `echo_return_loss`, `echo_return_loss_enhancement`

**Playout Stats:**

- `synthesized_samples_duration`, `synthesized_samples_events`
- `total_playout_delay`, `jitter_buffer_delay`

---

## 7. Handler Integration

### 7.1 PipelineContext Integration

```rust
// src/peer_connection/handler/mod.rs

use crate::statistics::accumulator::RTCStatsAccumulator;

#[derive(Default)]
pub(crate) struct PipelineContext {
    // Handler contexts
    pub(crate) demuxer_handler_context: DemuxerHandlerContext,
    pub(crate) ice_handler_context: IceHandlerContext,
    pub(crate) dtls_handler_context: DtlsHandlerContext,
    pub(crate) sctp_handler_context: SctpHandlerContext,
    pub(crate) datachannel_handler_context: DataChannelHandlerContext,
    pub(crate) srtp_handler_context: SrtpHandlerContext,
    pub(crate) interceptor_handler_context: InterceptorHandlerContext,
    pub(crate) endpoint_handler_context: EndpointHandlerContext,

    // Pipeline queues
    pub(crate) read_outs: VecDeque<RTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedBytesMut>,
    pub(crate) event_outs: VecDeque<RTCPeerConnectionEvent>,

    // Stats accumulator
    pub(crate) stats: RTCStatsAccumulator,
}
```

### 7.2 Handler Stats Collection Points

| Handler         | Stats Updated                        | Trigger                               |
|-----------------|--------------------------------------|---------------------------------------|
| **ICE**         | Candidate pair (packets, bytes, RTT) | handle_read/handle_write, STUN events |
| **ICE**         | Transport (bytes, state)             | State changes, packet flow            |
| **DTLS**        | Transport (DTLS state, cipher)       | Handshake completion                  |
| **DTLS**        | Certificates                         | Handshake completion                  |
| **SRTP**        | Transport (SRTP cipher)              | Key derivation                        |
| **Interceptor** | RTP stream (packets, bytes, RTCP)    | handle_read/handle_write              |
| **DataChannel** | Data channel (messages, bytes)       | handle_read/handle_write              |
| **DataChannel** | Peer connection (opened/closed)      | State changes                         |
| **Endpoint**    | Track references                     | Track events                          |

### 7.3 Example: ICE Handler Stats Update

```rust
impl<'a> IceHandler<'a> {
    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        // ... existing processing ...

        // Update stats
        if let Some(pair_id) = self.ctx.ice_transport.selected_candidate_pair_id() {
            if let Some(pair_stats) = self.stats.ice_candidate_pairs.get_mut(&pair_id) {
                pair_stats.on_packet_received(msg.message.len(), msg.now);
            }
        }
        self.stats.transport.on_packet_received(msg.message.len());

        Ok(())
    }
}
```

### 7.4 Example: Interceptor Handler Stats Update

```rust
impl<'a, I> InterceptorHandler<'a, I> {
    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(rtp_packet))) = &msg.message {
            let ssrc = rtp_packet.header.ssrc;
            let kind = self.get_kind_for_ssrc(ssrc);

            let stream_stats = self.stats.rtp_streams.get_or_create_inbound(ssrc, kind);
            stream_stats.on_rtp_received(
                rtp_packet.payload.len(),
                rtp_packet.header.marshal_size(),
                msg.now,
            );
        }

        // ... existing processing ...
        Ok(())
    }
}
```

---

## 8. Public API

### 8.1 RTCStatsReport and RTCStatsReportType

```rust
/// Enum containing all possible WebRTC stats types
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RTCStatsReportType {
    #[serde(rename = "codec")]
    Codec(RTCCodecStats),

    #[serde(rename = "inbound-rtp")]
    InboundRTP(RTCInboundRtpStreamStats),

    #[serde(rename = "outbound-rtp")]
    OutboundRTP(RTCOutboundRtpStreamStats),

    #[serde(rename = "remote-inbound-rtp")]
    RemoteInboundRTP(RTCRemoteInboundRtpStreamStats),

    #[serde(rename = "remote-outbound-rtp")]
    RemoteOutboundRTP(RTCRemoteOutboundRtpStreamStats),

    #[serde(rename = "media-source")]
    MediaSource(RTCMediaSourceStats),

    #[serde(rename = "media-playout")]
    MediaPlayout(RTCAudioPlayoutStats),

    #[serde(rename = "peer-connection")]
    PeerConnection(RTCPeerConnectionStats),

    #[serde(rename = "data-channel")]
    DataChannel(RTCDataChannelStats),

    #[serde(rename = "transport")]
    Transport(RTCTransportStats),

    #[serde(rename = "candidate-pair")]
    CandidatePair(RTCIceCandidatePairStats),

    #[serde(rename = "local-candidate")]
    LocalCandidate(RTCIceCandidateStats),

    #[serde(rename = "remote-candidate")]
    RemoteCandidate(RTCIceCandidateStats),

    #[serde(rename = "certificate")]
    Certificate(RTCCertificateStats),
}

/// WebRTC statistics report containing all stats keyed by ID
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RTCStatsReport {
    pub reports: HashMap<String, RTCStatsReportType>,
}

impl RTCStatsReport {
    /// Get a specific stat by ID
    pub fn get(&self, id: &str) -> Option<&RTCStatsReportType> {
        self.reports.get(id)
    }

    /// Iterate over all inbound RTP stats
    pub fn iter_inbound_rtp(&self) -> impl Iterator<Item=(&str, &RTCInboundRtpStreamStats)> {
        self.reports.iter().filter_map(|(id, stat)| match stat {
            RTCStatsReportType::InboundRTP(s) => Some((id.as_str(), s)),
            _ => None,
        })
    }

    /// Iterate over all outbound RTP stats
    pub fn iter_outbound_rtp(&self) -> impl Iterator<Item=(&str, &RTCOutboundRtpStreamStats)> {
        self.reports.iter().filter_map(|(id, stat)| match stat {
            RTCStatsReportType::OutboundRTP(s) => Some((id.as_str(), s)),
            _ => None,
        })
    }

    // ... similar methods for other types
}
```

### 8.2 RTCPeerConnection Stats Methods

```rust
impl<I> RTCPeerConnection<I>
where
    I: Interceptor,
{
    /// Returns a snapshot of all WebRTC statistics.
    ///
    /// # Arguments
    /// * `now` - The timestamp for the snapshot (typically `Instant::now()`)
    ///
    /// # Example
    /// ```no_run
    /// use std::time::Instant;
    ///
    /// let stats = pc.get_stats(Instant::now());
    /// for (id, stat) in &stats.reports {
    ///     match stat {
    ///         RTCStatsReportType::InboundRTP(inbound) => {
    ///             println!("Inbound {}: {} packets", id, inbound.packets_received);
    ///         }
    ///         _ => {}
    ///     }
    /// }
    /// ```
    pub fn get_stats(&self, now: Instant) -> RTCStatsReport {
        self.pipeline_context.stats.snapshot(now)
    }

    /// Returns statistics for a specific sender.
    pub fn get_stats_for_sender(&self, sender_id: RTCRtpSenderId, now: Instant) -> RTCStatsReport {
        // Filter to sender's SSRCs
        todo!()
    }

    /// Returns statistics for a specific receiver.
    pub fn get_stats_for_receiver(&self, receiver_id: RTCRtpReceiverId, now: Instant) -> RTCStatsReport {
        // Filter to receiver's SSRCs
        todo!()
    }
}
```

---

## 9. Application Integration APIs

### 9.1 Application-Provided Stats Types

```rust
/// Decoder statistics provided by the application
#[derive(Debug, Clone, Default)]
pub struct DecoderStatsUpdate {
    pub frames_decoded: u32,
    pub key_frames_decoded: u32,
    pub frames_rendered: u32,
    pub frame_width: u32,
    pub frame_height: u32,
    pub qp_sum: u64,
    pub total_decode_time: f64,
    pub total_inter_frame_delay: f64,
    pub total_squared_inter_frame_delay: f64,
    pub decoder_implementation: String,
    pub power_efficient_decoder: bool,
}

/// Encoder statistics provided by the application
#[derive(Debug, Clone, Default)]
pub struct EncoderStatsUpdate {
    pub frame_width: u32,
    pub frame_height: u32,
    pub frames_encoded: u32,
    pub key_frames_encoded: u32,
    pub qp_sum: u64,
    pub total_encode_time: f64,
    pub encoder_implementation: String,
    pub power_efficient_encoder: bool,
    pub scalability_mode: String,
}

/// Audio receiver statistics provided by the application
#[derive(Debug, Clone, Default)]
pub struct AudioReceiverStatsUpdate {
    pub total_samples_received: u64,
    pub concealed_samples: u64,
    pub silent_concealed_samples: u64,
    pub concealment_events: u64,
    pub inserted_samples_for_deceleration: u64,
    pub removed_samples_for_acceleration: u64,
    pub audio_level: f64,
    pub total_audio_energy: f64,
    pub total_samples_duration: f64,
    pub jitter_buffer_delay: f64,
    pub jitter_buffer_target_delay: f64,
    pub jitter_buffer_emitted_count: u64,
}

/// Audio source statistics provided by the application
#[derive(Debug, Clone, Default)]
pub struct AudioSourceStatsUpdate {
    pub audio_level: f64,
    pub total_audio_energy: f64,
    pub total_samples_duration: f64,
    pub echo_return_loss: f64,
    pub echo_return_loss_enhancement: f64,
}

/// Video source statistics provided by the application
#[derive(Debug, Clone, Default)]
pub struct VideoSourceStatsUpdate {
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub frames_per_second: f64,
}

/// Audio playout statistics provided by the application
#[derive(Debug, Clone, Default)]
pub struct AudioPlayoutStatsUpdate {
    pub synthesized_samples_duration: f64,
    pub synthesized_samples_events: u32,
    pub total_samples_duration: f64,
    pub total_playout_delay: f64,
    pub total_samples_count: u64,
}
```

### 9.2 Application Stats Reporting Methods

```rust
impl<I> RTCPeerConnection<I>
where
    I: Interceptor,
{
    /// Report decoder statistics for an inbound track
    pub fn report_decoder_stats(&mut self, ssrc: SSRC, stats: DecoderStatsUpdate) {
        if let Some(acc) = self.pipeline_context.stats.rtp_streams.inbound.get_mut(&ssrc) {
            acc.decoder_stats = Some(stats);
        }
    }

    /// Report encoder statistics for an outbound track
    pub fn report_encoder_stats(&mut self, ssrc: SSRC, stats: EncoderStatsUpdate) {
        if let Some(acc) = self.pipeline_context.stats.rtp_streams.outbound.get_mut(&ssrc) {
            acc.encoder_stats = Some(stats);
        }
    }

    /// Report audio receiver statistics for an inbound track
    pub fn report_audio_receiver_stats(&mut self, ssrc: SSRC, stats: AudioReceiverStatsUpdate) {
        if let Some(acc) = self.pipeline_context.stats.rtp_streams.inbound.get_mut(&ssrc) {
            acc.audio_receiver_stats = Some(stats);
        }
    }

    /// Report audio source statistics
    pub fn report_audio_source_stats(&mut self, track_id: &str, stats: AudioSourceStatsUpdate) {
        if let Some(acc) = self.pipeline_context.stats.media_sources.get_mut(track_id) {
            acc.audio_level = Some(stats.audio_level);
            acc.total_audio_energy = Some(stats.total_audio_energy);
            acc.total_samples_duration = Some(stats.total_samples_duration);
            acc.echo_return_loss = Some(stats.echo_return_loss);
            acc.echo_return_loss_enhancement = Some(stats.echo_return_loss_enhancement);
        }
    }

    /// Report video source statistics
    pub fn report_video_source_stats(&mut self, track_id: &str, stats: VideoSourceStatsUpdate) {
        if let Some(acc) = self.pipeline_context.stats.media_sources.get_mut(track_id) {
            acc.width = Some(stats.width);
            acc.height = Some(stats.height);
            acc.frames = Some(stats.frames);
            acc.frames_per_second = Some(stats.frames_per_second);
        }
    }

    /// Report audio playout statistics
    pub fn report_audio_playout_stats(&mut self, track_id: &str, stats: AudioPlayoutStatsUpdate) {
        let acc = self.pipeline_context.stats.audio_playout
            .entry(track_id.to_string())
            .or_default();
        acc.synthesized_samples_duration = stats.synthesized_samples_duration;
        acc.synthesized_samples_events = stats.synthesized_samples_events;
        acc.total_samples_duration = stats.total_samples_duration;
        acc.total_playout_delay = stats.total_playout_delay;
        acc.total_samples_count = stats.total_samples_count;
    }
}
```

---

## 10. Implementation Roadmap

### Phase 1: Core Infrastructure ✅ COMPLETED

**Status:** Completed on 2026-01-15

**Files Created:**

#### Accumulator Module (`src/statistics/accumulator/`)

- **`mod.rs`** - Master `RTCStatsAccumulator` struct that aggregates all category-specific accumulators with a
  `snapshot()` method that produces `RTCStatsReport`
- **`ice.rs`** - `IceCandidateAccumulator`, `IceCandidatePairAccumulator`, and `IceCandidatePairCollection` for ICE
  statistics
- **`transport.rs`** - `TransportStatsAccumulator` for transport-level stats (packets, bytes, ICE/DTLS state)
- **`certificate.rs`** - `CertificateStatsAccumulator` for certificate stats
- **`codec.rs`** - `CodecStatsAccumulator` for codec stats
- **`data_channel.rs`** - `DataChannelStatsAccumulator` with message/byte counters
- **`peer_connection.rs`** - `PeerConnectionStatsAccumulator` for peer connection level stats
- **`rtp_stream.rs`** - `InboundRtpStreamAccumulator`, `OutboundRtpStreamAccumulator`, and `RtpStreamStatsCollection`
- **`media_source.rs`** - `MediaSourceStatsAccumulator` for media source stats
- **`audio_playout.rs`** - `AudioPlayoutStatsAccumulator` for audio playout stats
- **`app_provided.rs`** - Application-provided stats update types (encoder, decoder, audio)

#### Report Module (`src/statistics/report.rs`)

- `RTCStatsReportEntry` enum with all stats types
- `RTCStatsReport` struct with map-like access and convenience methods

#### Stats Types Module (`src/statistics/stats/`)

- **`mod.rs`** - Base types: `RTCStatsType`, `RTCStats`, `RTCStatsId`, `RTCQualityLimitationReason`
- W3C WebRTC Stats API type definitions (moved from `src/stats/`)

**Files Modified:**

- **`src/statistics/mod.rs`** - Added `accumulator`, `report`, and `stats` submodules
- **`src/peer_connection/handler/mod.rs`** - Added `stats: RTCStatsAccumulator` to `PipelineContext`
- **`src/peer_connection/mod.rs`** - Added `get_stats(now: Instant)`, `stats()`, and `stats_mut()` methods to
  `RTCPeerConnection`

**Key Features Implemented:**

- ✅ Create `src/statistics/accumulator/` module structure
- ✅ Implement `RTCStatsAccumulator` master struct
- ✅ Add `stats: RTCStatsAccumulator` to `PipelineContext`
- ✅ Implement `get_stats(now: Instant)` on `RTCPeerConnection`
- ✅ Implement `RTCStatsReport` and `RTCStatsReportEntry`
- ✅ Incremental accumulation + snapshot pattern for deterministic testing
- ✅ Explicit timestamp parameter for all snapshot operations
- ✅ Application-provided stats API for encoder/decoder/audio stats that sansio can't collect
- ✅ Event-driven update methods (e.g., `on_rtp_received()`, `on_nack_sent()`)

### Phase 2: Basic Accumulators ✅ COMPLETED (as part of Phase 1)

**Status:** Completed on 2026-01-15

**Changes:**

- Renamed `src/stats/` to `src/statistics/`
- Created `src/statistics/stats/` subfolder for W3C stats types
- Moved base types (`RTCStatsType`, `RTCStats`, `RTCStatsId`, `RTCQualityLimitationReason`) to `statistics/stats/mod.rs`
- No re-exports from `statistics/mod.rs` - all imports use full paths
- Updated all import references throughout the codebase
- ✅ Implement `IceCandidateAccumulator`
- ✅ Implement `IceCandidatePairAccumulator`
- ✅ Implement `TransportStatsAccumulator`
- ✅ Implement `CertificateStatsAccumulator`
- ✅ Implement `CodecStatsAccumulator`
- ✅ Implement `PeerConnectionStatsAccumulator`

### Phase 3: RTP Stream Accumulators ✅ COMPLETED (as part of Phase 1)

- ✅ Implement `InboundRtpStreamAccumulator`
- ✅ Implement `OutboundRtpStreamAccumulator`
- ✅ Implement `RtpStreamStatsCollection`
- ✅ Add RTCP SR/RR parsing for remote stats

### Phase 4: Handler Integration ✅ COMPLETED

**Status:** Completed on 2026-01-14

**Changes:**

- ✅ Wire up ICE Handler stats collection
  - Tracks transport-level packet bytes sent/received
  - Tracks ICE state changes
  - Tracks selected candidate pair changes
- ✅ Wire up DTLS Handler stats collection
  - Tracks DTLS state changes on handshake completion
  - Tracks DTLS role (client/server)
  - Tracks SRTP cipher from DTLS-SRTP negotiation
  - Tracks TLS version and DTLS cipher
- ✅ Wire up SRTP Handler stats collection
  - Note: SRTP cipher is tracked by DTLS handler since cipher is determined during DTLS handshake
  - No additional stats needed beyond what DTLS handler provides
- ✅ Wire up Interceptor Handler stats collection
  - Parses RTCP Sender Reports (SR) for inbound stream remote stats
  - Parses RTCP Receiver Reports (RR) for outbound stream remote stats
- ✅ Wire up DataChannel Handler stats collection
  - Tracks messages sent/received with byte counts
  - Tracks data channel state changes (open/close)
  - Tracks peer connection data channel counts

#### Handler Stats Coverage Analysis

##### Demuxer Handler (`demuxer.rs`)

| Accumulator Method                    | Called | Location       | Notes            |
|---------------------------------------|--------|----------------|------------------|
| `transport.on_packet_received(bytes)` | ✅      | `handle_read`  | Raw packet bytes |
| `transport.on_packet_sent(bytes)`     | ✅      | `handle_write` | Raw packet bytes |

##### ICE Handler (`ice.rs`)

| Accumulator Method                                | Called | Location       | Notes                        |
|---------------------------------------------------|--------|----------------|------------------------------|
| `transport.on_ice_state_changed(state)`           | ✅      | `poll_event`   | On ConnectionStateChange     |
| `transport.on_selected_candidate_pair_changed()`  | ✅      | `poll_event`   | On SelectedCandidatePairChange |
| `ice_candidate_pairs.on_packet_sent()`            | ❌      | -              | Not implemented              |
| `ice_candidate_pairs.on_packet_received()`        | ❌      | -              | Not implemented              |
| `ice_candidate_pairs.on_rtt_measured()`           | ❌      | -              | Not implemented              |
| `ice_candidate_pairs.on_stun_request_*()`         | ❌      | -              | Not implemented              |
| `local_candidates` population                     | ❌      | -              | Not implemented              |
| `remote_candidates` population                    | ❌      | -              | Not implemented              |

**Note:** `ice_role` and `ice_local_username_fragment` are updated via helper methods in `internal.rs`:
- `ice_role` is set in `start_transports()` during initial connection setup
- `ice_local_username_fragment` is set in `ice_restart()` after ICE restart, reading from agent

##### DTLS Handler (`dtls.rs`)

| Accumulator Method                          | Called | Location                       | Notes                   |
|---------------------------------------------|--------|--------------------------------|-------------------------|
| `transport.on_dtls_state_changed(Connected)`| ✅      | `update_dtls_stats_from_profile` | On handshake complete |
| `transport.dtls_role`                       | ✅      | `update_dtls_stats_from_profile` | Direct assignment     |
| `transport.srtp_cipher`                     | ✅      | `update_dtls_stats_from_profile` | From SRTP profile     |
| `transport.tls_version`                     | ✅      | `update_dtls_stats_from_profile` | Hardcoded "DTLS 1.2"  |
| `transport.dtls_cipher`                     | ✅      | `update_dtls_stats_from_profile` | From `state.cipher_suite()` |
| `transport.local_certificate_id`            | ✅      | `update_dtls_stats_from_profile` | From RTCCertificate.stats_id |
| `transport.remote_certificate_id`           | ✅      | `update_dtls_stats_from_profile` | From peer cert fingerprint |
| `register_certificate()` (local)            | ✅      | `update_dtls_stats_from_profile` | DER + fingerprint     |
| `register_certificate()` (remote)           | ✅      | `update_dtls_stats_from_profile` | DER + SHA-256 fingerprint |

**DTLS Handler: 100% Complete** ✅

##### Interceptor Handler (`interceptor.rs`)

| Accumulator Method                        | Called | Location                     | Notes                      |
|-------------------------------------------|--------|------------------------------|----------------------------|
| `rtp_streams.inbound.on_rtcp_sr_received()` | ✅    | `process_read_rtcp_for_stats` | From RTCP SR              |
| `rtp_streams.outbound.on_rtcp_rr_received()`| ✅    | `process_read_rtcp_for_stats` | From RTCP RR              |
| `transport.on_ccfb_received()`            | ✅      | `process_read_rtcp_for_stats` | PT=205, FMT=11 per RFC 8888 |
| `transport.on_ccfb_sent()`                | ✅      | `process_write_rtcp_for_stats`| PT=205, FMT=11 per RFC 8888 |
| `rtp_streams.inbound.on_rtp_received()`   | ❌      | -                            | RTP packet stats not tracked |
| `rtp_streams.outbound.on_rtp_sent()`      | ❌      | -                            | RTP packet stats not tracked |
| `rtp_streams.inbound.on_nack_sent()`      | ❌      | -                            | RTCP feedback not tracked |
| `rtp_streams.inbound.on_pli_sent()`       | ❌      | -                            | RTCP feedback not tracked |
| `rtp_streams.inbound.on_fir_sent()`       | ❌      | -                            | RTCP feedback not tracked |
| `rtp_streams.outbound.on_nack_received()` | ❌      | -                            | RTCP feedback not tracked |
| `rtp_streams.outbound.on_pli_received()`  | ❌      | -                            | RTCP feedback not tracked |
| `rtp_streams.outbound.on_fir_received()`  | ❌      | -                            | RTCP feedback not tracked |

##### DataChannel Handler (`datachannel.rs`)

| Accumulator Method                         | Called | Location                     | Notes             |
|--------------------------------------------|--------|------------------------------|-------------------|
| `data_channels.on_message_received(bytes)` | ✅      | `handle_read`                | Per message       |
| `data_channels.on_message_sent(bytes)`     | ✅      | `handle_write`               | Per message       |
| `data_channels.on_state_changed(Open)`     | ✅      | `handle_read`, `handle_event`| On channel open   |
| `data_channels.on_state_changed(Closed)`   | ✅      | `handle_event`               | On SCTPStreamClosed |
| `peer_connection.on_data_channel_opened()` | ✅      | `handle_read`, `handle_event`| Counter increment |
| `peer_connection.on_data_channel_closed()` | ✅      | `handle_event`               | Counter increment |

**DataChannel Handler: 100% Complete** ✅

##### SRTP Handler (`srtp.rs`)

| Accumulator Method | Called | Location | Notes                              |
|--------------------|--------|----------|------------------------------------|
| (none)             | -      | -        | SRTP cipher tracked by DTLS handler |

##### Endpoint Handler (`endpoint.rs`)

| Accumulator Method | Called | Location | Notes                           |
|--------------------|--------|----------|---------------------------------|
| (not wired)        | ❌      | -        | Stats not passed to this handler |

#### Accumulator Field Coverage Analysis

##### TransportStatsAccumulator

| Field | Type | Collected | Handler/Location | Method/Line | Notes |
|-------|------|-----------|------------------|-------------|-------|
| `transport_id` | String | ✅ | Default impl | transport.rs:156 | Initialized as "RTCTransport_0" |
| `packets_sent` | u64 | ✅ | Demuxer | demuxer.rs:124 | `on_packet_sent()` |
| `packets_received` | u64 | ✅ | Demuxer | demuxer.rs:84 | `on_packet_received()` |
| `bytes_sent` | u64 | ✅ | Demuxer | demuxer.rs:124 | `on_packet_sent()` |
| `bytes_received` | u64 | ✅ | Demuxer | demuxer.rs:84 | `on_packet_received()` |
| `ice_role` | RTCIceRole | ✅ | internal.rs | internal.rs:904 | In `start_transports()` |
| `ice_local_username_fragment` | String | ✅ | internal.rs | internal.rs:891 | In `ice_restart()`, reads from agent |
| `ice_state` | RTCIceTransportState | ✅ | ICE | ice.rs:140 | `on_ice_state_changed()` |
| `dtls_state` | RTCDtlsTransportState | ✅ | DTLS | dtls.rs:68 | `on_dtls_state_changed()` |
| `dtls_role` | RTCDtlsRole | ✅ | DTLS | dtls.rs:71 | Direct assignment |
| `tls_version` | String | ✅ | DTLS | dtls.rs:84 | Hardcoded "DTLS 1.2" |
| `dtls_cipher` | String | ✅ | DTLS | dtls.rs:88-89 | From `state.cipher_suite()` |
| `srtp_cipher` | String | ✅ | DTLS | dtls.rs:81 | From SRTP profile |
| `selected_candidate_pair_id` | String | ✅ | ICE | ice.rs:161 | `on_selected_candidate_pair_changed()` |
| `selected_candidate_pair_changes` | u32 | ✅ | ICE | ice.rs:161 | `on_selected_candidate_pair_changed()` |
| `local_certificate_id` | String | ✅ | DTLS | dtls.rs:114 | From RTCCertificate.stats_id |
| `remote_certificate_id` | String | ✅ | DTLS | dtls.rs:144 | From peer cert fingerprint |
| `ccfb_messages_sent` | u32 | ✅ | Interceptor | interceptor.rs:99-108 | `process_write_rtcp_for_stats()` |
| `ccfb_messages_received` | u32 | ✅ | Interceptor | interceptor.rs:58-64 | `process_read_rtcp_for_stats()` |

**TransportStatsAccumulator Coverage: 19/19 fields = 100%** ✅

| Status | Count | Fields |
|--------|-------|--------|
| ✅ Fully Collected | 19 | transport_id, packets_sent/received, bytes_sent/received, ice_role, ice_local_username_fragment, ice_state, dtls_state, dtls_role, tls_version, dtls_cipher, srtp_cipher, selected_candidate_pair_id/changes, local/remote_certificate_id, ccfb_messages_sent/received |

#### Coverage Summary by Stats Category

| Category                 | Implemented | Not Implemented | Coverage |
|--------------------------|-------------|-----------------|----------|
| **Transport (bytes/state)** | 19       | 0               | 100%     |
| **ICE Candidates**       | 0           | ~10             | 0%       |
| **ICE Candidate Pairs**  | 1 (pair_id) | 7               | ~12%     |
| **DTLS/Certificates**    | 7           | 0               | 100%     |
| **Inbound RTP Stream**   | 1 (SR)      | 8               | ~11%     |
| **Outbound RTP Stream**  | 1 (RR)      | 6               | ~14%     |
| **DataChannel**          | 6           | 0               | 100%     |
| **PeerConnection**       | 2           | 0               | 100%     |
| **Codec**                | 0           | 5               | 0%       |
| **MediaSource**          | 0           | -               | App API  |

#### Priority Gaps for Future Implementation

1. **RTP packet-level stats** - `on_rtp_received()` / `on_rtp_sent()` not called anywhere
2. **ICE candidate population** - Candidates never added to accumulators
3. **RTCP feedback tracking** - NACK/PLI/FIR counts not tracked
4. **Codec stats** - Not populated from SDP/MediaEngine
5. **TWCC/congestion control** - ccfb_messages_sent/received not tracked

### Phase 5: Application Integration APIs ✅ COMPLETED (as part of Phase 1)

- ✅ Implement `DecoderStatsUpdate` and related types
- ✅ Implement `EncoderStatsUpdate` and related types
- ✅ Implement `AudioReceiverStatsUpdate` type
- ✅ Implement `AudioSourceStatsUpdate` and `VideoSourceStatsUpdate`
- ✅ Add `stats_mut()` method for application-provided stats updates

### Phase 6: Testing

- [ ] Unit tests for each accumulator type
- [ ] Integration tests for complete stats flow
- [ ] Tests for application-provided stats
- [ ] Performance benchmarks

---

## References

- [W3C WebRTC 1.0: Real-Time Communication Between Browsers](https://www.w3.org/TR/webrtc/)
- [W3C Identifiers for WebRTC's Statistics API](https://www.w3.org/TR/webrtc-stats/)
- [Pion WebRTC Stats Implementation](https://github.com/pion/webrtc/blob/master/stats.go)
- [webrtc-rs Stats Implementation](https://github.com/webrtc-rs/webrtc/tree/master/webrtc/src/stats)

# API stability policy

This document records how `rtc` and the protocol subcrates keep their public API extensible,
and the specific decisions taken before 1.0. It exists because `#[non_exhaustive]` and trait
sealing **cannot be introduced after 1.0** — adding either is itself a breaking change, so
the window closes when the major version lands.

The async wrapper keeps its own copy of this policy plus its trait decisions in
`webrtc/docs/semver.md`.

## The rule

> Mark a public enum `#[non_exhaustive]` when the set of variants is defined by something
> outside this codebase and can grow — an IANA registry, a protocol state machine, an error
> taxonomy, an event stream. Leave it exhaustive when the set is closed by construction — a
> fixed-width wire field, a binary role, a mathematically complete set — and where losing
> exhaustiveness checking would cost callers more than a future variant would.

`#[non_exhaustive]` does **not** affect matches inside the defining crate, but it does affect
that crate's examples, integration tests, and benchmarks, which are separate compilation
units. It also blocks downstream struct-literal construction of a non-exhaustive variant, and
makes an irrefutable `let` destructure of a single-variant enum illegal.

Because `rtc` re-exports all 15 protocol subcrates wholesale —

```rust
pub use {datachannel, dtls, ice, interceptor, mdns, media, rtcp, rtp,
         sansio, sctp, sdp, shared, srtp, stun, turn};
```

— their entire public surface is part of `rtc`'s public API and is frozen at 1.0 alongside it.
The subcrates are in scope for this policy, not an afterthought.

## Inventory

122 public enums, all with an explicit decision:

| Area | `#[non_exhaustive]` | Kept exhaustive |
|---|---:|---:|
| `rtc/src` | 34 | 0 |
| protocol subcrates | 69 | 19 |
| **total** | **103** | **19** |

### `rtc/src` — all 34 marked

Every directly declared enum in the core is `#[non_exhaustive]`: the W3C-facing state,
configuration, transport, statistics, event, and message enums. All of these track external
specifications (W3C WebRTC, IANA registries, RFC state machines) that add values over time.

### Protocol subcrates — kept exhaustive (19)

These are the deliberate exceptions. Each is closed by construction, and exhaustive matching
is worth more to callers than room for a variant we have no way to add.

| Crate | Enum | Why it cannot grow |
|---|---|---|
| `rtc-dtls` | `ExtendedMasterSecretType` | Request / Require / Disable — a complete policy triple. |
| `rtc-dtls` | `CryptoCcmTagLen` | CCM tag is 8 or 16 bytes. |
| `rtc-dtls` | `DtlsPadding` | Padding scheme marker. |
| `rtc-ice` | `Role` | Controlling / Controlled (RFC 8445). |
| `rtc-shared` | `EcnCodepoint` | Exactly four values in a two-bit field (RFC 3168). |
| `rtc-rtcp` | `ChunkType` | One-bit RLE discriminator. |
| `rtc-rtcp` | `TTLorHopLimitType` | Two-bit field. |
| `rtc-rtcp` | `StatusChunkTypeTcc` | One-bit field. |
| `rtc-rtcp` | `SymbolTypeTcc` | Two-bit field. |
| `rtc-rtcp` | `SymbolSizeTypeTcc` | One-bit field. |
| `rtc-rtcp` | `PacketStatusChunk` | Closed by its one-bit discriminator. |
| `rtc-media` | `Deinterleaved`, `Interleaved` | Buffer-layout markers. |
| `rtc-sctp` | `Side` | Client / Server. |
| `rtc-datachannel` | `DataChannelThreshold` | Low / High. |
| `rtc-rtp` | `CameraDirection` | Front / Back. |
| `rtc-rtp` | `VideoRotation` | 0° / 90° / 180° / 270°. |
| `rtc-sdp` | `Direction` | sendrecv / sendonly / recvonly / inactive (RFC 4566). |
| `rtc-sdp` | `ConnectionRole` | active / passive / actpass / holdconn (RFC 4145). |

### Protocol subcrates — marked (69)

Everything else, falling into four families:

- **IANA / protocol registries**, which grow by design: `CipherSuiteId`, `NamedCurve`,
  `SignatureScheme`, `HashAlgorithm`, `SignatureAlgorithm`, `SrtpProtectionProfile`,
  `ExtensionValue`, `HandshakeType`, `ContentType`, `ClientCertificateType`,
  `CompressionMethodId`, `EllipticCurveType`, `PacketType`, `SdesType`, `BlockType`,
  `PayloadProtocolIdentifier`, `MessageType`, `ChannelType`, `ProtectionProfile`,
  `H264NalUnitType`, `H265NalUnitType`, `UnitType`, `CandidateType`, `NetworkType`,
  `TcpType`, `SchemeType`, `ProtoType`, …
- **State machines**: `ConnectionState`, `GatheringState`, `CandidatePairState`,
  `RecvSendState`, `ReliabilityType`, …
- **Event streams**: `Event` (ice, turn, sctp), `EndpointEvent`, `DatagramEvent`,
  `StunEvent`, `ClientAgent`, `MdnsEvent`, `StreamEvent`, …
- **Error taxonomies**: `Error` (shared, media), `AssociationError`, `ConnectError`.

Also marked: wire sum types that gain arms when the protocol does — `Content`,
`HandshakeMessage`, `Extension`, `Message`, `Payload`, `H265Payload`, `HeaderExtension`,
`H26xNAL`, `Packet`, `CryptoPrivateKeyKind`, `NextHop`, `Kind`, `TransportProtocol`,
`IvfCodec`, `OggHeaderType`, `MulticastDnsMode`, `ClientAuthType`, `CipherSuiteHash`, and the
Windows interface-info enums in `rtc-shared::ifaces`.

## When adding a new public item

- **New public enum**: decide exhaustive-or-not *at the point of introduction* and record it
  here. After 1.0 the decision is frozen.
- **New variant on a `#[non_exhaustive]` enum**: minor release, no breakage.
- **New variant on an exhaustive enum**: major release. Reconsider the classification first.
- Matching a `#[non_exhaustive]` enum from another crate in this workspace — including from
  `rtc` onto a subcrate enum — requires a `_` arm. Prefer a fallback that degrades safely
  (skip the packet, return `Unspecified`) over `unreachable!()`.

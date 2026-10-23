# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `rtc`, from pion's renegotiation tests: a data channel added to a connection that was
  negotiated media-only never opened, because the SCTP client side was started only by the
  DTLS-handshake-complete event, which had long passed; it now starts when SCTP is started over
  a connection whose DTLS is already up. `add_track` reused a transceiver whose removal had not
  been negotiated yet, or whose remote only sends (pion `isSendAllowed`); it now creates a new
  one until the removal is settled.
- `rtc`, found by porting pion's `peerconnection_renegotiation_test.go` onto a deterministic
  in-memory network: every renegotiation replaced the receive track of a stream it already knew,
  so the next packet fired `OnTrack` again for the same track (it now fires once per track); a
  transceiver created `sendonly` (the local half of a `recvonly` offer, or one the application
  made) had no receiver, so when a later negotiation made it `sendrecv` it could never receive;
  the receiver now always exists and `RTCRtpTransceiver::receiver()` reports it while the
  direction receives.
- `rtc`, from pion's `peerconnection_go_test.go`: a remote candidate of an unknown type or
  transport (`ssltcp`) failed `add_remote_candidate` and the whole `set_remote_description`; both
  now discard it with a warning, and a description fails only when no usable candidate is left.
  An answerer holding a sender-only transceiver did not reuse it for a `sendrecv` offer and added
  a second one. `get_transceivers` no longer borrows the connection while iterated.
- `rtc`, found by porting pion's `peerconnection_test.go`: `set_configuration` applied part of a
  rejected call (it now validates everything first and changes nothing on error), accepted a
  change of the RTP header encryption policy (`ErrModifyingRTPHeaderEncryptionPolicy` now), and
  treated an unspecified bundle / RTCP-mux policy as a change; unspecified policies take their
  defaults at construction, so `get_configuration` reports what is in effect. Every description
  after the first got a random SDP origin version instead of the previous one plus one
  (RFC 9429 §5.2.2). A legacy `m=application ... DTLS/SCTP 5000` offer with `a=sctpmap` failed
  `set_remote_description` (the SCTP port was parsed as an RTP payload type) and was not treated
  as a data channel. A transceiver created from an inactive remote section was `recvonly` (it is `inactive`, as in pion).
- `rtc-dtls`, found by porting pion's `conn_test.go` onto the new handshake harness: an empty PSK
  client identity was rejected; hellos without an extension block were rejected, a ClientHello's
  session id was ignored (the parse went wrong when one was sent), trailing bytes after the
  extensions were accepted and a malformed known extension was skipped instead of rejecting the
  hello (as pion does); the server picked the SRTP profile in the client's order instead of its
  own; SNI was sent for IP literals and for names the application never configured; the
  ServerHello carried `supported_groups`; `renegotiation_info` was answered when the client had
  not offered it (the SCSV `0x00ff` is now understood); the client waited for the whole server
  flight before refusing an unsupported ServerHello version; a server holding several
  certificates always presented the first (the name map was never built and the lookup used the
  server's own name instead of the client's SNI); `ConfigBuilder::build` reports an identity
  without a PSK before a missing certificate, as pion does. `State::extended_master_secret()`
  is new.
- `rtc-interceptor`: `History` no longer downgrades an arrived packet to lost when later
  feedback says the same packet did not arrive (pion `TestHistoryArrivedIsNotDowngraded`);
  the first, positive report stands.
- `rtc-interceptor`: `convert_twcc` now stops at the feedback's declared `packet_status_count`
  and drops received symbols whose delta is missing, as pion does, instead of converting every
  chunk symbol (found by porting pion's `TestConvertTWCC`).
- `rtc-interceptor`: `convert_ccfb` merges report blocks that describe the same media SSRC
  instead of keeping only the last one (pion's `TestConvertCCFB`).
- `rtc-interceptor`: the NACK responder strips padding from RFC 4588 RTX retransmissions, as
  pion's packet factory does — the P-bit comes off and legacy payload-embedded padding is
  trimmed; a padding count larger than the payload is never buffered, so it is never
  retransmitted (pion's `TestRTPBuffer_*` padding family).
- `rtc-rtp`: `Header::get_extension` clones its payload `Bytes`, which allocates per packet in
  the `bytes` crate's promotable form; the congestion controller, the TWCC receiver/sender and
  the peer-connection demuxer now read the new borrowed `Header::get_extension_payload`
  instead (found by porting pion's `TestRecordDoesNotAllocateInSteadyState`; TWCC recording is
  now allocation-free in steady state).
- `rtc-srtp`: three pion-parity fixes found by porting pion's test suite (issue #9).
  - SRTP replay protection now windows over the full 48-bit packet index
    `roc << 16 | seq`, as pion's does, not the bare 16-bit sequence number: a replayed
    packet from a previous rollover used to look "new" again after the sequence number
    wrapped past it. `srtcp_replay_protection` likewise uses the plain sliding window over
    the 31-bit SRTCP index, so a long-behind index is too old rather than a wrap-around.
  - `Context::encrypt_rtcp` returns `ErrExceededMaxPackets` once an SSRC's SRTCP index
    reaches 2^31-1 (RFC 3711 section 9.2: rekey or end the session) instead of silently
    wrapping the index - and with it an already-spent keystream - back to 0.

### Added
- `rtc`: `RTCTrackEvent::OnClosing` and `OnClose` are now reported (they were defined and never
  sent): when a renegotiation stops announcing a receive track, its streams leave the
  interceptor chain, both events fire, and the transceiver can receive a later track with a
  fresh `OnTrack`.
- `rtc-mdns`: the DNS-SD helper layer of pion/mdns v2.2.2 `dns_sd.go` and `records.go`
  (issue #21), in the new public `dnssd` module: `ServiceInstance` with its
  `service_instance_name()`/`service_name()` derivation, `escape_instance_name` /
  `unescape_instance_name` / `parse_service_instance_name` (RFC 6763 §4.3), the
  `validate_service_*`/`validate_instance_name` rules (RFC 6763 §7), the `TxtEntry`
  key/value model with `new_txt_string`/`new_txt_binary`/`new_txt_flag` constructors and
  `encode_txt_record_strings`/`decode_txt_record_strings`/`validate_txt_entries`
  (RFC 6763 §6), and the crate-private PTR/SRV/TXT/A/AAAA record builders and parsers.
  The 70 pion tests (`dns_sd_test.go`, `records_test.go`) are ported, plus byte-compat
  vectors: nine records and record-sets packed by golang.org/x/net v0.35.0 `dns/dnsmessage`
  (the version pion pins) are reproduced byte-for-byte, compression pointers included.
  Known gap: TXT values that are not valid UTF-8 are rejected
  (`ErrTXTValueNotUtf8`) rather than carried, because the crate's TXT wire type is
  string-based (Go strings hold arbitrary bytes).
- `rtc-mdns`: the RFC 6762 §10 record cache of pion/mdns v2.2.2 `cache.go` (issue #22),
  in the new `cache` module: goodbye records (§10.1, one-second retention), the
  cache-flush bit with its one-second grace (§10.2), TTL clamping to 75 minutes, the
  80/85/90/95 % refresh thresholds of §5.2 with injected jitter, `sweep`, `reduce_ttls`,
  `flush_all`, and a 4096-entry cap evicting the soonest-to-expire record. Sans-I/O
  throughout: every method takes the `Instant` it needs and the jitter is a caller
  argument, so no clock is read and no `rand` is drawn inside the crate. The 41 pion
  `cache_test.go` tests are ported (a Go `time.Sleep` becomes advancing the injected
  instant; the goroutine race test is `na`: the cache is a single-owner `&mut self`
  type with no locks to exercise), plus the 4097-record capacity test and
  refresh-threshold tests pion has no counterpart for.
- `rtc`: `RTCConfigurationBuilder::with_always_negotiate_data_channels` (pion's
  `AlwaysNegotiateDataChannels`): offer an `m=application` section before any data channel
  exists, so the first channel created later needs no renegotiation. `set_configuration` can
  turn it on, never off, as in pion.
- `rtc-srtp`: the pion/srtp test suite is ported (issue #9): RFC 3711 appendix B.2 and
  RFC 6188 section 7.1 AES-CM keystream vectors, RFC 7714 sections 16/17 AEAD vectors
  (RTP and RTCP, both key sizes), rollover-counter and replay behaviour (replay windows,
  custom detector factories, `SetROC` burst-loss recovery, the 2^48/2^31 packet limits),
  truncated and crafted packets on both legs, the all-profiles `TestSrtpCipher` vector
  table, DTLS keying-material order, and Cryptex runtime flips on both legs.
- `rtc-dtls`: three plain-PSK cipher suites, as in pion/dtls v3.1.15:
  `TLS_PSK_WITH_AES_256_CCM_8` (`0xc0a9`, RFC 6655),
  `TLS_PSK_WITH_AES_128_CBC_SHA256` (`0x00ae`, RFC 5487) and
  `TLS_PSK_WITH_CHACHA20_POLY1305_SHA256` (`0xccab`, RFC 7905); each negotiates with pion in
  both directions over UDP and with rtc-dtls itself, with ring and with aws-lc-rs. The
  identity cases of pion's `TestPSK` now cover the three new suites too, and pion-encrypted
  records for them are decrypted as known-answer vectors. New public items: the three
  `CipherSuiteId` variants, `CipherSuiteAes256Ccm`,
  `CipherSuiteTlsPskWithAes128CbcSha256`, `CipherSuiteChaCha20Poly1305Sha256::new_psk`,
  `CryptoCbcSuite`, and the `new_cipher_suite_tls_psk_with_*` constructors.
- `rtc-crypto`: `AeadAlgorithm::Aes256Ccm8` and `CbcAlgorithm::Aes128Cbc`, implemented for both
  providers (ring and aws-lc-rs) with NIST known-answer vectors and cross-provider
  interoperability tests. `CryptoCcm` now selects the AES variant from the key length, as
  pion's `aes.NewCipher` does; `CryptoCbc` is parameterized over the cipher and record-MAC
  pairing, so AES-128-CBC with HMAC-SHA-256 (RFC 5487) sits beside AES-256-CBC with HMAC-SHA-1.
- `rtc-dtls`: ALPN (RFC 7301) as in pion/dtls: `ConfigBuilder::with_supported_protocols`, `State::negotiated_protocol`, the `alpn` extension, and the fatal `no_application_protocol` (120) alert when both sides offer protocols and none is shared. Verified both ways against pion/dtls v3.1.15 over UDP. New error variants `ErrAlpnInvalidFormat` and `ErrAlpnNoAppProto` in `rtc-shared`. New integration-test harness `rtc-dtls/tests/common` (two endpoints on a lossless in-memory network, with datagram tampering and alert capture).
- `rtc-interceptor`: pion's interceptor test suite is ported (issue #15): the twcc recorder
  (full feedback content, rolling wrap, min input, counts, duplicates, short and reordered
  deltas, chunk boundaries), the arrival-time map (erase/grow/shrink), the TWCC feedback
  receiver subtests, the nack generator/responder scenarios (exact NACK content with
  `skip_last_n`, stream filters, unbind, bypass, RTX exact sets), flexfec (decoder retention,
  multi-stream protection, whole-range and high-count round trips), RFC 8888 stream-log
  vectors, CCFB ingestion at the estimator, and a steady-state allocation test. The
  `interceptor` ledger is now `todo`-free: 111 `rust`, 27 `na`, 2 `gap`.
- `rtc-interceptor`: `NackGeneratorBuilder::with_streams_filter` /
  `NackResponderBuilder::with_streams_filter` (pion's `GeneratorStreamsFilter` /
  `ResponderStreamsFilter`) and `try_build` on both, which rejects an unusable buffer size
  with the new `ErrNackInvalidSize` where the infallible `build` stays inert.
- `rtc-rtp`: `Header::get_extension_payload`, the borrowed form of
  `Header::get_extension`.
- `rtc-stun`: pion/stun v4.0.1 attribute and error tests ported, plus the allocation budget suite.
  `tests/allocations.rs` (pion `TestAllocations`/`TestAllocationsGetters`) counts allocations
  through a `#[global_allocator]` wrapper: header-only setters and all getters are
  allocation-free on the steady-state path, attribute-adding setters perform exactly one
  (rtc-stun's attribute table owns a copy of the value; pion's borrows the message buffer).
  `tests/pion_ported.rs` ports the XORMappedAddress suite (GetFrom with UnexpectedEOF/
  overflow/short-value subtests, invalid family, AddTo round-trips for IPv4 and IPv6,
  String), the ERROR-CODE suite (truncated value, round-trip, no-default-reason, too-long
  reason, invalid code, reserved bits masked on read) and the error-identity, UNKNOWN-ATTRIBUTES
  encoding, invalid-cookie and reserved-type rows. Fixed: `Message::grow` allocated a temporary
  zeroed Vec on every regrow after `reset` (the reset/write path is now allocation-free);
  `XorMappedAddress::add_to_as`, `TextAttribute::get_from` (now reusing its String's capacity),
  `UnknownAttributes::add_to` and `ErrorCodeAttribute::add_to` allocated per call;
  ERROR-CODE codes whose class digit exceeds the 3-bit field are rejected with the new
  `ErrInvalidErrorCode` instead of being silently truncated.
- `rtc-sdp`: port pion/sdp v3.0.20 unit tests, malformed-input table and robustness suite
  (origin tolerance, S1..S16 key scenarios, JSEP builders, extmap errors and round-trip,
  codec lookups, 1 MiB line / 50k attributes / 10k m= sections / 100k CRLF lines / invalid
  UTF-8 / missing final newline never panic). Fixed: extmap URIs with invalid percent escapes
  (`%zz`) are rejected as in pion.
- `rtc-rtp`: RFC 8285 header-extension API parity with pion v1.10.6. `Header` gains
  `clear_extensions` (pion `ClearExtensions`) and `set_extension_with_profile` (pion
  `SetExtensionWithProfile`: profile upgrade/downgrade with re-encoding, refusing downgrades an
  existing extension cannot fit); `Packetizer` gains `generate_padding` (pion `GeneratePadding`:
  payload-less, 255-octet-padding packets at the latest timestamp). pion's
  `header_extension_test.go` (13 tests), the missing `packet_test.go` rows (14: ClearExtensions,
  padding-with-size termination, extension-without-payload, clones, marshal funcs, padding
  initialization, panic regressions), `sequencer_test.go` (6, incl. concurrency), the missing
  `packetizer_test.go` rows (roundtrip, generate-padding, empty payload) and the missing
  extension-helper tests (MarshalTo, playout-delay edge cases) are ported. Fixed: deleting the
  last extension now clears the extension flag and profile (pion behaviour); a raw-profile
  header with no extensions marshals as an empty block instead of erroring (pion issue #315);
  `new_random_sequencer` draws its start from the lower half of the sequence space (pion's
  `maxInitialRandomSequenceNumber`, needed for SRTP after loss).
- `rtc-media`: Ogg writer/reader parity with pion v4.2.24's `pkg/media/oggwriter`/`oggreader`.
  The writer gains the multiplexed API: `MultiTrackOggWriter`/`SeekableMultiTrackOggWriter`
  (pion's `Writer` + `WithSeekableOutput`) with per-track SSRC routing, duplicate-SSRC/serial
  rejection, lazy header start, `TrackOptions` (serial, sample rate, channel count/mapping,
  OpusTags overrides), `SeekableOggWriter` (pion's file-backed writer: close rewrites the last
  page with EOS), explicit channel-mapping families 1/2/255 with pion's validation,
  `OpusTags`/`UserComment` with vendor/user-comment validation, and Opus-duration granule
  positions (pion's `opusPacketSampleCount`) instead of RTP timestamp deltas. The reader
  gains exact per-family payload-length validation, the comment-count bound and
  missing-`=` rejection in `parse_opus_tags`, and `bytes_read` tracking. All 45 pion
  oggwriter/oggreader tests are ported. Fixed: payloads over 255*255 bytes corrupted the
  page segment count (`u8` overflow); the reader accepted OpusTags with an impossible comment
  count (unbounded allocation) and silently dropped comments without `=`.
- `rtc-media`: `fuzz/` with `ogg_reader`, `opus_head` and `opus_tags` targets (cargo-fuzz).
- `rtc-shared`: Ogg writer/reader error variants (`ErrInvalidChannelCount`, `ErrInvalidChannelMap`,
  `ErrInvalidOpusTags`, `ErrDuplicateTrackSSRC`, `ErrDuplicateTrackSerial`, `ErrTracksStarted`,
  `ErrPacketSSRCMismatch`, `ErrInvalidOpusPacket`, `ErrOutputNotOpened`).
- `rtc-sctp` + `rtc`: four SCTP congestion/timer tuning knobs, mirroring pion's
  `SettingEngine.SetSCTPRTOMax` / `SetSCTPMinCwnd` / `SetSCTPFastRtxWnd` / `SetSCTPCwndCAStep`.
  `TransportConfig::{with_rto_max, with_min_cwnd, with_fast_rtx_wnd, with_cwnd_ca_step}`
  (zero/unset = today's behaviour exactly: rto_max defaults to the RFC 9260 60 s, min_cwnd
  keeps the `cwnd = MTU` / `cwnd = ssthresh` resets, fast_rtx_wnd keeps the one-MTU
  fast-retransmit budget, cwnd_ca_step keeps `cwnd += MTU` in congestion avoidance), and
  `SettingEngineBuilder::{with_sctp_rto_max, with_sctp_min_cwnd, with_sctp_fast_rtx_wnd,
  with_sctp_cwnd_ca_step}` forwarding into the association's transport config. pion's
  `TestRTOManager` and `TestRtxTimer` (rtx_timer_test.go) are ported, plus one behaviour
  test per knob.
- `rtc-interceptor`: `PacketDump`, the belt-shaped port of pion's `interceptor/pkg/packetdump`:
  one interceptor sees both directions and forwards every packet unchanged, while writing a
  line per RTP/RTCP packet through pluggable filters, formatters and a `PacketDumpSink`
  (default: the packet's `Display` plus a newline, to `log::debug!`). New `Slot::PacketDump`
  (0), the wire-most slot: the dump sees departures after pacing and numbering, and arrivals
  before recovery and re-stamping. The nine pion packetdump tests are ported, plus forwarding,
  filter-cost, ordering and registry-placement tests.
- `rtc-interceptor`: `PacketDumpBuilder::rtcp_compound_filter` (pion's `RTCPFilter`), `rtp_binary_formatter` / `rtcp_binary_formatter` and `PacketDumpSink::write_bytes` (pion's binary format callbacks); a binary formatter turns the default text line off, as in pion.
- `rtc-media`: rtpdump reader and writer (`io::rtpdump`), byte-compatible with pion's
  `pkg/media/rtpdump` (preamble, binary header, packet records). New public items:
  `rtpdump::{Header, Packet, Reader, Writer}`; two `ErrRtpDump*` variants in `rtc-shared`.
  Two strictnesses beyond pion, both from the issue: records whose `plen` exceeds their length
  and records with empty payloads are rejected.
- `rtc-rtp`: H.266/VVC payloader and depacketizer ([RFC 9328]), byte-compatible with pion's
  `H266Packetizer`/`H266Depacketizer` (aggregation packets, fragmentation units, DONL handling).
  The 320 H.266 rows of the pion golden corpus now run, and pion's 13 `TestH266*` unit tests
  are ported. New public items: `codec::h266::{H266Payloader, H266Depacketizer, H266NALUHeader}`.
- `rtc-shared`: H.266 error variants (`ErrH266*`).

[RFC 9328]: https://datatracker.ietf.org/doc/html/rfc9328

### Fixed
- `rtc-dtls`: a PSK client with an empty identity was refused with
  `ErrInvalidClientKeyExchange`; an empty identity is legal (pion's `TestPSK` "Client identity
  empty" case) and now marshals as the two zero length bytes.
- `rtc-dtls`: `ConfigBuilder::build` checked `ErrServerMustHaveCertificate` before
  `ErrIdentityNoPsk`, so a server configured with an identity but no PSK and no certificate
  reported the wrong error; as in pion's `validateConfig`, the identity-without-PSK check now
  comes first (pion's `TestPSKConfiguration` "No PSK and identity specified" case).

### Changed (breaking, hence 0.22.0)
- `rtc-rtp`: `Header` gains `padding_size`; `HevcPayloader` is a struct with parameter-set state.
- `rtc-sctp`: `PayloadProtocolIdentifier` is a struct (it carries unknown values), not an enum.
- `rtc-media`: `OggWriter::new` takes `channel_count: u16` (pion rejects counts that wrap `u8`);
  granule positions advance by each packet's Opus duration (pion parity) instead of RTP timestamp
  deltas; `close` on an append-only output no longer duplicates the last payload as an EOS page
  (that corrupted streams; a proper EOS needs the seekable writers); `ogg_reader::UserComment`
  and `OpusTags` implement `PartialEq`/`Eq`.

### Added
- `rtc-turn`: a Sans-I/O **TURN server** (`rtc_turn::server`). Long-term credentials with
  verifiable nonces (stale-nonce `438`), allocations over UDP with IPv4 and IPv6 relays, Refresh,
  CreatePermission (all-or-nothing), ChannelBind, Send/Data indications and ChannelData, quotas,
  permission filtering, time-limited shared-secret credentials, `420` for unknown
  comprehension-required attributes, and an idempotent answer to a retransmitted Allocate. The
  application binds the relay sockets (`ServerEvent::BindRelay`). `proto::framing::frame_length`
  delimits messages on TCP and TLS streams. Interoperates with pion in both directions
  (`interop/run-turn.sh`).
- `rtc-mdns`: `MulticastSocket` joins the group on every local IPv4 interface, and
  `multicast_interfaces` / `is_route_error` / `set_multicast_interface` let a driver retry a send
  that the default multicast route refuses (a virtual NIC with no multicast route).
- `rtc-turn`: `EvenPort::new` and `EvenPort::reserve_port`.

### Fixed
- `rtc-rtp`: `Packet::unmarshal` of a `Bytes` takes one handle on the datagram instead of two
  extra reference counts.

### Security / hardening (ported from pion's tests)
- DTLS: the handshake fragment buffer is bounded in fragment count and bytes and reassembles
  overlapping retransmits; the handshake cache and the next-epoch packet queue are bounded.
- SCTP: DATA more than a bounded number of TSNs ahead of the cumulative TSN is not queued.
- RTCP: a maximum-length FIR or transport-wide CC packet no longer overflows the parser; marshal
  refuses packets the 16-bit length cannot describe, and NACKs may list up to that many pairs.
- Data channels: an OPEN message with a label or protocol over 65535 bytes is refused, not truncated.


### Security

- **SRTCP accepted forged packets with the E bit clear.** The authentication tag was only checked
  for encrypted SRTCP, so anyone able to send a datagram could inject RTCP (BYE, PLI, REMB, …) into
  a session. The tag is now verified before the E bit is looked at.
- **SRTP and SRTCP no longer allocate per-SSRC state before a packet authenticates.** The SSRC is
  read from an unauthenticated header, so spraying random SSRCs used to grow the receiver's memory
  without bound; state is now created only for an SSRC that has delivered an authentic packet.
- SRTP located the payload with the *re-marshalled* header size rather than the size on the wire, so
  a packet whose extension block was padded by the sender was encrypted from the wrong offset.
- Remotely triggerable panics fixed: SCTP error causes, the DCEP threshold parser, AV1 payloading
  and OBU parsing, RTCP SLI, and VP9 scalability-structure parsing.

### Added (transport performance)

- **RACK-TLP loss detection for SCTP** ([RFC 8985]; `TransportConfig::with_enable_rack`, on by
  default). A chunk is declared lost once a chunk sent after it has been delivered and a round
  trip plus a reordering allowance has passed, and a tail-loss probe re-sends the newest
  outstanding chunk after about two round trips of silence. Before, a lost tail left nothing to
  open a gap, so recovery waited for T3-rtx — one second at minimum, with the congestion window
  collapsed to one MTU. On a path that drops a few datagrams per second that was most of the
  throughput: over loopback on Linux, a 256 MiB transfer ran at 25–45 MiB/s and now runs at
  110–190 MiB/s. `AssociationStats` gains `get_num_rack_losses` and `get_num_pto_probes`.
- **Window-update SACK.** When the application drains a receive buffer that had been advertised
  as (nearly) full, the receiver now reports the reopened window at once (RFC 9260 §6.2) instead
  of leaving a stopped sender to find out from its next zero-window probe — a retransmission
  timeout away. Every transfer whose reader started a moment after the sender used to lose a
  second to this.

[RFC 8985]: https://datatracker.ietf.org/doc/html/rfc8985

- **`RTCDataChannel::outstanding_bytes_handle()` and `data_channel::OutstandingBytes`.** A cheap,
  clonable, lock-free view of a channel's outstanding send bytes (`get()`, plus `is_detached()` once
  the channel is gone). `outstanding_bytes()` itself is unchanged. A driver that keeps the core
  behind a lock can sample the handle without taking it, so an application polling for send room no
  longer contends with the I/O loop that is making room: on Linux the poll-style data-channel
  benchmark was spending most of its time waiting for that lock.
- The data-channel registry and the per-channel statistics are keyed with `FxHashMap` rather than
  SipHash: their keys are connection-local handles and SCTP stream ids, looked up for every
  acknowledged chunk.
- **`rtp::packet::PacketView`**, a borrowed, allocation-free parse of an RTP packet: the header
  fields, the CSRC list, the extension elements (`extension(id)`, `extensions()`) and the payload,
  all read from the datagram it was parsed from. `parse` accepts and rejects exactly what
  `Packet::unmarshal` does (a differential test holds it to that on 20,000 random inputs). It takes
  10 ns on a 1200-byte packet with three extensions, against 60 ns for an owned `Packet` and 26 ns
  for `Packet::unmarshal_reuse`: the owned forms pay for reference-counted payloads, which a packet
  that is inspected and forwarded never needed.
- `Packet::unmarshal_reuse` fills in one pass when the packet already owns an extension table
  (30 ns to 26 ns).
- SDP marshalling writes `m=`, `o=`, `c=` and `b=` lines piece by piece instead of through
  `format_args!`, and sizes its output from the attribute count; and the output goes through a small
  text writer that copies short pieces inline instead of calling `memcpy` for each. A browser offer
  marshals in 3.4 µs, down from 5.6 µs (pion: 4.2 µs). The writer is the only `unsafe` in `rtc-sdp`;
  it is Miri-clean and tested at every piece length.

### Changed (breaking)

- SDP `Attribute::key` and `Attribute::value` are `smol_str::SmolStr` instead of `String`. Text up
  to 23 bytes is stored inline, so parsing a browser offer allocates 219 times instead of 902 and
  runs in about 20 µs (pion: 23 µs). They dereference to `&str` and compare equal to `&str` and
  `String`; `Attribute::new` still takes `String`s, and `Attribute::from_parts` takes anything
  convertible. `SessionDescription::attribute` returns `Option<&str>`.

### Added

- **Differential tests against pion.** Every protocol parser — SDP, RTCP, RTP (and the codec
  depacketizers/payloaders), STUN, SCTP, DCEP, DTLS records, SRTP — is checked against pion's own
  verdicts and parsed fields on corpora of valid and mutated inputs harvested from pion's tests
  (`tests/pion_golden.rs`, regenerated with the Go oracle in `tests/oracle/`). Where we deliberately
  differ because pion is wrong (for example pion's H.265 payloader hangs at an MTU of 3 and its PACI
  accessor mis-parses the A bit), the test names the divergence.
- RTCP `ApplicationDefined` (APP) packets, `SdesType::Unknown`, and the SDP lexer/state machine are
  now ports of pion's, so malformed input is accepted and rejected the same way.
- `rtp::Header::peek` reads the routing fields of an RTP header without allocating, accepting and
  rejecting exactly what `Header::unmarshal` does; `Packet::unmarshal_reuse` parses into an existing
  packet and allocates nothing in steady state.
- `rtc_srtp::Context::{encrypt_rtp_into, decrypt_rtp_into}` append to a caller-owned buffer, so a
  send or receive loop that keeps one `BytesMut` allocates nothing per packet.
- `rtc_stun::Message::{get_value, build_with}` and `Attributes::find` borrow instead of copying and
  boxing.
- New fuzz targets: RTP depacketizers and payloaders, `Header::peek` against `Header::unmarshal`,
  SRTP/SRTCP unprotect and round trip, and DCEP.
- `benchmarks/pion-compare`: the same micro-benchmarks run against this workspace and against pion,
  side by side, with gates (see `docs/ci.md`).
- CI on Linux and macOS, x86-64 and arm64: see `docs/ci.md`.

### Changed

- **Hardware AES and SHA-1 everywhere, with no build flags.** `aes` 0.9, `ctr` 0.10, `ccm` 0.6,
  `sha1` 0.11, `hmac` 0.13 and `md-5` 0.11 detect the CPU's AES/SHA instructions at run time on
  aarch64 and x86-64. Before this, a downstream build on Apple silicon or Linux/arm64 silently used
  the software implementations unless it passed `--cfg aes_armv8`, which only worked inside this
  repository (`.cargo/config.toml` is not inherited by dependents). The AES-CTR key schedule is now
  expanded once per context rather than once per packet. SRTP AES-CM-HMAC-SHA1 is about 2.3×
  faster than before and about 2× faster than pion on the same machine.
- The workspace declares `rust-version = "1.91"`.
- Faster parsing and marshalling: RTCP compound packets, H.264 payloading (SIMD start-code
  search), SDP marshalling and codec-map construction, STUN decode and build.

### Fixed

- Many parse paths now agree with pion where we differed: RTP header/extension/padding validation,
  RTCP header lengths on re-marshal, TWCC status vectors, SDP fields and numeric ranges, STUN
  attribute ordering after MESSAGE-INTEGRITY, SCTP unknown PPIDs and reconfiguration results.

### Added

- **SCTP zero checksum (RFC 9653)**: `TransportConfig::with_enable_zero_checksum` advertises the capability (parameter 0x8001, EDMID 1, byte-compatible with pion/sctp) and accepts zero-checksum packets on the DTLS-protected association; the send side arms when the peer advertises back, and then skips the CRC-32C on the DATA/SACK/FORWARD-TSN hot paths. INIT and COOKIE ECHO stay checksummed per section 5; a zero-checksum packet reaching an association that never enabled it is dropped.
- **DTLS key logging**: `ConfigBuilder::with_key_logger` receives the NSS key log line once the master secret is derived, on both client and server ends — and both ends of the same association log the identical line, which is the property that makes the log usable.
- **sctp-transport stats entry** read live from the SCTP association (smoothed RTT, congestion window, receiver window, MTU, bytes sent/received), matching pion's `SCTPTransportStats`; `AssociationStats` gains byte counters (counted once per accepted DATA chunk, retransmissions not double-counted) and the association exposes `cwnd()`, `rwnd()`, `mtu()` alongside `rtt()`.
- **csrc stats entry** per (inbound stream, CSRC) with `packetsContributedTo`. `getContributingSources` / `getSynchronizationSources` were stubs returning empty lists; receivers now record CSRCs/SSRC per packet (RFC 3550 section 5.1) with a 10-second memory window, per-packet counting, and per-receiver origin timestamps.

### Added

- `RTCCrypto::new_hmac` returns a keyed `Mac` whose key schedule is derived once, mirroring the
  existing keyed cipher factories. It replaces the removed one-shot `hmac`/`verify_hmac`.
- **New `rtc-crypto` crate: a provider-neutral cryptographic API**
  ([webrtc#839](https://github.com/webrtc-rs/webrtc/issues/839),
  [rtc#128](https://github.com/webrtc-rs/rtc/issues/128)). `RTCCryptoProvider` bundles an
  `RTCCrypto` operations trait and an `RTCRandom` CSPRNG. Two built-in providers ship,
  `RingProvider` and `AwsLcRsProvider`, and applications can supply their own — for OpenSSL, a
  FIPS-validated module, an HSM, or a platform backend — by implementing the public traits. A
  reusable conformance suite (`rtc_crypto::conformance::assert_provider`, behind the
  `test-support` feature) validates any implementation against the same RFC vectors the built-ins
  pass.
- `SettingEngine::set_crypto_provider` selects the provider per peer connection. Two peer
  connections in one process may use different providers. There is no process-global provider to
  install.
- Explicit provider constructors on the standalone protocol crates:
  `rtc_dtls::ConfigBuilder::with_crypto_provider`, `rtc_srtp::Context::new_with_provider`, and
  `MessageIntegrity::{new_raw,new_short_term,new_long_term}_integrity_with_provider`.
- Provider-neutral certificate construction: `RTCCertificate::generate`,
  `RTCCertificate::generate_from_signing_key`, and `RTCCertificate::from_pkcs8`.
  `rcgen::CertificateParams` is re-exported from `rtc::peer_connection::certificate`, so callers
  no longer need a direct `rcgen` dependency to name it.
- DTLS record-protection benchmarks (`cargo bench --package rtc-dtls --bench record_protection`)
  and SRTP AEAD plus context-construction benchmarks, all reporting each enabled provider under
  identical inputs and separating one-time key-schedule cost from per-packet cost.

### Changed

- **No library code resolves a default crypto provider.** `crypto::default_provider()` is now
  called in exactly one place — peer-connection construction — where the application either
  supplied one via `SettingEngine::set_crypto_provider` or gets the feature-selected built-in.
  Every constructor below that takes an `Arc<dyn RTCCryptoProvider>` from its caller, so a
  `--no-default-features` build fails at configuration time instead of deep inside a handshake.
  The `*_with_provider` constructor pairs are collapsed into single provider-taking constructors
  (`Context::new`, `Client::new`, `Agent::new`, `Certificate::generate_self_signed`,
  `Certificate::from_pem`, `RTCCertificate::from_pem`, `RTCCertificate::get_fingerprints`, the
  `MessageIntegrity` constructors). `Default` impls that resolved a provider — `HandshakeConfig`,
  `rtc_dtls::State`, `Agent`, `RTCDtlsTransport` — are removed in favour of those constructors,
  and `ConfigBuilder::build` errors when no provider was configured rather than inventing one.
- Each protocol crate re-exports the crypto API (`rtc_srtp::crypto`, `rtc_stun::crypto`,
  `rtc_ice::crypto`, `rtc_turn::crypto`, `rtc_dtls::crypto_provider`) so standalone users can name
  `Arc<dyn RTCCryptoProvider>` without a direct `rtc-crypto` dependency.
- **`crypto-ring` and `crypto-aws-lc-rs` Cargo features are now additive.** Enabling both builds successfully
  and is covered in CI. Previously each of `rtc`, `rtc-dtls`, `rtc-srtp`, and `rtc-stun` carried a
  `compile_error!` rejecting the combination, which made an otherwise valid build fail whenever
  Cargo feature unification pulled in both. `rtc_crypto::default_provider()` still prefers `ring`
  when both are enabled, so default behaviour is unchanged.
- DTLS, SRTP, STUN, ICE, TURN, and the top-level `rtc` crate perform all cryptography through the
  configured provider. Protocol composition is unchanged and stays in its own crate: the TLS 1.2
  PRF in DTLS, SRTP key derivation and packet layout in SRTP, STUN integrity framing in STUN.
  Default algorithm selection and wire behaviour are unchanged.
- `rtc_dtls::State::export_keying_material` is now an inherent method returning `SecretVec`, and
  `rtc_srtp::Config::set_session_keys_from_keying_material` consumes the exported bytes. The
  top-level crate performs the handoff, so `rtc-srtp` and `rtc-dtls` remain independent of each
  other. `rtc_srtp::config::LABEL_EXTRACTOR_DTLS_SRTP` is now public for standalone callers.
- `rtc_stun::MessageIntegrity` changed from a public tuple struct to named fields and now holds
  its provider, because `Setter::add_to` and `check` have no parameter through which to receive
  one. Its key is stored as a `SecretVec`.
- **`MediaEngine::register_default_codecs` no longer registers `video/ulpfec`**
  ([#837](https://github.com/webrtc-rs/webrtc/issues/837)). The receive path does not recover
  media from ULPFEC packets, so offering the codec invited peers to send repair packets that
  could not be used. Applications that want it can still register it explicitly with
  `MIME_TYPE_ULP_FEC`, which remains public. **This changes the default offer's SDP**: payload
  type 116 is no longer present. ULPFEC will return to the defaults once receive-side recovery
  is implemented.
- Upgrade `nix` to the newer version that allow compile `ohos` targets.

### Fixed

- **Connect latency: the first DTLS flight no longer waits on a later flush, and can no
  longer overtake the ICE nomination.** When the controlling side's ICE selects a pair,
  the DTLS handler's `connect` buffers the ClientHello inside the endpoint; nothing in
  that event drained it, so the first flight waited for the driver's write drain of a
  later iteration — a ~200 ms tick on the wire. The handler now pumps the flight into
  its `write_outs` the moment `connect` returns, so it leaves on the same iteration's
  drain. Flushing it early resurfaces an ordering hazard the tick flush had been
  masking: the ClientHello could overtake the ICE nomination (USE-CANDIDATE) ahead of
  it, reach a peer whose pair was not yet selected, and be dropped — a full 1 s DTLS
  retransmit cycle. The ICE handler therefore front-inserts its agent's transmits in
  `poll_write`: the control plane stays first on the wire, its own order preserved.
  Measured end-to-end connect (in-process loopback, 20 rounds): median 204 ms → 2 ms.

### Deprecated

-

### Removed

These are deliberate pre-1.0 API removals, not behaviour changes. Every entry has a replacement;
see `docs/crypto-provider-migration.md` for before/after examples.

- Removed the partial `openssl` and `vendored-openssl` Cargo features from `rtc-srtp` and `rtc`; SRTP cryptography now uses the selected `rtc-crypto` provider for every protection profile. They selected only an alternate AES-CTR path and never implemented the full provider contract. An OpenSSL backend can return as a complete downstream `RTCCryptoProvider`.
- Removed `rtc_shared::crypto::KeyingMaterialExporter`. `rtc-shared` performs no cryptography and
  no longer carries a crypto bridge.
- Removed `rtc_srtp::Config::extract_session_keys_from_dtls`; use
  `set_session_keys_from_keying_material` with material exported from the DTLS session.
- Removed the default-resolving `MessageIntegrity::{new_raw_integrity, new_short_term_integrity,
  new_long_term_integrity}` constructors and the derived `Default` impl. `Default` produced a
  credential with an empty key, which is never valid; use the `_with_provider` constructors.
- Removed `rtc_dtls::crypto::CustomSigner` and `CryptoPrivateKey::from_custom_signer`. Implement
  `rtc_crypto::SigningKey` and use `CryptoPrivateKey::from_signing_key`. This is a superset of the
  old capability: non-exportable HSM and KMS keys are supported, and `to_pkcs8_der()` returns
  `Ok(None)` for them instead of fabricating key bytes.
- Removed `CryptoPrivateKey::from_key_pair`, its `TryFrom<&rcgen::KeyPair>` impl, and the
  `serialized_der` field.
- Removed `RTCCertificate::from_key_pair` and `from_key_pair_with_provider`; use
  `RTCCertificate::generate` or `generate_from_signing_key`.
- Removed the `Sec1`, `P256`, `RcGen`, `AesGcm`, and `Aes` variants from `rtc_shared::Error`,
  along with the `sec1`, `p256`, `rcgen`, `aes`, and `aes-gcm` dependencies of `rtc-shared`. These
  put crypto-crate types in the public API of every crate in the workspace and pinned their major
  versions there. Crypto failures now cross crate boundaries as `Error::Crypto(String)`.
- Removed `RTCCrypto::hmac` and `RTCCrypto::verify_hmac`. They are exactly
  `new_hmac(..)?.sign(..)` and `new_hmac(..)?.verify(..)`, and retaining them preserved a path
  that re-derives the HMAC key schedule on every call.
- Removed the four duplicated `compile_error!` backend guards and the four
  `extern crate aws_lc_rs as ring;` aliases.

### Fixed

- `rtc-crypto`'s AES-CTR keystream now uses a batched implementation instead of one
  `encrypt_block` call per 16-byte block, which defeated AES-NI / ARMv8 instruction pipelining.
  Roughly 9-10% faster on a 1200-byte SRTP payload.
- **SRTP no longer derives the HMAC key schedule on every packet.** `RTCCrypto::new_hmac` returns
  a keyed `Mac`, and `rtc-srtp` keys its SRTP and SRTCP MACs once per context instead of passing
  raw key bytes per packet. Roughly 40% faster per RTCP packet and 7% per 1200-byte RTP packet.
  A counting provider in `rtc-srtp/tests/provider_profiles.rs` guards the invariant.
- **DTLS CBC no longer derives its record MAC key on every record.** `CryptoCbc` holds two keyed
  `Mac` objects instead of passing raw key bytes to `prf_mac` per record: ~4% faster on encrypt and
  ~7% on decrypt, with the key schedule moving to epoch setup.
- STUN `MESSAGE-INTEGRITY` was measured against its pre-migration baseline and shows no regression
  (see `rtc-stun/benches/README.md`); it already used `ring`'s HMAC-SHA1 before G3.
- **The built-in `RTCRandom` implementations no longer read the operating system on every call.**
  DTLS generates a GCM explicit nonce and a CBC record IV per record; routing those through the
  backend's `SystemRandom` cost ~829 ns on `ring` and ~2196 ns on `aws-lc-rs`, against ~8 ns for
  the thread-local CSPRNG the pre-provider code used. They now use an OS-seeded, periodically
  reseeded thread-local CSPRNG, as BoringSSL and OpenSSL do internally. `SystemRandom` is still
  used where the backend owns the operation — keypair generation and signing. DTLS GCM encryption
  went from 1.015 µs to 262 ns per record. A deployment needing validated entropy everywhere
  supplies its own `RTCRandom`.
- **The `ring` provider composes RustCrypto's HMAC-SHA1.** `ring` exposes SHA-1 only as
  `HMAC_SHA1_FOR_LEGACY_USE_ONLY` and does not use the ARMv8 SHA-1 instructions: 4469 ns against
  RustCrypto's 1373 ns over a 1212-byte message. The built-in providers are already composite —
  AES-CTR, CCM, CBC and MD5 come from RustCrypto — so HMAC-SHA1 is composed the same way. This
  closes the gap without making `aws-lc-rs` the default, which would impose the `aws-lc-sys` C
  toolchain on every downstream build. SHA-256 stays on `ring`; `aws-lc-rs` keeps its own SHA-1.

**Net effect: every per-packet and per-record benchmark is at parity with or faster than the
pre-migration baseline on the default provider.** SRTP AES-CM/HMAC RTP encryption 1.725 µs before
and 1.723 µs after; DTLS GCM record encryption 270.5 ns before and 270.1 ns after; DTLS CBC 6-8%
faster than before. Context and epoch setup costs rose, which is the intended trade — key
schedules moved off the per-packet path. See the three `benches/README.md` files for the full
tables and methodology.

- Add RSA as an allowed private key kind in rtc_dtls::ConfigBuilder::
  validate- [PR #141](https://github.com/webrtc-rs/rtc/pull/141)

### Security

-

## [0.20.0] - 2026-07-31

### Added

- The `rtc` v0.20.0 is Sans-I/O protocol core with complete WebRTC stack (95%+ W3C API compliance)

[Unreleased]: https://github.com/webrtc-rs/rtc/compare/0.20.0...HEAD

[0.20.1]: https://github.com/webrtc-rs/rtc/compare/0.20.0...0.20.1

[0.20.0]: https://github.com/webrtc-rs/rtc/releases/tag/0.20.0

# Memory and performance issues

Analysis date: 2026-09-21.

Reviewed revision: `0e5393a8208879b9e07461bb31da9456a664b4a7`.

Scope: the peer-connection packet pipeline, SRTP, SCTP, DTLS, ICE, media sample
assembly, and interceptors. The
findings below combine source inspection with isolated release-build allocation
probes. They are not an end-to-end performance profile, and no throughput or
latency improvement has yet been measured. All issues are open.

**Status (2026-09-21):** all 15 issues were validated. 13 are fixed; issues 3 and 6 are partly
fixed, as described in their Resolution sections. Allocation and retained-heap measurements
are in each issue. Timings are still to come from `python3 scripts/bench.py upstream --rounds 3`,
which compares this fork with upstream webrtc-rs/rtc; upstream matches the pre-fix code everywhere
except `rtc-sctp`.

## Priorities

Address unbounded admission and incomplete resource accounting in issues 1, 9,
and 10 first. Issues 2 and the header-aware API change in 4 are small, concrete
allocation reductions. Prioritize issue 8 for applications that instantiate many
sample builders. Measure pipeline, routing, and the remaining CPU improvements
before committing to larger refactors.

| Issue | Opportunity | Evidence / expected benefit |
| --- | --- | --- |
| 1 | Avoid retaining state for rejected SRTP packets | Measured 1,551,752 bytes retained after 10,000 rejected packets with distinct SSRCs |
| 2 | Remove unused SCTP working buffer | Saves 64 KiB per started transport by default, up to 256 KiB at the configured maximum |
| 3 | Bound backlogs by bytes | Current 256-message receive limit permits 16 MiB of payload at the default message-size limit |
| 4 | Reuse RTP headers and encrypt owned buffers | Measured encryption allocations fall from three to one per packet with one RTP extension when using the existing header-aware API |
| 5 | Reuse pipeline scratch queues | Removes repeated temporary queue allocations; CPU benefit needs measurement |
| 6 | Cache negotiated routing metadata | Avoids repeated string allocation and transceiver scans, especially with many tracks |
| 7 | Bound retransmission history by bytes and age | Reduces retained payload storage; also bounds work when sequence numbers jump |
| 8 | Right-size sample-builder storage | Measured 11.5 MiB retained by one empty builder with `max_late=10` |
| 9 | Bound pre-handshake DTLS record queues | Measured 643,216 bytes retained after 10,000 tiny future-epoch records |
| 10 | Bound DTLS fragment metadata and reassembly work | Measured 917,796 bytes retained for fragments with zero payload; repeated scans and recursive concatenation add CPU cost |
| 11 | Remove DTLS record-path copies | Incoming records are copied at unpack, decrypt, and application-payload extraction boundaries |
| 12 | Prune ICE binding requests in place | Current expiry pass reallocates and moves all live entries on each request/response |
| 13 | Make NACK retry bookkeeping linear | Configured retry caps trigger linear membership searches inside a map-wide retain pass |
| 14 | Borrow congestion-control feedback | Current RTCP processing clones boxed packets and their owned report data before inspection |
| 15 | Borrow DTLS handshake-cache entries | Transcript inspection clones message bytes and uses an unnecessary buffered reader over memory |

## 1. Prevent rejected SRTP packets from retaining stream state

- [x] Fixed

### Finding

[SRTP decryption](rtc-srtp/src/context/srtp.rs) calls
`get_srtp_ssrc_state()` before packet authentication succeeds. The
[context state lookup](rtc-srtp/src/context/mod.rs) inserts a new map entry and
replay detector for an unknown SSRC. Authentication failure leaves that entry
allocated. [SRTCP decryption](rtc-srtp/src/context/srtcp.rs) follows the same
pattern.

The allocation probe sent 10,000 rejected RTP packets to a single AES-GCM context
with a 64-packet replay window:

| Input | Retained heap growth |
| --- | ---: |
| Repeated SSRC | 260 bytes |
| Distinct SSRC for every packet | 1,551,752 bytes, approximately 1.48 MiB |

These are live allocation bytes before dropping the context, not process RSS.
The SRTCP finding is based on source inspection; the probe measured RTP only.

### Proposed change

Authenticate unknown SSRCs using temporary state and insert persistent state only
after successful authentication. Keep existing replay and rollover handling for
known streams. Consider explicit admission limits for authenticated streams as a
separate resource policy.

Do not blindly evict authenticated SSRC state: recreating it can reset replay
protection or lose rollover information under the same keys.

### Validation

Repeat the allocation probe for RTP and RTCP and verify rejected, distinct SSRCs
do not produce memory growth proportional to packet count. Cover valid first
packets, authentication failure, duplicate packets, sequence wraparound, and
rollover handling.

### Resolution

Validated: the probe reproduced 1,551,752 retained bytes for distinct-SSRC rejected packets on
both SRTP and SRTCP (the SRTCP case is now measured, not inferred).

- `Context::decrypt_rtp_under_state` ([srtp.rs](rtc-srtp/src/context/srtp.rs)) and
  `decrypt_rtcp` ([srtcp.rs](rtc-srtp/src/context/srtcp.rs)) check an unknown SSRC against fresh
  state held on the stack and insert it only after authentication succeeds. Known streams keep
  the existing replay-check → decrypt → accept → rollover-update order.
- No admission limit for authenticated streams was added; that remains a separate policy.

| Input (10,000 rejected packets) | Before | After |
| --- | ---: | ---: |
| SRTP, repeated SSRC | 260 B | 0 B |
| SRTP, distinct SSRCs | 1,551,752 B | 0 B |
| SRTCP, repeated SSRC | 260 B | 0 B |
| SRTCP, distinct SSRCs | 1,551,752 B | 0 B |

Tests: forged packets for unknown SSRCs leave no state (RTP and RTCP, AES-CM and AES-GCM); the
first authentic packet after a forgery creates state and its replay is rejected; a forgery for a
known stream does not move its replay window or ROC; rollover across the wrap.

## 2. Remove the unused SCTP working buffer

- [x] Fixed

### Finding

[SCTP transport startup](src/peer_connection/transport/sctp/mod.rs) resizes
`internal_buffer` to the negotiated maximum message size. Production consumers in
the [SCTP handler](src/peer_connection/handler/sctp.rs) only read `.len()` to enforce
message-size limits. They no longer use the buffer as scratch storage: receive
reassembly goes directly into the delivered payload.

The allocation is normally 64 KiB per started transport and can reach 256 KiB,
depending on configuration and negotiation. At 10,000 transports with a 64 KiB
negotiated limit, this represents approximately 625 MiB of unnecessary allocated
storage. This saving applies to started SCTP transports, not every peer connection.

### Proposed change

Remove the vector and use the existing negotiated numeric limit for receive and
send checks. Preserve the current behavior before negotiation and retain all
message-size checks. Update comments and tests that still describe or manipulate
the working buffer.

### Validation

Verify negotiated message-size reporting and boundary enforcement for default,
smaller remote, maximum, and configured-unbounded sizes. Compare live heap before
and after starting many SCTP transports.

### Resolution

Validated. `internal_buffer` is gone; `SctpTransport::max_message_len()` returns the negotiated
size (0 before `start()`, as the empty vector did), and the handler's receive and send checks
use it. Comments and tests that described the buffer were updated.

| Retained heap | Before | After |
| --- | ---: | ---: |
| Connected data-channel pair (two transports) | 254,678 B | 126,576 B |

Tests: reported and enforced sizes agree for default, smaller-remote, configured-0 and
`Unbounded` configurations, and nothing passes before negotiation.

**Superseded on merge (2026-09-22).** `master` had removed the buffer independently (`de9db9a`),
and bounded message sizes differently (`6597f8a`, `846c77b`). Merging kept `master`'s design:
inbound messages are bounded by `local_max_message_size()` — this endpoint's advertised limit,
capped at the SCTP receive buffer, since a peer may send anything up to what was advertised — and
sends by the negotiated `max_message_size()`. `max_message_len()`, which enforced the negotiated
size in both directions, and its tests were dropped. The heap saving above is unchanged.

## 3. Bound application backlogs by bytes as well as message count

- [x] Fixed for the SCTP receive backlog; other queues unchanged

### Finding

The [SCTP handler](src/peer_connection/handler/sctp.rs) limits the downstream
receive backlog to 256 messages. At 64 KiB per message, that permits 16 MiB of
payload; at the maximum 256 KiB message size, it permits 64 MiB. These are
calculated payload ceilings, not measured typical usage, and exclude metadata
and SCTP's own reassembly buffers.

SCTP's receive-window limit does not cap bytes already transferred into the
[application data queue](src/peer_connection/handler/mod.rs). Backpressure exists,
but the application queue's count-based bound is comparatively large for big
messages.

Undrained media and outbound application queues also warrant explicit resource
policies. [Data-channel sends](src/data_channel/mod.rs) account for outstanding
bytes, but accounting alone is not a hard queue limit.

### Proposed change

Add a configurable byte budget alongside the message-count budget. Account for
bytes entering and leaving the application queue, including intermediate output
within the current pipeline traversal. Define whether one oversized message may
exceed the budget, or reject incompatible configurations, so a valid large
message cannot stall forever.

Preserve the pending-stream retry mechanism: SCTP readability is edge-triggered,
so stopping a drain without arranging a retry can deadlock a stream. Continue to
keep data-channel backpressure independent from media delivery.

For other queues, define policies appropriate to the data: reliable messages need
backpressure or explicit rejection; media needs a deliberate latency/drop policy.

### Validation

Extend the scenarios in
[data-channel backpressure tests](tests/data_channel_backpressure_rtc2rtc.rs).
Exercise mixed message sizes, stalled consumers, resumed consumers, multiple
streams, and simultaneous media. Measure peak retained bytes and verify eventual
delivery and forward progress.

### Resolution

Validated, and the bound was weaker than described. The SCTP handler snapshots the downstream
backlog when it is created for a traversal, but its `poll_read` resumes parked streams whenever
its own queue empties, which the pipeline's collection loop causes after every message. So one
traversal drained the whole reassembly queue: the existing backpressure test peaked at about 800
messages behind a "256-message" bound, and a 64 KiB byte budget let through 1,011,400 bytes.

- Byte budget alongside the count: default 1 MiB (SCTP's default receive window), configurable
  with `SettingEngineBuilder::with_sctp_read_backlog_bytes`. One message may overshoot it, so a
  valid message larger than the budget cannot stall; `0` is treated as `1`.
- The pipeline tracks `data_read_bytes` as messages enter and leave `data_read_outs`, and the
  handler counts what it has already emitted in the current traversal (`emitted`).
- Parked streams now resume when the application drains the data queue (`poll_read` /
  `poll_data_read` run a read traversal), not only on the next inbound datagram. Without this,
  a correctly bounded stream waited for the throttled peer's next probe.

| Stalled consumer (real sockets) | Before | After |
| --- | ---: | ---: |
| Original test, peak backlog | ~800 messages | 256 messages (658 B) |
| Original test, delivery after the stall ends | 1.03 s | 0.014 s |
| Mixed 200 B–60 KB, two channels, 64 KiB budget: peak backlog | ~1 MB | 85,200 B |
| Same, delivery after the stall ends | — | 0.73 s |

Tests: handler tests for the byte bound, the overshoot rule, per-traversal accounting (fails
with the old code: 8 messages instead of 4) and progress with a budget smaller than every
message; a new socket scenario in
[data_channel_backpressure_rtc2rtc.rs](tests/data_channel_backpressure_rtc2rtc.rs) with mixed
sizes and two channels, checking the peak via a `#[doc(hidden)]`
`RTCPeerConnection::data_read_backlog_bytes()`.

Not done: media and outbound application queues still have no explicit policy. A media
drop/latency policy and hard send-queue limits change delivery semantics and need an API
decision.

## 4. Reuse parsed RTP headers and encrypt owned buffers in place

- [x] Fixed for RTP; RTCP unchanged

### Finding

The [SRTP write handler](src/peer_connection/handler/srtp.rs) serializes an RTP
packet, then calls `encrypt_rtp()`, which parses the header again even though the
original packet still has it. The
[existing context API](rtc-srtp/src/context/srtp.rs) already provides
`encrypt_rtp_with_header()`.

For a warmed AES-GCM context and a serialized 1,220-byte RTP packet containing one
header extension, the allocation probe measured:

| API | Allocation calls per encryption |
| --- | ---: |
| `encrypt_rtp()` | 3 |
| `encrypt_rtp_with_header()` | 1 |

The count excludes packet construction, serialization, and context setup. It is
not a count for the complete peer-connection path and does not establish a
throughput improvement.

The [AES-GCM cipher](rtc-srtp/src/cipher/cipher_aead_aes_gcm.rs) also allocates a
new buffer and copies the entire serialized packet before encrypting its payload
in place. The [AES-CM cipher](rtc-srtp/src/cipher/cipher_aes_cm_hmac_sha1.rs) has a
similar outgoing copy. On receive, the handler calls `decrypt_rtp()` and then
`Packet::unmarshal()`, parsing the RTP header twice.

### Proposed change

First, use `encrypt_rtp_with_header()` in the handler. Then evaluate owned-buffer
encryption/decryption APIs accepting `BytesMut`, with capacity reserved for the
authentication tag and any protocol trailer. Marshal directly into that buffer.
Consider returning or retaining the parsed receive header so packet construction
does not parse it again.

Preserve authentication, replay-state commit ordering, padding, extension parsing,
and error behavior. Do not expose unauthenticated plaintext on failure.

### Validation

Repeat allocation counts with no extensions, multiple extensions, audio-sized
packets, and MTU-sized packets. Run existing profile, authentication, replay, and
round-trip coverage. Use the [SRTP benchmarks](rtc-srtp/benches/README.md) and an
end-to-end packet benchmark to establish actual throughput and latency effects.

### Resolution

Validated (3 vs 1 allocations reproduced).

- The SRTP `Cipher` trait gained `encrypt_rtp_in_place` / `decrypt_rtp_in_place` on `BytesMut`;
  the slice methods are provided wrappers. AES-CM authenticates before decrypting; the in-place
  AEAD path's buffer is owned and dropped on failure, so unauthenticated plaintext is never
  exposed.
- New `Context::encrypt_rtp_packet(&rtp::Packet)` marshals into a buffer sized for the tag and
  encrypts there, using the packet's own header. `Context::decrypt_rtp_packet(BytesMut)`
  decrypts in the datagram's buffer and returns the parsed packet, parsing the header once.
- The [SRTP handler](src/peer_connection/handler/srtp.rs) uses both. SRTCP still goes through
  the copying API; it is a small fraction of traffic.

Allocation report (`bench.py run --bench rtc-bench:allocations`), per packet, including
issues 5 and 6:

| Workload | Send before → after | Receive before → after |
| --- | ---: | ---: |
| `Track/video/no-interceptors` | 4.24 (3,079 B) → 2.05 (1,248 B) | 6.05 (2,395 B) → 2.05 (44 B) |
| `Track/video/default-interceptors` | 4.25 → 2.06 | 6.07 → 2.06 |
| `Track/audio/default-interceptors` | 5.41 → 3.09 | 7.16 → 3.02 |

Tests: owned and slice APIs produce identical bytes and packets (CSRCs, extensions, padding)
for both cipher families; truncated input; wraparound.

## 5. Reuse pipeline scratch queues and avoid redundant traversal

- [x] Fixed

### Finding

[Peer-connection reads](src/peer_connection/handler/mod.rs) create a temporary
`VecDeque` and push the input packet into it on every call. Write and event
traversals also use temporary queues. The
[interceptor chain](rtc-interceptor/src/chain.rs) constructs a fresh queue from
each input packet and discards it after walking the chain.

Nonempty temporary queues allocate storage that is not reused across calls.
An empty `VecDeque::new()` alone does not allocate.

`RTCPeerConnection::poll_write()` also walks every handler before returning a
packet, even when its final output queue already contains buffered output.

### Proposed change

Retain reusable scratch queues per direction, or evaluate an inline representation
for the common single-packet case with support for generated output. Evaluate
draining final buffered output before performing another full handler traversal.

Preserve the ordering of generated packets, retransmissions, and control traffic.
An empty incoming queue does not mean no work exists: pacers and jitter buffers
can release packets after timeouts. Bound retained scratch capacity if rare large
bursts would otherwise permanently inflate per-connection memory.

### Validation

Measure allocations per packet and CPU cost for single-packet and burst workloads
with short and long interceptor chains. Verify timeout-driven output, generated
RTCP, retransmissions, ordering, and starvation behavior.

### Resolution

Validated.

- `handle_read` and `poll_write` reuse per-connection scratch belts, trimmed back to 16 entries
  after a burst. Events keep a per-call queue, since they are too rare to be worth retained
  storage.
- `poll_write` and `poll_event` return already-buffered output without walking all eight
  handlers again. Everything is still FIFO.
- The interceptor [chain](rtc-interceptor/src/chain.rs) reuses one belt for all walks, also
  trimmed to 16. Walks with an empty belt still run, so timeout-released packets are
  unaffected.

The allocation effect is part of the issue 4 table; timings are in the benchmark section below.

## 6. Cache negotiated routing metadata

- [x] Partly fixed: allocations removed, no SSRC index

### Finding

[RTP header-extension lookup](src/peer_connection/handler/interceptor.rs) builds
owned URI strings to find negotiated MID/RID/RRID extension IDs and copies
extension payloads into owned strings. This lookup is reached from per-packet
stream establishment, including checks for repair-stream pairing.

Stream establishment repeatedly scans transceivers and coding parameters. The
[endpoint's track lookup](src/peer_connection/handler/endpoint.rs) scans them again
to associate an SSRC with a track. Some setup metadata, such as MID, is cloned
before the already-established-stream early return.

### Proposed change

Cache negotiated extension IDs, borrow extension text where possible, and
maintain SSRC-to-stream/track indexes for established streams. Move setup-only
cloning after the established-stream check where practical.

Invalidate caches on renegotiation, stream replacement, stop, and changes to
repair-stream pairing. Preserve MID/RID fallback for previously unseen SSRCs.

### Validation

Benchmark packet processing as track and simulcast-layer counts increase. Cover
declared and undeclared SSRCs, RTX arriving before primary media, late RRID
pairing, renegotiation, and stopped or replaced tracks. CPU gains remain
unmeasured and are likely workload-dependent.

### Resolution

Validated.

- Header-extension lookup no longer allocates: `MediaEngine::negotiated_header_extension_id(&str)`
  replaces building owned URI strings, and MID/RID/RRID values are borrowed from the header
  instead of copied (`Header::get_extension` also cloned each `Bytes`). That was up to six
  allocations per packet for any packet carrying an extension.
- `bind_declared_ssrc` now clones the MID only after the already-established early return, which
  removed one allocation per received packet (6.05 → 3.05 → 2.05 receive allocations across
  issues 4 and 6).

Not done: SSRC-to-stream/track indexes. Transceivers, codings and RRID pairings are mutated from
many places, so an index needs invalidation hooks. The benchmark section shows how per-packet
receive cost scales with track count.

## 7. Bound retransmission history by bytes and age

- [x] Fixed (metrics not exposed)

### Finding

The [NACK responder](rtc-interceptor/src/nack/responder.rs) defaults to a
1,024-packet send buffer per NACK-enabled local stream. A full buffer of
1,200-byte payloads references approximately 1.17 MiB of payload storage, plus
packet metadata and header allocations.

RTP payloads use shared `Bytes`, so cloning a packet does not deep-copy its payload.
The issue is retained lifetime: retransmission history keeps the backing storage
alive. Shared payloads across streams must not be double-counted when estimating
process-wide memory.

The [send buffer](rtc-interceptor/src/nack/send_buffer.rs) also clears missing
sequence numbers one at a time. A forward jump larger than the buffer revisits
the same slots repeatedly. The
[receive log](rtc-interceptor/src/nack/receive_log.rs) uses a similar gap-clearing
loop for its bitmap.

### Proposed change

Add byte and age limits alongside the packet limit, sized to the desired
retransmission recovery window. Expire stale history even if a stream becomes
idle. Expose enough metrics to assess the tradeoff between memory and recoverable
loss.

For large sequence jumps, clear the relevant buffer once rather than iterating
over every skipped sequence number. Preserve serial-number wraparound and
out-of-order semantics.

### Validation

Measure retained heap for active and idle streams and confirm age-based expiry
releases storage. Test loss recovery within and outside the configured window,
large gaps, duplicate packets, out-of-order packets, and sequence wraparound.

### Resolution

Validated. The harness's `stream_rtp` shares one payload across packets, so the probe streams
distinct 1,200-byte payloads to show retention.

- `NackResponderBuilder::with_max_bytes` (unbounded by default) and `with_max_age` (3 s by
  default, `None` to disable). Oldest packets are evicted first; the newest packet is always
  kept. Lookups check age themselves.
- An idle stream asks for one wake-up, when its newest packet ages out, which releases the
  whole history. Active streams evict as they add, so there is no per-packet timer.
- Large forward jumps clear the send buffer and the receive log in one pass instead of per
  skipped sequence number.
- Bug fixed on the way: a late packet older than the whole window used to displace the newer
  packet sharing its slot.
- Cost: each history slot stores its send time as a u64 offset, +8 bytes per slot (8 KiB per
  1024-slot stream).

| Retained heap, video pair with default interceptors | Before | After |
| --- | ---: | ---: |
| 2,000 distinct payloads, then 10 s idle | 1,557,243 B | 319,871 B |
| Connected, before any media | 230,396 B | 241,921 B |

Tests: byte accounting, byte-limit eviction order, age expiry and the idle deadline, large jumps
across the wrap, out-of-window late packets, and receive-log jump equivalence (unit and
integration). Metrics for the memory/recoverable-loss trade-off are not exposed.

## 8. Right-size sample-builder storage

- [x] Fixed

### Finding

[SampleBuilder::new](rtc-media/src/io/sample_builder/mod.rs) allocates two
65,536-entry tables: `Vec<Option<Packet>>` and `Vec<Option<Sample>>`. Their size is
independent of `max_late`, including for a builder that has never received a
packet.

A release-build allocation probe on arm64 measured **12,058,624 bytes (11.5 MiB)**
of retained heap for `SampleBuilder::new(10, OpusPacket, 48000)`. On this build,
`Option<Packet>` is 112 bytes and `Option<Sample>` is 72 bytes:
`65,536 × (112 + 72) = 12,058,624`. This excludes future payload storage.
One hundred such builders therefore allocate about 1.12 GiB before receiving
media. This applies to applications using the sample builder, not every peer
connection automatically.

### Proposed change

Use a sequence-tagged ring sized for the supported reorder window, or lazily
allocated pages if full sequence-space indexing must remain available. Store
prepared samples in a separate bounded FIFO instead of another full sequence
table. Define the prepared-output backlog limit independently from `max_late`.

Do not simply reduce the vector lengths: indexing and
[sequence-location iteration](rtc-media/src/io/sample_builder/sample_sequence_location.rs)
currently assume the full `u16` sequence space. Preserve packet identity when
ring slots are reused, wraparound, and the accepted range of `max_late`.

### Validation

Measure empty and populated builders with small and large reorder windows. Test
wraparound, reordering, duplicates, missing fragments, large frames, and callers
that delay popping prepared samples. Preserve the existing shared-buffer path
for single-packet samples.

### Resolution

Validated: 12,058,624 bytes in 2 allocations for every `max_late` from 0 to 65,535. The probe
also found the prepared-sample table's `u16` cursor wrapping: 70,000 pushes without pops returned
4,463 samples, reported 0 drops, and left about 7.5 MB unreachable.

- Packets live in `PacketRing` ([mod.rs](rtc-media/src/io/sample_builder/mod.rs)): allocated
  on the first push (16 slots, or fewer for a small `max_late`) and doubling only when the held
  span exceeds its length, which `max_late` bounds.
- Every lookup and release checks the packet's own sequence number, so a reused slot never
  answers for another packet.
- Prepared samples go in a `VecDeque`. The new `with_max_prepared_samples` defaults to 65,535,
  what the old table held. When full, the oldest waiting sample is discarded and counted in the
  next sample's `prev_dropped_packets`.
- The public API is otherwise unchanged. A randomized old-vs-new comparison over about 12.4 M
  packets (loss, reordering, duplicates, jumps, wraparound, `max_late` 0–65,535) produced
  identical samples.

| Measurement | Before | After |
| --- | ---: | ---: |
| Empty builder, any `max_late` | 12,058,624 B | 0 B |
| Opus, 10,000 packets, pop after each push | 12,058,724 B | 2,212 B |
| VP8 with reordering and 1% loss, `max_late` 50 | 12,103,344 B | 52,208 B |
| 70,000 pushes without pops: samples returned / drops reported | 4,463 / 0 | 65,584 / 4,415 |
| Push + pop per packet, Opus / VP8 (single stream) | 29.7 / 106.5 ns | 30.8 / 110.3 ns |

The single-stream microbenchmark is about 3.5% slower, mostly from the per-lookup sequence check
that keeps packet identity.

## 9. Bound pre-handshake DTLS record queues

- [x] Fixed

### Finding

[DTLSConn::handle_incoming_packet](rtc-dtls/src/conn/mod.rs) appends next-epoch
records to `incoming_encrypted_packets` while the handshake is incomplete. Other
branches enqueue records when cipher initialization is pending. The next-epoch
branch occurs before replay checking and authentication, and the queue has no
explicit byte or record-count bound.

The record-layer probe created a fresh connection without initialized traffic
keys and fed 10,000 25-byte next-epoch records. Retained heap increased by
**643,216 bytes**, including record storage and queue capacity. This was an
isolated `DTLSConn::read()` probe, without network traffic or handshake timer
advancement; it establishes the queue's growth behavior, not an end-to-end
connection lifetime or attack rate. Handshake timeouts limit time, but do not
bound how much can arrive before they fire.

### Proposed change

Apply byte and count budgets before enqueueing records, shared across the
branches that feed this queue. Define behavior on saturation and release queued
storage on terminal handshake failure. Where useful, suppress duplicate queued
epoch/sequence pairs without marking unauthenticated records as accepted by the
replay detector.

Preserve legitimate reordering, especially Finished arriving before
ChangeCipherSpec. The existing post-handshake future-epoch discard should remain.

### Validation

Feed repeated and distinct future-epoch records while initialization is stalled;
verify a fixed retained-memory bound and cleanup after failure. Exercise normal
handshakes, reordered Finished/ChangeCipherSpec, retransmissions, and transitions
that drain queued records once the cipher becomes ready.

### Resolution

Fixed in [conn/mod.rs](rtc-dtls/src/conn/mod.rs).

- All three branches that queue records share one budget (64 records, 64 KiB); new records are
  dropped when it is full.
- Queued records are never marked in the replay window.
- The queue and the fragment buffer are released on handshake failure (retransmits exhausted)
  and on fatal alert or close_notify.
- Behaviour fix: a Finished that arrives before its ChangeCipherSpec in a separate datagram used
  to be dropped when the queue drained; it is now re-queued until the epoch advances.

| Probe | Before | After |
| --- | ---: | ---: |
| 10,000 × 25 B next-epoch records | 643,216 B | 3,648 B |
| 10,000 × 1,213 B next-epoch records | 12,523,216 B | 67,550 B |
| Same, after the handshake fails | 12,523,216 B | 0 B |

## 10. Bound DTLS fragment metadata and make reassembly linear

- [x] Fixed

### Finding

The [DTLS fragment buffer](rtc-dtls/src/fragment_buffer/mod.rs) limits the sum of
fragment payload lengths to approximately two million bytes. It does not count
`Fragment` entries, vector capacity, or map entries. Each accepted fragment is
appended without offset deduplication, so payload bytes alone do not bound total
memory.

The probe fed 10,000 epoch-zero handshake records containing zero-payload
fragments for message sequence 1, while sequence 0 remained missing. Retained
heap increased by **917,796 bytes**, despite the fragment payload-byte sum
remaining zero. Each record used a different record sequence number so replay
checking did not suppress the input. The figure includes connection-side
bookkeeping, not only the fragment vector. This is a malformed-input retention
fixture, not normal handshake behavior.

There are also two algorithmic costs:

- `push()` recomputes `size()` by scanning all stored fragments before checking
  whether the record is even a handshake. Inserting N retained fragments can
  therefore require quadratic cumulative scanning.
- `append_message()` recursively searches the fragment list for each next offset
  and allocates/copies the accumulated suffix at every recursion level. For N
  equal-sized fragments of a complete message, list searches and cumulative
  copying can both be quadratic. Deep fragmentation also increases stack depth.

### Proposed change

Track retained bytes and fragment/message counts incrementally. Bound metadata
as well as payload, validate zero-length and overlapping fragment cases, discard
obsolete message sequences, and deduplicate fragments according to a defined
overlap policy.

Reassemble into one bounded destination using validated offsets and received-range
tracking, or order fragments and copy each payload once. Avoid recursive suffix
construction. Validate advertised message lengths against limits before allocating
a destination.

### Validation

Cover empty fragments, duplicates, overlaps, missing earlier messages, sparse
offsets, out-of-order arrival, and one message divided into many tiny fragments.
Measure retained allocation bytes including metadata. Increase fragment count
while holding total payload constant to detect superlinear work. Verify ordinary
certificate handshakes and retransmission behavior remain correct.

### Resolution

Rewritten [fragment buffer](rtc-dtls/src/fragment_buffer/mod.rs).

- Each message is allocated once at its advertised length, capped at 128 KiB per message, and
  the 2 MB budget now includes bookkeeping. Fragments are copied into place and tracked with a
  received-bytes bitmap, with incremental size accounting.
- A record is rejected whole if any fragment in it is malformed or inconsistent with its
  message.
- Overlaps: the latest bytes win until the message is complete. Messages already popped, or 16
  or more ahead of the next expected one, are dropped.
- A fragment's payload is `fragment_length` bytes (RFC 6347); the old code took
  `min(length, rest of record)`. Application data is no longer rejected when the buffer is
  nearly full.

| Probe | Before | After |
| --- | ---: | ---: |
| 10,000 zero-payload fragments (issue fixture) | 917,796 B | 560 B |
| 10,000 zero-payload fragments, seqs 1..=10,000 | 2,780,832 B | 3,444 B |
| 16 KiB message in 2,048 fragments | 671 ms | 227 µs |

## 11. Remove DTLS record-path copies

- [x] Fixed (some copies deferred)

### Finding

The data-channel receive path crosses several allocating ownership boundaries:

1. [unpack_datagram](rtc-dtls/src/record_layer/mod.rs) copies every record into a
   separate `Vec<u8>` inside a newly built vector of records.
2. [AES-GCM decryption](rtc-dtls/src/crypto/crypto_gcm.rs) allocates another vector
   and copies the record header and encrypted payload before decrypting in place.
3. [ApplicationData::unmarshal](rtc-dtls/src/application_data.rs) reads the
   decrypted payload into another vector. Its subsequent `Bytes` conversion
   already avoids an additional copy, but the read itself still copies.

On send, [process_packet](rtc-dtls/src/conn/mod.rs) marshals into a new vector,
then passes a borrowed slice to the cipher, which allocates its output. Datagram
compaction can copy the encoded records again. This is separate from the SRTP
media path in issue 4 and affects sustained SCTP/data-channel traffic.

### Proposed change

Carry owned buffers through record parsing and cipher APIs. Use bounded slices or
buffer splits to identify records, decrypt an owned mutable region, and transfer
the application payload's ownership downstream. Marshal outbound records with
space for nonce/tag overhead, and add a direct ownership path when a datagram
contains just one record.

Avoid retaining a large datagram allocation indefinitely through a tiny slice.
Preserve multi-record framing, authentication failure behavior, and the lifetime
requirements of records queued across handshake transitions.

### Validation

Measure allocations and copied bytes for small and near-MTU data-channel messages,
single- and multi-record datagrams, and each supported cipher. Compare complete
data-channel transfers with cipher-only benchmarks. Copy elimination is supported
by source inspection; no end-to-end speedup is established yet.

### Resolution

- `unpack_datagram` returns borrowed records after checking the whole datagram's framing.
- Each record gets one exact-size buffer and is decrypted in place (`CipherSuite::decrypt_in_place`
  and `encrypt_in_place`, provided methods, so existing implementers are unaffected).
- Application data goes downstream as a view of that buffer.
- On send, each record is marshalled once with room for the cipher overhead, encrypted in place,
  and becomes the datagram when it starts one.

| Per record | Before | After |
| --- | ---: | ---: |
| AES-GCM send / receive allocations | 10 / 6 | 2 / 2 |
| AES-CCM send / receive | 12 / 7 | 2 / 2 |
| ChaCha20 send / receive | 11 / 7 | 2 / 2 |
| AES-CBC send / receive | 17 / 10 | 3 / 3 |

End to end (allocation report, per message): `DataChannel/reliable/1KiB` send 15.12 → 7.07,
receive 16.12 → 11.31; `DataChannel/reliable/16KiB` send 186.88 → 66.66, receive 201.53 → 126.25.

Deferred:

- Taking ownership of the caller's datagram (the `bytes` API cannot tell whether it is shared or
  oversized).
- Plaintext handshake records.
- The copy in `DTLSConn::write`.

## 12. Prune ICE binding requests in place

- [x] Fixed

### Finding

[invalidate_pending_binding_requests](rtc-ice/src/agent/mod.rs) drains the pending
vector into a fresh vector, then replaces the original. The pass runs from both
`send_binding_request()` and `handle_inbound_binding_success()`, even when no
requests have expired.

While N requests remain live, each call scans and moves those entries and may
grow the replacement allocation repeatedly. A burst adding N requests within the
expiry window incurs cumulative quadratic scanning/moving. Success handling also
searches linearly by transaction ID and removes from the middle of the vector.

### Proposed change

Use `retain` as a small first step to eliminate the replacement allocations.
This preserves linear work per expiry pass; it does not fix the cumulative
scaling by itself. If candidate-rich workloads justify it, maintain a transaction
lookup index and an expiry queue, and prune once per relevant time advance or
batch instead of once per inserted request.

Preserve the existing handling of instants earlier than a request timestamp,
expiry boundaries, ICE restarts, and request/response matching. Only use an
ordered expiry queue if timestamp ordering is guaranteed.

### Validation

Benchmark bursts with many candidate pairs and pending transactions, including
all-live, partially expired, and all-expired cases. Count allocations separately
from execution time. Test response matching and cleanup across restarts and role
changes.

### Resolution

- `PendingBindingRequests` ([agent/mod.rs](rtc-ice/src/agent/mod.rs)) prunes with `retain`.
- It keeps a lower bound on the oldest request's timestamp and skips the scan while even that
  request is live. No timestamp ordering is assumed.
- There is no transaction index: response handling still scans candidates and pairs linearly,
  so an index would not change the complexity.

| N = 1,000 requests | Before | After |
| --- | ---: | ---: |
| All-live burst: bytes requested | 130.5 MB | 1.07 MB |
| All-live burst: time | 11.1 ms | 1.4 ms |
| 1,000 responses: time | 6.1 ms | 1.9 ms |

## 13. Make NACK retry bookkeeping linear

- [x] Fixed

### Finding

When a retry cap is configured, the
[NACK generator](rtc-interceptor/src/nack/generator.rs) uses
`nack_count.retain(|seq, _| missing.contains(seq))`. Membership in the `missing`
vector is linear, so cleanup costs O(C × M) for C tracked retry counts and M
missing sequence numbers. This runs on periodic feedback generation under loss.
The default unlimited-retry configuration does not populate the count map, so
the quadratic count-cleanup concern applies to configured retry caps.

The code also skips cleanup when every currently missing packet has exhausted its
retry allowance, leaving obsolete entries until a later cleanup opportunity. In
the default unlimited mode it clones the missing-sequence vector solely to create
the feedback input.

### Proposed change

Use constant-time membership from the receive bitmap or a sequence-tagged count
ring aligned with the receive window. A temporary set is another option, but its
allocation cost should be measured. Perform expiry cleanup independently of
whether another NACK will be emitted. Borrow the missing list when retry limiting
is disabled instead of cloning it.

### Validation

Benchmark sparse and burst loss with 512- and 32,768-packet receive windows and
with retry caps both enabled and disabled. Preserve retry counts, wraparound,
skip-last-N behavior, and feedback contents when packets arrive late or exhaust
their retry allowances.

### Resolution

- Retry counts are pruned with `ReceiveLog::is_missing` (constant time; brute-force checked
  against `missing_seq_numbers` over the whole u16 space) before counting, so stale counts go
  even in a round that sends nothing.
- Unlimited mode no longer clones the missing list or touches the count map.

Tests: counts released for late arrivals when no NACK is sent, per-packet limits, and no counts
in unlimited mode.

## 14. Borrow congestion-control feedback instead of cloning it

- [x] Fixed

### Finding

[CongestionControlInterceptor::handle_read](rtc-interceptor/src/cc/interceptor.rs)
calls `rtcp_packets.to_vec()` before passing each packet to `self.ingest()`.
The input is a vector of boxed trait objects, and
[Box<dyn rtcp::Packet>::clone](rtc-rtcp/src/packet.rs) calls each packet's
`cloned()` implementation. This allocates replacement boxes and clones owned
report vectors; it is not a cheap shared-pointer clone. Packets unrelated to
congestion control are copied too.

The stated reason is avoiding a borrow conflict, but the packet belongs to the
local `msg` argument, not to `self`. The borrow ends before attributes are added
to the message.

### Proposed change

Iterate over references to the original RTCP packets while ingesting feedback.
Optionally accept `&dyn rtcp::Packet` in `ingest()` rather than `&Box<...>`.
Keep forwarding the original message and attaching target-bitrate updates after
the read-only packet borrow ends.

### Validation

Measure allocation counts for compound RTCP containing TWCC/CCFB reports and
unrelated report types. Verify identical history updates, estimator output,
target-bitrate attributes, and downstream feedback delivery. This affects the
optional congestion-control interceptor; it is not enabled in every default chain.

### Resolution

`handle_read` iterates the packets by reference and `ingest` takes `&dyn rtcp::Packet`.

| Compound RTCP | Allocations per read, before → after |
| --- | ---: |
| TWCC + RR + PLI | 17 → 10 |
| CCFB + RR + PLI | 14 → 7 |
| RR + PLI only | 4 → 0 |

A test feeds each interceptor, old and new, identical input and checks for identical history,
estimates, attributes and forwarded packets.

## 15. Borrow DTLS handshake-cache entries during transcript inspection

- [x] Fixed

### Finding

[HandshakeCache::pull and full_pull_map](rtc-dtls/src/handshake/handshake_cache.rs)
scan cached messages for every rule and clone matching `HandshakeCacheItem`s,
including their byte vectors. A later matching item can replace an earlier clone
within the same search. `pull_and_merge()` then copies selected bytes again into
the transcript buffer.

`full_pull_map()` also wraps an already-memory-backed slice in `BufReader`, adding
a staging allocation for each parsed selected message. These costs occur during
handshake progression and retries, so they matter most for connection churn and
large certificate messages rather than established media throughput.

### Proposed change

Select the final matching entry by reference before parsing it. Return borrowed
entries or iterate selected slices when building transcript bytes. Parse directly
from a slice using its `Read` implementation rather than allocating a `BufReader`.
Reserve the merged transcript length once when a contiguous transcript is required.

Keep transcript ordering, latest-message selection, epoch/client matching, and
mandatory-rule validation identical. Do not discard the whole cache at handshake
completion without analyzing final-flight retransmission and duplicate-Finished
handling, which still consult handshake state.

### Validation

Measure allocations per completed handshake and per retransmission using small
and large certificate chains. Verify Finished, extended-master-secret derivation,
missing or optional messages, cookie retries, and final-flight retransmission.

### Resolution

- `HandshakeCache::find`/`pull` select the latest match by reference, and `full_pull_map`
  parses directly from the cached slice.
- Transcripts are sized once.
- The send path marshals each handshake message once for both the cache and the fragments,
  dropping the 8 KiB `BufWriter`s.

| Full in-memory handshake, both sides | Before | After |
| --- | ---: | ---: |
| 1 certificate | 836 allocs, 965 KB | 482 allocs, 409 KB |
| 8-certificate chain | 938 allocs, 1.11 MB | 545 allocs, 451 KB |

These figures include issues 9–11. The cache change alone accounts for 75–84 allocations and
107–158 KB per handshake.

## Found while fixing these issues (not fixed)

- **Sample builder purge stalls.** In `purge_buffers`, once `build_sample` has emptied `filled`,
  the loop still releases `filled.head` and advances it past `tail`, so `filled` wraps to about
  65,535 entries. With `max_late = 0` and a maximum time delay set, each such push rescans the
  range 65,536 times, about 1–2 s per push. A sender may be able to trigger this.
- **Sample builder duration at wraparound.** `for i in consume.tail..self.active.tail` is a plain
  `u16` range, so it is empty across the wrap and the sample gets duration 0.
- **Sample builder counter overflow.** `dropped_packets +=` can overflow a `u16`, which panics in
  debug builds.
- **DTLS certificate parsing.** `HandshakeMessageCertificate::unmarshal` allocates
  `vec![0; certificate_len]` from a peer-supplied 24-bit length before reading, up to 16 MiB per
  parse.
- **DTLS final-flight retransmission.** A server that has completed never resends its final
  flight, because `Endpoint` runs the handshake only while it is incomplete.
- **SSRC routing scans** (issue 6) and **media/outbound queue policies** (issue 3) remain open
  by design.

## Measurement plan

Use release builds and compare on the same machine, crypto provider, negotiated
profile, and dependency versions. Existing crypto optimizations and shared RTP
payloads should remain intact.

Workloads:

- Steady audio and MTU-sized video traffic.
- Many peer connections, tracks, and simulcast layers.
- Packet loss, reordering, retransmissions, and large sequence gaps.
- Stalled and resumed data-channel consumers with mixed message sizes.
- Connection and stream churn, including idle periods after traffic stops.
- Rejected packets with repeated and distinct SSRCs.
- Empty and active sample builders at different reorder-window sizes.
- Stalled DTLS handshakes, future-epoch records, and fragmented certificates.
- ICE connectivity-check bursts with many pending transactions.
- Compound RTCP feedback and NACK retry limits under sustained loss.

Record allocations per packet, retained heap per connection, peak queue bytes,
throughput, and p99 packet-processing latency. Include loss-recovery and delivery
behavior so lower memory usage is not mistaken for an improvement when it merely
drops more useful traffic.

The working tree also contains a [benchmarking guide](docs/benchmarking.md) and
[end-to-end harness](benchmarks/rtc-bench) covering assembled-stack and allocation
measurements. Use those where applicable; the isolated probes here supplement
that coverage for retained-memory cases. The benchmark infrastructure was not
modified as part of this issues-document update.

## Allocation probe reproduction

The original isolated probe was created outside the repository at
`/tmp/rtc-memory-audit`. Its source is included below because that temporary path
is not durable. It used the local crate sources, the default `ring` provider, and
an optimized release build. Exact byte counts can vary by target and dependency
version.

Create a temporary Cargo binary with edition `2024` and these dependencies,
replacing `/path/to/rtc` with the checkout's absolute path:

```toml
[dependencies]
rtc-srtp = { path = "/path/to/rtc/rtc-srtp" }
rtc-crypto = { path = "/path/to/rtc/rtc-crypto" }
rtc-rtp = { path = "/path/to/rtc/rtc-rtp" }
rtc-shared = { path = "/path/to/rtc/rtc-shared", default-features = false, features = ["marshal"] }
```

Copy the checkout's `Cargo.lock` into the temporary project to retain dependency
versions, then run `cargo run --offline --release --manifest-path
/path/to/probe/Cargo.toml` from the checkout. Offline execution requires cached
dependencies. Use the following as `src/main.rs`:

```rust
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use rtc_shared::marshal::Unmarshal;
use rtc_srtp::{
    context::Context,
    option::srtp_replay_protection,
    protection_profile::ProtectionProfile,
};

struct Counting;
static CALLS: AtomicIsize = AtomicIsize::new(0);
static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            CALLS.fetch_add(1, Ordering::Relaxed);
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn main() {
    encryption_allocations();
    rejected_packet_retention();
}

fn encryption_allocations() {
    let provider = rtc_crypto::default_provider().unwrap();
    let mut packet = vec![0u8; 1220];
    packet[0] = 0x90;
    packet[1] = 96;
    packet[3] = 1;
    packet[11] = 1;
    packet[12..20].copy_from_slice(&[0xbe, 0xde, 0, 1, 0x10, 0x61, 0, 0]);
    let header = rtc_rtp::Header::unmarshal(&mut packet.as_slice()).unwrap();

    for reuse_header in [false, true] {
        let mut ctx = Context::new(
            &[0; 16], &[0; 12], ProtectionProfile::AeadAes128Gcm,
            None, None, provider.crypto(),
        ).unwrap();
        drop(ctx.encrypt_rtp(&packet).unwrap());
        let baseline = CALLS.load(Ordering::Relaxed);
        for _ in 0..10_000 {
            if reuse_header {
                drop(ctx.encrypt_rtp_with_header(&packet, &header).unwrap());
            } else {
                drop(ctx.encrypt_rtp(&packet).unwrap());
            }
        }
        let allocations = CALLS.load(Ordering::Relaxed) - baseline;
        println!(
            "reuse_header={reuse_header}: allocations per packet={}",
            allocations / 10_000,
        );
    }
}

fn rejected_packet_retention() {
    let provider = rtc_crypto::default_provider().unwrap();
    for unique in [false, true] {
        let mut ctx = Context::new(
            &[0; 16], &[0; 12], ProtectionProfile::AeadAes128Gcm,
            Some(srtp_replay_protection(64)), None, provider.crypto(),
        ).unwrap();
        let baseline = LIVE.load(Ordering::Relaxed);
        let mut packet = [0u8; 28];
        packet[0] = 0x80;
        packet[1] = 96;
        packet[3] = 1;
        for i in 0..10_000u32 {
            let ssrc = if unique { i } else { 1 };
            packet[8..12].copy_from_slice(&ssrc.to_be_bytes());
            assert!(ctx.decrypt_rtp(&packet).is_err());
        }
        let growth = LIVE.load(Ordering::Relaxed) - baseline;
        drop(ctx);
        println!("unique_ssrcs={unique}: retained heap growth={growth} bytes");
    }
}
```

This is an allocation-counting fixture, not a cryptographic traffic generator or
a timing benchmark. It deliberately repeats the encryption input; the resulting
ciphertexts are immediately discarded and must not be used as real traffic.
The counting allocator uses the trait's default implementations for allocation
operations it does not override, so counts should be compared using the same
fixture rather than treated as a complete allocator performance profile.


## Follow-up allocation probe reproduction

Issues 8–10 were measured on arm64 using the same release-build allocation
counter approach. Add the following dependencies to the temporary project above:

```toml
rtc-media = { path = "/path/to/rtc/rtc-media" }
rtc-dtls = { path = "/path/to/rtc/rtc-dtls" }
```

Refresh the temporary project's lockfile from the checkout before running so the
new dependencies use the checkout's versions. Save the following as
`src/bin/followup.rs`, and run:

```sh
cargo run --offline --release --manifest-path /path/to/probe/Cargo.toml --bin followup
```

If the project now contains both binaries, add `--bin rtc-memory-audit` when
rerunning the original probe (or use the package name chosen for that binary).

This fixture constructs local objects and feeds in-memory records only. It does
not send network traffic or advance the handshake through its normal event loop.
Counts include live allocation sizes and container capacity, but not allocator
bookkeeping or process RSS. Setup allocations precede each baseline.

```rust
use rtc_dtls::{cipher_suite::CipherSuiteId, config::ConfigBuilder, conn::DTLSConn};
use rtc_media::io::sample_builder::SampleBuilder;
use rtc_rtp::codec::opus::OpusPacket;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, Ordering};
struct Counting;
static CALLS: AtomicIsize = AtomicIsize::new(0);
static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            CALLS.fetch_add(1, Ordering::Relaxed);
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn main() {
    println!("Follow-up allocation probes");
    let before = LIVE.load(Ordering::Relaxed);
    let builder = SampleBuilder::new(10, OpusPacket, 48000);
    std::hint::black_box(&builder);
    let growth = LIVE.load(Ordering::Relaxed) - before;
    println!("empty SampleBuilder(max_late=10): {growth} bytes");
    println!(
        "Option<Packet>={} Option<Sample>={}",
        size_of::<Option<rtc_rtp::Packet>>(),
        size_of::<Option<rtc_media::Sample>>()
    );
    drop(builder);
    for future_epoch in [true, false] {
        let provider = rtc_crypto::default_provider().unwrap();
        let cfg = ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_cipher_suites(vec![CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256])
            .with_psk(Some(Arc::new(|_| Ok(vec![1, 2, 3, 4]))))
            .with_psk_identity_hint(Some(b"probe".to_vec()))
            .build(true, None)
            .unwrap();
        let mut conn = DTLSConn::new(Arc::new(cfg), true, None);
        // Handshake record: epoch 1 with opaque payload, or epoch 0 with a
        // zero-length fragment of message_sequence 1 while sequence 0 is missing.
        let mut record = [0u8; 25];
        record[0..3].copy_from_slice(&[22, 0xfe, 0xfd]);
        record[4] = u8::from(future_epoch);
        record[12] = 12;
        record[13] = 1;
        record[18] = 1;
        let before = LIVE.load(Ordering::Relaxed);
        for seq in 0..10000u64 {
            record[5..11].copy_from_slice(&seq.to_be_bytes()[2..]);
            conn.read(&record).unwrap();
        }
        let growth = LIVE.load(Ordering::Relaxed) - before;
        println!("DTLS future_epoch={future_epoch}, 10000 records: {growth} retained bytes");
        drop(conn);
    }
}
```

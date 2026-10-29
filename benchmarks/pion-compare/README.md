# rtc vs pion, side by side

Two small programs run the same micro-benchmarks — one against this workspace, one against
[pion](https://github.com/pion) — and `compare.py` prints them next to each other and fails if
we fall behind where we have promised not to.

```sh
python3 benchmarks/pion-compare/compare.py                       # ring (default)
python3 benchmarks/pion-compare/compare.py --backend aws-lc-rs
python3 benchmarks/pion-compare/compare.py --allocator mimalloc  # Rust side on mimalloc
python3 benchmarks/pion-compare/compare.py --no-gate             # report only
```

Needs a Rust toolchain and Go (the pion half is `go/`, pinned in `go/go.mod`).

## What is measured

| Benchmark | rtc call | pion call |
|---|---|---|
| `rtp unmarshal 1200B` | `PacketView::parse` (borrowed) | `Packet.Unmarshal` into a reused struct of subslices |
| `rtp unmarshal reuse (Bytes) 1200B` | `Packet::unmarshal_reuse` (owning, reference-counted) | — (no peer) |
| `rtp unmarshal fresh 1200B` | `Packet::unmarshal` | `Packet.Unmarshal` into a new struct |
| `rtp marshal 1200B` | `Packet::marshal_to` | `Packet.MarshalTo` |
| `srtp cm-hmac-80 encrypt/decrypt 1200B` | `Context::{encrypt,decrypt}_rtp_into` into a reused buffer | `EncryptRTP/DecryptRTP(dst[:0], …)` |
| `srtp cm-hmac-80 encrypt alloc 1200B` | `Context::encrypt_rtp` | `EncryptRTP(nil, …)` |
| `srtp gcm-128 encrypt 1200B` | `encrypt_rtp_into` | `EncryptRTP(dst[:0], …)` |
| `stun decode+getters+integrity` | `Message::decode` + getters + integrity + fingerprint, one reused message | same |
| `stun build binding request` | `Message::build` on a reused message | `Message.Build` |
| `stun add 3 attributes+reset` | `Message::add` of DATA (10 B), LIFETIME and CHANNEL-NUMBER (4 B), then `reset`; what every TURN message is built from | `Message.Add` ×3 + `Reset` |
| `sdp unmarshal / marshal / codec map` | `SessionDescription` | `sdp.SessionDescription` |
| `rtcp unmarshal SR+SDES+REMB` | `rtcp::packet::unmarshal` | `rtcp.Unmarshal` |
| `vp8 / h264 payload 30KB mtu1200` | `Payloader::payload` | `Payloader.Payload` |
| `dtls handshake`, `dtls app data 1200B` | two in-memory `Endpoint`s, one self-signed ECDSA P-256 certificate | `dtls.Client`/`dtls.Server` over an in-memory packet pipe (`go/pipe.go`) |
| `sctp message 1200B / 100B` | `Endpoint`/`Association` pair on a zero-latency wire, one message written and read | `sctp.Client`/`sctp.Server` over the same pipe, a reader goroutine |
| `ice connect, one host pair` | two sans-IO `Agent`s run until `Connected` (virtual clock; no sockets) | two `ice.Agent`s over loopback UDP; **CPU time** per session, because pion's wall time is its check timer. The Rust side excludes socket setup, which the application does. |
| `twcc record`, `twcc record 100 + build feedback` | `rtc_interceptor::bench::TwccRecorder` (the `bench` feature) | pion's own `BenchmarkRecord` / `BenchmarkRecordAndBuildFeedbackPacket` |
| `datachannel open parse+marshal` | `Message::unmarshal` then `marshal` of a DCEP `DATA_CHANNEL_OPEN` | `datachannel.TryMarshalUnmarshal` (parse then marshal) |
| `mdns query build`, `mdns answer query` | `Mdns::query_now` + `poll_write`; `handle_read` + `poll_write` for a local name | `dnsmessage` packing a question; unpacking a question and packing the A answer, as pion/mdns does |

Each pair uses the same input bytes and the same buffer-reuse conventions, so "faster" means the
same work done in less time. Both programs print `name  N ns/op  N B/op  N allocs/op`; `compare.py`
runs each several times, keeps the fastest run, and compares.

## Gates

`compare.py` fails when

* a benchmark we win is more than 25 % slower than pion (shared CI runners are noisy), or
  allocates more than pion does; or
* a benchmark marked a known gap in `GATES` regresses past its recorded ceiling.

Some lines are allocation-bound: an RTCP compound packet is nine small boxes and vectors, the same
nine pion makes, but pion's runtime allocates from its own arena while Rust asks the system's
`malloc`, whose cost varies by platform (it is highest on macOS). `--allocator mimalloc` runs the
Rust side on an allocator a server would deploy; on it RTCP unmarshal is faster than pion, on the
system allocator it is a recorded gap.

CI runs this on Linux x86-64, Linux arm64 and macOS arm64 for every pull request, and nightly with
more repetitions on both crypto providers.

## Adding a benchmark

Add it to `src/main.rs` and `go/main.go` under the same name, with the same conventions, and
rerun. If the new line is a win it is gated automatically; if it is a known gap, record its
ceiling in `GATES`.

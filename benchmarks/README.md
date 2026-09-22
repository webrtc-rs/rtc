# Benchmarks

Benchmarks that do not belong to a single crate. The per-crate ones live in each crate's
`benches/`. [`docs/benchmarking.md`](../docs/benchmarking.md) covers the whole suite and how to run
and compare it; `python3 scripts/bench.py list` prints every target.

| Directory | What | Workspace member |
|---|---|---|
| [`rtc-bench/`](rtc-bench) | End-to-end benchmarks of a connected `RTCPeerConnection` — setup, data-channel throughput, the RTP path, allocations per packet — and the in-memory, virtual-clock harness they share | Yes, never published |
| [`aead-gcm/`](aead-gcm) | A one-off AES-GCM comparison between `ring` and RustCrypto `aes-gcm` | No, on purpose: see its `Cargo.toml` |
| [`external-consumer/`](external-consumer) | rtc's AES paths as an application depending on rtc builds them — outside this repository's `.cargo/config.toml` — run by `bench.py external` | No, on purpose: see its README |
| [`simd-probes/`](simd-probes) | Exploratory kernel probes behind [`SIMD.md`](../SIMD.md); not the production implementations | No |

```bash
python3 scripts/bench.py run --bench rtc-bench:data_channel   # one end-to-end target
python3 scripts/bench.py run -p rtc-bench --providers all     # all of them, both crypto backends
python3 scripts/bench.py run --bench rtc-bench:allocations     # allocations per packet and message
python3 scripts/bench.py upstream --rounds 3                    # this fork vs. upstream webrtc-rs/rtc
python3 scripts/bench.py external                               # AES as an application builds it
```

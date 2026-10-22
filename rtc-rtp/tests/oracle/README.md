# pion/rtp oracle

`tests/pion_golden.rs` replays inputs through this crate and compares with what pion/rtp (v1.10.6)
did with the same input (`tests/data/pion_rtp_golden.jsonl`): RTP packets, codec depacketizers
(H.264, VP8, VP9, Opus, H.265, AV1) and payloaders (H.264, VP8, VP9, Opus, G.711/G.722, H.265, AV1).

1. `instrument_rtp.py <copy of pion/rtp>` hooks every `Unmarshal`/`Payload` to log its input
   (kind, op, MTU, hex) to `$ORACLE_OUT`; `go test ./...` there yields the seeds.
2. `rtp_corpus.py seeds.jsonl <per-kind> <max-bytes> out.jsonl [kinds]` mutates them.
   MTUs below 6 are not generated: pion's H.265 payloader never terminates on an MTU of 3.
3. `go run ./tests/oracle < corpus.jsonl > golden.jsonl` records pion's answers. The VP9 payloader is
   seeded with a fixed picture id so output is deterministic.

Large sweep: `PION_RTP_GOLDEN=big.jsonl PION_RTP_REPORT=report.jsonl cargo test --release --test pion_golden`.

Intended differences from pion (see `pion_golden.rs`):
- AV1 payloads follow libwebrtc's packetization, so they are checked by round trip (the OBU stream
  pion rebuilds from its own payloads) and MTU, not byte for byte.
- A PACI packet's F bit follows RFC 7798; pion computes it from the wrong bit.
- Empty frames for payloaders (Go nil vs empty), LEB128 sizes longer than 8 bytes, a packet whose
  last AV1 element is a skipped temporal delimiter.

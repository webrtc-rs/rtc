# pion/rtcp oracle

`tests/pion_golden.rs` replays datagrams through this crate and compares with what pion/rtcp
(v1.2.20) did with the same input (`tests/data/pion_rtcp_golden.jsonl`).

How the golden file is made:

1. `instrument.py <copy of pion/rtcp> rtcp '<regex of Unmarshal methods>'` hooks every packet type's
   `Unmarshal` to log its input (hex) to `$ORACLE_OUT`; `go test` then yields ~470 real packets.
2. `ONLY_PT=205:15 bincorpus.py seeds.hex <count> <max-bytes> out.jsonl fix` mutates them
   (bit flips, truncation, appended bytes, spliced packets, length-field fixes). `ONLY_PT` restricts
   the seeds to one packet type, which finds deep divergences the global mix hides.
3. `go run ./tests/oracle < out.jsonl > golden.jsonl` records pion's verdict, re-marshalled bytes and,
   for transport-wide CC, the parsed fields.

Large sweep: `PION_RTCP_GOLDEN=big.jsonl PION_RTCP_REPORT=report.jsonl cargo test --release --test pion_golden`.

Intended differences from pion (see `pion_golden.rs`): a CCFB block or XR block that overruns its packet
is rejected here and accepted by pion; TWCC and XR are compared on parsed fields / verdict because pion
re-emits stale header lengths and zeroes reserved bytes.

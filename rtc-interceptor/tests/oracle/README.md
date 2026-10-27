# pion/interceptor NACK oracle

`src/nack/pion_golden_test.rs` replays `tests/data/pion_nack_golden.jsonl` through this crate's NACK
`ReceiveLog` and `SendBuffer` and compares every answer with pion/interceptor v0.1.49.

`receive_log.go` is pion's `pkg/nack/receive_log.go`, unchanged except that its two `internal`
imports (a power-of-two check and the half-range constant) are replaced by the copies in `util.go`.
`main.go` also holds pion's `internal/rtpbuffer.RTPBuffer` reduced to the sequence numbers it is
keyed by, and generates the input: random arrival sequences that are in order, lossy, reordered,
duplicated, start near the 16-bit wrap, and sometimes jump by more than half the sequence space.
Each row is one sequence and every answer pion gave (`get`, and `missingSeqNumbers` as a count, a
hash and the first few numbers).

```sh
GOFLAGS=-mod=mod go run . -n 800 > ../data/pion_nack_golden.jsonl
```

`PION_NACK_GOLDEN=<file> cargo test -p rtc-interceptor --lib matches_pion_nack -- --nocapture`
replays another file and lists the divergences instead of failing.

Found: nothing. The two buffers agree with pion on all 800 sequences.

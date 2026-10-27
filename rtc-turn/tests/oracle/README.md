# pion/turn protocol oracle

`proto/` is a verbatim copy of pion/turn v5.1.2's `internal/proto` (MIT licence; Go does not let
another module import an `internal` package). `main.go` classifies a datagram as a TURN peer does
(STUN message, ChannelData, or neither) and reports what that package finds: for a STUN message
every TURN attribute getter's result (`absent`, `err`, or `ok <value>`), for ChannelData the
decoded channel number and payload and the bytes a re-encode produces.
`tests/pion_golden.rs` replays `tests/data/pion_turn_golden.jsonl` through this crate.

Seeds: `go run . -gen` (every TURN method and attribute, ChannelData of several sizes);
`mutate.py` adds truncations, bit flips, interesting bytes and edited message lengths. Regenerate:

```sh
python3 mutate.py 6000 > /tmp/in.jsonl
GOFLAGS=-mod=mod go run . < /tmp/in.jsonl > ../data/pion_turn_golden.jsonl
```

`PION_TURN_GOLDEN=<file> cargo test -p rtc-turn --test pion_golden -- --nocapture` replays another
file and lists the divergences instead of failing.

## What it found

`DONT-FRAGMENT` with a value was accepted; it has no value part (RFC 5766 §14.8) and pion rejects it.

## Intended difference

`EVEN-PORT`: pion's `firstBitSet` is `(1 << 8) - 1`, not `1 << 7`, so it writes `0xFF` and reads any
non-zero byte as "reserve the next port". RFC 5766 §14.6 gives that meaning to the first bit alone
and has the other seven ignored on receipt; this crate follows the RFC. Interoperable either way
for `0x00` and `0x80`, and for `0xFF` which sets the first bit.

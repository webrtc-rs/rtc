# pion/ice candidate oracle

`tests/pion_candidate_golden.rs` replays `tests/data/pion_candidate_golden.jsonl` through
`unmarshal_candidate` and compares it with pion/ice v4.4.8's `UnmarshalCandidate`: whether the line
parses, and then the type, network, address, port, priority, component, foundation, related
address, TCP type and what `Marshal` writes back.

Seeds are in `main.go` (every candidate type, IPv6, mDNS names, TCP types, extensions, lines from
pion's own tests, malformed lines); `mutate.py` drops, duplicates and replaces tokens, truncates, and
edits bytes. Regenerate:

```sh
python3 mutate.py 5000 > /tmp/in.jsonl
GOFLAGS=-mod=mod go run . < /tmp/in.jsonl > ../data/pion_candidate_golden.jsonl
```

`PION_ICE_GOLDEN=<file> cargo test -p rtc-ice --test pion_candidate_golden -- --nocapture` replays
another file and lists the divergences instead of failing.

## What it found

* `tcptype ACTIVE` (any case) was rejected; pion's `NewTCPType` is case-insensitive and
  implementations in the wild send upper case.
* The priority computed for a candidate line without one used `256 - component` in 32 bits, which
  overflows for a component above 256 (a panic in debug builds, a different value than pion's in
  release). It now wraps in 16 bits, as pion's does.

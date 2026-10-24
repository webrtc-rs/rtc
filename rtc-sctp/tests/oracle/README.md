# pion/sctp oracle

`src/pion_golden_test.rs` replays packets through this crate and compares with pion/sctp v1.12.0
(`tests/data/pion_sctp_golden.jsonl`): the verdict (checksum verified), the chunk types found and the
bytes pion marshals the packet back to.

pion keeps its packet type private, so the oracle needs `oracle_export.go.txt` (rename to
`oracle_export.go`) added to a copy of the `sctp` package; it exports `OracleRun`. Seeds come from
hooking `packet.unmarshal` and every `chunk*.unmarshal` in that copy and running its tests
(`instrument.py`, plus a one-line hook in `packet.go`); `sctp_corpus.py` wraps lone chunks in packets,
mutates, and re-computes the CRC-32C for most mutants so they reach the chunk parsers.

Intended differences from pion (see `normalize` and the match arms in the test):
- non-zero chunk padding and trailing bytes are ignored here (RFC 4960 §3.2), refused by pion;
- reserved chunk flags are written as zero; value-less chunks do not echo extra bytes;
- INIT parameters that say "stop processing" are refused while parsing, not in `check()`;

I-DATA and I-FORWARD-TSN (RFC 8260) rows were added from a generator that builds structured chunks of
those types (random flags, TSNs, identifiers, payload lengths, odd lengths, duplicate stream entries),
wraps them, optionally mutates and re-checksums them, and runs them through the same oracle. About
180,000 such inputs were compared and agree; 2,500 of them are in the corpus.

Four more golden files come from the same pion/sctp v1.12.0 copy, each with a small exporter added to
the package (like `oracle_export.go.txt`), a generator of random cases and a replay test here:
`pion_sched_golden.jsonl` (round-robin / weighted-fair stream schedulers: push/pop sequences, pop
order must match; 100,000 more sequences were compared offline, `PION_SCHED_GOLDEN=<file>`),
`pion_wmin_golden.jsonl` (`windowedMin`; 200,000 offline, `PION_WMIN_GOLDEN`) and
`pion_reassembly_golden.jsonl` (reassembly queue, DATA and I-DATA, ordered and unordered, with
dropped, duplicated and shuffled fragments, reads, forwards and the descriptor limit; every step
compares completeness, error, message read, readability and byte count; 300,000 offline,
`PION_REASSEMBLY_GOLDEN`). The exporters are not kept in the tree.

Unordered DATA with a duplicated TSN is left out of the reassembly corpus: pion sorts fragments with
an unstable sort, so its result for equal TSNs is arbitrary (the association drops duplicate TSNs
before the reassembly queue sees them).

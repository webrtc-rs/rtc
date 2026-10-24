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

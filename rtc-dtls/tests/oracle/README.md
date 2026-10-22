# pion/dtls oracle (record layer)

`tests/pion_golden.rs` replays DTLS records through this crate's `RecordLayer::unmarshal` and compares
with pion's `recordlayer.RecordLayer` (v3.1.15): verdict, content type and the re-marshalled bytes.
Seeds are pion's own records plus every handshake message body its tests parse, wrapped in a
handshake header and a record header; `FIX=dtls bincorpus.py ... fix` mutates them and repairs the
record/handshake length fields for most mutants.

`tests/data/pion_dtls_golden.jsonl` holds vectors on which the two agree, as a regression net. A large
sweep (40,000 mutants) finds no panic, and these intended differences:
- pion checks each handshake message's internal lengths in its own way (it ignores trailing bytes in
  CertificateRequest/ServerHelloDone, rejects them in Certificate); this crate requires a message to
  consume exactly the bytes its header announces;
- ServerKeyExchange/ClientKeyExchange are not compared: pion is told the key exchange algorithm, this
  crate infers it from the bytes.

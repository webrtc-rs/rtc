# pion/datachannel oracle

pion exposes only `TryMarshalUnmarshal` (parse + re-marshal, 0/1), so the oracle records a verdict per
DCEP message. Seeds are hand-built OPEN messages (every channel type, empty/long labels and protocols)
and ACKs; `bincorpus.py` mutates them.

Intended differences from pion (see `pion_golden.rs`): types 0x00/0x01 are this crate's internal
control messages and are refused as DCEP; an OPEN with a channel type RFC 8832 does not define is
refused; bytes after an OPEN's label and protocol are ignored.

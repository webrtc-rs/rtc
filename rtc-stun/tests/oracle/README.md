# pion/stun oracle

`tests/pion_golden.rs` replays datagrams through this crate and compares with pion/stun v4.0.1
(`tests/data/pion_stun_golden.jsonl`): message type, transaction id, attributes (including the
RFC 8489 rule that attributes after MESSAGE-INTEGRITY are dropped, except FINGERPRINT and
MESSAGE-INTEGRITY-SHA256), FINGERPRINT and short-term MESSAGE-INTEGRITY checks, typed attribute
getters (XOR-MAPPED-ADDRESS, MAPPED-ADDRESS, ERROR-CODE, USERNAME, REALM, NONCE, SOFTWARE,
UNKNOWN-ATTRIBUTES) and a re-encode.

Seeds come from hooking `Message.Decode`/`Encode` in a copy of pion/stun and running its tests, plus
`go run ./tests/oracle -gen` (well-formed messages of many shapes); `bincorpus.py` mutates them.

Intended difference: a USERNAME/REALM/NONCE/SOFTWARE value that is not UTF-8 is converted lossily.

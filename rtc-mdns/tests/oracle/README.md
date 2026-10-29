# dnsmessage oracle

`src/message/pion_golden_test.rs` replays `tests/data/pion_dnsmessage_golden.jsonl` through this
crate's message codec and compares it with `golang.org/x/net/dns/dnsmessage` v0.50.0, the codec
pion/mdns uses (the version pion's `go.mod` resolves). Each row is a message — one of 24 well-formed
seeds, or a mutation of one — with whether pion could unpack it, the header, the questions and
record headers it found, and the bytes `Pack` produces from what it unpacked.

Seeds: `go run . -gen` (every common record type, compression, an EDNS0 OPT record). `mutate.py`
adds every truncation, bit flips, bytes set to interesting values, bad compression pointers,
edited section counts and trailing junk. Regenerate:

```sh
python3 mutate.py 6000 > /tmp/in.jsonl
GOFLAGS=-mod=mod go run . < /tmp/in.jsonl > ../data/pion_dnsmessage_golden.jsonl
```

`PION_MDNS_GOLDEN=<file> cargo test -p rtc-mdns --lib matches_pion_dnsmessage -- --nocapture`
replays another file and lists the divergences instead of failing.

## What it found

The next record starts where the previous record's `RDLENGTH` says it ends. This crate used to start
it where the body parser stopped, so a packet with a wrong `RDLENGTH` was split into different
records than every other parser splits it into. Fixed in `unpack_resource_body`.

## Intended differences

The test skips a row only for one of these reasons, so anything else must match byte for byte:

* **Names and TXT strings must be UTF-8** (RFC 6762 §16). pion keeps their bytes.
* **Record types outside the modelled set** (A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, OPT; ANY
  as a question): pion keeps any other as an `UnknownResource` and understands SVCB/HTTPS. Here a
  message holding one is not unpacked whole, and a question of such a type reads as type 0. The
  responder reads records one at a time and skips those it does not understand, so neither matters
  to it.
* **Header AD and CD bits and an RCode above 5** are not modelled; an mDNS message leaves them zero
  and the receiver ignores them (RFC 6762 §18).

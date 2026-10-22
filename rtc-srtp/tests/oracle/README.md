# pion/srtp oracle

`tests/pion_golden.rs` runs protect/unprotect operations through this crate and compares with
pion/srtp v3.1.3, on a fresh context with master key `00 01 02 ...` and salt `10 11 12 ...`
(`tests/data/pion_srtp_golden.jsonl`). Profiles: AES-CM-HMAC-SHA1 (80/32, 128/256) and AEAD AES-GCM
(128/256). Encryption vectors are valid RTP/RTCP packets (from the `rtc-rtp`/`rtc-rtcp` corpora);
decryption vectors are pion's own ciphertexts, intact and with bits flipped, truncated or extended.

The first run of this oracle found two bugs now fixed: the SRTCP receive path returned early for
packets with the E bit clear *without checking the authentication tag* (forged RTCP could be
injected), and the SRTP ciphers took the header length from `marshal_size()` rather than the
packet's true wire length.

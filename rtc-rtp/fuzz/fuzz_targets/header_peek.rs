#![no_main]

//! `Header::peek` is what SRTP trusts in place of a full parse, so it must agree with
//! `Header::unmarshal` on every input: same accept/reject, same fields.

use libfuzzer_sys::fuzz_target;
use rtc_rtp::Header;
use rtc_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let parsed = Header::unmarshal(&mut buf);
    let peeked = Header::peek(data);
    match (parsed, peeked) {
        (Ok(h), Ok(s)) => {
            assert_eq!(h.marker, s.marker);
            assert_eq!(h.payload_type, s.payload_type);
            assert_eq!(h.sequence_number, s.sequence_number);
            assert_eq!(h.timestamp, s.timestamp);
            assert_eq!(h.ssrc, s.ssrc);
            assert_eq!(Header::wire_len(data).unwrap(), s.header_len);
        }
        (Err(a), Err(b)) => assert_eq!(a, b),
        (a, b) => panic!("peek disagrees with unmarshal: {a:?} vs {b:?}"),
    }
});

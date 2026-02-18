#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::handshake::handshake_random::HandshakeRandom;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = HandshakeRandom::unmarshal(&mut cursor);
});

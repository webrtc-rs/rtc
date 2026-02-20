#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::handshake::Handshake;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = Handshake::unmarshal(&mut cursor);
});

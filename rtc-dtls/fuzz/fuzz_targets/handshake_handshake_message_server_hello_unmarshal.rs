#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::handshake::handshake_message_server_hello::HandshakeMessageServerHello;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = HandshakeMessageServerHello::unmarshal(&mut cursor);
});

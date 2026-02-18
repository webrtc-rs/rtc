#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::handshake::handshake_message_server_hello_done::HandshakeMessageServerHelloDone;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = HandshakeMessageServerHelloDone::unmarshal(&mut cursor);
});

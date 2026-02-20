#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::handshake::handshake_message_hello_verify_request::HandshakeMessageHelloVerifyRequest;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = HandshakeMessageHelloVerifyRequest::unmarshal(&mut cursor);
});

#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::handshake::handshake_message_client_key_exchange::HandshakeMessageClientKeyExchange;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = HandshakeMessageClientKeyExchange::unmarshal(&mut cursor);
});

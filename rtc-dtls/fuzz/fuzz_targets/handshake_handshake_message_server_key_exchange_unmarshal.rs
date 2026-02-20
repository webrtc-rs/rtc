#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::handshake::handshake_message_server_key_exchange::HandshakeMessageServerKeyExchange;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = HandshakeMessageServerKeyExchange::unmarshal(&mut cursor);
});

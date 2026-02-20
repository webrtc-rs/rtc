#![no_main]
use libfuzzer_sys::fuzz_target;
use rand::RngExt;
use rtc_dtls::content::{Content, ContentType};

fuzz_target!(|data: &[u8]| {
    let all_content_type = [
        ContentType::ChangeCipherSpec,
        ContentType::Alert,
        ContentType::Handshake,
        ContentType::ApplicationData,
        ContentType::Invalid,
    ];
    let index = rand::rng().random_range(0..all_content_type.len());
    let content_type = all_content_type.get(index).unwrap();
    let mut cursor = std::io::Cursor::new(data);
    let _ = Content::unmarshal(*content_type, &mut cursor);
});

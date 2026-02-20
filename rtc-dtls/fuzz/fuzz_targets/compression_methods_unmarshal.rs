#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::compression_methods::CompressionMethods;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = CompressionMethods::unmarshal(&mut cursor);
});

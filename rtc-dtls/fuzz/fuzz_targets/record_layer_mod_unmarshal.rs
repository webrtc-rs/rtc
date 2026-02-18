#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::record_layer::RecordLayer;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = RecordLayer::unmarshal(&mut cursor);
});

#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::application_data::ApplicationData;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = ApplicationData::unmarshal(&mut cursor);
});

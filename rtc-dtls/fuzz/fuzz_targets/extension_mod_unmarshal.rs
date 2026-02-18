#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::extension::Extension;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = Extension::unmarshal(&mut cursor);
});

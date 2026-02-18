#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::alert::Alert;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = Alert::unmarshal(&mut cursor);
});

#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::change_cipher_spec::ChangeCipherSpec;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = ChangeCipherSpec::unmarshal(&mut cursor);
});

#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::extension::renegotiation_info::ExtensionRenegotiationInfo;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = ExtensionRenegotiationInfo::unmarshal(&mut cursor);
});

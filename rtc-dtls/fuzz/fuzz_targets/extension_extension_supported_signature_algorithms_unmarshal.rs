#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::extension::extension_supported_signature_algorithms::ExtensionSupportedSignatureAlgorithms;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = ExtensionSupportedSignatureAlgorithms::unmarshal(&mut cursor);
});

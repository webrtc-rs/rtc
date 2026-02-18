#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::extension::extension_use_extended_master_secret::ExtensionUseExtendedMasterSecret;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = ExtensionUseExtendedMasterSecret::unmarshal(&mut cursor);
});

#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::extension::extension_server_name::ExtensionServerName;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = ExtensionServerName::unmarshal(&mut cursor);
});

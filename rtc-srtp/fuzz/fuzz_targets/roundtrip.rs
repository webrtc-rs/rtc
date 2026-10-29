#![no_main]

//! Whatever RTP/RTCP packet the header parser accepts must survive protect -> unprotect
//! byte-for-byte, on every profile.

use libfuzzer_sys::fuzz_target;
use rtc_srtp::context::Context;
use rtc_srtp::protection_profile::ProtectionProfile;

const PROFILES: [ProtectionProfile; 4] = [
    ProtectionProfile::Aes128CmHmacSha1_80,
    ProtectionProfile::Aes256CmHmacSha1_32,
    ProtectionProfile::AeadAes128Gcm,
    ProtectionProfile::AeadAes256Gcm,
];

fn pair(profile: ProtectionProfile) -> (Context, Context) {
    let provider = rtc_crypto::default_provider().unwrap();
    let key: Vec<u8> = (0..profile.key_len() as u8).collect();
    let salt: Vec<u8> = (0..profile.salt_len() as u8).map(|i| 0x40 + i).collect();
    let make = || Context::new(&key, &salt, profile, None, None, provider.crypto()).unwrap();
    (make(), make())
}

fuzz_target!(|data: &[u8]| {
    for profile in PROFILES {
        let (mut sender, mut receiver) = pair(profile);

        if let Ok(protected) = sender.encrypt_rtp(data) {
            let plain = receiver
                .decrypt_rtp(&protected)
                .expect("a packet we just protected must unprotect");
            assert_eq!(&plain[..], data, "{profile:?}: RTP round trip");
        }
        if let Ok(protected) = sender.encrypt_rtcp(data) {
            let plain = receiver
                .decrypt_rtcp(&protected)
                .expect("an RTCP packet we just protected must unprotect");
            assert_eq!(&plain[..], data, "{profile:?}: RTCP round trip");
        }
    }
});

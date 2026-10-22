#![no_main]

//! Bytes straight off the network go into `decrypt_rtp` / `decrypt_rtcp`: they must be refused
//! (nearly always at authentication), never panic, and never leave per-SSRC state behind.

use libfuzzer_sys::fuzz_target;
use rtc_srtp::context::Context;
use rtc_srtp::option::{srtcp_replay_protection, srtp_replay_protection};
use rtc_srtp::protection_profile::ProtectionProfile;
use std::cell::RefCell;

const PROFILES: [ProtectionProfile; 4] = [
    ProtectionProfile::Aes128CmHmacSha1_80,
    ProtectionProfile::Aes128CmHmacSha1_32,
    ProtectionProfile::AeadAes128Gcm,
    ProtectionProfile::AeadAes256Gcm,
];

thread_local! {
    static CONTEXTS: RefCell<Vec<Context>> = RefCell::new(
        PROFILES
            .iter()
            .map(|&profile| {
                let provider = rtc_crypto::default_provider().unwrap();
                let key: Vec<u8> = (0..profile.key_len() as u8).collect();
                let salt: Vec<u8> = (0..profile.salt_len() as u8).map(|i| 0x40 + i).collect();
                Context::new(
                    &key,
                    &salt,
                    profile,
                    Some(srtp_replay_protection(64)),
                    Some(srtcp_replay_protection(64)),
                    provider.crypto(),
                )
                .unwrap()
            })
            .collect()
    );
}

fuzz_target!(|data: &[u8]| {
    CONTEXTS.with(|contexts| {
        for context in contexts.borrow_mut().iter_mut() {
            let _ = context.decrypt_rtp(data);
            let _ = context.decrypt_rtcp(data);
        }
    });
});

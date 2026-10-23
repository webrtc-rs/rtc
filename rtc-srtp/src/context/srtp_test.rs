use super::*;
use shared::marshal::*;

/// The built-in provider, for tests only. Library code never resolves a default: every public
/// constructor takes the provider from its caller.
fn test_crypto_provider() -> std::sync::Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

use bytes::{Bytes, BytesMut};
use lazy_static::lazy_static;

struct RTPTestCase {
    sequence_number: u16,
    encrypted_ctr: Bytes,
    encrypted_gcm: Bytes,
}

impl RTPTestCase {
    /// The encrypted payload for a profile: the vector doubles as payload-plus-tag, 10 bytes for
    /// AES-CM's HMAC tag, 16 for AEAD-GCM's.
    fn encrypted(&self, profile: ProtectionProfile) -> &Bytes {
        match profile {
            ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => {
                &self.encrypted_gcm
            }
            _ => &self.encrypted_ctr,
        }
    }
}

lazy_static! {
    static ref RTP_TEST_CASE_DECRYPTED: Bytes = Bytes::from_static(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    static ref RTP_TEST_CASES: Vec<RTPTestCase> = vec![
        RTPTestCase {
            sequence_number: 5000,
            encrypted_ctr: Bytes::from_static(&[
                0x6d, 0xd3, 0x7e, 0xd5, 0x99, 0xb7, 0x2d, 0x28, 0xb1, 0xf3, 0xa1, 0xf0, 0xc, 0xfb,
                0xfd, 0x8
            ]),
            encrypted_gcm: Bytes::from_static(&[
                0x05, 0x39, 0x62, 0xbb, 0x50, 0x2a, 0x08, 0x19, 0xc7, 0xcc, 0xc9, 0x24, 0xb8,
                0xd9, 0x7a, 0xe5, 0xad, 0x99, 0x06, 0xc7, 0x3b, 0x00
            ]),
        },
        RTPTestCase {
            sequence_number: 5001,
            encrypted_ctr: Bytes::from_static(&[
                0xda, 0x47, 0xb, 0x2a, 0x74, 0x53, 0x65, 0xbd, 0x2f, 0xeb, 0xdc, 0x4b, 0x6d, 0x23,
                0xf3, 0xde
            ]),
            encrypted_gcm: Bytes::from_static(&[
                0xb0, 0xbc, 0xfc, 0xb0, 0x15, 0x2c, 0xa0, 0x15, 0xb5, 0xa8, 0xcd, 0xd, 0x65,
                0xfa, 0x98, 0xb3, 0x09, 0xb1, 0xf8, 0x4b, 0x1c, 0xfa
            ]),
        },
        RTPTestCase {
            sequence_number: 5002,
            encrypted_ctr: Bytes::from_static(&[
                0x6e, 0xa7, 0x69, 0x8d, 0x24, 0x6d, 0xdc, 0xbf, 0xec, 0x2, 0x1c, 0xd1, 0x60, 0x76,
                0xc1, 0xe
            ]),
            encrypted_gcm: Bytes::from_static(&[
                0x5e, 0x20, 0x6a, 0xbf, 0x58, 0x7e, 0x24, 0xc0, 0x15, 0x94, 0x7a, 0xe2, 0x49,
                0x25, 0xd4, 0xd4, 0x08, 0xe2, 0xf1, 0x47, 0x7a, 0x33
            ]),
        },
        RTPTestCase {
            sequence_number: 5003,
            encrypted_ctr: Bytes::from_static(&[
                0x24, 0x7e, 0x96, 0xc8, 0x7d, 0x33, 0xa2, 0x92, 0x8d, 0x13, 0x8d, 0xe0, 0x76, 0x9f,
                0x08, 0xdc
            ]),
            encrypted_gcm: Bytes::from_static(&[
                0xb0, 0x63, 0x14, 0xe7, 0xd2, 0x29, 0xca, 0x92, 0x8c, 0x97, 0x25, 0xd2, 0x50,
                0x69, 0x6e, 0x1b, 0x04, 0xb9, 0x37, 0xa5, 0xa1, 0xc5
            ]),
        },
        RTPTestCase {
            sequence_number: 5004,
            encrypted_ctr: Bytes::from_static(&[
                0x75, 0x43, 0x28, 0xe4, 0x3a, 0x77, 0x59, 0x9b, 0x2e, 0xdf, 0x7b, 0x12, 0x68, 0x0b,
                0x57, 0x49
            ]),
            encrypted_gcm: Bytes::from_static(&[
                0xb2, 0x4f, 0x19, 0x53, 0x79, 0x8a, 0x9b, 0x9e, 0xe5, 0x22, 0x93, 0x14, 0x50,
                0x8a, 0x8c, 0xd5, 0xfc, 0x61, 0xbf, 0x95, 0xd1, 0xfb
            ]),
        },
        RTPTestCase{
            sequence_number: 65535, // upper boundary
            encrypted_ctr: Bytes::from_static(&[
                0xaf, 0xf7, 0xc2, 0x70, 0x37, 0x20, 0x83, 0x9c, 0x2c, 0x63, 0x85, 0x15, 0x0e, 0x44,
                0xca, 0x36
            ]),
            encrypted_gcm: Bytes::from_static(&[
                0x40, 0x44, 0x6c, 0xd1, 0x33, 0x5f, 0xca, 0x9b, 0x2e, 0xa3, 0xe5, 0x03, 0xd7,
                0x82, 0x36, 0xd8, 0xb7, 0xe8, 0x97, 0x3c, 0xe6, 0xb6
            ]),
        },
    ];
}

/// pion's `buildTestContext`: the shared 16-byte key / 14-byte salt, sliced to what the profile
/// takes (pion's helper slices the same way, and is only ever used with the 128-bit profiles).
fn build_test_context(profile: ProtectionProfile) -> Result<Context> {
    let master_key = [
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ];
    let master_salt = [
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ];

    Context::new(
        &master_key[..profile.key_len().min(master_key.len())],
        &master_salt[..profile.salt_len().min(master_salt.len())],
        profile,
        None,
        None,
        test_crypto_provider().crypto(),
    )
}

#[test]
fn test_rtp_invalid_auth() -> Result<()> {
    let invalid_salt = Bytes::from_static(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    let mut encrypt_context = build_test_context(ProtectionProfile::Aes128CmHmacSha1_80)?;
    let mut invalid_context = Context::new(
        &Bytes::from_static(&[
            0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e,
            0x28, 0x89,
        ]),
        &invalid_salt,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )?;

    for test_case in &*RTP_TEST_CASES {
        let pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number: test_case.sequence_number,
                ..Default::default()
            },
            payload: RTP_TEST_CASE_DECRYPTED.clone(),
        };

        let pkt_raw = pkt.marshal()?;
        let out = encrypt_context.encrypt_rtp(&pkt_raw)?;

        let result = invalid_context.decrypt_rtp(&out);
        assert!(
            result.is_err(),
            "Managed to decrypt with incorrect salt for packet with SeqNum: {}",
            test_case.sequence_number
        );
    }

    Ok(())
}

/// pion's `TestRTPLifecycleNewAlloc`: the golden vectors, both cipher families, through the
/// allocating calls.
#[test]
fn test_rtp_lifecyle() -> Result<()> {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let mut encrypt_context = build_test_context(profile)?;
        let mut decrypt_context = build_test_context(profile)?;
        let auth_tag_len = profile.rtp_auth_tag_len() + profile.aead_auth_tag_len();

        for test_case in RTP_TEST_CASES.iter() {
            let decrypted_pkt = rtp::Packet {
                header: rtp::Header {
                    sequence_number: test_case.sequence_number,
                    ..Default::default()
                },
                payload: RTP_TEST_CASE_DECRYPTED.clone(),
            };

            let decrypted_raw = decrypted_pkt.marshal()?;

            let encrypted_pkt = rtp::Packet {
                header: rtp::Header {
                    sequence_number: test_case.sequence_number,
                    ..Default::default()
                },
                payload: test_case.encrypted(profile).clone(),
            };

            let encrypted_raw = encrypted_pkt.marshal()?;
            let actual_encrypted = encrypt_context.encrypt_rtp(&decrypted_raw)?;
            assert_eq!(
                actual_encrypted, encrypted_raw,
                "{profile:?}: RTP packet with SeqNum invalid encryption: {}",
                test_case.sequence_number
            );

            let actual_decrypted = decrypt_context.decrypt_rtp(&encrypted_raw)?;
            assert_ne!(
                encrypted_raw[..encrypted_raw.len() - auth_tag_len].to_vec(),
                actual_decrypted,
                "{profile:?}: DecryptRTP improperly encrypted in place"
            );

            assert_eq!(
                actual_decrypted, decrypted_raw,
                "{profile:?}: RTP packet with SeqNum invalid decryption: {}",
                test_case.sequence_number,
            )
        }
    }

    Ok(())
}

//TODO: BenchmarkEncryptRTP
//TODO: BenchmarkEncryptRTPInPlace
//TODO: BenchmarkDecryptRTP

fn media_context(profile: ProtectionProfile) -> Context {
    let provider = test_crypto_provider();
    let key: Vec<u8> = (0..profile.key_len() as u8).collect();
    let salt: Vec<u8> = (0..profile.salt_len() as u8).map(|i| 0x20 + i).collect();
    Context::new(
        &key,
        &salt,
        profile,
        Some(srtp_replay_protection(64)),
        None,
        provider.crypto(),
    )
    .unwrap()
}

fn rtp_packet(ssrc: u32, seq: u16, payload_len: usize) -> Vec<u8> {
    let mut p = vec![0x80, 96, (seq >> 8) as u8, seq as u8, 0, 0, 0, 1];
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend((0..payload_len).map(|i| i as u8));
    p
}

/// The SSRC is read from an unauthenticated header, so spraying forged packets with random SSRCs
/// must not make the receiver allocate per-SSRC state.
#[test]
fn test_unauthenticated_packets_create_no_ssrc_state() {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let mut receiver = media_context(profile);
        for ssrc in 0..1000u32 {
            let mut forged = rtp_packet(0x1000_0000 + ssrc, 1, 100);
            forged.extend_from_slice(&[0xEE; 16]);
            assert!(receiver.decrypt_rtp(&forged).is_err());
        }
        assert!(
            receiver.srtp_ssrc_states.is_empty(),
            "{profile:?}: forged packets left per-SSRC state behind"
        );
    }
}

/// An SSRC is tracked once a packet for it authenticates, and replays are then refused.
#[test]
fn test_authenticated_packet_creates_state_and_blocks_replay() {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let mut sender = media_context(profile);
        let mut receiver = media_context(profile);
        let plain = rtp_packet(0xABCD, 7, 200);
        let protected = sender.encrypt_rtp(&plain).unwrap();

        assert_eq!(&receiver.decrypt_rtp(&protected).unwrap()[..], &plain[..]);
        assert_eq!(receiver.srtp_ssrc_states.len(), 1);
        assert!(
            receiver.decrypt_rtp(&protected).is_err(),
            "{profile:?}: replayed packet was accepted"
        );
    }
}

/// `*_into` appends to a caller-owned buffer, matches the allocating calls, and leaves the
/// buffer untouched on failure.
#[test]
fn test_rtp_into_appends_and_restores_on_error() {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::Aes256CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
        ProtectionProfile::AeadAes256Gcm,
    ] {
        let mut sender = media_context(profile);
        let mut reference = media_context(profile);
        let mut receiver = media_context(profile);

        let mut dst = BytesMut::from(&b"prefix"[..]);
        let mut sent = Vec::new();
        for seq in 0..4u16 {
            let plain = rtp_packet(0x77, seq, 50 + seq as usize);
            let start = dst.len();
            sender.encrypt_rtp_into(&mut dst, &plain).unwrap();
            let expected = reference.encrypt_rtp(&plain).unwrap();
            assert_eq!(&dst[start..], &expected[..], "{profile:?} seq {seq}");
            sent.push((plain, dst[start..].to_vec()));
        }
        assert_eq!(&dst[..6], b"prefix");

        let mut out = BytesMut::new();
        for (plain, protected) in &sent {
            out.clear();
            receiver.decrypt_rtp_into(&mut out, protected).unwrap();
            assert_eq!(&out[..], &plain[..]);
        }

        // A corrupt packet leaves whatever was already in the buffer alone.
        let mut bad = sent[0].1.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xFF;
        let mut keep = BytesMut::from(&b"keep"[..]);
        assert!(
            media_context(profile)
                .decrypt_rtp_into(&mut keep, &bad)
                .is_err()
        );
        assert_eq!(&keep[..], b"keep");
    }
}

/// In-place protection must give the same bytes as the copying calls, and in-place unprotection
/// must undo it exactly.
#[test]
fn test_rtp_in_place_matches_copying_calls() {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::Aes128CmHmacSha1_32,
        ProtectionProfile::Aes256CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
        ProtectionProfile::AeadAes256Gcm,
    ] {
        let mut sender = media_context(profile);
        let mut reference = media_context(profile);
        let mut receiver = media_context(profile);
        let overhead = sender.rtp_overhead();
        assert!(overhead >= 4, "{profile:?}: overhead {overhead}");

        for seq in 0..6u16 {
            let plain = rtp_packet(0x99, seq, 10 + 37 * seq as usize);

            let mut packet = BytesMut::with_capacity(plain.len() + overhead);
            packet.extend_from_slice(&plain);
            let before = packet.as_ptr();
            sender.encrypt_rtp_in_place(&mut packet).unwrap();
            assert_eq!(
                packet.as_ptr(),
                before,
                "{profile:?}: the reserved capacity must be enough to avoid reallocating"
            );
            assert_eq!(packet.len(), plain.len() + overhead);
            assert_eq!(
                &packet[..],
                &reference.encrypt_rtp(&plain).unwrap()[..],
                "{profile:?} seq {seq}"
            );

            let protected = packet.clone();
            receiver.decrypt_rtp_in_place(&mut packet).unwrap();
            assert_eq!(&packet[..], &plain[..], "{profile:?} seq {seq}");

            // A tampered packet is refused, and the CM profiles leave it byte-for-byte alone.
            let mut tampered = protected.clone();
            let n = tampered.len();
            tampered[n - 1] ^= 1;
            let snapshot = tampered.clone();
            assert!(
                media_context(profile)
                    .decrypt_rtp_in_place(&mut tampered)
                    .is_err()
            );
            if matches!(
                profile,
                ProtectionProfile::Aes128CmHmacSha1_80
                    | ProtectionProfile::Aes128CmHmacSha1_32
                    | ProtectionProfile::Aes256CmHmacSha1_80
            ) {
                assert_eq!(
                    tampered, snapshot,
                    "{profile:?}: rejected packet was modified"
                );
            }
        }
    }
}

/// pion's `TestRTPLifecycleInPlace`: the golden vectors through the in-place calls, with enough
/// spare capacity reserved that the packet never moves.
#[test]
fn test_rtp_lifecycle_in_place() -> Result<()> {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let mut encrypt_context = build_test_context(profile)?;
        let mut decrypt_context = build_test_context(profile)?;
        let overhead = encrypt_context.rtp_overhead();

        for test_case in RTP_TEST_CASES.iter() {
            let decrypted_pkt = rtp::Packet {
                header: rtp::Header {
                    sequence_number: test_case.sequence_number,
                    ..Default::default()
                },
                payload: RTP_TEST_CASE_DECRYPTED.clone(),
            };
            let decrypted_raw = decrypted_pkt.marshal()?;

            let encrypted_pkt = rtp::Packet {
                header: rtp::Header {
                    sequence_number: test_case.sequence_number,
                    ..Default::default()
                },
                payload: test_case.encrypted(profile).clone(),
            };
            let encrypted_raw = encrypted_pkt.marshal()?;

            let mut encrypt_input = BytesMut::with_capacity(decrypted_raw.len() + overhead);
            encrypt_input.extend_from_slice(&decrypted_raw);
            let before = encrypt_input.as_ptr();
            encrypt_context.encrypt_rtp_in_place(&mut encrypt_input)?;
            assert_eq!(
                encrypt_input.as_ptr(),
                before,
                "{profile:?}: EncryptRTP failed to encrypt in place"
            );
            assert_eq!(
                encrypt_input, encrypted_raw,
                "{profile:?}: RTP packet with SeqNum invalid encryption: {}",
                test_case.sequence_number
            );

            let mut decrypt_input = BytesMut::from(&encrypted_raw[..]);
            let before = decrypt_input.as_ptr();
            decrypt_context.decrypt_rtp_in_place(&mut decrypt_input)?;
            assert_eq!(
                decrypt_input.as_ptr(),
                before,
                "{profile:?}: DecryptRTP failed to decrypt in place"
            );
            assert_eq!(
                decrypt_input, decrypted_raw,
                "{profile:?}: RTP packet with SeqNum invalid decryption: {}",
                test_case.sequence_number
            );
        }
    }

    Ok(())
}

/// pion's `TestRTPReplayProtection`: with a 64-packet window the golden vectors round-trip
/// byte-for-byte, and the second copy of a packet is refused as a replay.
#[test]
fn test_rtp_replay_protection() -> Result<()> {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        for test_case in RTP_TEST_CASES.iter() {
            let mut encrypt_context = build_test_context(profile)?;
            let mut decrypt_context = Context::new(
                &build_key(profile),
                &build_salt(profile),
                profile,
                Some(srtp_replay_protection(64)),
                None,
                test_crypto_provider().crypto(),
            )?;

            let decrypted_pkt = rtp::Packet {
                header: rtp::Header {
                    sequence_number: test_case.sequence_number,
                    ..Default::default()
                },
                payload: RTP_TEST_CASE_DECRYPTED.clone(),
            };
            let decrypted_raw = decrypted_pkt.marshal()?;

            let encrypted_pkt = rtp::Packet {
                header: rtp::Header {
                    sequence_number: test_case.sequence_number,
                    ..Default::default()
                },
                payload: test_case.encrypted(profile).clone(),
            };
            let encrypted_raw = encrypted_pkt.marshal()?;

            let actual_encrypted = encrypt_context.encrypt_rtp(&decrypted_raw)?;
            assert_eq!(
                actual_encrypted, encrypted_raw,
                "{profile:?}: RTP packet with SeqNum invalid encryption: {}",
                test_case.sequence_number
            );

            let actual_decrypted = decrypt_context.decrypt_rtp(&encrypted_raw)?;
            assert_eq!(
                actual_decrypted, decrypted_raw,
                "{profile:?}: RTP packet with SeqNum invalid decryption: {}",
                test_case.sequence_number
            );

            // A second copy of the same packet is a replay.
            assert!(matches!(
                decrypt_context.decrypt_rtp(&encrypted_raw),
                Err(Error::SrtpSsrcDuplicated(0, seq)) if seq == test_case.sequence_number
            ));
        }
    }

    Ok(())
}

/// The key `pion`'s `buildTestContext` slices for a profile.
fn build_key(profile: ProtectionProfile) -> Vec<u8> {
    [
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ][..profile.key_len().min(16)]
        .to_vec()
}

/// The salt `pion`'s `buildTestContext` slices for a profile.
fn build_salt(profile: ProtectionProfile) -> Vec<u8> {
    [
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ][..profile.salt_len().min(14)]
        .to_vec()
}

/// pion's `TestRTPReplayDetectorFactory`: a custom detector factory runs exactly once for the
/// one SSRC a first packet establishes.
#[test]
fn test_rtp_replay_detector_factory() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    let data = &RTP_TEST_CASES[0];

    let count = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    let factory: ContextOption = Box::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        Box::<NoOpReplayDetector>::default()
    });

    let mut decrypt_context = Context::new(
        &build_key(profile),
        &build_salt(profile),
        profile,
        Some(factory),
        None,
        test_crypto_provider().crypto(),
    )?;

    let pkt = rtp::Packet {
        header: rtp::Header {
            sequence_number: data.sequence_number,
            ..Default::default()
        },
        payload: data.encrypted(profile).clone(),
    };
    let encrypted_raw = pkt.marshal()?;

    decrypt_context.decrypt_rtp(&encrypted_raw)?;
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "the replay detector factory must run once per SSRC"
    );

    Ok(())
}

/// pion's `TestRTPLegacyReplayDetector`: a detector that only offers the one-phase Check API
/// must still catch replays. Our `ReplayDetector` trait is two-phase by construction, so the
/// "legacy detector" here is the plain sliding window over the full 48-bit packet index, the
/// detector pion's legacy wrapper delegates to.
#[test]
fn test_rtp_legacy_replay_detector() -> Result<()> {
    let profile = ProtectionProfile::Aes128CmHmacSha1_80;
    let data = &RTP_TEST_CASES[0];

    let factory: ContextOption = Box::new(|| {
        Box::new(SlidingWindowDetector::new(
            64,
            (u32::MAX as u64) << 16 | 0xFFFF,
        ))
    });
    let mut decrypt_context = Context::new(
        &build_key(profile),
        &build_salt(profile),
        profile,
        Some(factory),
        None,
        test_crypto_provider().crypto(),
    )?;

    let pkt = rtp::Packet {
        header: rtp::Header {
            sequence_number: data.sequence_number,
            ..Default::default()
        },
        payload: data.encrypted(profile).clone(),
    };
    let encrypted_raw = pkt.marshal()?;

    decrypt_context.decrypt_rtp(&encrypted_raw)?;

    assert!(
        decrypt_context.decrypt_rtp(&encrypted_raw).is_err(),
        "the replayed packet must still be rejected"
    );

    Ok(())
}

/// pion's `TestRTPDecryptShotenedPacket`: every truncation of a real packet, from 1 byte to the
/// full length minus one, must error — never panic or slice out of range.
#[test]
fn test_rtp_decrypt_shotened_packet() -> Result<()> {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        for test_case in RTP_TEST_CASES.iter() {
            let mut decrypt_context = build_test_context(profile)?;

            let encrypted_pkt = rtp::Packet {
                header: rtp::Header {
                    sequence_number: test_case.sequence_number,
                    ..Default::default()
                },
                payload: test_case.encrypted(profile).clone(),
            };
            let encrypted_raw = encrypted_pkt.marshal()?;

            for i in 1..encrypted_raw.len() - 1 {
                let packet = &encrypted_raw[..i];
                assert!(
                    decrypt_context.decrypt_rtp(packet).is_err(),
                    "{profile:?}: decrypt_rtp must not accept a {i}-byte packet"
                );
            }
        }
    }

    Ok(())
}

/// pion's `TestRTPMaxPackets`: the 2^48 SRTP packet limit of RFC 3711 section 9.2. With the ROC
/// at 2^32-1 and the sequence number at the top of the range, the next rollover would push the
/// packet index past 2^48, and the context must refuse rather than let the ROC wrap to 0.
#[test]
fn test_rtp_max_packets() -> Result<()> {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let mut context = build_test_context(profile)?;

        // Upper boundary of the rollover counter.
        context.set_roc(1, u32::MAX);

        let pkt0 = rtp::Packet {
            header: rtp::Header {
                ssrc: 1,
                sequence_number: 0xffff,
                ..Default::default()
            },
            payload: vec![0, 1].into(),
        };
        let raw0 = pkt0.marshal()?;
        context.encrypt_rtp(&raw0)?;

        let pkt1 = rtp::Packet {
            header: rtp::Header {
                ssrc: 1,
                sequence_number: 0,
                ..Default::default()
            },
            payload: vec![0, 1].into(),
        };
        let raw1 = pkt1.marshal()?;
        assert_eq!(
            context.encrypt_rtp(&raw1).err(),
            Some(Error::ErrExceededMaxPackets),
            "{profile:?}: the SRTP packet index must not pass 2^48"
        );
    }

    Ok(())
}

/// pion's `TestRTPBurstLossWithSetROC`: packets spanning several rollovers, with a burst of loss
/// in the middle, each decrypted after telling the receiver the sender's ROC for it — the
/// `SetROC` handshake a repair flow (RTX, RFC 4588-style) needs.
#[test]
fn test_rtp_burst_loss_with_set_roc() -> Result<()> {
    struct PacketWithRoc {
        raw: Vec<u8>,
        enc: BytesMut,
        roc: u32,
    }

    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let mut encrypt_context = build_test_context(profile)?;

        let mut pkts: Vec<PacketWithRoc> = Vec::new();
        encrypt_context.set_roc(1, 3);
        for i in 0x8c00..0x20400u32 {
            let pkt = rtp::Packet {
                header: rtp::Header {
                    marker: true,
                    ssrc: 1,
                    sequence_number: i as u16,
                    ..Default::default()
                },
                payload: Bytes::from(vec![(i >> 16) as u8, (i >> 8) as u8, i as u8]),
            };
            let raw = pkt.marshal()?.to_vec();
            let enc = encrypt_context.encrypt_rtp(&raw)?;
            let roc = encrypt_context.get_roc(1).unwrap_or_default();

            // The burst loss: everything in this range never arrives.
            if 0x9000 < i && i < 0x20100 {
                continue;
            }
            pkts.push(PacketWithRoc { raw, enc, roc });
        }

        let mut decrypt_context = build_test_context(profile)?;
        for p in &pkts {
            decrypt_context.set_roc(1, p.roc);
            let decrypted = decrypt_context
                .decrypt_rtp(&p.enc)
                .unwrap_or_else(|e| panic!("{profile:?}: roc={}, seq lost: {e}", p.roc));
            assert_eq!(&decrypted[..], &p.raw[..], "{profile:?}: roc={}", p.roc);
        }
    }

    Ok(())
}

/// pion's `TestDecryptInvalidSRTP`: a crafted packet that parses as a header must fail
/// authentication, not panic.
#[test]
fn test_decrypt_invalid_srtp() -> Result<()> {
    let key = [0x01; 16];
    let salt = [0x01; 14];
    let mut decrypt_context = Context::new(
        &key,
        &salt,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )?;

    let packet = [
        0x41, 0x02, 0x07, 0xf9, 0xf9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb5, 0x73,
        0x19, 0xf6, 0x91, 0xbb, 0x3e, 0xa5, 0x21, 0x07,
    ];
    assert!(decrypt_context.decrypt_rtp(&packet).is_err());

    Ok(())
}

/// pion's `TestProtectionProfileAes128CmHmacSha1_32`: the short-tag profile round-trips.
#[test]
fn test_protection_profile_aes128_cm_hmac_sha1_32() -> Result<()> {
    let profile = ProtectionProfile::Aes128CmHmacSha1_32;
    let mut encrypt_context = build_test_context(profile)?;
    let mut decrypt_context = build_test_context(profile)?;

    let pkt = rtp::Packet {
        header: rtp::Header {
            sequence_number: 5000,
            ..Default::default()
        },
        payload: RTP_TEST_CASE_DECRYPTED.clone(),
    };
    let pkt_raw = pkt.marshal()?;

    let out = encrypt_context.encrypt_rtp(&pkt_raw)?;
    let decrypted = decrypt_context.decrypt_rtp(&out)?;

    assert_eq!(
        decrypted, pkt_raw,
        "Decrypted RTP packet does not match original"
    );

    Ok(())
}

/// pion's `TestSRTPFailedAuthDoesNotGrowSSRCMap`: a packet that fails authentication must not
/// leave per-SSRC state behind (the SSRC is read from an unauthenticated header).
#[test]
fn test_srtp_failed_auth_does_not_grow_ssrc_map() -> Result<()> {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let mut encrypt_context = build_test_context(profile)?;

        // All-zero key and salt: the authentication tag will never match.
        let mut decrypt_context = Context::new(
            &vec![0; profile.key_len()],
            &vec![0; profile.salt_len()],
            profile,
            None,
            None,
            test_crypto_provider().crypto(),
        )?;

        let pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number: 5000,
                ssrc: 0xDEAD_BEEF,
                ..Default::default()
            },
            payload: RTP_TEST_CASE_DECRYPTED.clone(),
        };
        let pkt_raw = pkt.marshal()?;

        let encrypted = encrypt_context.encrypt_rtp(&pkt_raw)?;
        assert!(
            decrypt_context.decrypt_rtp(&encrypted).is_err(),
            "{profile:?}: DecryptRTP must fail when key does not match"
        );
        assert!(
            decrypt_context.srtp_ssrc_states.is_empty(),
            "{profile:?}: SRTP SSRC state map must not grow after failed authentication"
        );
    }

    Ok(())
}

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
    encrypted: Bytes,
}

lazy_static! {
    static ref RTP_TEST_CASE_DECRYPTED: Bytes = Bytes::from_static(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    static ref RTP_TEST_CASES: Vec<RTPTestCase> = vec![
        RTPTestCase {
            sequence_number: 5000,
            encrypted: Bytes::from_static(&[
                0x6d, 0xd3, 0x7e, 0xd5, 0x99, 0xb7, 0x2d, 0x28, 0xb1, 0xf3, 0xa1, 0xf0, 0xc, 0xfb,
                0xfd, 0x8
            ]),
        },
        RTPTestCase {
            sequence_number: 5001,
            encrypted: Bytes::from_static(&[
                0xda, 0x47, 0xb, 0x2a, 0x74, 0x53, 0x65, 0xbd, 0x2f, 0xeb, 0xdc, 0x4b, 0x6d, 0x23,
                0xf3, 0xde
            ]),
        },
        RTPTestCase {
            sequence_number: 5002,
            encrypted: Bytes::from_static(&[
                0x6e, 0xa7, 0x69, 0x8d, 0x24, 0x6d, 0xdc, 0xbf, 0xec, 0x2, 0x1c, 0xd1, 0x60, 0x76,
                0xc1, 0x0e
            ]),
        },
        RTPTestCase {
            sequence_number: 5003,
            encrypted: Bytes::from_static(&[
                0x24, 0x7e, 0x96, 0xc8, 0x7d, 0x33, 0xa2, 0x92, 0x8d, 0x13, 0x8d, 0xe0, 0x76, 0x9f,
                0x08, 0xdc
            ]),
        },
        RTPTestCase {
            sequence_number: 5004,
            encrypted: Bytes::from_static(&[
                0x75, 0x43, 0x28, 0xe4, 0x3a, 0x77, 0x59, 0x9b, 0x2e, 0xdf, 0x7b, 0x12, 0x68, 0x0b,
                0x57, 0x49
            ]),
        },
        RTPTestCase{
            sequence_number: 65535, // upper boundary
            encrypted: Bytes::from_static(&[
                0xaf, 0xf7, 0xc2, 0x70, 0x37, 0x20, 0x83, 0x9c, 0x2c, 0x63, 0x85, 0x15, 0x0e, 0x44,
                0xca, 0x36
            ]),
        },
    ];
}

fn build_test_context() -> Result<Context> {
    let master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let master_salt = Bytes::from_static(&[
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ]);

    Context::new(
        &master_key,
        &master_salt,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )
}

#[test]
fn test_rtp_invalid_auth() -> Result<()> {
    let master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let invalid_salt = Bytes::from_static(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    let mut encrypt_context = build_test_context()?;
    let mut invalid_context = Context::new(
        &master_key,
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

#[test]
fn test_rtp_lifecyle() -> Result<()> {
    let mut encrypt_context = build_test_context()?;
    let mut decrypt_context = build_test_context()?;
    let auth_tag_len = ProtectionProfile::Aes128CmHmacSha1_80.rtp_auth_tag_len();

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
            payload: test_case.encrypted.clone(),
        };

        let encrypted_raw = encrypted_pkt.marshal()?;
        let actual_encrypted = encrypt_context.encrypt_rtp(&decrypted_raw)?;
        assert_eq!(
            actual_encrypted, encrypted_raw,
            "RTP packet with SeqNum invalid encryption: {}",
            test_case.sequence_number
        );

        let actual_decrypted = decrypt_context.decrypt_rtp(&encrypted_raw)?;
        assert_ne!(
            encrypted_raw[..encrypted_raw.len() - auth_tag_len].to_vec(),
            actual_decrypted,
            "DecryptRTP improperly encrypted in place"
        );

        assert_eq!(
            actual_decrypted, decrypted_raw,
            "RTP packet with SeqNum invalid decryption: {}",
            test_case.sequence_number,
        )
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

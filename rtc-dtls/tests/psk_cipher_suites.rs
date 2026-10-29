//! The three plain-PSK cipher suites of [iamleson98/rtc#23]: `TLS_PSK_WITH_AES_256_CCM_8`
//! (RFC 6655), `TLS_PSK_WITH_AES_128_CBC_SHA256` (RFC 5487) and
//! `TLS_PSK_WITH_CHACHA20_POLY1305_SHA256` (RFC 7905): per-suite negotiation and record
//! exchange, a server's refusal of a client that offers none of them, one server configuration
//! serving every PSK suite, and known-answer decryption of pion-produced records.
//!
//! The pion `TestPSK` identity cases and `TestPSKConfiguration` live in `tests/psk.rs`, whose
//! tables these suites joined.
//!
//! [iamleson98/rtc#23]: https://github.com/iamleson98/rtc/issues/23

mod common;

use std::sync::Arc;

use common::*;
use rtc_dtls::cipher_suite::CipherSuiteId;
use rtc_dtls::config::ConfigBuilder;
use rtc_dtls::record_layer::record_layer_header::RECORD_LAYER_HEADER_SIZE;
use shared::error::{Error, Result};

/// The pre-shared key pion's `TestPSK` hands to both callbacks.
const PSK: &[u8] = &[0xAB, 0xC1, 0x23];

/// The three suites this file is about, plus the pre-existing PSK suites the pion cases were
/// originally written against.
const NEW_SUITES: [CipherSuiteId; 3] = [
    CipherSuiteId::Tls_Psk_With_Aes_256_Ccm_8,
    CipherSuiteId::Tls_Psk_With_Aes_128_Cbc_Sha256,
    CipherSuiteId::Tls_Psk_With_ChaCha20_Poly1305_Sha256,
];

const ALL_PSK_SUITES: [CipherSuiteId; 6] = [
    CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,
    CipherSuiteId::Tls_Psk_With_Aes_128_Ccm,
    CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
    CipherSuiteId::Tls_Psk_With_Aes_256_Ccm_8,
    CipherSuiteId::Tls_Psk_With_Aes_128_Cbc_Sha256,
    CipherSuiteId::Tls_Psk_With_ChaCha20_Poly1305_Sha256,
];

/// The callback type `ConfigBuilder::with_psk` takes.
type PskCallback = Arc<dyn (Fn(&[u8]) -> Result<Vec<u8>>) + Send + Sync>;

/// A PSK callback that answers with [`PSK`] unless the peer's identity hint is `expected_hint`,
/// mirroring the identity checks pion's `TestPSK` performs inside its callbacks.
fn psk_callback(expected_hint: Option<&[u8]>) -> PskCallback {
    let expected_hint = expected_hint.map(<[u8]>::to_vec);
    Arc::new(move |hint| {
        if let Some(expected) = &expected_hint
            && hint != expected.as_slice()
        {
            return Err(Error::Other(format!(
                "TestPSK: got invalid identity expected({:02x?}) actual({:02x?})",
                expected, hint
            )));
        }
        Ok(PSK.to_vec())
    })
}

/// A PSK client offering `suites`, identifying as `identity`.
fn psk_client(suites: &[CipherSuiteId], identity: &[u8]) -> ConfigBuilder {
    builder()
        .with_cipher_suites(suites.to_vec())
        .with_psk(Some(psk_callback(None)))
        .with_psk_identity_hint(Some(identity.to_vec()))
}

/// A PSK server offering `suites`, announcing `identity_hint` (omitted when `None`, in which
/// case no ServerKeyExchange is sent at all).
fn psk_server(suites: &[CipherSuiteId], identity_hint: Option<&[u8]>) -> ConfigBuilder {
    let mut config = builder()
        .with_cipher_suites(suites.to_vec())
        .with_psk(Some(psk_callback(None)));
    if let Some(identity_hint) = identity_hint {
        config = config.with_psk_identity_hint(Some(identity_hint.to_vec()));
    }
    config
}

/// Both sides offer only `suite`; the handshake must complete, negotiate exactly it, and carry
/// application data both ways.
fn negotiate_and_exchange(suite: CipherSuiteId) -> Outcome {
    let mut out = handshake(
        psk_client(&[suite], b"Client Identity"),
        psk_server(&[suite], None),
    );
    assert!(out.ok(), "the handshake must complete for {suite}");
    assert_eq!(
        out.client_state()
            .expect("a client connection state")
            .cipher_suite()
            .expect("a negotiated suite")
            .id(),
        suite,
        "the client must have negotiated the one suite offered"
    );
    assert_eq!(
        out.server_state()
            .expect("a server connection state")
            .cipher_suite()
            .expect("a negotiated suite")
            .id(),
        suite,
        "the server must have negotiated the one suite offered"
    );
    assert_eq!(client_sends(&mut out, b"psk record"), b"psk record");
    out
}

#[test]
fn test_psk_with_aes_256_ccm_8_negotiates_and_carries_data() {
    negotiate_and_exchange(CipherSuiteId::Tls_Psk_With_Aes_256_Ccm_8);
}

#[test]
fn test_psk_with_aes_128_cbc_sha256_negotiates_and_carries_data() {
    negotiate_and_exchange(CipherSuiteId::Tls_Psk_With_Aes_128_Cbc_Sha256);
}

#[test]
fn test_psk_with_chacha20_poly1305_sha256_negotiates_and_carries_data() {
    negotiate_and_exchange(CipherSuiteId::Tls_Psk_With_ChaCha20_Poly1305_Sha256);
}

/// A server offering only one of the new suites refuses a client that offers none of it: the
/// handshake fails with `insufficient_security` (alert 71), as pion's does.
#[test]
fn test_psk_server_refuses_a_client_offering_none_of_its_suites() {
    for suite in NEW_SUITES {
        let out = handshake(
            psk_client(
                &[CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8],
                b"Client Identity",
            ),
            psk_server(&[suite], None),
        );
        assert!(!out.ok(), "no shared suite means no handshake ({suite})");
        assert!(
            matches!(out.server_error, Some(Error::ErrCipherSuiteNoIntersection)),
            "the server must refuse the client, got {:?} ({suite})",
            out.server_error
        );
        assert_eq!(
            out.alerts(Dir::ServerToClient),
            // fatal (2), insufficient_security (71)
            vec![(2, 71)],
            "one fatal insufficient_security alert ({suite})"
        );
    }
}

/// The three new suites all advertise `is_psk`, so one server configuration holding all six PSK
/// suites negotiates each of them with a client that offers only one, and the PSK suites are
/// never offered to certificate clients.
#[test]
fn test_psk_server_offering_all_psk_suites_serves_each_new_suite() {
    for suite in NEW_SUITES {
        let out = handshake(
            psk_client(&[suite], b"Client Identity"),
            psk_server(&ALL_PSK_SUITES, None),
        );
        assert!(out.ok(), "the server must serve {suite} from the full list");
        assert_eq!(
            out.server_state()
                .expect("a server connection state")
                .cipher_suite()
                .expect("a negotiated suite")
                .id(),
            suite,
            "the client's single offered suite must win"
        );
    }
}

/// Decodes a hex string, for the pion-generated records below.
fn hex(s: &str) -> Vec<u8> {
    s.bytes()
        .collect::<Vec<_>>()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[hi, lo]| {
            let nib = |b: u8| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => panic!("not hex: {b}"),
            };
            (nib(*hi) << 4) | nib(*lo)
        })
        .collect()
}

/// Keying material the pion records below were produced with; identical to the unit tests in
/// the suite files, so the same constants generate both sides' keys.
const KAT_MASTER_SECRET: &[u8] = &[0x42; 48];
const KAT_CLIENT_RANDOM: &[u8] = &[0x11; 32];
const KAT_SERVER_RANDOM: &[u8] = &[0x22; 32];

/// One application-data record per suite, DTLS 1.2, epoch 1, sequence number 7, payload
/// `a pion-encrypted PSK record`, produced by this throwaway Go program against
/// `github.com/pion/dtls/v3 v3.1.15` (not committed; see the issue):
///
/// ```go
/// suite.Init(masterSecret, clientRandom, serverRandom, true) // 0x42*48, 0x11*32, 0x22*32
/// raw := header.Marshal()  // ContentType application data, version {0xfe, 0xfd},
///                          // epoch 0x0001, sequence number 7, ContentLen 27
/// raw = append(raw, []byte("a pion-encrypted PSK record")...)
/// encrypted, _ := suite.Encrypt(&recordlayer.RecordLayer{Header: header}, raw)
/// ```
///
/// pion encrypted as the client, so these are decrypted here as the server. The CCM record
/// carries its 8-byte explicit nonce and the CBC record its 16-byte random IV inline, so the
/// bytes are self-contained; the ChaCha20 record's nonce is derived from the epoch and
/// sequence number.
const PION_AES_256_CCM_8_RECORD: &str = "17fefd0001000000000007002b0001000000000007e7a1dad7f9feb9f04b7739ee6197dc89f0f1458c7c34881201a1103aaa30e8739e1d0d";
const PION_AES_128_CBC_SHA256_RECORD: &str = "17fefd000100000000000700509655c32c9d29f5f2ffa551a05b5ef175101db651f6c4eac1586ad6dd299577164587e16d5a1202d23a085a65db43237f94a570fb2e60581db7e0af48fe64c6b23738a4ffd825831e5013191a1d24bda1";
const PION_CHACHA20_POLY1305_SHA256_RECORD: &str = "17fefd0001000000000007002b7d6bc15a4f56189979b7faeed3dfa93d9ad5881a4a747fa711a1401f04e1ee61b3847d04d5c0217588ea06";

/// rtc-dtls decrypts the exact records pion produced, byte for byte.
#[test]
fn test_psk_decrypts_pion_encrypted_records() {
    for (suite, record) in [
        (
            CipherSuiteId::Tls_Psk_With_Aes_256_Ccm_8,
            PION_AES_256_CCM_8_RECORD,
        ),
        (
            CipherSuiteId::Tls_Psk_With_Aes_128_Cbc_Sha256,
            PION_AES_128_CBC_SHA256_RECORD,
        ),
        (
            CipherSuiteId::Tls_Psk_With_ChaCha20_Poly1305_Sha256,
            PION_CHACHA20_POLY1305_SHA256_RECORD,
        ),
    ] {
        let mut server = rtc_dtls::cipher_suite::cipher_suite_for_id(suite).unwrap();
        server
            .init(
                provider(),
                KAT_MASTER_SECRET,
                KAT_CLIENT_RANDOM,
                KAT_SERVER_RANDOM,
                false,
            )
            .expect("the pion keying material initializes the suite");

        let decrypted = server
            .decrypt(&hex(record))
            .unwrap_or_else(|e| panic!("{suite} must decrypt the pion record: {e}"));
        assert_eq!(
            &decrypted[RECORD_LAYER_HEADER_SIZE..],
            b"a pion-encrypted PSK record".as_slice(),
            "{suite}: the pion plaintext must come back out"
        );
    }
}

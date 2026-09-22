use super::crypto_ccm::*;
use super::*;
use crate::content::ContentType;
use crate::record_layer::record_layer_header::{
    PROTOCOL_VERSION1_2, ProtocolVersion, RECORD_LAYER_HEADER_SIZE,
};
use crate::signature_hash_algorithm::HashAlgorithm;
use bytes::BytesMut;

#[test]
fn test_generate_key_signature() -> Result<()> {
    let provider = crypto::default_provider().map_err(crypto_error)?;
    let scheme = crypto::SignatureScheme::EcdsaP256Sha256;
    let signing_key = provider
        .crypto()
        .generate_signing_key(scheme)
        .map_err(crypto_error)?;
    let private_key = CryptoPrivateKey::from_signing_key(signing_key.clone());

    let client_random = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let server_random = vec![
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
        0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
        0x8e, 0x8f,
    ];
    let public_key = vec![
        0x20, 0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a,
        0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28,
        0x80, 0xb6, 0x15,
    ];
    let signature = generate_key_signature(
        &client_random,
        &server_random,
        &public_key,
        NamedCurve::X25519,
        &SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha256,
            signature: SignatureAlgorithm::Ecdsa,
        },
        &private_key,
    )?;

    provider
        .crypto()
        .verify_signature(
            scheme,
            signing_key.public_key(),
            &value_key_message(
                &client_random,
                &server_random,
                &public_key,
                NamedCurve::X25519,
            ),
            &signature,
        )
        .map_err(crypto_error)?;

    Ok(())
}

#[test]
fn test_exported_signing_key_can_be_imported() -> Result<()> {
    let provider = crypto::default_provider().map_err(crypto_error)?;
    let scheme = crypto::SignatureScheme::EcdsaP256Sha256;
    let generated = provider
        .crypto()
        .generate_signing_key(scheme)
        .map_err(crypto_error)?;
    let pkcs8 = generated
        .to_pkcs8_der()
        .map_err(crypto_error)?
        .expect("built-in generated keys are exportable");
    let imported = provider
        .crypto()
        .import_signing_key(scheme, pkcs8.as_ref())
        .map_err(crypto_error)?;
    let signature = imported
        .sign(scheme, b"imported DTLS key")
        .map_err(crypto_error)?;

    provider
        .crypto()
        .verify_signature(
            scheme,
            imported.public_key(),
            b"imported DTLS key",
            &signature,
        )
        .map_err(crypto_error)
}

#[cfg(all(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
#[test]
fn test_cross_provider_signature_verification() -> Result<()> {
    // The providers are concrete types here, not `dyn RTCCryptoProvider`, so the trait has to
    // be in scope for `.crypto()`. Scoped to this test because it is the only one that needs it
    // and the test only exists when both provider features are on.
    use crypto::RTCCryptoProvider;

    let ring = crypto::providers::RingProvider::new();
    let aws = crypto::providers::AwsLcRsProvider::new();
    let scheme = crypto::SignatureScheme::EcdsaP256Sha256;

    for (signer, verifier) in [
        (
            ring.crypto() as &dyn crypto::RTCCrypto,
            aws.crypto() as &dyn crypto::RTCCrypto,
        ),
        (
            aws.crypto() as &dyn crypto::RTCCrypto,
            ring.crypto() as &dyn crypto::RTCCrypto,
        ),
    ] {
        let key = signer.generate_signing_key(scheme).map_err(crypto_error)?;
        let signature = key
            .sign(scheme, b"cross-provider DTLS signature")
            .map_err(crypto_error)?;
        verifier
            .verify_signature(
                scheme,
                key.public_key(),
                b"cross-provider DTLS signature",
                &signature,
            )
            .map_err(crypto_error)?;
    }

    Ok(())
}

#[test]
fn test_ccm_encryption_and_decryption() -> Result<()> {
    let key = vec![
        0x18, 0x78, 0xac, 0xc2, 0x2a, 0xd8, 0xbd, 0xd8, 0xc6, 0x01, 0xa6, 0x17, 0x12, 0x6f, 0x63,
        0x54,
    ];
    let iv = vec![0x0e, 0xb2, 0x09, 0x06];

    let mut ccm = CryptoCcm::new(
        crypto::default_provider().map_err(crypto_error)?,
        &CryptoCcmTagLen::CryptoCcmTagLength,
        &key,
        &iv,
        &key,
        &iv,
    )?;

    let rlh = RecordLayerHeader {
        content_type: ContentType::ApplicationData,
        protocol_version: ProtocolVersion {
            major: 0xfe,
            minor: 0xff,
        },
        epoch: 0,
        sequence_number: 18,
        content_len: 3,
    };

    let raw = vec![
        0x17, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x03, 0xff, 0xaa,
        0xbb,
    ];

    let cipher_text = ccm.encrypt(&rlh, &raw)?;

    assert_eq!(
        &cipher_text[RECORD_LAYER_HEADER_SIZE - 2..RECORD_LAYER_HEADER_SIZE],
        [0, 27],
        "RecordLayer size updating failed \nexp: {:?} \nactual {:?} ",
        [0, 27],
        &cipher_text[RECORD_LAYER_HEADER_SIZE - 2..RECORD_LAYER_HEADER_SIZE]
    );

    let plain_text = ccm.decrypt(&cipher_text)?;

    assert_eq!(
        raw[RECORD_LAYER_HEADER_SIZE..],
        plain_text[RECORD_LAYER_HEADER_SIZE..],
        "Decryption failed \nexp: {:?} \nactual {:?} ",
        &raw[RECORD_LAYER_HEADER_SIZE..],
        &plain_text[RECORD_LAYER_HEADER_SIZE..]
    );

    Ok(())
}

#[test]
fn test_certificate_verify() -> Result<()> {
    let provider = crypto::default_provider().map_err(crypto_error)?;
    let plain_text: Vec<u8> = vec![
        0x6f, 0x47, 0x97, 0x85, 0xcc, 0x76, 0x50, 0x93, 0xbd, 0xe2, 0x6a, 0x69, 0x0b, 0xc3, 0x03,
        0xd1, 0xb7, 0xe4, 0xab, 0x88, 0x7b, 0xa6, 0x52, 0x80, 0xdf, 0xaa, 0x25, 0x7a, 0xdb, 0x29,
        0x32, 0xe4, 0xd8, 0x28, 0x28, 0xb3, 0xe8, 0x04, 0x3c, 0x38, 0x16, 0xfc, 0x78, 0xe9, 0x15,
        0x7b, 0xc5, 0xbd, 0x7d, 0xfc, 0xcd, 0x83, 0x00, 0x57, 0x4a, 0x3c, 0x23, 0x85, 0x75, 0x6b,
        0x37, 0xd5, 0x89, 0x72, 0x73, 0xf0, 0x44, 0x8c, 0x00, 0x70, 0x1f, 0x6e, 0xa2, 0x81, 0xd0,
        0x09, 0xc5, 0x20, 0x36, 0xab, 0x23, 0x09, 0x40, 0x1f, 0x4d, 0x45, 0x96, 0x62, 0xbb, 0x81,
        0xb0, 0x30, 0x72, 0xad, 0x3a, 0x0a, 0xac, 0x31, 0x63, 0x40, 0x52, 0x0a, 0x27, 0xf3, 0x34,
        0xde, 0x27, 0x7d, 0xb7, 0x54, 0xff, 0x0f, 0x9f, 0x5a, 0xfe, 0x07, 0x0f, 0x4e, 0x9f, 0x53,
        0x04, 0x34, 0x62, 0xf4, 0x30, 0x74, 0x83, 0x35, 0xfc, 0xe4, 0x7e, 0xbf, 0x5a, 0xc4, 0x52,
        0xd0, 0xea, 0xf9, 0x61, 0x4e, 0xf5, 0x1c, 0x0e, 0x58, 0x02, 0x71, 0xfb, 0x1f, 0x34, 0x55,
        0xe8, 0x36, 0x70, 0x3c, 0xc1, 0xcb, 0xc9, 0xb7, 0xbb, 0xb5, 0x1c, 0x44, 0x9a, 0x6d, 0x88,
        0x78, 0x98, 0xd4, 0x91, 0x2e, 0xeb, 0x98, 0x81, 0x23, 0x30, 0x73, 0x39, 0x43, 0xd5, 0xbb,
        0x70, 0x39, 0xba, 0x1f, 0xdb, 0x70, 0x9f, 0x91, 0x83, 0x56, 0xc2, 0xde, 0xed, 0x17, 0x6d,
        0x2c, 0x3e, 0x21, 0xea, 0x36, 0xb4, 0x91, 0xd8, 0x31, 0x05, 0x60, 0x90, 0xfd, 0xc6, 0x74,
        0xa9, 0x7b, 0x18, 0xfc, 0x1c, 0x6a, 0x1c, 0x6e, 0xec, 0xd3, 0xc1, 0xc0, 0x0d, 0x11, 0x25,
        0x48, 0x37, 0x3d, 0x45, 0x11, 0xa2, 0x31, 0x14, 0x0a, 0x66, 0x9f, 0xd8, 0xac, 0x74, 0xa2,
        0xcd, 0xc8, 0x79, 0xb3, 0x9e, 0xc6, 0x66, 0x25, 0xcf, 0x2c, 0x87, 0x5e, 0x5c, 0x36, 0x75,
        0x86,
    ];

    //test ECDSA256
    let certificate_ecdsa256 = Certificate::generate_self_signed(
        vec!["localhost".to_owned()],
        crypto::default_provider().map_err(crypto_error)?.crypto(),
    )?;
    let ecdsa_algorithm = SignatureHashAlgorithm {
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::Ecdsa,
    };
    let cert_verify_ecdsa256 = generate_certificate_verify(
        &plain_text,
        &ecdsa_algorithm,
        &certificate_ecdsa256.private_key,
    )?;
    verify_certificate_verify(
        provider.crypto(),
        &plain_text,
        &ecdsa_algorithm,
        &cert_verify_ecdsa256,
        &certificate_ecdsa256
            .certificate
            .iter()
            .map(|x| x.as_ref().to_owned())
            .collect::<Vec<Vec<u8>>>(),
        false,
    )?;

    //test ED25519
    let certificate_ed25519 = Certificate::generate_self_signed_with_alg(
        vec!["localhost".to_owned()],
        &rcgen::PKCS_ED25519,
        crypto::default_provider().map_err(crypto_error)?.crypto(),
    )?;
    let ed25519_algorithm = SignatureHashAlgorithm {
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::Ed25519,
    };
    let cert_verify_ed25519 = generate_certificate_verify(
        &plain_text,
        &ed25519_algorithm,
        &certificate_ed25519.private_key,
    )?;
    verify_certificate_verify(
        provider.crypto(),
        &plain_text,
        &ed25519_algorithm,
        &cert_verify_ed25519,
        &certificate_ed25519
            .certificate
            .iter()
            .map(|x| x.as_ref().to_owned())
            .collect::<Vec<Vec<u8>>>(),
        false,
    )?;

    Ok(())
}

#[derive(Debug)]
struct MockSigner {
    call_count: std::sync::Arc<std::sync::Mutex<usize>>,
    last_message: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    signature: Vec<u8>,
}

impl SigningKey for MockSigner {
    fn supports(&self, _scheme: CryptoSignatureScheme) -> bool {
        true
    }

    fn public_key(&self) -> PublicKey<'_> {
        PublicKey {
            encoding: PublicKeyEncoding::SubjectPublicKeyInfoDer,
            bytes: &[],
        }
    }

    fn sign(
        &self,
        _scheme: CryptoSignatureScheme,
        message: &[u8],
    ) -> std::result::Result<Vec<u8>, crypto::CryptoError> {
        *self.call_count.lock().unwrap() += 1;
        *self.last_message.lock().unwrap() = message.to_vec();
        Ok(self.signature.clone())
    }
}

#[test]
fn test_external_signing_key_is_invoked_for_signing() -> Result<()> {
    let expected_signature = vec![0xca, 0xfe, 0xba, 0xbe];
    let call_count = std::sync::Arc::new(std::sync::Mutex::new(0usize));
    let last_message = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let private_key = CryptoPrivateKey::from_signing_key(std::sync::Arc::new(MockSigner {
        call_count: std::sync::Arc::clone(&call_count),
        last_message: std::sync::Arc::clone(&last_message),
        signature: expected_signature.clone(),
    }));
    assert!(
        private_key
            .signing_key
            .to_pkcs8_der()
            .map_err(crypto_error)?
            .is_none()
    );

    let client_random = [0x01u8, 0x02, 0x03, 0x04];
    let server_random = [0x05u8, 0x06, 0x07, 0x08];
    let public_key = [0x09u8, 0x0a, 0x0b];
    let named_curve = NamedCurve::X25519;
    let expected_key_message =
        value_key_message(&client_random, &server_random, &public_key, named_curve);
    let algorithm = SignatureHashAlgorithm {
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::Ecdsa,
    };

    let key_signature = generate_key_signature(
        &client_random,
        &server_random,
        &public_key,
        named_curve,
        &algorithm,
        &private_key,
    )?;

    assert_eq!(*call_count.lock().unwrap(), 1);
    assert_eq!(&*last_message.lock().unwrap(), &expected_key_message);
    assert_eq!(key_signature, expected_signature);

    let handshake_bodies = b"certificate-verify-handshake-bodies";
    let cert_verify = generate_certificate_verify(handshake_bodies, &algorithm, &private_key)?;

    assert_eq!(*call_count.lock().unwrap(), 2);
    assert_eq!(&*last_message.lock().unwrap(), handshake_bodies);
    assert_eq!(cert_verify, expected_signature);

    Ok(())
}

/// The record-protection API shared by the record ciphers, so one test can drive them all.
trait RecordCipher {
    fn encrypt(&mut self, h: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>>;
    fn encrypt_in_place(&mut self, h: &RecordLayerHeader, raw: &mut BytesMut) -> Result<()>;
    fn decrypt(&mut self, r: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_in_place(&mut self, r: &mut BytesMut) -> Result<()>;
}

macro_rules! impl_record_cipher {
    ($($cipher:ty),*) => {$(
        impl RecordCipher for $cipher {
            fn encrypt(&mut self, h: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
                <$cipher>::encrypt(self, h, raw)
            }
            fn encrypt_in_place(&mut self, h: &RecordLayerHeader, raw: &mut BytesMut) -> Result<()> {
                <$cipher>::encrypt_in_place(self, h, raw)
            }
            fn decrypt(&mut self, r: &[u8]) -> Result<Vec<u8>> {
                <$cipher>::decrypt(self, r)
            }
            fn decrypt_in_place(&mut self, r: &mut BytesMut) -> Result<()> {
                <$cipher>::decrypt_in_place(self, r)
            }
        }
    )*};
}

impl_record_cipher!(
    crypto_gcm::CryptoGcm,
    CryptoCcm,
    crypto_chacha20::CryptoChaCha20,
    crypto_cbc::CryptoCbc
);

/// A cipher's name with a sender and a receiver keyed so each decrypts what the other
/// encrypts.
type RecordCipherPair = (&'static str, Box<dyn RecordCipher>, Box<dyn RecordCipher>);

fn record_cipher_pairs() -> Result<Vec<RecordCipherPair>> {
    let provider = crypto::default_provider().map_err(crypto_error)?;
    let (k16a, k16b, k32a, k32b) = ([0x11; 16], [0x22; 16], [0x33; 32], [0x44; 32]);
    let (iv4a, iv4b, iv12a, iv12b, mac_a, mac_b) =
        ([1; 4], [2; 4], [3; 12], [4; 12], [5; 20], [6; 20]);
    let p = || provider.clone();
    let ccm = |tag: &CryptoCcmTagLen| -> Result<(Box<dyn RecordCipher>, Box<dyn RecordCipher>)> {
        Ok((
            Box::new(CryptoCcm::new(p(), tag, &k16a, &iv4a, &k16b, &iv4b)?),
            Box::new(CryptoCcm::new(p(), tag, &k16b, &iv4b, &k16a, &iv4a)?),
        ))
    };
    let (ccm16_tx, ccm16_rx) = ccm(&CryptoCcmTagLen::CryptoCcmTagLength)?;
    let (ccm8_tx, ccm8_rx) = ccm(&CryptoCcmTagLen::CryptoCcm8TagLength)?;
    Ok(vec![
        (
            "AES-128-GCM",
            Box::new(crypto_gcm::CryptoGcm::new(p(), &k16a, &iv4a, &k16b, &iv4b)?),
            Box::new(crypto_gcm::CryptoGcm::new(p(), &k16b, &iv4b, &k16a, &iv4a)?),
        ),
        ("AES-128-CCM", ccm16_tx, ccm16_rx),
        ("AES-128-CCM-8", ccm8_tx, ccm8_rx),
        (
            "CHACHA20-POLY1305",
            Box::new(crypto_chacha20::CryptoChaCha20::new(
                p(),
                &k32a,
                &iv12a,
                &k32b,
                &iv12b,
            )?),
            Box::new(crypto_chacha20::CryptoChaCha20::new(
                p(),
                &k32b,
                &iv12b,
                &k32a,
                &iv12a,
            )?),
        ),
        (
            "AES-256-CBC",
            Box::new(crypto_cbc::CryptoCbc::new(
                p(),
                &k32a,
                &mac_a,
                &k32b,
                &mac_b,
            )?),
            Box::new(crypto_cbc::CryptoCbc::new(
                p(),
                &k32b,
                &mac_b,
                &k32a,
                &mac_a,
            )?),
        ),
    ])
}

/// Protecting and unprotecting in place produce what the copying calls do, interoperate with
/// them in both directions, and reject the same tampering.
#[test]
fn test_record_ciphers_in_place_match_copying_calls() -> Result<()> {
    for (name, mut sender, mut receiver) in record_cipher_pairs()? {
        for (sequence_number, len) in [0usize, 1, 15, 16, 17, 100, 1200].into_iter().enumerate() {
            let header = RecordLayerHeader {
                content_type: ContentType::ApplicationData,
                protocol_version: PROTOCOL_VERSION1_2,
                epoch: 1,
                sequence_number: sequence_number as u64,
                content_len: len as u16,
            };
            let mut raw = vec![];
            header.marshal(&mut raw)?;
            raw.extend((0..len).map(|i| i as u8));

            let mut in_place = BytesMut::from(&raw[..]);
            sender.encrypt_in_place(&header, &mut in_place)?;
            let copied = sender.encrypt(&header, &raw)?;
            assert_eq!(in_place.len(), copied.len(), "{name}/{len}: record length");
            for record in [&in_place[..], &copied[..]] {
                assert_eq!(record[..11], raw[..11], "{name}/{len}: header");
                let content_len = u16::from_be_bytes([record[11], record[12]]) as usize;
                assert_eq!(content_len, record.len() - RECORD_LAYER_HEADER_SIZE);
            }

            for record in [&in_place[..], &copied[..]] {
                let expected = receiver.decrypt(record)?;
                assert_eq!(
                    expected[RECORD_LAYER_HEADER_SIZE..],
                    raw[RECORD_LAYER_HEADER_SIZE..]
                );
                let mut decrypted = BytesMut::from(record);
                receiver.decrypt_in_place(&mut decrypted)?;
                assert_eq!(
                    &decrypted[..],
                    &expected[..],
                    "{name}/{len}: in-place decrypt"
                );

                let mut tampered = BytesMut::from(record);
                let last = tampered.len() - 1;
                tampered[last] ^= 0x01;
                assert!(receiver.decrypt(&tampered).is_err(), "{name}/{len}: tamper");
                assert!(
                    receiver.decrypt_in_place(&mut tampered).is_err(),
                    "{name}/{len}: tamper in place"
                );
            }
        }

        // ChangeCipherSpec is not encrypted and passes through untouched.
        let change_cipher_spec = [0x14, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 9, 0, 1, 1];
        assert_eq!(receiver.decrypt(&change_cipher_spec)?, change_cipher_spec);
        let mut passthrough = BytesMut::from(&change_cipher_spec[..]);
        receiver.decrypt_in_place(&mut passthrough)?;
        assert_eq!(&passthrough[..], &change_cipher_spec[..]);
    }

    Ok(())
}

use super::crypto_ccm::*;
use super::*;
use crate::content::ContentType;
use crate::record_layer::record_layer_header::{ProtocolVersion, RECORD_LAYER_HEADER_SIZE};
use crate::signature_hash_algorithm::HashAlgorithm;

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
        hash: HashAlgorithm::Ed25519,
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

#[test]
fn test_verify_key_signature_ecdsa_p384_sha256() -> Result<()> {
    let provider = crypto::default_provider().map_err(crypto_error)?;

    const CERT_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0x51, 0x30, 0x81, 0xd8, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01,
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x14, 0x31,
        0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
        0x68, 0x6f, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x76,
        0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
        0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xd9, 0xf9, 0xfe, 0x7a, 0xe3, 0xc8, 0x03, 0x88,
        0x78, 0xd1, 0x2b, 0x44, 0xab, 0xa2, 0x6a, 0xfd, 0x54, 0x0a, 0x7b, 0xe7, 0x94, 0x29, 0xf3,
        0x82, 0x7a, 0xb9, 0x78, 0x02, 0xbc, 0x11, 0x6a, 0xc0, 0xa8, 0x34, 0x47, 0xf3, 0xa6, 0x79,
        0x7f, 0xca, 0x37, 0xea, 0x6a, 0x80, 0x3f, 0xcc, 0xb4, 0x2b, 0xd5, 0x02, 0x9f, 0x1f, 0x9d,
        0x10, 0xe7, 0x6b, 0x6a, 0x4c, 0x26, 0x0d, 0xa1, 0x53, 0x56, 0x62, 0x49, 0x93, 0xc1, 0x46,
        0xa6, 0x83, 0x1d, 0x17, 0xcb, 0xbb, 0xe9, 0x6e, 0xaf, 0xe2, 0xa3, 0x77, 0x59, 0x88, 0x2d,
        0x03, 0x41, 0xa8, 0x45, 0xd7, 0xd7, 0x7d, 0xbd, 0x64, 0x1d, 0x79, 0x0e, 0x61, 0x30, 0x0a,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65,
        0x02, 0x31, 0x00, 0xf6, 0xdc, 0xe5, 0x18, 0x22, 0x6b, 0xd4, 0xcc, 0x23, 0x58, 0x2c, 0x9c,
        0xe9, 0x19, 0xed, 0x53, 0x96, 0xec, 0xe3, 0x08, 0xf2, 0xcf, 0xc3, 0xac, 0x92, 0x66, 0x9d,
        0x87, 0x45, 0xe8, 0xc3, 0x69, 0x5a, 0xa1, 0x38, 0xbe, 0xc6, 0xbe, 0xfa, 0xb7, 0xc4, 0xe4,
        0xa7, 0xdb, 0xe2, 0xef, 0x2d, 0x8b, 0x02, 0x30, 0x4c, 0x45, 0x5d, 0xaa, 0x5e, 0x44, 0x07,
        0x28, 0xd3, 0x49, 0x3b, 0xcd, 0xff, 0x3a, 0x2e, 0x99, 0xf6, 0x07, 0x0a, 0x47, 0x30, 0xef,
        0xb8, 0x53, 0x62, 0xbe, 0xe6, 0x0b, 0xab, 0xc6, 0xd5, 0x24, 0x46, 0x5b, 0x85, 0x6e, 0x54,
        0x2f, 0xa6, 0xfd, 0x1d, 0xbd, 0x98, 0x1f, 0x32, 0x93, 0xf2, 0x86,
    ];
    const SIGNATURE: &[u8] = &[
        0x30, 0x65, 0x02, 0x30, 0x47, 0x16, 0xc1, 0xe8, 0xbf, 0x6b, 0x46, 0x4d, 0x13, 0x15, 0xf1,
        0x70, 0xe0, 0xf6, 0xb9, 0xba, 0x20, 0x92, 0x15, 0xa9, 0x0b, 0x69, 0xb0, 0xad, 0xe6, 0x38,
        0x7a, 0x58, 0x81, 0x5b, 0x2a, 0xa6, 0xd0, 0x8f, 0x96, 0x6f, 0x49, 0x5e, 0x80, 0xbd, 0x2e,
        0xb7, 0x7e, 0x6b, 0x5d, 0x83, 0x21, 0x8f, 0x02, 0x31, 0x00, 0x95, 0x05, 0xe1, 0x74, 0x3d,
        0x4b, 0xd0, 0x7f, 0x55, 0x0b, 0x83, 0x86, 0x1a, 0x34, 0x85, 0xc1, 0x54, 0x68, 0xfb, 0x08,
        0x7a, 0x59, 0x71, 0x9d, 0xb3, 0xdd, 0x23, 0x7e, 0xd6, 0x1e, 0x12, 0x43, 0x66, 0xf5, 0xc2,
        0xea, 0x4a, 0x6e, 0x80, 0x1d, 0xab, 0x4e, 0xb7, 0xaa, 0xe6, 0x6d, 0x26, 0xfe,
    ];

    let message = b"dtls-verify-key-signature-p384-sha256";
    let algorithm = SignatureHashAlgorithm {
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::Ecdsa,
    };

    let raw_certs = vec![CERT_DER.to_vec()];

    verify_key_signature(
        provider.crypto(),
        message,
        &algorithm,
        SIGNATURE,
        &raw_certs,
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

    // The mock claims to support every scheme, so the pair validation is what gates the label
    // mismatches below.
    assert!(matches!(
        generate_key_signature(
            &client_random,
            &server_random,
            &public_key,
            named_curve,
            &SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Ed25519,
            },
            &private_key,
        ),
        Err(Error::ErrInvalidSignatureAlgorithm)
    ));

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

// Port of pion `TestHandshakeSignatureSchemeBinding` (ANT-2026-0Q4PYECH): a valid signature
// must not authenticate a different scheme, or an empty digest in place of the handshake
// transcript. Every non-PSS row of pion's table is reproduced; the two RSA-PSS rows are omitted
// because no provider implements PSS signing yet.
#[test]
fn test_handshake_signature_scheme_binding() -> Result<()> {
    let provider = crypto::default_provider().map_err(crypto_error)?;
    let message: &[u8] = b"handshake transcript";

    struct Case {
        name: &'static str,
        key: CryptoPrivateKey,
        cert: Vec<u8>,
        hash: HashAlgorithm,
        signature: SignatureAlgorithm,
        valid: bool,
    }

    let mut cases = vec![];

    // An RSA key and self-signed certificate. ring cannot generate RSA keypairs, so the
    // 2048-bit PKCS#8 test fixture shared with rtc-crypto is imported and rcgen signs the
    // certificate with it.
    let rsa_pem = include_str!("../../../rtc-crypto/tests/data/rsa-2048.pkcs8.pem");
    let rsa_key_pair = KeyPair::from_pem(rsa_pem).map_err(|e| Error::Other(e.to_string()))?;
    let rsa_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .map_err(|e| Error::Other(e.to_string()))?;
    let rsa_cert = rsa_params
        .self_signed(&rsa_key_pair)
        .map_err(|e| Error::Other(e.to_string()))?;
    let rsa_key = CryptoPrivateKey::from_key_pair(&rsa_key_pair, provider.crypto())?;
    let rsa_cert_der = rsa_cert.der().as_ref().to_vec();

    // An ECDSA P-256 key and self-signed certificate.
    let certificate_ecdsa =
        Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())?;
    let ecdsa_key = certificate_ecdsa.private_key.clone();
    let ecdsa_cert_der = certificate_ecdsa
        .certificate
        .first()
        .expect("self-signed certificate")
        .as_ref()
        .to_vec();

    // An Ed25519 key and self-signed certificate.
    let certificate_ed25519 = Certificate::generate_self_signed_with_alg(
        vec!["localhost".to_owned()],
        &rcgen::PKCS_ED25519,
        provider.crypto(),
    )?;
    let ed25519_key = certificate_ed25519.private_key.clone();
    let ed25519_cert_der = certificate_ed25519
        .certificate
        .first()
        .expect("self-signed certificate")
        .as_ref()
        .to_vec();

    cases.push(Case {
        name: "RSA",
        key: rsa_key.clone(),
        cert: rsa_cert_der.clone(),
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::Rsa,
        valid: true,
    });
    cases.push(Case {
        name: "ECDSA",
        key: ecdsa_key.clone(),
        cert: ecdsa_cert_der.clone(),
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::Ecdsa,
        valid: true,
    });
    cases.push(Case {
        name: "Ed25519",
        key: ed25519_key.clone(),
        cert: ed25519_cert_der.clone(),
        hash: HashAlgorithm::Ed25519,
        signature: SignatureAlgorithm::Ed25519,
        valid: true,
    });
    cases.push(Case {
        name: "RSA labeled ECDSA",
        key: rsa_key.clone(),
        cert: rsa_cert_der.clone(),
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::Ecdsa,
        valid: false,
    });
    cases.push(Case {
        name: "ECDSA labeled RSA",
        key: ecdsa_key.clone(),
        cert: ecdsa_cert_der.clone(),
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::Rsa,
        valid: false,
    });
    cases.push(Case {
        name: "Ed25519 labeled ECDSA",
        key: ed25519_key.clone(),
        cert: ed25519_cert_der.clone(),
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::Ecdsa,
        valid: false,
    });
    cases.push(Case {
        name: "Ed25519 wrong hash",
        key: ed25519_key.clone(),
        cert: ed25519_cert_der.clone(),
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::Ed25519,
        valid: false,
    });
    cases.push(Case {
        name: "RSA empty digest labeled Ed25519",
        key: rsa_key.clone(),
        cert: rsa_cert_der.clone(),
        hash: HashAlgorithm::Ed25519,
        signature: SignatureAlgorithm::Ed25519,
        valid: false,
    });
    cases.push(Case {
        name: "RSA empty digest scheme 0801",
        key: rsa_key.clone(),
        cert: rsa_cert_der.clone(),
        hash: HashAlgorithm::Ed25519,
        signature: SignatureAlgorithm::Rsa,
        valid: false,
    });
    cases.push(Case {
        name: "RSA no hash",
        key: rsa_key.clone(),
        cert: rsa_cert_der.clone(),
        hash: HashAlgorithm::Md2,
        signature: SignatureAlgorithm::Rsa,
        valid: false,
    });
    cases.push(Case {
        name: "RSA unknown hash",
        key: rsa_key.clone(),
        cert: rsa_cert_der.clone(),
        hash: HashAlgorithm::Unsupported,
        signature: SignatureAlgorithm::Rsa,
        valid: false,
    });
    cases.push(Case {
        name: "ECDSA empty digest",
        key: ecdsa_key.clone(),
        cert: ecdsa_cert_der.clone(),
        hash: HashAlgorithm::Ed25519,
        signature: SignatureAlgorithm::Ecdsa,
        valid: false,
    });

    for tc in cases {
        let raw_certs = vec![tc.cert.clone()];
        let algorithm = SignatureHashAlgorithm {
            hash: tc.hash,
            signature: tc.signature,
        };

        if tc.valid {
            let signature = generate_certificate_verify(message, &algorithm, &tc.key)
                .unwrap_or_else(|e| panic!("{}: generate_certificate_verify failed: {e}", tc.name));

            verify_certificate_verify(
                provider.crypto(),
                message,
                &algorithm,
                &signature,
                &raw_certs,
                false,
            )
            .unwrap_or_else(|e| panic!("{}: verify_certificate_verify failed: {e}", tc.name));
            verify_key_signature(
                provider.crypto(),
                message,
                &algorithm,
                &signature,
                &raw_certs,
                false,
            )
            .unwrap_or_else(|e| panic!("{}: verify_key_signature failed: {e}", tc.name));

            assert!(
                verify_certificate_verify(
                    provider.crypto(),
                    b"changed transcript",
                    &algorithm,
                    &signature,
                    &raw_certs,
                    false
                )
                .is_err(),
                "{}: a changed transcript must not verify",
                tc.name
            );
            assert!(
                verify_key_signature(
                    provider.crypto(),
                    b"changed transcript",
                    &algorithm,
                    &signature,
                    &raw_certs,
                    false
                )
                .is_err(),
                "{}: a changed transcript must not verify",
                tc.name
            );
        } else {
            assert!(
                matches!(
                    verify_certificate_verify(
                        provider.crypto(),
                        message,
                        &algorithm,
                        &[],
                        &raw_certs,
                        false
                    ),
                    Err(Error::ErrInvalidSignatureAlgorithm)
                ),
                "{}: verify_certificate_verify must reject the scheme",
                tc.name
            );
            assert!(
                matches!(
                    verify_key_signature(
                        provider.crypto(),
                        message,
                        &algorithm,
                        &[],
                        &raw_certs,
                        false
                    ),
                    Err(Error::ErrInvalidSignatureAlgorithm)
                ),
                "{}: verify_key_signature must reject the scheme",
                tc.name
            );
            assert!(
                matches!(
                    generate_key_signature(&[], &[], &[], NamedCurve::X25519, &algorithm, &tc.key),
                    Err(Error::ErrInvalidSignatureAlgorithm)
                ),
                "{}: generate_key_signature must reject the scheme",
                tc.name
            );
            assert!(
                matches!(
                    generate_certificate_verify(message, &algorithm, &tc.key),
                    Err(Error::ErrInvalidSignatureAlgorithm)
                ),
                "{}: generate_certificate_verify must reject the scheme",
                tc.name
            );
        }
    }

    Ok(())
}

// RSA-PSS certificate with id-RSASSA-PSS OID (1.2.840.113549.1.1.10), copied verbatim from pion's
// `crypto_test.go` (`rsaPSSCertificate`), which notes: "Go's x509.CreateCertificate does not
// support creating RSA-PSS certificates, and x509.ParsePKCS8PrivateKey cannot parse RSA-PSS
// private keys. Therefore we use this cert for OID validation testing only."
const RSA_PSS_CERTIFICATE: &str = "
-----BEGIN CERTIFICATE-----
MIIDdTCCAimgAwIBAgIUOvVXWgzlj9KVp4TQe+ZATB3PkvswQQYJKoZIhvcNAQEK
MDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEF
AKIDAgEgMBcxFTATBgNVBAMMDFJTQS1QU1MtVGVzdDAeFw0yNjAxMjQwNDE1MzFa
Fw0yNzAxMjQwNDE1MzFaMBcxFTATBgNVBAMMDFJTQS1QU1MtVGVzdDCCASAwCwYJ
KoZIhvcNAQEKA4IBDwAwggEKAoIBAQCpwVkHm2eU336pNtW7VYuu7nWUkSZxr9Oz
DAQrZbLsdcSeWj/sSe37/EPmtQrH8f8mK7OR7mY1DrodHyAqyGeeHIwTaAMdrrMX
X0RiPbid7w6MU3QZ1q5Hp8IAf8sLrQofchFRLDw6XkMcI4hbWtVJ9GwZiOO2gpDk
uS7SBLEiEzKHme+UzPMFUa2xCypYd/bpO0F+h9vtPDFTCRfK6EFf7mb/QAl1UwfO
Xq5+hMMiKWyhK2OIKhYc98k7eV7nlC4rz5tMY2v1tUJA6/fAZEmAREVE740hxmkN
qN5Enm5tF/ipROPbmQnyCkwtZxKTLi0tz8RTq7lZXRoQr9fo/6ufAgMBAAGjUzBR
MB0GA1UdDgQWBBRpdc2ssJhWnWTm4DPJLW3aDy71WTAfBgNVHSMEGDAWgBRpdc2s
sJhWnWTm4DPJLW3aDy71WTAPBgNVHRMBAf8EBTADAQH/MEEGCSqGSIb3DQEBCjA0
oA8wDQYJYIZIAWUDBAIBBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAIBBQCi
AwIBIAOCAQEATkolVgnlASfTEvMElGmrLTRVPBovk7ZCpER+/H316xswuUDWKn9t
BUhSCYinj5yywgwgx4sErnB5YkB+SR2kkE8WMAU0SNTh2kLUr4TrdqM1o0S5hGQT
awGCPIWZjip3V0TeAqC4sWTgdy2EBYPEJ0AZGm50/yJlWiOzsdDbzceKjremCxLF
Qgkrd/H9mRfIsybvQZ0SbhCWTbNiGpv+O3q4rJ8l3FiaNc9xt+9/FbzeRIipmVb3
ACeCkdjZt/3rjb/tZRHcURgXYi2109wQOaIE5tAQYFCvaKp3HNdWGU1K5+AO0SIY
k2mwB2RsEXa29/Xzj1eMyG33CDgo55AtDw==
-----END CERTIFICATE-----
";

// Port of pion `TestCertificateOIDValidation`: a PSS signature scheme must be paired with the
// certificate public key OID its family requires. Of pion's four subtests, the two mismatch
// cases are reproduced here; the `PSS_with_idRSASSAPSS_OID_succeeds` case is skipped by pion
// itself, and `RSAE_with_rsaEncryption_OID_succeeds` needs RSA-PSS signing, which no crypto
// provider implements — the signature bytes are irrelevant to the assertion either way, since
// the OID check fires before any cryptographic work, so a fixed dummy signature stands in.
#[test]
fn test_certificate_oid_validation() -> Result<()> {
    let provider = crypto::default_provider().map_err(crypto_error)?;

    let client_random = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let server_random = vec![0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let public_key = vec![0x10, 0x11, 0x12, 0x13];
    let message = value_key_message(
        &client_random,
        &server_random,
        &public_key,
        NamedCurve::X25519,
    );
    let dummy_signature = vec![0x42; 256];

    // A certificate with the rsaEncryption OID, built from the shared RSA fixture.
    let rsa_pem = include_str!("../../../rtc-crypto/tests/data/rsa-2048.pkcs8.pem");
    let rsa_key_pair = KeyPair::from_pem(rsa_pem).map_err(|e| Error::Other(e.to_string()))?;
    let rsa_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .map_err(|e| Error::Other(e.to_string()))?;
    let rsa_cert = rsa_params
        .self_signed(&rsa_key_pair)
        .map_err(|e| Error::Other(e.to_string()))?;
    let rsa_encryption_cert_bytes = rsa_cert.der().as_ref().to_vec();

    // A certificate with the id-RSASSA-PSS OID, pion's fixture verbatim.
    let pss_cert_block = pem::parse_many(RSA_PSS_CERTIFICATE)
        .map_err(|e| Error::InvalidPEM(e.to_string()))?
        .pop()
        .expect("RSA-PSS certificate fixture");
    let pss_cert_bytes = pss_cert_block.contents().to_vec();

    // PSS with rsaEncryption OID fails: the PSS family requires id-RSASSA-PSS.
    let algorithm = SignatureHashAlgorithm {
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::RsaPssPssSha256,
    };
    assert!(
        matches!(
            verify_key_signature(
                provider.crypto(),
                &message,
                &algorithm,
                &dummy_signature,
                &[rsa_encryption_cert_bytes],
                false,
            ),
            Err(Error::ErrInvalidCertificateOID)
        ),
        "PSS with rsaEncryption OID must fail with errInvalidCertificateOID"
    );

    // RSAE with id-RSASSA-PSS OID fails: the RSAE family requires rsaEncryption.
    let algorithm = SignatureHashAlgorithm {
        hash: HashAlgorithm::Sha256,
        signature: SignatureAlgorithm::RsaPssRsaeSha256,
    };
    assert!(
        matches!(
            verify_key_signature(
                provider.crypto(),
                &message,
                &algorithm,
                &dummy_signature,
                &[pss_cert_bytes],
                false,
            ),
            Err(Error::ErrInvalidCertificateOID)
        ),
        "RSAE with id-RSASSA-PSS OID must fail with errInvalidCertificateOID"
    );

    Ok(())
}

// DER helpers for `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` with a
// fabricated modulus, so a certificate can carry an RSA public key nobody holds the private half
// of — exactly pion's `TestPeerRSAKeySizeLimit`, which builds keys as `2^(bits-1) + 1` with
// exponent 65537.
fn der_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
}

fn der_positive_integer(bytes: &[u8], out: &mut Vec<u8>) {
    out.push(0x02);
    let pad = !bytes.is_empty() && bytes[0] & 0x80 != 0;
    let content_len = bytes.len() + usize::from(pad);
    der_length(content_len, out);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(bytes);
}

fn der_rsa_public_key(modulus_bits: usize) -> Vec<u8> {
    // modulus = 2^(modulus_bits - 1) + 1, so its bit length is exactly `modulus_bits` for every
    // value in pion's table, 2048 through 131072.
    let byte_len = modulus_bits.div_ceil(8);
    let mut modulus = vec![0u8; byte_len];
    // The top bit, `modulus_bits - 1` counting from the least significant end, lands in the
    // first byte of the big-endian array; its place within that byte is `(bits - 1) % 8`.
    modulus[byte_len - 1 - (modulus_bits - 1) / 8] = 1 << ((modulus_bits - 1) % 8);
    *modulus.last_mut().expect("non-empty modulus") |= 0x01;

    let mut body = Vec::new();
    der_positive_integer(&modulus, &mut body);
    der_positive_integer(&[0x01, 0x00, 0x01], &mut body); // 65537

    let mut out = vec![0x30];
    der_length(body.len(), &mut out);
    out.extend_from_slice(&body);
    out
}

// A certificate subject public key that is a fabricated RSA key: pion needs only the modulus,
// not the expensive keypair behind it.
struct FabricatedRsaKey {
    der: Vec<u8>,
}

impl rcgen::PublicKeyData for FabricatedRsaKey {
    fn der_bytes(&self) -> &[u8] {
        &self.der
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_RSA_SHA256
    }
}

// Port of pion `TestPeerRSAKeySizeLimit`: a peer RSA public key above 8192 bits is rejected when
// the certificate is parsed, before any verification work, for the RSA and RSA-PSS-RSAE
// algorithms pion checks. The `bits <= maxPeerRSAKeyBits` PSS case is not asserted: it needs
// RSA-PSS verification, which no crypto provider implements.
#[test]
fn test_peer_rsa_key_size_limit() -> Result<()> {
    let provider = crypto::default_provider().map_err(crypto_error)?;

    let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| Error::Other(e.to_string()))?;
    let issuer_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .map_err(|e| Error::Other(e.to_string()))?;
    let issuer_cert = issuer_params
        .self_signed(&issuer_key)
        .map_err(|e| Error::Other(e.to_string()))?;
    let issuer_der = issuer_cert.der().as_ref().to_vec();
    let issuer = rcgen::Issuer::from_params(&issuer_params, &issuer_key);

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(issuer_der.clone()))
        .map_err(|e| Error::Other(e.to_string()))?;
    let client_verifier: std::sync::Arc<dyn rustls::server::danger::ClientCertVerifier> =
        rustls::server::WebPkiClientVerifier::builder(std::sync::Arc::new(roots.clone()))
            .build()
            .map_err(|e| Error::Other(e.to_string()))?;
    let server_verifier: std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier> =
        rustls::client::WebPkiServerVerifier::builder(std::sync::Arc::new(roots))
            .build()
            .map_err(|e| Error::Other(e.to_string()))?;

    let leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .map_err(|e| Error::Other(e.to_string()))?;

    for bits in [2048, 8191, 8192, 8193, 131072] {
        let der = leaf_params
            .signed_by(
                &FabricatedRsaKey {
                    der: der_rsa_public_key(bits),
                },
                &issuer,
            )
            .map_err(|e| Error::Other(e.to_string()))?
            .der()
            .as_ref()
            .to_vec();
        let chain = vec![der.clone()];
        let oversized = bits > 8192;

        // loadCerts rejects an oversized key before anything else sees the certificate.
        match (load_certs(&chain), oversized) {
            (Ok(_), false) => {}
            (Err(Error::ErrPeerRSAKeyTooLarge), true) => {}
            (result, _) => panic!("{bits} bits: unexpected load_certs result: {result:?}"),
        }

        for signature in [
            SignatureAlgorithm::Rsa,
            SignatureAlgorithm::RsaPssRsaeSha256,
        ] {
            let algorithm = SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature,
            };
            // A nil signature, as in pion: verification of it fails, but the parse limit comes
            // first for an oversized key.
            let expected = match (oversized, signature) {
                (false, SignatureAlgorithm::Rsa) => Error::ErrKeySignatureMismatch,
                (true, _) => Error::ErrPeerRSAKeyTooLarge,
                (false, _) => continue, // needs RSA-PSS verification, a provider gap
            };
            assert!(
                matches!(
                    verify_key_signature(
                        provider.crypto(),
                        b"handshake",
                        &algorithm,
                        &[],
                        &chain,
                        false,
                    ),
                    Err(ref e) if *e == expected
                ),
                "{bits} bits, {signature:?}: expected {expected:?} from verify_key_signature"
            );
            assert!(
                matches!(
                    verify_certificate_verify(
                        provider.crypto(),
                        b"handshake",
                        &algorithm,
                        &[],
                        &chain,
                        false,
                    ),
                    Err(ref e) if *e == expected
                ),
                "{bits} bits, {signature:?}: expected {expected:?} from verify_certificate_verify"
            );
        }

        if oversized {
            // The oversized intermediate is rejected before rustls chain verification runs.
            let full_chain = vec![issuer_der.clone(), der];
            assert!(
                matches!(
                    verify_client_cert(&full_chain, &client_verifier),
                    Err(Error::ErrPeerRSAKeyTooLarge)
                ),
                "{bits} bits: verify_client_cert must reject the oversized key"
            );
            assert!(
                matches!(
                    verify_server_cert(&full_chain, &server_verifier, ""),
                    Err(Error::ErrPeerRSAKeyTooLarge)
                ),
                "{bits} bits: verify_server_cert must reject the oversized key"
            );
        }
    }

    Ok(())
}

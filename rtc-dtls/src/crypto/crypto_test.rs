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

#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
#[test]
fn test_cross_provider_signature_verification() -> Result<()> {
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
    let certificate_ecdsa256 = Certificate::generate_self_signed(vec!["localhost".to_owned()])?;
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

impl CustomSigner for MockSigner {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, String> {
        *self.call_count.lock().unwrap() += 1;
        *self.last_message.lock().unwrap() = message.to_vec();
        Ok(self.signature.clone())
    }

    fn clone_box(&self) -> Box<dyn CustomSigner> {
        Box::new(MockSigner {
            call_count: std::sync::Arc::clone(&self.call_count),
            last_message: std::sync::Arc::clone(&self.last_message),
            signature: self.signature.clone(),
        })
    }
}

#[test]
fn test_custom_signer_is_invoked_for_signing() -> Result<()> {
    let expected_signature = vec![0xca, 0xfe, 0xba, 0xbe];
    let call_count = std::sync::Arc::new(std::sync::Mutex::new(0usize));
    let last_message = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let private_key = CryptoPrivateKey::from_custom_signer(Box::new(MockSigner {
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

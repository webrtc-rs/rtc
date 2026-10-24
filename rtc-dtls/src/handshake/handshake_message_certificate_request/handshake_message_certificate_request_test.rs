use super::*;
use crate::signature_hash_algorithm::*;

use std::io::{BufReader, BufWriter};

#[test]
fn test_handshake_message_certificate_request() -> Result<()> {
    let raw_certificate_request = vec![
        0x02, 0x01, 0x40, 0x00, 0x0C, 0x04, 0x03, 0x04, 0x01, 0x05, 0x03, 0x05, 0x01, 0x06, 0x01,
        0x02, 0x01, 0x00, 0x00,
    ];

    let parsed_certificate_request = HandshakeMessageCertificateRequest {
        certificate_types: vec![
            ClientCertificateType::RsaSign,
            ClientCertificateType::EcdsaSign,
        ],
        signature_hash_algorithms: vec![
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Ecdsa,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Rsa,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha384,
                signature: SignatureAlgorithm::Ecdsa,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha384,
                signature: SignatureAlgorithm::Rsa,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha512,
                signature: SignatureAlgorithm::Rsa,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha1,
                signature: SignatureAlgorithm::Rsa,
            },
        ],
    };

    let mut reader = BufReader::new(raw_certificate_request.as_slice());
    let c = HandshakeMessageCertificateRequest::unmarshal(&mut reader)?;
    assert_eq!(
        c, parsed_certificate_request,
        "parsedCertificateRequest unmarshal: got {c:?}, want {parsed_certificate_request:?}"
    );

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        c.marshal(&mut writer)?;
    }
    assert_eq!(
        raw, raw_certificate_request,
        "parsedCertificateRequest marshal: got {raw:?}, want {raw_certificate_request:?}"
    );

    Ok(())
}

// Port of pion `TestHandshakeMessageCertificateRequest_SkipsUnknownAlgorithms`: unrecognized
// signature algorithm pairs in a CertificateRequest (Firefox's DSA offers) are silently skipped
// rather than causing a handshake failure.
#[test]
fn test_handshake_message_certificate_request_skips_unknown_algorithms() -> Result<()> {
    let raw = vec![
        0x02,       // cert types length: 2
        0x01, 0x40, // RSASign, ECDSASign
        0x00, 0x0C, // sig algs length: 12 bytes (6 pairs)
        0x04, 0x03, // SHA256+ECDSA  (valid)
        0x04, 0x01, // SHA256+RSA    (valid)
        0x04, 0x02, // SHA256+DSA    (unknown, skip) - Firefox 0x0402
        0x05, 0x02, // SHA384+DSA    (unknown, skip) - Firefox 0x0502
        0x06, 0x02, // SHA512+DSA    (unknown, skip) - Firefox 0x0602
        0x02, 0x02, // SHA1+DSA      (unknown, skip) - Firefox 0x0202
        0x00, 0x00, // CAs length: 0
    ];

    let mut reader = BufReader::new(raw.as_slice());
    let c = HandshakeMessageCertificateRequest::unmarshal(&mut reader)?;
    assert_eq!(
        c.signature_hash_algorithms,
        vec![
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Ecdsa,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Rsa,
            },
        ]
    );

    Ok(())
}

// Port of pion `TestHandshakeMessageCertificateRequest_CertificateTypesTooLong`: the certificate
// types vector is prefixed with a one-byte length, so more than 255 entries cannot be marshaled.
#[test]
fn test_handshake_message_certificate_request_certificate_types_too_long() {
    let c = HandshakeMessageCertificateRequest {
        certificate_types: vec![ClientCertificateType::RsaSign; 256],
        signature_hash_algorithms: vec![],
    };

    let mut raw = vec![];
    let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
    assert!(matches!(
        c.marshal(&mut writer),
        Err(Error::ErrCertificateTypesTooLong)
    ));
}

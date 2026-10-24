use super::*;

use std::io::{BufReader, BufWriter};

#[test]
fn test_extension_supported_signature_algorithms() -> Result<()> {
    let raw_extension_supported_signature_algorithms =
        vec![0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03]; //0x00, 0x0d,
    let parsed_extension_supported_signature_algorithms = ExtensionSupportedSignatureAlgorithms {
        signature_hash_algorithms: vec![
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Ecdsa,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha384,
                signature: SignatureAlgorithm::Ecdsa,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha512,
                signature: SignatureAlgorithm::Ecdsa,
            },
        ],
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        parsed_extension_supported_signature_algorithms.marshal(&mut writer)?;
    }

    assert_eq!(
        raw, raw_extension_supported_signature_algorithms,
        "extensionSupportedSignatureAlgorithms marshal: got {raw:?}, want {raw_extension_supported_signature_algorithms:?}"
    );

    let mut reader = BufReader::new(raw.as_slice());
    let new_extension_supported_signature_algorithms =
        ExtensionSupportedSignatureAlgorithms::unmarshal(&mut reader)?;

    assert_eq!(
        new_extension_supported_signature_algorithms,
        parsed_extension_supported_signature_algorithms,
        "extensionSupportedSignatureAlgorithms unmarshal: got {new_extension_supported_signature_algorithms:?}, want {parsed_extension_supported_signature_algorithms:?}"
    );

    Ok(())
}

// Port of pion `TestExtensionSupportedSignatureAlgorithms_PSSSchemes`: PSS schemes use the full
// `u16` signature-scheme encoding (TLS 1.3 style) and round-trip through the extension. The raw
// bytes are pion's minus the two extension-type bytes, which this crate's extension marshal
// prefixes at the `Extension` level.
#[test]
fn test_extension_supported_signature_algorithms_pss_schemes() -> Result<()> {
    let raw_extension_with_pss = vec![
        0x00, 0x08, // Extension length (8 bytes)
        0x00, 0x06, // Algorithms length (6 bytes = 3 schemes)
        0x08, 0x04, // RSA_PSS_RSAE_SHA256 (0x0804)
        0x08, 0x05, // RSA_PSS_RSAE_SHA384 (0x0805)
        0x08, 0x09, // RSA_PSS_PSS_SHA256 (0x0809)
    ];
    let parsed_extension_with_pss = ExtensionSupportedSignatureAlgorithms {
        signature_hash_algorithms: vec![
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::RsaPssRsaeSha256,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha384,
                signature: SignatureAlgorithm::RsaPssRsaeSha384,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::RsaPssPssSha256,
            },
        ],
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        parsed_extension_with_pss.marshal(&mut writer)?;
    }
    assert_eq!(raw, raw_extension_with_pss, "marshal PSS schemes");

    let mut reader = BufReader::new(raw.as_slice());
    let roundtrip = ExtensionSupportedSignatureAlgorithms::unmarshal(&mut reader)?;
    assert_eq!(
        roundtrip, parsed_extension_with_pss,
        "unmarshal PSS schemes"
    );

    Ok(())
}

// Port of pion `TestExtensionSupportedSignatureAlgorithms_MixedPSSAndNonPSS`: PSS and non-PSS
// schemes interleave in one extension, and Ed25519 (0x0807) is not treated as PSS despite being
// in the 0x08xx range.
#[test]
fn test_extension_supported_signature_algorithms_mixed_pss_and_non_pss() -> Result<()> {
    let raw_extension_mixed = vec![
        0x00, 0x0a, // Extension length (10 bytes)
        0x00, 0x08, // Algorithms length (8 bytes = 4 schemes)
        0x08, 0x04, // RSA_PSS_RSAE_SHA256 (0x0804) - PSS
        0x04, 0x01, // RSA PKCS#1 with SHA256 - Non-PSS
        0x04, 0x03, // ECDSA with SHA256 - Non-PSS
        0x08, 0x07, // Ed25519 (0x0807) - Not PSS despite being in the 0x08xx range
    ];
    let parsed_extension_mixed = ExtensionSupportedSignatureAlgorithms {
        signature_hash_algorithms: vec![
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::RsaPssRsaeSha256,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Rsa,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Ecdsa,
            },
            SignatureHashAlgorithm {
                hash: HashAlgorithm::Ed25519,
                signature: SignatureAlgorithm::Ed25519,
            },
        ],
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        parsed_extension_mixed.marshal(&mut writer)?;
    }
    assert_eq!(raw, raw_extension_mixed, "marshal mixed PSS and non-PSS");

    let mut reader = BufReader::new(raw.as_slice());
    let roundtrip = ExtensionSupportedSignatureAlgorithms::unmarshal(&mut reader)?;
    assert_eq!(roundtrip, parsed_extension_mixed, "unmarshal mixed schemes");

    Ok(())
}

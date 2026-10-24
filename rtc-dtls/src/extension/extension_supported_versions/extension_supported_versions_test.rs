//! Ported from pion/dtls v3.1.15 `pkg/protocol/extension/supported_versions_test.go`.
//!
//! pion's concrete `SupportedVersions.Unmarshal` receives the extension with its type code and
//! validates it; here the generic [`Extension::unmarshal`] path plays that role, so the fixtures
//! are the byte-for-byte pion ones.

use super::*;
use crate::record_layer::record_layer_header::*;

use std::io::{BufReader, BufWriter};

fn marshal(ext: &ExtensionSupportedVersions) -> Result<Vec<u8>> {
    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::SupportedVersions(ext.clone()).marshal(&mut writer)?;
    }
    Ok(raw)
}

fn unmarshal(raw: &[u8]) -> Result<ExtensionSupportedVersions> {
    match Extension::unmarshal(&mut BufReader::new(raw))? {
        Extension::SupportedVersions(ext) => Ok(ext),
        _ => Err(Error::ErrInvalidExtensionType),
    }
}

/// pion's `TestSupportedVersions_ClientHello_RoundTrip`.
#[test]
fn supported_versions_client_hello_round_trip() -> Result<()> {
    let ext = ExtensionSupportedVersions {
        versions: vec![
            PROTOCOL_VERSION1_3,
            PROTOCOL_VERSION1_2,
            // even though DTLS v1.0 isn't supported, it should still be marshaled/unmarshaled
            // correctly.
            PROTOCOL_VERSION1_0,
        ],
    };

    // length=7, listLen=6, 3 version pairs
    let raw_expected = [
        0x00, 0x2b, // extension type
        0x00, 0x07, // extension_data length
        0x06, // versions length (bytes)
        0xfe, 0xfc, // DTLS v1.3
        0xfe, 0xfd, // DTLS v1.2
        0xfe, 0xff, // DTLS v1.0
    ];

    let raw = marshal(&ext)?;
    assert_eq!(raw, raw_expected);

    let round_tripped = unmarshal(&raw)?;
    assert_eq!(round_tripped.versions, ext.versions);
    Ok(())
}

/// pion's `TestSupportedVersions_ServerHello_RoundTrip`.
#[test]
fn supported_versions_server_hello_round_trip() -> Result<()> {
    // Server/HRR form: exactly one entry in versions.
    let ext = ExtensionSupportedVersions {
        versions: vec![PROTOCOL_VERSION1_3],
    };

    // length=2, selected_version = 0xfe,0xfc
    let raw_expected = [
        0x00, 0x2b, // extension type
        0x00, 0x02, // extension_data length
        0xfe, 0xfc, // selected_version
    ];

    let raw = marshal(&ext)?;
    assert_eq!(raw, raw_expected);

    let round_tripped = unmarshal(&raw)?;
    assert_eq!(round_tripped.versions, [PROTOCOL_VERSION1_3]);
    Ok(())
}

/// pion's `TestSupportedVersions_ClientHello_Marshal_Invalid`.
#[test]
fn supported_versions_client_hello_marshal_invalid() -> Result<()> {
    let ext = ExtensionSupportedVersions {
        versions: vec![
            PROTOCOL_VERSION1_3,
            PROTOCOL_VERSION1_2,
            // even though DTLS v1.0 isn't supported, it should still be marshaled/unmarshaled
            // correctly.
            PROTOCOL_VERSION1_0,
            ProtocolVersion {
                major: 0xfe,
                minor: 0x00,
            }, // invalid version
        ],
    };

    // In this case we want it to error to protect against malformed messages/DOS attacks.
    assert_eq!(
        marshal(&ext).unwrap_err(),
        Error::ErrInvalidDtlsVersion,
        "an invalid DTLS version must be rejected on marshal"
    );
    Ok(())
}

/// pion's `TestSupportedVersions_ClientHello_Unmarshal_Invalid`.
#[test]
fn supported_versions_client_hello_unmarshal_invalid() -> Result<()> {
    // note that the invalid version is excluded from the parsed list.
    let ext = ExtensionSupportedVersions {
        versions: vec![
            PROTOCOL_VERSION1_3,
            PROTOCOL_VERSION1_2,
            // even though DTLS v1.0 isn't supported, it should still be marshaled/unmarshaled
            // correctly.
            PROTOCOL_VERSION1_0,
        ],
    };

    let raw = [
        0x00, 0x2b, // extension type
        0x00, 0x09, // extension_data length
        0x08, // versions length (bytes)
        0xfe, 0xfc, // DTLS v1.3
        0xfe, 0xfd, // DTLS v1.2
        0xfe, 0xff, // DTLS v1.0
        0xfe, 0x00, // invalid version
    ];

    // In this case we don't want it to error because valid versions can still be parsed.
    let round_tripped = unmarshal(&raw)?;
    assert_eq!(round_tripped.versions, ext.versions);
    Ok(())
}

/// pion's `TestSupportedVersions_Marshal_LengthBounds`.
#[test]
fn supported_versions_marshal_length_bounds() -> Result<()> {
    // list with length > 254 bytes, each version is 2 bytes.
    // so 128 versions -> 256 bytes (it should error).
    let too_many = vec![PROTOCOL_VERSION1_2; 128];

    let ext = ExtensionSupportedVersions { versions: too_many };
    assert_eq!(
        marshal(&ext).unwrap_err(),
        Error::ErrInvalidSupportedVersionsFormat
    );
    Ok(())
}

/// pion's `TestSupportedVersions_Unmarshal_Errors`.
#[test]
fn supported_versions_unmarshal_errors() -> Result<()> {
    let cases: [(&str, &[u8]); 5] = [
        (
            "invalid extension type",
            &[
                0x00, 0x0d, // signature_algorithms, not supported_versions
            ],
        ),
        (
            "empty extension_data",
            &[
                0x00, 0x2b, // extension type
                0x00, 0x00, // length = 0
            ],
        ),
        (
            "client list odd length",
            // length=4, listLen=3 (odd), 3 bytes follow
            &[
                0x00, 0x2b, // extension type
                0x00, 0x04, // length = 4
                0x03, // listLen = 3
                0xfe, 0xfd, 0xfe, // extra byte, parsing as list must fail
            ],
        ),
        (
            "client list length mismatch",
            // extension_data length=3, but listLen=4 -> mismatch
            &[
                0x00, 0x2b, // extension type
                0x00, 0x03, // length = 3
                0x04, // listLen = 4
                0xfe, 0xfd, // but only 2 bytes present
            ],
        ),
        (
            "server selected wrong size",
            // extension_data length=3 for server form (must be exactly 2 for server form)
            &[
                0x00, 0x2b, // extension type
                0x00, 0x03, // length = 3
                0xfe, 0xfc, 0x00,
            ],
        ),
    ];

    for (name, raw) in cases {
        let err = unmarshal(raw).unwrap_err();
        if name == "invalid extension type" {
            // pion's concrete method rejects the foreign type 0x000d with errInvalidExtensionType
            // before parsing. Through the generic enum dispatch that type is routed to the
            // signature_algorithms parser, which rejects the truncated buffer instead; the
            // scenario — a buffer whose type is not supported_versions must not parse — holds.
            // An unknown type still yields the exact pion error:
            assert_eq!(
                unmarshal(&[0x00, 0xff, 0x00, 0x02, 0xfe, 0xfc]).unwrap_err(),
                Error::ErrInvalidExtensionType
            );
        } else {
            assert_eq!(
                err,
                Error::ErrInvalidSupportedVersionsFormat,
                "case {name} must be rejected"
            );
        }
    }
    Ok(())
}

/// pion's `TestExtensionsUnmarshal_SupportedVersions_ClientHello`, through the generic
/// `Extension` unmarshal path.
#[test]
fn extensions_unmarshal_supported_versions_client_hello() -> Result<()> {
    let supported_versions_ext = [
        0x00, 0x2b, // extension type
        0x00, 0x05, // extension_data length = 5
        0x04, // list length = 4
        0xfe, 0xfc, // DTLS v1.3
        0xfe, 0xfd, // DTLS v1.2
    ];

    let sv = unmarshal(&supported_versions_ext)?;
    assert_eq!(sv.versions, [PROTOCOL_VERSION1_3, PROTOCOL_VERSION1_2]);
    Ok(())
}

/// pion's `TestExtensionsUnmarshal_SupportedVersions_ServerHello`, through the generic
/// `Extension` unmarshal path.
#[test]
fn extensions_unmarshal_supported_versions_server_hello() -> Result<()> {
    // only selected_version DTLS v1.3
    let supported_versions_ext = [
        0x00, 0x2b, // extension type
        0x00, 0x02, // extension_data length = 2
        0xfe, 0xfc, // selected_version = DTLS v1.3
    ];

    let sv = unmarshal(&supported_versions_ext)?;
    // Server/HRR form yields a single entry in versions.
    assert_eq!(sv.versions, [PROTOCOL_VERSION1_3]);
    Ok(())
}

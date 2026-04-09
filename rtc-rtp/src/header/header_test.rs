use super::*;
use shared::error::Error;
use shared::marshal::Marshal;

/// Helper: create a minimal valid header and marshal it, returning the result.
fn marshal_header(header: &Header) -> shared::error::Result<usize> {
    let mut buf = vec![0u8; header.marshal_size()];
    header.marshal_to(&mut &mut buf[..])
}

// -- CSRC validation --

#[test]
fn test_too_many_csrcs() {
    let header = Header {
        csrc: vec![0u32; 16],
        ..Default::default()
    };
    let err = marshal_header(&header).unwrap_err();
    assert!(
        matches!(err, Error::TooManyCSRCs(16)),
        "expected TooManyCSRCs(16), got {err:?}"
    );
}

#[test]
fn test_max_csrcs_valid() {
    let header = Header {
        csrc: vec![0u32; 15],
        ..Default::default()
    };
    assert!(marshal_header(&header).is_ok());
}

// -- One-byte extension payload size validation --

#[test]
fn test_one_byte_extension_payload_zero_length() {
    let header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_ONE_BYTE,
        extensions: vec![Extension {
            id: 1,
            payload: Bytes::new(),
        }],
        ..Default::default()
    };
    let err = marshal_header(&header).unwrap_err();
    assert!(
        matches!(err, Error::OneByteHeaderExtensionPayloadOutOfRange(0)),
        "expected OneByteHeaderExtensionPayloadOutOfRange(0), got {err:?}"
    );
}

#[test]
fn test_one_byte_extension_payload_too_large() {
    let header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_ONE_BYTE,
        extensions: vec![Extension {
            id: 1,
            payload: Bytes::from(vec![0u8; 17]),
        }],
        ..Default::default()
    };
    let err = marshal_header(&header).unwrap_err();
    assert!(
        matches!(err, Error::OneByteHeaderExtensionPayloadOutOfRange(17)),
        "expected OneByteHeaderExtensionPayloadOutOfRange(17), got {err:?}"
    );
}

#[test]
fn test_valid_one_byte_extension_boundaries() {
    // 1 byte payload -- minimum valid
    let header_min = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_ONE_BYTE,
        extensions: vec![Extension {
            id: 1,
            payload: Bytes::from(vec![0u8; 1]),
        }],
        ..Default::default()
    };
    assert!(marshal_header(&header_min).is_ok());

    // 16 byte payload -- maximum valid
    let header_max = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_ONE_BYTE,
        extensions: vec![Extension {
            id: 1,
            payload: Bytes::from(vec![0u8; 16]),
        }],
        ..Default::default()
    };
    assert!(marshal_header(&header_max).is_ok());
}

// -- Two-byte extension payload size validation --

#[test]
fn test_two_byte_extension_payload_too_large() {
    let header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_TWO_BYTE,
        extensions: vec![Extension {
            id: 1,
            payload: Bytes::from(vec![0u8; 256]),
        }],
        ..Default::default()
    };
    let err = marshal_header(&header).unwrap_err();
    assert!(
        matches!(err, Error::TwoByteHeaderExtensionPayloadTooLarge(256)),
        "expected TwoByteHeaderExtensionPayloadTooLarge(256), got {err:?}"
    );
}

#[test]
fn test_valid_two_byte_extension_boundary() {
    let header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_TWO_BYTE,
        extensions: vec![Extension {
            id: 1,
            payload: Bytes::from(vec![0u8; 255]),
        }],
        ..Default::default()
    };
    assert!(marshal_header(&header).is_ok());
}

// -- One-byte extension ID validation (RFC 8285 section 4.2) --

#[test]
fn test_one_byte_extension_id_zero_rejected() {
    let header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_ONE_BYTE,
        extensions: vec![Extension {
            id: 0,
            payload: Bytes::from(vec![0xAB]),
        }],
        ..Default::default()
    };
    let err = marshal_header(&header).unwrap_err();
    assert!(
        matches!(err, Error::ErrRfc8285oneByteHeaderIdrange),
        "expected ErrRfc8285oneByteHeaderIdrange, got {err:?}"
    );
}

#[test]
fn test_one_byte_extension_id_fifteen_rejected() {
    let header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_ONE_BYTE,
        extensions: vec![Extension {
            id: 15,
            payload: Bytes::from(vec![0xAB]),
        }],
        ..Default::default()
    };
    let err = marshal_header(&header).unwrap_err();
    assert!(
        matches!(err, Error::ErrRfc8285oneByteHeaderIdrange),
        "expected ErrRfc8285oneByteHeaderIdrange, got {err:?}"
    );
}

#[test]
fn test_one_byte_extension_id_fourteen_valid() {
    let header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_ONE_BYTE,
        extensions: vec![Extension {
            id: 14,
            payload: Bytes::from(vec![0xAB]),
        }],
        ..Default::default()
    };
    assert!(marshal_header(&header).is_ok());
}

// -- Two-byte extension ID validation (RFC 8285 section 4.3) --

#[test]
fn test_two_byte_extension_id_zero_rejected() {
    let header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_TWO_BYTE,
        extensions: vec![Extension {
            id: 0,
            payload: Bytes::from(vec![0xAB]),
        }],
        ..Default::default()
    };
    let err = marshal_header(&header).unwrap_err();
    assert!(
        matches!(err, Error::ErrRfc8285twoByteHeaderIdrange),
        "expected ErrRfc8285twoByteHeaderIdrange, got {err:?}"
    );
}

#[test]
fn test_two_byte_extension_id_one_valid() {
    let header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_TWO_BYTE,
        extensions: vec![Extension {
            id: 1,
            payload: Bytes::from(vec![0xAB]),
        }],
        ..Default::default()
    };
    assert!(marshal_header(&header).is_ok());
}

#[test]
fn test_two_byte_extension_id_255_valid() {
    let header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_TWO_BYTE,
        extensions: vec![Extension {
            id: 255,
            payload: Bytes::from(vec![0xAB]),
        }],
        ..Default::default()
    };
    assert!(marshal_header(&header).is_ok());
}

// -- Two-byte zero-length payload (valid per RFC 8285) --

#[test]
fn test_two_byte_extension_zero_length_payload_valid() {
    let header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_TWO_BYTE,
        extensions: vec![Extension {
            id: 1,
            payload: Bytes::new(),
        }],
        ..Default::default()
    };
    assert!(marshal_header(&header).is_ok());
}

// -- set_extension API consistency (Issue #1) --

#[test]
fn test_set_extension_rejects_zero_byte_payload_one_byte_profile() {
    let mut header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_ONE_BYTE,
        ..Default::default()
    };
    let err = header.set_extension(1, Bytes::new()).unwrap_err();
    assert!(
        matches!(err, Error::ErrRfc8285oneByteHeaderSize),
        "expected ErrRfc8285oneByteHeaderSize, got {err:?}"
    );
}

// -- Total extension payload overflow (Issue #5) --

#[test]
fn test_extension_payload_total_overflow() {
    // Build a header with enough extensions to exceed u16::MAX total payload bytes.
    // Two-byte profile allows up to 255 bytes per extension; we need ~258 extensions
    // of 255 bytes each to exceed 65535.
    let count = 258;
    let extensions: Vec<Extension> = (1..=count)
        .map(|i| Extension {
            id: (i % 255 + 1) as u8,
            payload: Bytes::from(vec![0xAA; 255]),
        })
        .collect();
    let header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_TWO_BYTE,
        extensions,
        ..Default::default()
    };
    let err = marshal_header(&header).unwrap_err();
    assert!(
        matches!(err, Error::ExtensionPayloadTotalOverflow(_)),
        "expected ExtensionPayloadTotalOverflow, got {err:?}"
    );
}

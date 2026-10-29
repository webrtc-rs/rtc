use bytes::{Bytes, BytesMut};

use shared::error::Result;

use super::*;

#[test]
fn test_playout_delay_extension_roundtrip() -> Result<()> {
    let test = PlayoutDelayExtension {
        max_delay: 2345,
        min_delay: 1234,
    };

    let mut raw = BytesMut::with_capacity(test.marshal_size());
    raw.resize(test.marshal_size(), 0);
    test.marshal_to(&mut raw)?;
    let raw = raw.freeze();
    let buf = &mut raw.clone();
    let out = PlayoutDelayExtension::unmarshal(buf)?;
    assert_eq!(test, out);

    Ok(())
}

#[test]
fn test_playout_delay_value_overflow() -> Result<()> {
    let test = PlayoutDelayExtension {
        max_delay: u16::MAX,
        min_delay: u16::MAX,
    };

    let mut dst = BytesMut::with_capacity(test.marshal_size());
    dst.resize(test.marshal_size(), 0);
    let result = test.marshal_to(&mut dst);
    assert!(result.is_err());

    Ok(())
}

// pion TestPlayoutDelayExtensionTooSmall.
#[test]
fn test_playout_delay_extension_too_small() {
    let mut buf = &vec![0u8; 0][..];
    assert!(PlayoutDelayExtension::unmarshal(&mut buf).is_err());
}

// pion TestPlayoutDelayExtension (values from the wire and back).
#[test]
fn test_playout_delay_extension() -> Result<()> {
    let raw = Bytes::from_static(&[0x01, 0x01, 0x00]);
    let buf = &mut raw.clone();
    let t1 = PlayoutDelayExtension::unmarshal(buf)?;
    let t2 = PlayoutDelayExtension {
        min_delay: 1 << 4,
        max_delay: 1 << 8,
    };
    assert_eq!(t1, t2);

    let mut dst = BytesMut::with_capacity(t2.marshal_size());
    dst.resize(t2.marshal_size(), 0);
    t2.marshal_to(&mut dst)?;
    assert_eq!(raw, dst);
    Ok(())
}

// pion TestPlayoutDelayExtensionExtraBytes: trailing bytes are ignored.
#[test]
fn test_playout_delay_extension_extra_bytes() -> Result<()> {
    let mut raw = Bytes::from_static(&[0x01, 0x01, 0x00, 0xff, 0xff]);
    let t1 = PlayoutDelayExtension::unmarshal(&mut raw)?;
    assert_eq!(
        PlayoutDelayExtension {
            min_delay: 1 << 4,
            max_delay: 1 << 8,
        },
        t1
    );
    Ok(())
}

// pion TestPlayoutDelayExtensionMarshalTo.
#[test]
fn test_playout_delay_extension_marshal_to() -> Result<()> {
    let ext = PlayoutDelayExtension {
        min_delay: 100,
        max_delay: 200,
    };
    let mut buf = vec![0u8; ext.marshal_size()];
    let n = ext.marshal_to(&mut buf)?;
    assert_eq!(ext.marshal_size(), n);
    assert!(ext.marshal_to(&mut []).is_err());
    Ok(())
}

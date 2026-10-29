use super::*;
use bytes::{Bytes, BytesMut};
use shared::error::Result;

#[test]
fn test_transport_cc_extension_too_small() -> Result<()> {
    let mut buf = &vec![0u8; 0][..];
    let result = TransportCcExtension::unmarshal(&mut buf);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_transport_cc_extension() -> Result<()> {
    let raw = Bytes::from_static(&[0x00, 0x02]);
    let buf = &mut raw.clone();
    let t1 = TransportCcExtension::unmarshal(buf)?;
    let t2 = TransportCcExtension {
        transport_sequence: 2,
    };
    assert_eq!(t1, t2);

    let mut dst = BytesMut::with_capacity(t2.marshal_size());
    dst.resize(t2.marshal_size(), 0);
    t2.marshal_to(&mut dst)?;
    assert_eq!(raw, dst.freeze());

    Ok(())
}

#[test]
fn test_transport_cc_extension_extra_bytes() -> Result<()> {
    let mut raw = Bytes::from_static(&[0x00, 0x02, 0x00, 0xff, 0xff]);
    let buf = &mut raw;
    let t1 = TransportCcExtension::unmarshal(buf)?;
    let t2 = TransportCcExtension {
        transport_sequence: 2,
    };
    assert_eq!(t1, t2);

    Ok(())
}

// pion TestTransportCCExtensionMarshalTo.
#[test]
fn test_transport_cc_extension_marshal_to() -> Result<()> {
    let t = TransportCcExtension {
        transport_sequence: 2,
    };
    let mut buf = vec![0u8; t.marshal_size()];
    let n = t.marshal_to(&mut buf)?;
    assert_eq!(t.marshal_size(), n);
    assert_eq!(&[0x00, 0x02][..], &buf[..n]);
    assert!(t.marshal_to(&mut []).is_err());
    Ok(())
}

use super::*;
use bytes::BytesMut;
use shared::error::Result;

#[test]
fn test_ntp_64_extension_roundtrip() -> Result<()> {
    let tests = vec![
        Ntp64Extension::new(0),
        Ntp64Extension::new(123456),
        Ntp64Extension::new(0xa0c65b1000000000),
        Ntp64Extension::new(u64::MAX),
    ];

    for test in &tests {
        assert_eq!(test.marshal_size(), NTP_64_EXTENSION_SIZE);

        let mut raw = BytesMut::with_capacity(test.marshal_size());
        raw.resize(test.marshal_size(), 0);
        test.marshal_to(&mut raw)?;
        let raw = raw.freeze();
        let buf = &mut raw.clone();
        let out = Ntp64Extension::unmarshal(buf)?;
        assert_eq!(*test, out);
    }

    Ok(())
}

#[test]
fn test_ntp_64_extension_unmarshal_too_small() {
    let raw = BytesMut::from(&[0u8; 4][..]).freeze();
    let buf = &mut raw.clone();
    assert!(Ntp64Extension::unmarshal(buf).is_err());
}

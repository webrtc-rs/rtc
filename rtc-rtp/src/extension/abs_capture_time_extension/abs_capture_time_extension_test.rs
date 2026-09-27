use super::*;
use bytes::BytesMut;
use shared::error::Result;

#[test]
fn test_abs_capture_time_extension_roundtrip_without_offset() -> Result<()> {
    let tests = vec![
        AbsCaptureTimeExtension::new(123456),
        AbsCaptureTimeExtension::new(0xa0c65b1000000000),
    ];

    for test in &tests {
        assert_eq!(test.marshal_size(), ABS_CAPTURE_TIME_EXTENSION_SIZE);

        let mut raw = BytesMut::with_capacity(test.marshal_size());
        raw.resize(test.marshal_size(), 0);
        test.marshal_to(&mut raw)?;
        let raw = raw.freeze();
        let buf = &mut raw.clone();
        let out = AbsCaptureTimeExtension::unmarshal(buf)?;
        assert_eq!(*test, out);
        assert_eq!(out.estimated_capture_clock_offset, None);
    }

    Ok(())
}

#[test]
fn test_abs_capture_time_extension_roundtrip_with_offset() -> Result<()> {
    let tests = vec![
        AbsCaptureTimeExtension::new_with_clock_offset(123456, -42),
        AbsCaptureTimeExtension::new_with_clock_offset(0xa0c65b1000000000, 0x0000000200000000),
    ];

    for test in &tests {
        assert_eq!(
            test.marshal_size(),
            ABS_CAPTURE_TIME_EXTENSION_SIZE_WITH_OFFSET
        );

        let mut raw = BytesMut::with_capacity(test.marshal_size());
        raw.resize(test.marshal_size(), 0);
        test.marshal_to(&mut raw)?;
        let raw = raw.freeze();
        let buf = &mut raw.clone();
        let out = AbsCaptureTimeExtension::unmarshal(buf)?;
        assert_eq!(*test, out);
    }

    Ok(())
}

#[test]
fn test_abs_capture_time_extension_unmarshal_too_small() {
    let raw = BytesMut::from(&[0u8; 4][..]).freeze();
    let buf = &mut raw.clone();
    assert!(AbsCaptureTimeExtension::unmarshal(buf).is_err());
}

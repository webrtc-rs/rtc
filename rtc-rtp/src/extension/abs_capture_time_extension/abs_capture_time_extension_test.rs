use super::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789)
}

fn close(a: SystemTime, b: SystemTime) -> bool {
    let d = match a.duration_since(b) {
        Ok(d) => d,
        Err(e) => e.duration(),
    };
    d < Duration::from_millis(1)
}

// pion TestAbsCaptureTimeExtension_Roundtrip, positive offset.
#[test]
fn test_roundtrip_positive_offset() -> Result<()> {
    let e1 = AbsCaptureTimeExtension::new(t0());
    let raw = e1.marshal()?;
    assert_eq!(ABS_CAPTURE_TIME_EXTENSION_SIZE, raw.len());
    let o1 = AbsCaptureTimeExtension::unmarshal(&mut raw.clone())?;
    assert!(close(o1.capture_time(), t0()));
    assert_eq!(None, o1.estimated_capture_clock_offset_nanos());

    let e2 = AbsCaptureTimeExtension::with_capture_clock_offset(t0(), 1_250_000_000);
    let raw = e2.marshal()?;
    assert_eq!(ABS_CAPTURE_TIME_EXTENDED_EXTENSION_SIZE, raw.len());
    let o2 = AbsCaptureTimeExtension::unmarshal(&mut raw.clone())?;
    assert!(close(o2.capture_time(), t0()));
    assert_eq!(
        Some(1_250_000_000),
        o2.estimated_capture_clock_offset_nanos()
    );
    Ok(())
}

// pion TestAbsCaptureTimeExtension_Roundtrip, negative offset (pion issue 247).
#[test]
fn test_roundtrip_negative_offset() -> Result<()> {
    let e = AbsCaptureTimeExtension::with_capture_clock_offset(t0(), -250_000_000);
    let raw = e.marshal()?;
    let o = AbsCaptureTimeExtension::unmarshal(&mut raw.clone())?;
    assert_eq!(Some(-250_000_000), o.estimated_capture_clock_offset_nanos());
    assert!(o.estimated_capture_clock_offset.unwrap() < 0);
    Ok(())
}

// pion TestAbsCaptureTimeExtensionMarshalTo.
#[test]
fn test_marshal_to() -> Result<()> {
    for ext in [
        AbsCaptureTimeExtension::new(t0()),
        AbsCaptureTimeExtension::with_capture_clock_offset(t0(), 100_000_000),
    ] {
        let mut buf = vec![0u8; ext.marshal_size()];
        let n = ext.marshal_to(&mut buf)?;
        assert_eq!(ext.marshal_size(), n);
        assert_eq!(ext.marshal()?.as_ref(), &buf[..]);
        assert!(ext.marshal_to(&mut []).is_err());
    }
    Ok(())
}

#[test]
fn test_unmarshal_too_small() {
    assert!(AbsCaptureTimeExtension::unmarshal(&mut &[0u8; 7][..]).is_err());
}

// Known answers produced by pion rtp v1.10.6 for the same inputs:
// (offset ns, wire bytes, offset ns read back).
#[test]
fn test_known_answers() -> Result<()> {
    let ts = "e8fe6f801f9add37";
    for (offset, tail, back) in [
        (0, "", None),
        (1_250_000_000, "0000000140000000", Some(1_250_000_000)),
        (-250_000_000, "ffffffffc0000000", Some(-250_000_000)),
        (100_000_000, "0000000019999999", Some(99_999_999)),
        (7_000_000_003, "000000070000000c", Some(7_000_000_002)),
    ] {
        let e = if offset == 0 {
            AbsCaptureTimeExtension::new(t0())
        } else {
            AbsCaptureTimeExtension::with_capture_clock_offset(t0(), offset)
        };
        let raw = e.marshal()?;
        assert_eq!(format!("{ts}{tail}"), hex(&raw));
        let o = AbsCaptureTimeExtension::unmarshal(&mut raw.clone())?;
        assert_eq!(back, o.estimated_capture_clock_offset_nanos());
        assert_eq!(
            1_700_000_000_123_456_788,
            o.capture_time()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

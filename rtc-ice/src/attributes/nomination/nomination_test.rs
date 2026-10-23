use super::*;

// pion TestNominationAttribute.
#[test]
fn test_nomination_attribute() -> Result<()> {
    // AddTo and GetFrom
    let mut m = Message::new();
    NominationAttribute::new(0x123456).add_to_default(&mut m)?;
    let mut parsed = NominationAttribute::default();
    parsed.get_from_default(&m)?;
    assert_eq!(0x123456, parsed.value);
    // reserved byte stays zero, value is big-endian in the low 24 bits
    assert_eq!(
        vec![0, 0x12, 0x34, 0x56],
        m.get(DEFAULT_NOMINATION_ATTRIBUTE)?
    );

    // 24-bit value boundary
    let mut m = Message::new();
    NominationAttribute::new(MAX_NOMINATION_VALUE).add_to_default(&mut m)?;
    let mut parsed = NominationAttribute::default();
    parsed.get_from_default(&m)?;
    assert_eq!(MAX_NOMINATION_VALUE, parsed.value);

    // String representation
    let s = NominationAttribute::new(12345).to_string();
    assert!(s.contains("NOMINATION") && s.contains("12345"));

    Ok(())
}

#[test]
fn test_nomination_attribute_errors_and_custom_type() -> Result<()> {
    let m = Message::new();
    let mut a = NominationAttribute::default();
    assert!(a.get_from_default(&m).is_err(), "absent attribute");

    let mut m = Message::new();
    m.add(DEFAULT_NOMINATION_ATTRIBUTE, &[0, 1, 2]);
    assert_eq!(
        Err(Error::ErrAttributeSizeInvalid),
        a.get_from_default(&m),
        "short attribute"
    );

    // a custom type does not collide with the default one
    let custom = AttrType(0xC002);
    let mut m = Message::new();
    NominationSetter {
        value: 7,
        attr_type: custom,
    }
    .add_to(&mut m)?;
    assert!(m.contains(custom));
    assert!(!m.contains(DEFAULT_NOMINATION_ATTRIBUTE));
    let mut a = NominationAttribute::default();
    a.get_from_with_type(&m, custom)?;
    assert_eq!(7, a.value);
    Ok(())
}

// pion TestNominationValueBoundaries
#[test]
fn test_nomination_value_boundaries() -> Result<()> {
    // zero round-trips
    let mut m = Message::new();
    NominationAttribute::new(0).add_to_default(&mut m)?;
    let mut parsed = NominationAttribute::new(99);
    parsed.get_from_default(&m)?;
    assert_eq!(0, parsed.value);

    // anything above 24 bits is truncated on the wire
    let overflow = 1u32 << 25;
    let mut m = Message::new();
    NominationAttribute::new(overflow).add_to_default(&mut m)?;
    let mut parsed = NominationAttribute::default();
    parsed.get_from_default(&m)?;
    assert_eq!(overflow & 0xFF_FFFF, parsed.value);
    let mut m = Message::new();
    NominationAttribute::new(0x0123_4567).add_to_default(&mut m)?;
    parsed.get_from_default(&m)?;
    assert_eq!(0x23_4567, parsed.value);

    // a configurable type: the default reader does not see it
    let custom = AttrType(0x0040);
    let mut m = Message::new();
    NominationAttribute::new(12345).add_to_with_type(&mut m, custom)?;
    assert!(NominationAttribute::default().get_from_default(&m).is_err());
    let mut parsed = NominationAttribute::default();
    parsed.get_from_with_type(&m, custom)?;
    assert_eq!(12345, parsed.value);

    // the setter form
    let custom = AttrType(0x0050);
    let mut m = Message::new();
    NominationSetter {
        value: 98765,
        attr_type: custom,
    }
    .add_to(&mut m)?;
    let mut parsed = NominationAttribute::default();
    parsed.get_from_with_type(&m, custom)?;
    assert_eq!(98765, parsed.value);
    assert!(NominationAttribute::default().get_from_default(&m).is_err());
    Ok(())
}

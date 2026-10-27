use super::*;

#[test]
fn test_dont_fragment_false() -> Result<()> {
    let mut dont_fragment = DontFragmentAttr::default();

    let mut m = Message::new();
    m.write_header();
    assert!(dont_fragment.get_from(&m).is_err(), "should not be set");

    Ok(())
}

#[test]
fn test_dont_fragment_add_to() -> Result<()> {
    let mut dont_fragment = DontFragmentAttr::default();

    let mut m = Message::new();
    dont_fragment.add_to(&mut m)?;
    m.write_header();

    let mut decoded = Message::new();
    decoded.write(&m.raw)?;
    assert!(dont_fragment.get_from(&m).is_ok(), "should be set");

    Ok(())
}

#[test]
fn dont_fragment_with_a_value_is_malformed() {
    use stun::attributes::ATTR_DONT_FRAGMENT;
    let mut m = Message::new();
    m.add(ATTR_DONT_FRAGMENT, &[1, 2, 3, 4]);
    assert!(DontFragmentAttr.get_from(&m).is_err());

    // The empty attribute, which is what the RFC defines, still reads.
    let mut ok = Message::new();
    DontFragmentAttr.add_to(&mut ok).unwrap();
    assert!(DontFragmentAttr.get_from(&ok).is_ok());
}

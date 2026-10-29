use super::*;

#[test]
fn dtls_in_stun_round_trips_and_reports_absence() -> Result<()> {
    let mut m = Message::new();
    let mut got = DtlsInStunAttr::default();
    assert_eq!(got.get_from(&m), Err(Error::ErrAttributeNotFound));

    let want = DtlsInStunAttr(vec![22, 254, 253, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3, 1, 2, 3]);
    want.add_to(&mut m)?;
    m.write_header();

    // Survives encoding and decoding, not only the in-memory attribute list.
    let mut decoded = Message::new();
    decoded.raw = m.raw.clone();
    decoded.decode()?;
    got.get_from(&decoded)?;
    assert_eq!(got, want);
    Ok(())
}

#[test]
fn dtls_in_stun_pads_unaligned_values() -> Result<()> {
    let mut m = Message::new();
    DtlsInStunAttr(vec![1, 2, 3]).add_to(&mut m)?;
    m.write_header();
    // 4-byte attribute header, 3 value bytes, 1 padding byte.
    assert_eq!(m.length, 8);
    let mut got = DtlsInStunAttr::default();
    got.get_from(&m)?;
    assert_eq!(got.0, vec![1, 2, 3]);
    Ok(())
}

#[test]
fn dtls_in_stun_ack_round_trips_zero_to_four_values() -> Result<()> {
    for acks in [
        vec![],
        vec![7],
        vec![1, 2],
        vec![0xdead_beef, 0, u32::MAX, 42],
    ] {
        let mut m = Message::new();
        DtlsInStunAckAttr(acks.clone()).add_to(&mut m)?;
        m.write_header();
        let mut decoded = Message::new();
        decoded.raw = m.raw.clone();
        decoded.decode()?;
        let mut got = DtlsInStunAckAttr(vec![9, 9, 9]);
        got.get_from(&decoded)?;
        assert_eq!(got.0, acks);
    }
    Ok(())
}

#[test]
fn dtls_in_stun_ack_rejects_too_many_and_misaligned_values() {
    let mut m = Message::new();
    assert_eq!(
        DtlsInStunAckAttr(vec![1, 2, 3, 4, 5]).add_to(&mut m),
        Err(Error::ErrAttributeSizeInvalid)
    );

    let mut m = Message::new();
    m.add(ATTR_DTLS_IN_STUN_ACK, &[0; 5]);
    assert_eq!(
        DtlsInStunAckAttr::default().get_from(&m),
        Err(Error::ErrAttributeSizeInvalid)
    );

    let mut m = Message::new();
    m.add(ATTR_DTLS_IN_STUN_ACK, &[0; 20]);
    assert_eq!(
        DtlsInStunAckAttr::default().get_from(&m),
        Err(Error::ErrAttributeSizeInvalid)
    );

    let m = Message::new();
    assert_eq!(
        DtlsInStunAckAttr::default().get_from(&m),
        Err(Error::ErrAttributeNotFound)
    );
}

#[test]
fn attribute_numbers_and_names_match_the_draft() {
    assert_eq!(ATTR_DTLS_IN_STUN.value(), 0xC070);
    assert_eq!(ATTR_DTLS_IN_STUN_ACK.value(), 0xC071);
    assert_eq!(ATTR_DTLS_IN_STUN.to_string(), "DTLS-IN-STUN");
    assert_eq!(
        ATTR_DTLS_IN_STUN_ACK.to_string(),
        "DTLS-IN-STUN-ACKNOWLEDGEMENT"
    );
}

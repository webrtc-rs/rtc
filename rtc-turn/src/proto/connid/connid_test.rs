use super::*;

#[test]
fn connection_id_round_trips() -> Result<()> {
    for id in [0u32, 1, 0xdead_beef, u32::MAX] {
        let mut m = Message::new();
        ConnectionId(id).add_to(&mut m)?;
        m.write_header();

        let mut decoded = Message::new();
        decoded.raw = m.raw.clone();
        decoded.decode()?;

        let mut got = ConnectionId::default();
        got.get_from(&decoded)?;
        assert_eq!(got, ConnectionId(id));
    }
    Ok(())
}

#[test]
fn connection_id_reports_absence_and_bad_sizes() {
    let m = Message::new();
    assert_eq!(
        ConnectionId::default().get_from(&m),
        Err(shared::error::Error::ErrAttributeNotFound)
    );

    for len in [0usize, 3, 5, 8] {
        let mut m = Message::new();
        m.add(ATTR_CONNECTION_ID, &vec![0u8; len]);
        assert!(
            ConnectionId::default().get_from(&m).is_err(),
            "a {len}-byte value is not a connection id"
        );
    }
}

#[test]
fn connection_id_has_the_rfc_6062_attribute_number() {
    assert_eq!(ATTR_CONNECTION_ID.value(), 0x002a);
    assert_eq!(ATTR_CONNECTION_ID.to_string(), "CONNECTION-ID");
}

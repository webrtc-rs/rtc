use super::*;
use shared::error::Error;

#[test]
fn test_data_add_to() -> Result<()> {
    let mut m = Message::new();
    let d = Data(vec![1, 2, 33, 44, 0x13, 0xaf]);
    d.add_to(&mut m)?;
    m.write_header();

    //"GetFrom"
    {
        let mut decoded = Message::new();
        decoded.write(&m.raw)?;

        let mut data_decoded = Data::default();
        data_decoded.get_from(&decoded)?;
        assert_eq!(data_decoded, d);

        //"HandleErr"
        {
            let m = Message::new();
            let mut handle = Data::default();
            if let Err(err) = handle.get_from(&m) {
                assert_eq!(
                    Error::ErrAttributeNotFound,
                    err,
                    "{err} should be not found"
                );
            }
        }
    }
    Ok(())
}

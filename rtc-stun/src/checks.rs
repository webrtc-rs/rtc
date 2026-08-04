use crate::attributes::*;
use shared::error::*;

/// Check_size returns ErrAttrSizeInvalid if got is not equal to expected.
pub fn check_size(_at: AttrType, got: usize, expected: usize) -> Result<()> {
    if got == expected {
        Ok(())
    } else {
        Err(Error::ErrAttributeSizeInvalid)
    }
}

/// Is_attr_size_invalid returns true if error means that attribute size is invalid.
pub fn is_attr_size_invalid(err: &Error) -> bool {
    Error::ErrAttributeSizeInvalid == *err
}

pub(crate) fn check_fingerprint(got: u32, expected: u32) -> Result<()> {
    if got == expected {
        Ok(())
    } else {
        Err(Error::ErrFingerprintMismatch)
    }
}

/// Check_overflow returns ErrAttributeSizeOverflow if got is bigger that max.
pub fn check_overflow(_at: AttrType, got: usize, max: usize) -> Result<()> {
    if got <= max {
        Ok(())
    } else {
        Err(Error::ErrAttributeSizeOverflow)
    }
}

/// Is_attr_size_overflow returns true if error means that attribute size is too big.
pub fn is_attr_size_overflow(err: &Error) -> bool {
    Error::ErrAttributeSizeOverflow == *err
}

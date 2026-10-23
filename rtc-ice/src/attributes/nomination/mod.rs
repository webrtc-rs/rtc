#[cfg(test)]
mod nomination_test;

use shared::error::*;
use stun::attributes::AttrType;
use stun::message::*;

/// The STUN attribute type used for renomination unless configured otherwise.
///
/// Matches libwebrtc and pion (`DefaultNominationAttribute`); the value follows
/// draft-thatcher-ice-renomination-01, which has no IANA assignment yet.
pub const DEFAULT_NOMINATION_ATTRIBUTE: AttrType = AttrType(0xC001);

/// The largest nomination value the attribute can carry (24 bits).
pub const MAX_NOMINATION_VALUE: u32 = (1 << 24) - 1;

/// The nomination attribute of draft-thatcher-ice-renomination: a 24-bit value that the
/// controlling agent increments with every renomination, so the controlled agent can tell the
/// newest nomination from a stale one.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct NominationAttribute {
    /// The nomination value (only the low 24 bits go on the wire).
    pub value: u32,
}

impl NominationAttribute {
    /// A nomination attribute carrying `value`.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self { value }
    }

    /// Adds the attribute to `m` under the attribute type `typ`.
    pub fn add_to_with_type(&self, m: &mut Message, typ: AttrType) -> Result<()> {
        m.add(
            typ,
            &[
                0,
                (self.value >> 16) as u8,
                (self.value >> 8) as u8,
                self.value as u8,
            ],
        );
        Ok(())
    }

    /// Reads the attribute of type `typ` from `m`.
    pub fn get_from_with_type(&mut self, m: &Message, typ: AttrType) -> Result<()> {
        let v = m.get(typ)?;
        if v.len() < 4 {
            return Err(Error::ErrAttributeSizeInvalid);
        }

        // The value is the low 24 bits; the first byte is reserved.
        self.value = u32::from(v[1]) << 16 | u32::from(v[2]) << 8 | u32::from(v[3]);
        Ok(())
    }

    /// Adds the attribute under [`DEFAULT_NOMINATION_ATTRIBUTE`].
    pub fn add_to_default(&self, m: &mut Message) -> Result<()> {
        self.add_to_with_type(m, DEFAULT_NOMINATION_ATTRIBUTE)
    }

    /// Reads the attribute under [`DEFAULT_NOMINATION_ATTRIBUTE`].
    pub fn get_from_default(&mut self, m: &Message) -> Result<()> {
        self.get_from_with_type(m, DEFAULT_NOMINATION_ATTRIBUTE)
    }
}

impl std::fmt::Display for NominationAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NOMINATION: {}", self.value)
    }
}

/// A STUN setter that adds a nomination attribute under a configurable attribute type
/// (pion's `NominationSetter`).
#[derive(Clone, Copy, Debug)]
pub struct NominationSetter {
    /// The nomination value.
    pub value: u32,
    /// The STUN attribute type to carry it.
    pub attr_type: AttrType,
}

impl Setter for NominationSetter {
    fn add_to(&self, m: &mut Message) -> Result<()> {
        NominationAttribute::new(self.value).add_to_with_type(m, self.attr_type)
    }
}

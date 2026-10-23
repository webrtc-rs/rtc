#[cfg(test)]
mod uattrs_test;

use crate::attributes::*;
use crate::message::*;
use shared::error::*;

use std::fmt;

/// UNKNOWN-ATTRIBUTES attribute.
///
/// RFC 5389 Section 15.9.
pub struct UnknownAttributes(pub Vec<AttrType>);

impl fmt::Display for UnknownAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            write!(f, "<nil>")
        } else {
            let s = self
                .0
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            write!(f, "{s}")
        }
    }
}

// type size is 16 bit.
const ATTR_TYPE_SIZE: usize = 2;

impl Setter for UnknownAttributes {
    // add_to adds UNKNOWN-ATTRIBUTES attribute to message.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        if self.0.len() <= 20 {
            // A stack buffer sized for the attribute's natural limit (20
            // types, the maximum that fits one attribute): adding must not
            // allocate (pion's TestAllocations pins zero allocations here).
            let mut v = [0u8; ATTR_TYPE_SIZE * 20];
            for (i, t) in self.0.iter().enumerate() {
                v[i * ATTR_TYPE_SIZE..(i + 1) * ATTR_TYPE_SIZE]
                    .copy_from_slice(&t.value().to_be_bytes());
            }
            m.add(ATTR_UNKNOWN_ATTRIBUTES, &v[..self.0.len() * ATTR_TYPE_SIZE]);
        } else {
            let mut v = Vec::with_capacity(ATTR_TYPE_SIZE * self.0.len());
            for t in &self.0 {
                v.extend_from_slice(&t.value().to_be_bytes());
            }
            m.add(ATTR_UNKNOWN_ATTRIBUTES, &v);
        }
        Ok(())
    }
}

impl Getter for UnknownAttributes {
    // GetFrom parses UNKNOWN-ATTRIBUTES from message.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        let v = m.get_value(ATTR_UNKNOWN_ATTRIBUTES)?;
        if v.len() % ATTR_TYPE_SIZE != 0 {
            return Err(Error::ErrBadUnknownAttrsSize);
        }
        self.0.clear();
        let mut first = 0usize;
        while first < v.len() {
            let last = first + ATTR_TYPE_SIZE;
            self.0
                .push(AttrType(u16::from_be_bytes([v[first], v[first + 1]])));
            first = last;
        }
        Ok(())
    }
}

//! The `CONNECTION-ID` attribute of [RFC 6062 §6.2.1]: names one peer data connection, so a client
//! can bind a new TCP connection to it.
//!
//! [RFC 6062 §6.2.1]: https://www.rfc-editor.org/rfc/rfc6062#section-6.2.1
#[cfg(test)]
mod connid_test;

use std::fmt;

use shared::error::Result;
use stun::attributes::ATTR_CONNECTION_ID;
use stun::checks::*;
use stun::message::*;

const CONNECTION_ID_SIZE: usize = 4;

/// `ConnectionId` represents the `CONNECTION-ID` attribute: an opaque 32-bit value the server
/// assigns to a peer data connection.
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct ConnectionId(pub u32);

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Setter for ConnectionId {
    /// Adds `CONNECTION-ID` to the message.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        m.add(ATTR_CONNECTION_ID, &self.0.to_be_bytes());
        Ok(())
    }
}

impl Getter for ConnectionId {
    /// Decodes `CONNECTION-ID` from the message.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        let v = m.get_value(ATTR_CONNECTION_ID)?;
        check_size(ATTR_CONNECTION_ID, v.len(), CONNECTION_ID_SIZE)?;
        self.0 = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
        Ok(())
    }
}

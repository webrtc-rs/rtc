//! The two STUN attributes of DTLS-in-STUN (draft-ietf-mmusic-dtls-in-stun): a DTLS handshake
//! record rides inside an ICE connectivity check instead of waiting for the check to succeed, and
//! each side acknowledges what it has received so lost records are retransmitted. pion/ice ships
//! the same two attribute types (`sped.go`); wiring them into a handshake is up to the application,
//! which sees every binding request through
//! [`BindingRequestHandler`](crate::agent::agent_config::BindingRequestHandler).
#[cfg(test)]
mod dtls_in_stun_test;

use shared::error::*;
use stun::attributes::{ATTR_DTLS_IN_STUN, ATTR_DTLS_IN_STUN_ACK};
use stun::message::*;

/// `DTLS-IN-STUN`: the DTLS record(s) embedded in a STUN message.
#[derive(Default, PartialEq, Eq, Debug, Clone)]
pub struct DtlsInStunAttr(pub Vec<u8>);

impl Setter for DtlsInStunAttr {
    /// Adds `DTLS-IN-STUN` to the message.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        m.add(ATTR_DTLS_IN_STUN, &self.0);
        Ok(())
    }
}

impl Getter for DtlsInStunAttr {
    /// Decodes `DTLS-IN-STUN` from the message.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        let v = m.get_value(ATTR_DTLS_IN_STUN)?;
        self.0.clear();
        self.0.extend_from_slice(v);
        Ok(())
    }
}

/// The most acknowledgements one attribute carries.
pub const DTLS_IN_STUN_ACK_MAX_VALUES: usize = 4;
const ACK_VALUE_SIZE: usize = 4;

/// `DTLS-IN-STUN-ACKNOWLEDGEMENT`: up to four 32-bit acknowledgements of DTLS packets received,
/// whether they arrived embedded in STUN or not.
#[derive(Default, PartialEq, Eq, Debug, Clone)]
pub struct DtlsInStunAckAttr(pub Vec<u32>);

impl Setter for DtlsInStunAckAttr {
    /// Adds `DTLS-IN-STUN-ACKNOWLEDGEMENT` to the message.
    ///
    /// # Errors
    ///
    /// [`Error::ErrAttributeSizeInvalid`] if there are more than four acknowledgements.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        if self.0.len() > DTLS_IN_STUN_ACK_MAX_VALUES {
            return Err(Error::ErrAttributeSizeInvalid);
        }
        let mut v = [0u8; DTLS_IN_STUN_ACK_MAX_VALUES * ACK_VALUE_SIZE];
        for (i, ack) in self.0.iter().enumerate() {
            v[i * ACK_VALUE_SIZE..(i + 1) * ACK_VALUE_SIZE].copy_from_slice(&ack.to_be_bytes());
        }
        m.add(ATTR_DTLS_IN_STUN_ACK, &v[..self.0.len() * ACK_VALUE_SIZE]);
        Ok(())
    }
}

impl Getter for DtlsInStunAckAttr {
    /// Decodes `DTLS-IN-STUN-ACKNOWLEDGEMENT` from the message.
    ///
    /// # Errors
    ///
    /// [`Error::ErrAttributeSizeInvalid`] if the value is longer than four acknowledgements or
    /// not a whole number of them.
    fn get_from(&mut self, m: &Message) -> Result<()> {
        let v = m.get_value(ATTR_DTLS_IN_STUN_ACK)?;
        if v.len() > DTLS_IN_STUN_ACK_MAX_VALUES * ACK_VALUE_SIZE || v.len() % ACK_VALUE_SIZE != 0 {
            return Err(Error::ErrAttributeSizeInvalid);
        }
        self.0 = v
            .chunks_exact(ACK_VALUE_SIZE)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        Ok(())
    }
}

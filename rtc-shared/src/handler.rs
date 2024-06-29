use crate::error::Result;
use retty::transport::Transmit;
use std::time::Instant;

pub trait RTCHandler {
    /// Associated event input message type
    type Ein: 'static;
    /// Associated event output message type
    type Eout: 'static;
    /// Associated read input message type
    type Rin: 'static;
    /// Associated read output message type
    type Rout: 'static;
    /// Associated write input message type
    type Win: 'static;
    /// Associated write output message type for
    type Wout: 'static;

    /// Handles Rin and returns Rout for next inbound handler handling
    fn handle_read(&mut self, msg: Transmit<Self::Rin>) -> Result<()>;

    /// Polls Rout from internal queue for next inbound handler handling
    fn poll_read(&mut self) -> Option<Transmit<Self::Rout>>;

    /// Handles Win and returns Wout for next outbound handler handling
    fn handle_write(&mut self, msg: Transmit<Self::Win>) -> Result<()>;

    /// Polls Wout from internal queue for next outbound handler handling
    fn poll_write(&mut self) -> Option<Transmit<Self::Wout>>;

    /// Handles event
    fn handle_event(&mut self, _evt: Self::Ein) -> Result<()> {
        Ok(())
    }

    /// Polls event
    fn poll_event(&mut self) -> Option<Self::Eout> {
        None
    }

    /// Handles timeout
    fn handle_timeout(&mut self, _now: Instant) -> Result<()> {
        Ok(())
    }

    /// Polls timeout
    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }
}

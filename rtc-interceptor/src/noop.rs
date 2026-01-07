//! NoOp Interceptor - A pass-through terminal for interceptor chains.

use crate::Packet;
use shared::error::Error;
use std::collections::VecDeque;
use std::time::Instant;

/// A no-operation interceptor that simply queues messages for pass-through.
///
/// `NoopInterceptor` serves as the innermost layer of an interceptor chain.
/// It accepts messages via `handle_read`/`handle_write`/etc and returns them
/// unchanged via `poll_read`/`poll_write`/etc.
///
/// # Example
///
/// ```ignore
/// use rtc_interceptor::NoopInterceptor;
/// use sansio::Protocol;
///
/// let mut noop = NoopInterceptor::new();
/// noop.handle_read(Packet::Rtp(...)).unwrap();
/// assert!(noop.poll_read().is_some());
/// ```
pub struct NoopInterceptor {
    read_queue: VecDeque<Packet>,
    write_queue: VecDeque<Packet>,
}

impl NoopInterceptor {
    /// Create a new NoopInterceptor.
    pub fn new() -> Self {
        Self {
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

impl Default for NoopInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl sansio::Protocol<Packet, Packet, ()> for NoopInterceptor {
    type Rout = Packet;
    type Wout = Packet;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: Packet) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: Packet) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_event(&mut self, _evt: ()) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        None
    }

    fn handle_timeout(&mut self, _now: Self::Time) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        self.read_queue.clear();
        self.write_queue.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sansio::Protocol;

    fn dummy_rtp_packet() -> Packet {
        Packet::Rtp(rtp::Packet::default())
    }

    #[test]
    fn test_noop_read_write() {
        let mut noop = NoopInterceptor::new();

        // Test read
        let pkt1 = dummy_rtp_packet();
        let pkt2 = dummy_rtp_packet();
        noop.handle_read(pkt1.clone()).unwrap();
        noop.handle_read(pkt2.clone()).unwrap();
        assert_eq!(noop.poll_read(), Some(pkt1));
        assert_eq!(noop.poll_read(), Some(pkt2));
        assert_eq!(noop.poll_read(), None);

        // Test write
        let pkt3 = dummy_rtp_packet();
        let pkt4 = dummy_rtp_packet();
        noop.handle_write(pkt3.clone()).unwrap();
        noop.handle_write(pkt4.clone()).unwrap();
        assert_eq!(noop.poll_write(), Some(pkt3));
        assert_eq!(noop.poll_write(), Some(pkt4));
        assert_eq!(noop.poll_write(), None);
    }

    #[test]
    fn test_noop_close_clears_queues() {
        let mut noop = NoopInterceptor::new();

        noop.handle_read(dummy_rtp_packet()).unwrap();
        noop.handle_write(dummy_rtp_packet()).unwrap();

        noop.close().unwrap();

        assert_eq!(noop.poll_read(), None);
        assert_eq!(noop.poll_write(), None);
    }
}

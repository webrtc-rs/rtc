//! NoOp Interceptor - A pass-through terminal for interceptor chains.

use crate::TaggedPacket;
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
/// noop.handle_read(TaggedPacket::Rtp(...)).unwrap();
/// assert!(noop.poll_read().is_some());
/// ```
pub struct NoopInterceptor {
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
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

impl sansio::Protocol<TaggedPacket, TaggedPacket, ()> for NoopInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
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

    fn dummy_rtp_packet() -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: Default::default(),
            message: crate::Packet::Rtp(rtp::Packet::default()),
        }
    }

    #[test]
    fn test_noop_read_write() {
        let mut noop = NoopInterceptor::new();

        // Test read
        let pkt1 = dummy_rtp_packet();
        let pkt2 = dummy_rtp_packet();
        let pkt1_message = pkt1.message.clone();
        let pkt2_message = pkt2.message.clone();
        noop.handle_read(pkt1).unwrap();
        noop.handle_read(pkt2).unwrap();
        assert_eq!(noop.poll_read().unwrap().message, pkt1_message);
        assert_eq!(noop.poll_read().unwrap().message, pkt2_message);
        assert!(noop.poll_read().is_none());

        // Test write
        let pkt3 = dummy_rtp_packet();
        let pkt4 = dummy_rtp_packet();
        let pkt3_message = pkt3.message.clone();
        let pkt4_message = pkt4.message.clone();
        noop.handle_write(pkt3).unwrap();
        noop.handle_write(pkt4).unwrap();
        assert_eq!(noop.poll_write().unwrap().message, pkt3_message);
        assert_eq!(noop.poll_write().unwrap().message, pkt4_message);
        assert!(noop.poll_write().is_none());
    }

    #[test]
    fn test_noop_close_clears_queues() {
        let mut noop = NoopInterceptor::new();

        noop.handle_read(dummy_rtp_packet()).unwrap();
        noop.handle_write(dummy_rtp_packet()).unwrap();

        noop.close().unwrap();

        assert!(noop.poll_read().is_none());
        assert!(noop.poll_write().is_none());
    }
}

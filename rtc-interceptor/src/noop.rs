//! NoOp Interceptor - A pass-through terminal for interceptor chains.

use sansio::Protocol;
use shared::error::Error;
use std::collections::VecDeque;
use std::time::Instant;

/// A no-operation interceptor that simply queues messages for pass-through.
///
/// `NoopInterceptor` serves as the innermost layer of an interceptor chain.
/// It accepts messages via `handle_read`/`handle_write`/etc and returns them
/// unchanged via `poll_read`/`poll_write`/etc.
///
/// # Type Parameters
///
/// - `Rin`: Read input message type
/// - `Win`: Write input message type
/// - `Ein`: Event input type
///
/// # Example
///
/// ```ignore
/// use rtc_interceptor::NoopInterceptor;
/// use sansio::Protocol;
///
/// let mut noop: NoopInterceptor<String, String, ()> = NoopInterceptor::new();
/// noop.handle_read("hello".to_string()).unwrap();
/// assert_eq!(noop.poll_read(), Some("hello".to_string()));
/// ```
pub struct NoopInterceptor<Rin, Win, Ein> {
    read_queue: VecDeque<Rin>,
    write_queue: VecDeque<Win>,
    event_queue: VecDeque<Ein>,
}

impl<Rin, Win, Ein> NoopInterceptor<Rin, Win, Ein> {
    /// Create a new NoopInterceptor.
    pub fn new() -> Self {
        Self {
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
            event_queue: VecDeque::new(),
        }
    }
}

impl<Rin, Win, Ein> Default for NoopInterceptor<Rin, Win, Ein> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Rin, Win, Ein> Protocol<Rin, Win, Ein> for NoopInterceptor<Rin, Win, Ein> {
    type Rout = Rin;
    type Wout = Win;
    type Eout = Ein;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: Rin) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: Win) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_event(&mut self, evt: Ein) -> Result<(), Self::Error> {
        self.event_queue.push_back(evt);
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.event_queue.pop_front()
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

    #[test]
    fn test_noop_read_write() {
        let mut noop: NoopInterceptor<i32, i32, ()> = NoopInterceptor::new();

        // Test read
        noop.handle_read(1).unwrap();
        noop.handle_read(2).unwrap();
        assert_eq!(noop.poll_read(), Some(1));
        assert_eq!(noop.poll_read(), Some(2));
        assert_eq!(noop.poll_read(), None);

        // Test write
        noop.handle_write(10).unwrap();
        noop.handle_write(20).unwrap();
        assert_eq!(noop.poll_write(), Some(10));
        assert_eq!(noop.poll_write(), Some(20));
        assert_eq!(noop.poll_write(), None);
    }

    #[test]
    fn test_noop_close_clears_queues() {
        let mut noop: NoopInterceptor<i32, i32, ()> = NoopInterceptor::new();

        noop.handle_read(1).unwrap();
        noop.handle_write(2).unwrap();

        noop.close().unwrap();

        assert_eq!(noop.poll_read(), None);
        assert_eq!(noop.poll_write(), None);
    }
}

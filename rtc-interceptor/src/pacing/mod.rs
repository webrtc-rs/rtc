//! Pacing interceptor — leaky-bucket rate limiter over a queue, drained on `handle_timeout`.
//!
//! See [`PacerInterceptor`] and [`PacerBuilder`].
//!
//! # Design
//!
//! Packets are paced with a token-bucket:
//!
//! ```text
//! for queued packets where budget(now) > 8*len:
//!   consume budget and forward via inner.handle_write tagged with now
//! ```
//!
//! Shape:
//!
//! | previous | this implementation |
//! |---|---|---|
//! | `BindLocalStream` wraps a writer | `handle_write` enqueues |
//! | ticker task | `handle_timeout(now)` drains affordable packets via `inner.handle_write` tagged with `now` (rule 3) |
//! | channel queue 1M + `sync.Mutex` | `VecDeque` + `&mut self` |
//! | `SetRate` via factory map | `set_pacing_rate` on the concrete interceptor |
//!
//! # Chain position
//!
//! **Outermost on write**, innermost-or-none on read (pacing has no read path).
//! Listed outermost first per `registry.rs`:
//!
//! ```text
//! outermost  pacing
//!            FEC encode (repair packets)
//!            RTCP reports (SR)
//!            NACK responder
//!            TWCC sender
//! innermost  rtpfb / send history
//! ```
//!
//! Pacing outermost is a correctness property (registry rule): everything below
//! must observe the release instant, otherwise history counts queue time as
//! network time. History innermost is why pacing cannot keep a separate send
//! history — it must sit above it.
//!
//! # Scheduling discipline
//!
//! - `poll_timeout` returns `None` when the queue is empty — otherwise the whole
//!   chain would wake at the pacing rate forever on an idle connection.
//! - The returned instant **must advance** beyond the `now` just handed to
//!   `handle_timeout`. Computing it as `now + interval` unconditionally is the
//!   busy-loop fixed in #862. This port computes it from the budget:
//!   `now + time_until(head_bits)`.
//! - Budget is a pure function of the `now` handed in, so pacing is
//!   reproducible with a deterministic clock.

pub(crate) mod bucket;
pub(crate) mod interceptor;

pub use interceptor::{
    DEFAULT_INITIAL_RATE, DEFAULT_INTERVAL, DEFAULT_QUEUE_SIZE, PacerBuilder, PacerInterceptor,
};

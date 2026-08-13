//! Jitter buffer (internal module).
//!
//! Absorbs arrival-time variation and reordering so packets reach the application in sequence
//! order. This module holds the data structure; the playout policy that decides *when* a packet
//! is due arrives with the interceptor.
//!
//! # Deliberate differences from `pion/interceptor`
//!
//! - **One buffer per SSRC.** Upstream's `ReceiverInterceptor` holds a single buffer for every
//!   remote stream and ignores `info.SSRC` when binding, so two streams sort against each other's
//!   sequence numbers. [`JitterBuffer`] binds to the first SSRC it sees and rejects any other.
//! - **Ordering is wrap-safe.** Upstream's priority queue compares raw `u16` values, so a packet
//!   after a wrap sorts a whole cycle early. Ordering here is by extended sequence number.
//! - **Duplicates collapse.** Upstream inserts equal priorities, leaving two copies of a
//!   retransmitted packet in the ordering.
//! - **No `ErrPopWhileBuffering`.** That sentinel is an artifact of a synchronous reader; in
//!   sans-I/O a buffering stream simply yields nothing yet.
//!
//! # References
//!
//! - [RFC 3550](https://datatracker.ietf.org/doc/html/rfc3550) - RTP, sequence numbers and jitter
pub(crate) mod buffer;
pub(crate) mod sequence;

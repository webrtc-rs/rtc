//! Pacing (internal module).
//!
//! Releases outgoing packets at a target rate instead of as fast as the application produces
//! them. Without it, a frame's worth of packets leaves in a burst, arrives as a burst, and is
//! read by congestion control as the path queueing — so the estimate falls even though the path
//! was fine.
//!
//! The rate is driven by a bandwidth estimator through
//! [`Pacer::set_target_bitrate`](pacer::Pacer::set_target_bitrate).
pub(crate) mod pacer;
pub(crate) mod sender;

//! Congestion control: the estimator seam, and the interceptor that drives it.
//!
//! The algorithm is a plain object behind [`BandwidthEstimator`](estimator::BandwidthEstimator),
//! not an interceptor — see there for why.
//!
//! The interceptor that feeds it belongs at the **wire-most** position in the chain, because that
//! is the only one that sees every byte that leaves: nothing exits except through the interceptors
//! ahead of it in the walk, so a retransmission or a FEC repair packet cannot slip past unrecorded.

pub(crate) mod estimator;
pub(crate) mod interceptor;

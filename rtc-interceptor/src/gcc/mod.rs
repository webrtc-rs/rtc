//! Google Congestion Control, ported as synchronous functions of the instants handed in.
//!
//! Upstream fans acknowledgements into two goroutines over two channels and lets the stages lag
//! independently; here each stage is a direct call. That is the same simplification that made the
//! pacer's release schedule assertable: with no concurrency and no clock of its own, a given
//! feedback sequence produces one bitrate trajectory, every time.
//!
//! The pipeline, wire-to-estimate:
//!
//! ```text
//! PacketReports ─▶ ArrivalGroupAccumulator ─▶ Kalman ─▶ (overuse detector) ─▶ (rate control)
//!                  group bursts, measure      filter      P7-05                P7-06
//!                  the delay gradient         the trend
//! ```

pub(crate) mod arrival_group;
pub(crate) mod estimator;
pub(crate) mod kalman;
pub(crate) mod loss;
pub(crate) mod overuse;
pub(crate) mod rate_calc;
pub(crate) mod rate_control;
pub(crate) mod slope;
pub(crate) mod state;
pub(crate) mod threshold;

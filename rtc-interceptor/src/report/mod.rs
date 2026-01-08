//! RTCP Report Interceptors
//!
//! This module provides interceptors for handling RTCP reports:
//!
//! - [`ReceiverReportInterceptor`]: Generates RTCP Receiver Reports based on
//!   incoming RTP packet statistics.
//! - [`SenderReportInterceptor`]: Filters hop-by-hop RTCP reports that should
//!   not be forwarded end-to-end.
//!
//! # Example
//!
//! ```ignore
//! use rtc_interceptor::{Registry, report::{ReceiverReportInterceptor, SenderReportInterceptor}};
//!
//! let chain = Registry::new()
//!     .with(SenderReportInterceptor::new)
//!     .with(ReceiverReportInterceptor::new)
//!     .build();
//! ```

mod receiver_report;
pub(crate) mod receiver_stream;
mod sender_report;
pub(crate) mod sender_stream;

//TODO: pub use receiver_report::{ReceiverReportConfig, ReceiverReportInterceptor};
//TODO: pub use sender_report::SenderReportInterceptor;

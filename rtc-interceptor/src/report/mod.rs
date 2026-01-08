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
//! use rtc_interceptor::{Registry, SenderReportBuilder, ReceiverReportBuilder};
//!
//! let chain = Registry::new()
//!     .with(SenderReportBuilder::new().build())
//!     .with(ReceiverReportBuilder::new().build())
//!     .build();
//! ```

pub(crate) mod receiver_report;
pub(crate) mod receiver_stream;
pub(crate) mod sender_report;
pub(crate) mod sender_stream;

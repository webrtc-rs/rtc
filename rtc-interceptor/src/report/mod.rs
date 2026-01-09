//! RTCP Report Interceptors.
//!
//! This module provides interceptors for generating and handling RTCP reports
//! as specified in RFC 3550 (RTP: A Transport Protocol for Real-Time Applications).
//!
//! # Interceptors
//!
//! - [`SenderReportInterceptor`]: Generates RTCP Sender Reports (SR) for local streams
//!   and filters hop-by-hop RTCP feedback that shouldn't be forwarded end-to-end.
//! - [`ReceiverReportInterceptor`]: Generates RTCP Receiver Reports (RR) based on
//!   incoming RTP packet statistics (loss, jitter, etc.).
//!
//! # Sender Reports (SR)
//!
//! Sender Reports contain:
//! - NTP timestamp (wall-clock time)
//! - RTP timestamp (media time)
//! - Sender's packet count and octet count
//! - Optional report blocks for streams the sender is also receiving
//!
//! # Receiver Reports (RR)
//!
//! Receiver Reports contain report blocks with:
//! - Fraction of packets lost since last report
//! - Cumulative packets lost
//! - Extended highest sequence number received
//! - Interarrival jitter estimate
//! - Last SR timestamp (LSR) and delay since last SR (DLSR)
//!
//! # References
//!
//! - [RFC 3550](https://datatracker.ietf.org/doc/html/rfc3550) - RTP: A Transport Protocol for Real-Time Applications
//! - [RFC 3611](https://datatracker.ietf.org/doc/html/rfc3611) - RTP Control Protocol Extended Reports (RTCP XR)
//!
//! # Example
//!
//! ```ignore
//! use rtc_interceptor::{Registry, SenderReportBuilder, ReceiverReportBuilder};
//! use std::time::Duration;
//!
//! let chain = Registry::new()
//!     // Sender Report for outgoing streams
//!     .with(SenderReportBuilder::new()
//!         .with_interval(Duration::from_secs(1))
//!         .build())
//!     // Receiver Report for incoming streams
//!     .with(ReceiverReportBuilder::new()
//!         .with_interval(Duration::from_secs(1))
//!         .build())
//!     .build();
//! ```

pub(crate) mod receiver;
pub(crate) mod receiver_stream;
pub(crate) mod sender;
pub(crate) mod sender_stream;

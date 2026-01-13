//! RTC Interceptor - Sans-IO interceptor framework for RTP/RTCP processing.
//!
//! This crate provides a composable interceptor framework built on top of the
//! [`sansio::Protocol`] trait. Interceptors can process, modify, or generate
//! RTP/RTCP packets as they flow through the pipeline.
//!
//! # Available Interceptors
//!
//! ## RTCP Reports
//!
//! | Interceptor | Description |
//! |-------------|-------------|
//! | [`SenderReportInterceptor`] | Generates RTCP Sender Reports (SR) for local streams and filters hop-by-hop RTCP feedback |
//! | [`ReceiverReportInterceptor`] | Generates RTCP Receiver Reports (RR) based on incoming RTP statistics |
//!
//! ## NACK (Negative Acknowledgement)
//!
//! | Interceptor | Description |
//! |-------------|-------------|
//! | [`NackGeneratorInterceptor`] | Detects missing RTP packets and generates NACK requests (RFC 4585) |
//! | [`NackResponderInterceptor`] | Buffers sent packets and retransmits on NACK, with optional RTX support (RFC 4588) |
//!
//! ## TWCC (Transport Wide Congestion Control)
//!
//! | Interceptor | Description |
//! |-------------|-------------|
//! | [`TwccSenderInterceptor`] | Adds transport-wide sequence numbers to outgoing RTP packets |
//! | [`TwccReceiverInterceptor`] | Tracks incoming packets and generates TransportLayerCC feedback |
//!
//! ## Utility
//!
//! | Interceptor | Description |
//! |-------------|-------------|
//! | [`NoopInterceptor`] | Pass-through terminal for interceptor chains |
//!
//! # Design
//!
//! Each interceptor wraps an inner `Interceptor` and can:
//! - Process incoming/outgoing RTP/RTCP packets
//! - Modify packet contents (headers, payloads)
//! - Generate new packets (e.g., RTCP Sender/Receiver Reports)
//! - Handle timeouts for periodic tasks (e.g., report generation)
//! - Track stream statistics and state
//!
//! All interceptors work with [`TaggedPacket`] (RTP or RTCP packets with transport metadata).
//! The innermost interceptor is typically [`NoopInterceptor`], which serves as the terminal.
//!
//! # No Direction Concept
//!
//! **Important:** Unlike PeerConnection's pipeline where `read` and `write` have
//! opposite processing direction orders, interceptors have **no direction concept**.
//!
//! In PeerConnection's pipeline:
//! ```text
//! Read:  Network → HandlerA → HandlerB → HandlerC → Application
//! Write: Application → HandlerC → HandlerB → HandlerA → Network
//!        (reversed order)
//! ```
//!
//! In Interceptor chains, all operations flow in the **same direction**:
//! ```text
//! handle_read:    Outer → Inner (A.handle_read calls B.handle_read calls C.handle_read)
//! handle_write:   Outer → Inner (A.handle_write calls B.handle_write calls C.handle_write)
//! handle_event:   Outer → Inner (A.handle_event calls B.handle_event calls C.handle_event)
//! handle_timeout: Outer → Inner (A.handle_timeout calls B.handle_timeout calls C.handle_timeout)
//!
//! poll_read:    Outer → Inner (A.poll_read calls B.poll_read calls C.poll_read)
//! poll_write:   Outer → Inner (A.poll_write calls B.poll_write calls C.poll_write)
//! poll_event:   Outer → Inner (A.poll_event calls B.poll_event calls C.poll_event)
//! poll_timeout: Outer → Inner (A.poll_timeout calls B.poll_timeout calls C.poll_timeout)
//! ```
//!
//! This means interceptors are symmetric - they process `read`, `write`, and `event`
//! in the same structural order. The distinction between "inbound" and "outbound"
//! is semantic (based on message content), not structural (based on call order).
//!
//! # Quick Start
//!
//! ```ignore
//! use rtc_interceptor::{
//!     Registry, SenderReportBuilder, ReceiverReportBuilder,
//!     NackGeneratorBuilder, NackResponderBuilder,
//!     TwccSenderBuilder, TwccReceiverBuilder,
//! };
//! use std::time::Duration;
//!
//! // Build a full-featured interceptor chain
//! let chain = Registry::new()
//!     // RTCP reports
//!     .with(SenderReportBuilder::new()
//!         .with_interval(Duration::from_secs(1))
//!         .build())
//!     .with(ReceiverReportBuilder::new()
//!         .with_interval(Duration::from_secs(1))
//!         .build())
//!     // NACK for packet loss recovery
//!     .with(NackGeneratorBuilder::new()
//!         .with_size(512)
//!         .with_interval(Duration::from_millis(100))
//!         .build())
//!     .with(NackResponderBuilder::new()
//!         .with_size(1024)
//!         .build())
//!     // TWCC for congestion control
//!     .with(TwccSenderBuilder::new().build())
//!     .with(TwccReceiverBuilder::new()
//!         .with_interval(Duration::from_millis(100))
//!         .build())
//!     .build();
//! ```
//!
//! # Stream Binding
//!
//! Before interceptors can process packets for a stream, the stream must be bound:
//!
//! ```ignore
//! use rtc_interceptor::{StreamInfo, RTCPFeedback, RTPHeaderExtension};
//!
//! // Create stream info with NACK and TWCC support
//! let stream_info = StreamInfo {
//!     ssrc: 0x12345678,
//!     clock_rate: 90000,
//!     mime_type: "video/VP8".to_string(),
//!     payload_type: 96,
//!     rtcp_feedback: vec![RTCPFeedback {
//!         typ: "nack".to_string(),
//!         parameter: String::new(),
//!     }],
//!     rtp_header_extensions: vec![RTPHeaderExtension {
//!         uri: "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01".to_string(),
//!         id: 5,
//!     }],
//!     ..Default::default()
//! };
//!
//! // Bind for outgoing streams (sender side)
//! chain.bind_local_stream(&stream_info);
//!
//! // Bind for incoming streams (receiver side)
//! chain.bind_remote_stream(&stream_info);
//! ```
//!
//! # Creating Custom Interceptors
//!
//! Use the derive macros to easily create custom interceptors:
//!
//! ```ignore
//! use rtc_interceptor::{Interceptor, interceptor, TaggedPacket, StreamInfo};
//! use std::collections::VecDeque;
//!
//! #[derive(Interceptor)]
//! pub struct MyInterceptor<P: Interceptor> {
//!     #[next]
//!     next: P,  // The next interceptor in the chain (can use any field name)
//!     buffer: VecDeque<TaggedPacket>,
//! }
//!
//! #[interceptor]
//! impl<P: Interceptor> MyInterceptor<P> {
//!     #[overrides]
//!     fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
//!         // Custom logic here
//!         self.next.handle_read(msg)
//!     }
//! }
//! ```
//!
//! - `#[derive(Interceptor)]` - Marks a struct as an interceptor, requires `#[next]` field
//! - `#[interceptor]` - Generates `Protocol` and `Interceptor` trait implementations
//! - `#[overrides]` - Marks methods with custom implementations (non-marked methods delegate to next)
//!
//! See the [`Interceptor`] trait documentation for more details.

#![warn(rust_2018_idioms)]
#![allow(dead_code)]

use shared::TransportMessage;
use std::time::Instant;

mod noop;
mod registry;

pub(crate) mod nack;
pub(crate) mod report;
pub(crate) mod stream_info;
pub(crate) mod twcc;

pub use nack::{
    generator::{NackGeneratorBuilder, NackGeneratorInterceptor},
    responder::{NackResponderBuilder, NackResponderInterceptor},
};
pub use noop::NoopInterceptor;
pub use registry::Registry;
pub use report::{
    receiver::{ReceiverReportBuilder, ReceiverReportInterceptor},
    sender::{SenderReportBuilder, SenderReportInterceptor},
};
pub use stream_info::{RTCPFeedback, RTPHeaderExtension, StreamInfo};
pub use twcc::{
    receiver::{TwccReceiverBuilder, TwccReceiverInterceptor},
    sender::{TwccSenderBuilder, TwccSenderInterceptor},
};

// Re-export derive macros for creating custom interceptors
// - `Interceptor` derive macro: marks a struct as an interceptor with #[next] field
// - `interceptor` attribute macro: generates Protocol and Interceptor trait implementations
pub use interceptor_derive::{Interceptor, interceptor};

/// RTP/RTCP Packet
///
/// An enum representing either an RTP or RTCP packet that can be processed
/// by interceptors in the chain.
#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    /// RTP (Real-time Transport Protocol) packet containing media data
    Rtp(rtp::Packet),
    /// RTCP (RTP Control Protocol) packets for feedback and statistics
    Rtcp(Vec<Box<dyn rtcp::Packet>>),
}

/// Tagged packet with transport metadata.
///
/// A [`TransportMessage`] wrapping a [`Packet`], which includes transport-level
/// context such as source/destination addresses and protocol information.
/// This is the primary message type passed through interceptor chains.
pub type TaggedPacket = TransportMessage<Packet>;

/// Trait for RTP/RTCP interceptors with fixed Protocol type parameters.
///
/// `Interceptor` is a marker trait that requires implementors to also implement
/// [`sansio::Protocol`] with specific fixed type parameters for RTP/RTCP processing:
/// - `Rin`, `Win`, `Rout`, `Wout` = [`TaggedPacket`]
/// - `Ein`, `Eout` = `()`
/// - `Time` = [`Instant`]
/// - `Error` = [`shared::error::Error`]
///
/// This trait adds stream binding methods and provides a [`with()`](Interceptor::with)
/// method for composable chaining of interceptors.
///
/// # Creating Custom Interceptors
///
/// ## Using Derive Macros (Recommended)
///
/// The easiest way to create a custom interceptor is using the derive macros:
///
/// ```ignore
/// use rtc_interceptor::{Interceptor, interceptor, TaggedPacket, Packet, StreamInfo};
/// use std::collections::VecDeque;
///
/// #[derive(Interceptor)]
/// pub struct MyInterceptor<P: Interceptor> {
///     #[next]
///     next: P,  // The next interceptor in the chain
///     buffer: VecDeque<TaggedPacket>,
/// }
///
/// #[interceptor]
/// impl<P: Interceptor> MyInterceptor<P> {
///     #[overrides]
///     fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
///         // Custom logic here
///         self.next.handle_read(msg)
///     }
/// }
/// ```
///
/// The `#[derive(Interceptor)]` macro requires a `#[next]` field that contains the
/// next interceptor in the chain. The `#[interceptor]` attribute on the impl block
/// generates the `Protocol` and `Interceptor` trait implementations, delegating
/// non-overridden methods to the next interceptor.
///
/// Use `#[overrides]` to mark methods with custom implementations.
///
/// ## Manual Implementation
///
/// For more control, you can implement the traits manually:
///
/// ```ignore
/// pub struct MyInterceptor<P> {
///     inner: P,
/// }
///
/// impl<P: Interceptor> Protocol<TaggedPacket, TaggedPacket, ()> for MyInterceptor<P> {
///     type Rout = TaggedPacket;
///     type Wout = TaggedPacket;
///     type Eout = ();
///     type Time = Instant;
///     type Error = shared::error::Error;
///     // ... implement Protocol methods
/// }
///
/// impl<P: Interceptor> Interceptor for MyInterceptor<P> {
///     fn bind_local_stream(&mut self, _info: &StreamInfo) {}
///     fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
///     fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
///     fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
/// }
/// ```
///
/// # Using with Registry
///
/// ```ignore
/// let chain = Registry::new()
///     .with(|inner| MyInterceptor { next: inner, buffer: VecDeque::new() });
/// ```
pub trait Interceptor:
    sansio::Protocol<
        TaggedPacket,
        TaggedPacket,
        (),
        Rout = TaggedPacket,
        Wout = TaggedPacket,
        Eout = (),
        Time = Instant,
        Error = shared::error::Error,
    > + Sized
{
    /// Wrap this interceptor with another layer.
    ///
    /// The wrapper function receives `self` and returns a new interceptor
    /// that wraps it.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::time::Duration;
    /// use rtc_interceptor::{NoopInterceptor, SenderReportBuilder};
    ///
    /// // Using the builder pattern (recommended)
    /// let chain = NoopInterceptor::new()
    ///     .with(SenderReportBuilder::new().with_interval(Duration::from_secs(1)).build());
    /// ```
    fn with<O, F>(self, f: F) -> O
    where
        F: FnOnce(Self) -> O,
        O: Interceptor,
    {
        f(self)
    }

    /// bind_local_stream lets you modify any outgoing RTP packets. It is called once for per LocalStream. The returned method
    /// will be called once per rtp packet.
    fn bind_local_stream(&mut self, info: &StreamInfo);

    /// unbind_local_stream is called when the Stream is removed. It can be used to clean up any data related to that track.
    fn unbind_local_stream(&mut self, info: &StreamInfo);

    /// bind_remote_stream lets you modify any incoming RTP packets. It is called once for per RemoteStream. The returned method
    /// will be called once per rtp packet.
    fn bind_remote_stream(&mut self, info: &StreamInfo);

    /// unbind_remote_stream is called when the Stream is removed. It can be used to clean up any data related to that track.
    fn unbind_remote_stream(&mut self, info: &StreamInfo);
}

#[cfg(test)]
mod derive_tests {
    use super::*;
    #[allow(unused_imports)]
    use shared::error::Error;

    /// Test interceptor that uses the derive macro.
    /// It should automatically delegate all Protocol and Interceptor methods to inner.
    #[derive(Interceptor)]
    pub struct SimplePassthrough<P: Interceptor> {
        #[next]
        inner: P,
    }

    // Empty impl block - #[interceptor] generates all delegations
    #[interceptor]
    impl<P: Interceptor> SimplePassthrough<P> {}

    impl<P: Interceptor> SimplePassthrough<P> {
        fn new(inner: P) -> Self {
            Self { inner }
        }
    }

    #[test]
    fn test_derive_interceptor_basic() {
        // Build a chain with the derived interceptor
        let mut chain = SimplePassthrough::new(NoopInterceptor::new());

        // Test that delegation works
        let pkt = TaggedPacket {
            now: std::time::Instant::now(),
            transport: Default::default(),
            message: Packet::Rtp(rtp::Packet::default()),
        };

        // handle_write should delegate to inner
        sansio::Protocol::handle_write(&mut chain, pkt).unwrap();

        // poll_write should return the packet from inner
        let result = sansio::Protocol::poll_write(&mut chain);
        assert!(result.is_some());
    }

    #[test]
    fn test_derive_interceptor_close() {
        let mut chain = SimplePassthrough::new(NoopInterceptor::new());

        // close should delegate to inner without error
        sansio::Protocol::close(&mut chain).unwrap();
    }

    #[test]
    fn test_derive_interceptor_stream_binding() {
        let mut chain = SimplePassthrough::new(NoopInterceptor::new());

        let info = StreamInfo {
            ssrc: 12345,
            ..Default::default()
        };

        // These should delegate to inner without panic
        chain.bind_local_stream(&info);
        chain.unbind_local_stream(&info);
        chain.bind_remote_stream(&info);
        chain.unbind_remote_stream(&info);
    }
}

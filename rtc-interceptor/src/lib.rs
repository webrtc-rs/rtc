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
//! ```
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
//! # Type-Erasing a Chain
//!
//! A chain's type spells out its whole composition
//! (`TwccReceiverInterceptor<SenderReportInterceptor<…>>`), and it propagates into every type
//! that holds the peer connection built from it. That is fine when the chain is fixed at compile
//! time, and a problem when it is chosen at runtime or has to live in your own structs.
//!
//! [`Interceptor`] is object safe, so [`Registry::boxed`] can erase the chain to
//! [`BoxedInterceptor`] — one concrete type, whatever it was built from:
//!
//! ```
//! use rtc_interceptor::{BoxedInterceptor, NackGeneratorBuilder, Registry, SenderReportBuilder};
//!
//! # let nack_enabled = true; // e.g. from configuration, negotiated SDP, …
//! // Two different chain types, unified by `.boxed()`.
//! let chain: BoxedInterceptor = if nack_enabled {
//!     Registry::new()
//!         .with(SenderReportBuilder::new().build())
//!         .with(NackGeneratorBuilder::new().build())
//!         .boxed()
//!         .build()
//! } else {
//!     Registry::new().with(SenderReportBuilder::new().build()).boxed().build()
//! };
//! ```
//!
//! The cost is one virtual call per chain entry point (`handle_read`, `poll_write`,
//! `handle_timeout`, …); the layers inside still call each other through static dispatch and
//! inline as before. `Box<P>` and `&mut P` both implement [`Interceptor`], so a boxed or borrowed
//! chain satisfies an `I: Interceptor` bound like any other.
//!
//! # Stream Binding
//!
//! Before interceptors can process packets for a stream, the stream must be bound:
//!
//! ```
//! use rtc_interceptor::{Interceptor, RTCPFeedback, RTPHeaderExtension, Registry, StreamInfo};
//!
//! let mut chain = Registry::new().build();
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
//! ```
//! use rtc_interceptor::{Interceptor, StreamInfo, TaggedPacket, interceptor};
//! use sansio::Protocol;
//! use shared::error::Error; // the generated `Protocol` impl names it
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
#![warn(missing_docs)]
#![allow(dead_code)]

use shared::TransportMessage;
use std::time::Instant;

mod noop;
mod registry;

pub(crate) mod flexfec;
pub(crate) mod intervalpli;
pub(crate) mod jitterbuffer;
pub(crate) mod nack;
pub(crate) mod report;
pub(crate) mod rfc8888;
pub(crate) mod rtpfb;
pub(crate) mod stream_info;
pub(crate) mod twcc;

pub use flexfec::bit_array::BitArray;
pub use flexfec::coverage::{MAX_FEC_PACKETS, MAX_MEDIA_PACKETS, ProtectionCoverage};
pub use flexfec::draft03::decoder::{FlexFec03Decoder, ParseError as FlexFecParseError};
pub use flexfec::draft03::encoder::FlexFec03Encoder;
pub use flexfec::draft03::receiver::{FlexFec03ReceiveBuilder, FlexFec03ReceiveInterceptor};
pub use flexfec::draft03::sender::{
    DEFAULT_NUM_FEC_PACKETS, DEFAULT_NUM_MEDIA_PACKETS, FlexFec03SendBuilder,
    FlexFec03SendInterceptor,
};
pub use intervalpli::generator::{
    DEFAULT_INTERVAL as INTERVAL_PLI_DEFAULT_INTERVAL, IntervalPliBuilder, IntervalPliInterceptor,
};
pub use jitterbuffer::buffer::{
    JitterBuffer, JitterBufferStats, Rejected, State as JitterBufferState,
};
pub use jitterbuffer::receiver::{
    DEFAULT_CAPACITY as JITTER_BUFFER_DEFAULT_CAPACITY,
    DEFAULT_DEPTH as JITTER_BUFFER_DEFAULT_DEPTH, JitterBufferBuilder, JitterBufferInterceptor,
};
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
pub use rfc8888::recorder::CcFeedbackRecorder;
pub use rfc8888::sender::{
    DEFAULT_INTERVAL as RFC8888_DEFAULT_INTERVAL,
    DEFAULT_MAX_REPORT_SIZE as RFC8888_DEFAULT_MAX_REPORT_SIZE, Rfc8888Builder, Rfc8888Interceptor,
};
pub use rtpfb::acknowledgement::{Acknowledgement, PacketReport, Report};
pub use rtpfb::convert::{convert_ccfb, convert_twcc};
pub use rtpfb::history::History;
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
#[non_exhaustive]
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
/// ```
/// use rtc_interceptor::{Interceptor, StreamInfo, TaggedPacket, interceptor};
/// use sansio::Protocol;
/// use shared::error::Error; // the generated `Protocol` impl names it
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
/// For more control, you can implement the traits manually. The sketch below omits the
/// `Protocol` method bodies, so it is not compiled — see [`NoopInterceptor`] for a complete
/// hand-written implementation:
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
/// A builder is just a closure from the next layer to the wrapping one, so a custom
/// interceptor can be added the same way as a built-in:
///
/// ```
/// use rtc_interceptor::{Registry, SenderReportBuilder};
///
/// let registry = Registry::new().with(SenderReportBuilder::new().build());
/// // ...or with a closure: `.with(|inner| MyInterceptor { next: inner, .. })`
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
    > + Send
    + Sync
{
    /// Wrap this interceptor with another layer.
    ///
    /// The wrapper function receives `self` and returns a new interceptor
    /// that wraps it.
    ///
    /// # Example
    ///
    /// ```
    /// use rtc_interceptor::{Interceptor, NoopInterceptor, SenderReportBuilder};
    /// use std::time::Duration;
    ///
    /// // `Interceptor` must be in scope for `with` to resolve.
    /// let chain = NoopInterceptor::new()
    ///     .with(SenderReportBuilder::new().with_interval(Duration::from_secs(1)).build());
    /// ```
    fn with<O, F>(self, f: F) -> O
    where
        Self: Sized,
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

/// A type-erased interceptor chain.
///
/// `Interceptor` is object safe, so a chain built at runtime can be erased into this one
/// concrete type. That lets an application store a `RTCPeerConnection<BoxedInterceptor>`
/// (see [`Registry::boxed`]) instead of being generic over the chain's type.
pub type BoxedInterceptor = Box<dyn Interceptor>;

impl<P: Interceptor + ?Sized> Interceptor for Box<P> {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        (**self).bind_local_stream(info)
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        (**self).unbind_local_stream(info)
    }

    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        (**self).bind_remote_stream(info)
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        (**self).unbind_remote_stream(info)
    }
}

/// Blanket implementation for mutable references.
///
/// This lets a borrowed chain satisfy an `Interceptor` bound, so a function taking
/// `I: Interceptor` by value can be called with `&mut chain` and leave ownership with the
/// caller. It mirrors [`sansio::Protocol`]'s own `&mut P` implementation, and the same idiom
/// in `std` (`impl Read for &mut R`, `impl Iterator for &mut I`).
///
/// This is only expressible because [`Interceptor`] does not require `'static`: `&'a mut P`
/// outlives only `'a`. See [`Registry::boxed`], which carries that bound locally instead.
impl<P: Interceptor + ?Sized> Interceptor for &mut P {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        (**self).bind_local_stream(info)
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        (**self).unbind_local_stream(info)
    }

    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        (**self).bind_remote_stream(info)
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        (**self).unbind_remote_stream(info)
    }
}

#[cfg(test)]
mod derive_test {
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

    /// Consumes an interceptor by value, as the `Registry`/`with` builders do.
    fn takes_by_value<I: Interceptor>(mut interceptor: I, info: &StreamInfo) {
        interceptor.bind_local_stream(info);
        interceptor.unbind_local_stream(info);
    }

    #[test]
    fn test_borrowed_chain_satisfies_interceptor_bound() {
        let mut chain = SimplePassthrough::new(NoopInterceptor::new());
        let info = StreamInfo {
            ssrc: 12345,
            ..Default::default()
        };

        // `&mut chain` satisfies a by-value `I: Interceptor` bound thanks to the blanket impl.
        takes_by_value(&mut chain, &info);

        // Ownership stayed with us, so the chain is still usable afterwards.
        takes_by_value(&mut chain, &info);
        chain.bind_remote_stream(&info);

        // The borrow also still drives the Protocol side.
        let pkt = TaggedPacket {
            now: std::time::Instant::now(),
            transport: Default::default(),
            message: Packet::Rtp(rtp::Packet::default()),
        };
        sansio::Protocol::handle_write(&mut chain, pkt).unwrap();
        assert!(sansio::Protocol::poll_write(&mut chain).is_some());
    }

    #[test]
    fn test_boxed_chain_still_satisfies_interceptor_bound() {
        // The `Box<P>` impl coexists with the new `&mut P` impl.
        let chain: BoxedInterceptor = Box::new(SimplePassthrough::new(NoopInterceptor::new()));
        let info = StreamInfo {
            ssrc: 999,
            ..Default::default()
        };
        takes_by_value(chain, &info);
    }
}

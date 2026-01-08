//! RTC Interceptor - Sans-IO interceptor framework for RTP/RTCP processing
//!
//! This crate provides a composable interceptor framework built on top of the
//! [`sansio::Protocol`] trait. Interceptors can process, modify, or generate
//! RTP/RTCP packets as they flow through the pipeline.
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

#![warn(rust_2018_idioms)]
#![allow(dead_code)]

use shared::TransportMessage;
use std::time::Instant;

mod noop;
mod registry;

pub(crate) mod report;
pub mod stream_info;

use crate::stream_info::StreamInfo;
pub use noop::NoopInterceptor;
pub use registry::Registry;
pub use report::{
    receiver_report::{ReceiverReportBuilder, ReceiverReportInterceptor},
    sender_report::{SenderReportBuilder, SenderReportInterceptor},
};

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
/// Each interceptor must explicitly implement both `Protocol` and `Interceptor` traits.
///
/// # Example
///
/// ```ignore
/// // Define a custom interceptor
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
///
/// // Use with the builder
/// let chain = Registry::new()
///     .with(MyInterceptor::new);
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

//! RTC Interceptor - Sans-IO interceptor framework for RTP/RTCP processing
//!
//! This crate provides a composable interceptor framework built on top of the
//! [`sansio::Protocol`] trait. Interceptors can process, modify, or generate
//! RTP/RTCP packets as they flow through the pipeline.
//!
//! # Design
//!
//! Each interceptor wraps an inner `Interceptor` and can:
//! - Process incoming/outgoing messages
//! - Transform message types
//! - Generate new messages (e.g., RTCP reports)
//! - Handle timeouts for periodic tasks
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
//! use rtc_interceptor::{Registry, Interceptor};
//!
//! let chain = Registry::new()
//!     .with(SenderReportInterceptor::new)
//!     .with(ReceiverReportInterceptor::new)
//!     .build();
//! ```

#![warn(rust_2018_idioms)]
#![allow(dead_code)]

use std::time::Instant;

mod noop;
mod registry;

mod report;
mod stream_info;

use crate::stream_info::StreamInfo;
pub use noop::NoopInterceptor;
pub use registry::Registry;
use shared::TransportMessage;

/// RTP/RTCP Packet
#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    Rtp(rtp::Packet),
    Rtcp(Vec<Box<dyn rtcp::Packet>>),
}

pub type TaggedPacket = TransportMessage<Packet>;

/// Interceptor extends [`Protocol`] with composable chaining via [`with()`](Interceptor::with).
///
/// This trait fixes the Protocol type parameters for RTP/RTCP interceptor chains:
/// - `Rin`, `Win`, `Rout`, `Wout` = [`TaggedPacket`]
/// - `Ein`, `Eout` = `()`
/// - `Time` = [`Instant`]
/// - `Error` = [`shared::error::Error`]
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
///     fn bind_local_stream(&self, _info: &StreamInfo) {}
///     fn unbind_local_stream(&self, _info: &StreamInfo) {}
///     fn bind_remote_stream(&self, _info: &StreamInfo) {}
///     fn unbind_remote_stream(&self, _info: &StreamInfo) {}
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
    /// let chain = NoopInterceptor::new()
    ///     .with(SenderReportInterceptor::new)
    ///     .with(ReceiverReportInterceptor::new);
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
    fn bind_local_stream(&self, info: &StreamInfo);

    /// unbind_local_stream is called when the Stream is removed. It can be used to clean up any data related to that track.
    fn unbind_local_stream(&self, info: &StreamInfo);

    /// bind_remote_stream lets you modify any incoming RTP packets. It is called once for per RemoteStream. The returned method
    /// will be called once per rtp packet.
    fn bind_remote_stream(&self, info: &StreamInfo);

    /// unbind_remote_stream is called when the Stream is removed. It can be used to clean up any data related to that track.
    fn unbind_remote_stream(&self, info: &StreamInfo);
}

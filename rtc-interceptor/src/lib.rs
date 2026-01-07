//! RTC Interceptor - Sans-IO interceptor framework for RTP/RTCP processing
//!
//! This crate provides a composable interceptor framework built on top of the
//! [`sansio::Protocol`] trait. Interceptors can process, modify, or generate
//! RTP/RTCP packets as they flow through the pipeline.
//!
//! # Design
//!
//! Each interceptor wraps an inner `Protocol` and can:
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

use sansio::Protocol;

mod noop;
mod registry;

//TODO: mod report;

pub use noop::NoopInterceptor;
pub use registry::Registry;

/// Interceptor extends [`Protocol`] for composable message processing.
///
/// Any type implementing `Protocol` can be used as an interceptor.
/// Chain interceptors by wrapping inner protocols.
///
/// # Example
///
/// ```ignore
/// // Define a custom interceptor
/// pub struct MyInterceptor<P> {
///     inner: P,
/// }
///
/// impl<P: Protocol<Msg, Msg, Evt>> Protocol<Msg, Msg, Evt> for MyInterceptor<P> {
///     // ... implement Protocol methods
/// }
///
/// // Use with the builder
/// let chain = Registry::new()
///     .with(MyInterceptor::new)
///     .build();
/// ```
pub trait Interceptor<Rin, Win, Ein>: Protocol<Rin, Win, Ein> + Sized {
    /// Wrap this interceptor with another layer.
    ///
    /// The wrapper function receives `self` and returns a new interceptor
    /// that wraps it.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let chain = NoopProtocol::new()
    ///     .wrap(SenderReportInterceptor::new)
    ///     .wrap(ReceiverReportInterceptor::new);
    /// ```
    fn wrap<O, F>(self, f: F) -> O
    where
        F: FnOnce(Self) -> O,
        O: Interceptor<Rin, Win, Ein>,
    {
        f(self)
    }
}

// Blanket impl: any Protocol + Sized is an Interceptor
impl<P, Rin, Win, Ein> Interceptor<Rin, Win, Ein> for P where P: Protocol<Rin, Win, Ein> + Sized {}

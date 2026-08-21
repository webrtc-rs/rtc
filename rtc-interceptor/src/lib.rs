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
//! ## Congestion control
//!
//! | Interceptor | Description |
//! |-------------|-------------|
//! | [`PacerInterceptor`] | Releases outgoing packets at a target rate rather than in bursts |
//! | [`Rfc8888Interceptor`] | Reports per-packet arrival times back to the sender (RFC 8888) |
//!
//! ## Utility
//!
//! | Interceptor | Description |
//! |-------------|-------------|
//! | [`NoopInterceptor`] | Ends the inbound RTCP path; the last interceptor in a chain |
//!
//! # Design
//!
//! A chain is a flat list of interceptors driven over a shared belt. Each one can:
//! - transform a packet passing through, or swallow it to drop or delay it
//! - emit packets it generated or was holding, which rejoin the belt and carry on
//! - act on timeouts, for periodic work like report generation
//! - track stream statistics and state
//!
//! All interceptors work with [`TaggedPacket`] — an RTP or RTCP packet with transport metadata,
//! carrying [`Attribute`]s that say what happened to it on the way. No interceptor holds a
//! reference to another; [`Registry`] assembles the list and walks it. [`Registry::build`] appends
//! [`NoopInterceptor`] last, so inbound RTCP stops before the application — control traffic the
//! interceptors act on is not media the caller asked for.
//!
//! # Direction
//!
//! A chain is a flat list ordered by **distance from the wire**: the first interceptor is closest to the
//! network, the last closest to the application. Direction is a property of the walk, not of the
//! structure:
//!
//! ```text
//! read   (network → application)   forward:  first → … → last
//! write  (application → network)   reverse:  last  → … → first
//! ```
//!
//! Each interceptor is fed from a shared belt and its output is collected back onto it, so **what a
//! interceptor emits is seen by every interceptor still ahead of it in the walk**. A retransmission emitted
//! mid-chain still gets paced, numbered and recorded, because there is no way out of the chain
//! except through the interceptors that follow.
//!
//! One list serves both directions, so "closest to the wire" means one thing rather than opposite
//! things per direction — which is why the send history and the FEC decoder sit next to each
//! other, one being the last thing on the way out and the other the first on the way in.
//!
//! # Quick Start
//!
//! ```
//! use rtc_interceptor::{
//!     NackGeneratorBuilder, NackResponderBuilder, ReceiverReportBuilder,
//!     Registry, SenderReportBuilder, TwccReceiverBuilder, TwccSenderBuilder,
//! };
//! use std::time::Duration;
//!
//! // Listed wire-to-application, which is the order they run in on the read path and the
//! // reverse of the order they run in on the write path.
//! let chain = Registry::new()
//!     .with(TwccSenderBuilder::new().build())
//!     .with(NackResponderBuilder::new().build())
//!     .with(NackGeneratorBuilder::new().build())
//!     .with(TwccReceiverBuilder::new().build())
//!     .with(ReceiverReportBuilder::new().build())
//!     .with(SenderReportBuilder::new().with_interval(Duration::from_secs(1)).build())
//!     .build();
//!
//! // `build` appends [`NoopInterceptor`] last, so inbound RTCP — control traffic the interceptors
//! // above act on — stops there rather than arriving mixed in with the application's media.
//! # let _ = chain;
//! ```
//!
//! # One chain type
//!
//! [`Registry::build`] returns a single concrete type whatever it was built from, so a struct can
//! hold one without a type parameter and two connections with different chains share a collection:
//!
//! ```
//! use rtc_interceptor::{NackGeneratorBuilder, Registry, SenderReportBuilder};
//!
//! # let nack_enabled = true; // e.g. from configuration, negotiated SDP, …
//! let chain = if nack_enabled {
//!     Registry::new().with(NackGeneratorBuilder::new().build()).build()
//! } else {
//!     Registry::new().with(SenderReportBuilder::new().build()).build()
//! };
//! ```
//!
//! The cost is one virtual call per interceptor per packet, which is nothing beside SRTP.
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
//! # Writing your own
//!
//! Implement [`sansio::Protocol`] and [`Interceptor`], then add it wherever it belongs in the
//! list. What `handle_*` takes in, `poll_*` gives back — so even a pass-through needs a queue,
//! because the queue is what the next interceptor is fed from:
//!
//! ```
//! use rtc_interceptor::{Interceptor, Registry, StreamInfo, TaggedPacket};
//! use sansio::Protocol;
//! use std::collections::VecDeque;
//! use std::time::Instant;
//!
//! /// Counts packets on their way out.
//! #[derive(Default)]
//! struct Counter {
//!     sent: u64,
//!     read_queue: VecDeque<TaggedPacket>,
//!     write_queue: VecDeque<TaggedPacket>,
//! }
//!
//! impl Protocol<TaggedPacket, TaggedPacket, ()> for Counter {
//!     type Rout = TaggedPacket;
//!     type Wout = TaggedPacket;
//!     type Eout = ();
//!     type Error = shared::error::Error;
//!     type Time = Instant;
//!
//!     fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
//!         self.read_queue.push_back(msg);
//!         Ok(())
//!     }
//!
//!     fn poll_read(&mut self) -> Option<Self::Rout> {
//!         self.read_queue.pop_front()
//!     }
//!
//!     fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
//!         self.sent += 1;
//!         self.write_queue.push_back(msg); // queueing nothing would swallow it
//!         Ok(())
//!     }
//!
//!     fn poll_write(&mut self) -> Option<Self::Wout> {
//!         self.write_queue.pop_front()
//!     }
//! }
//!
//! impl Interceptor for Counter {
//!     fn bind_local_stream(&mut self, _info: &StreamInfo) {}
//!     fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
//!     fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
//!     fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
//! }
//!
//! let chain = Registry::new().with(Counter::default()).build();
//! # let _ = chain;
//! ```
//!
//! Queue nothing to drop or delay a packet, and queue delayed or generated ones whenever they are
//! ready — from [`handle_timeout`](sansio::Protocol::handle_timeout), say. They leave through
//! `poll_*` and continue through every interceptor ahead.

#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

use std::time::Instant;

pub(crate) mod chain;
pub(crate) mod noop;
pub(crate) mod registry;

pub(crate) mod cc;
pub(crate) mod flexfec;
pub(crate) mod gcc;
pub(crate) mod intervalpli;
pub(crate) mod jitterbuffer;
pub(crate) mod nack;
pub(crate) mod pacing;
pub(crate) mod packet;
pub(crate) mod report;
pub(crate) mod rfc8888;
pub(crate) mod rtpfb;
pub(crate) mod stream_info;
pub(crate) mod twcc;

pub use cc::estimator::{BandwidthEstimator, ConstantBitrate, EstimatorStats};
pub use cc::interceptor::{
    CongestionControlBuilder, CongestionControlInterceptor,
    DEFAULT_PRUNE_HORIZON as CONGESTION_CONTROL_DEFAULT_PRUNE_HORIZON,
};
pub use flexfec::bit_array::BitArray;
pub use gcc::arrival_group::{
    ArrivalGroup, ArrivalGroupAccumulator, DEFAULT_BURST_INTERVAL as GCC_DEFAULT_BURST_INTERVAL,
    InterGroupDelay,
};
pub use gcc::kalman::Kalman;
pub use gcc::slope::{DelayTrend, SlopeEstimator};
pub use flexfec::coverage::{MAX_FEC_PACKETS, MAX_MEDIA_PACKETS, ProtectionCoverage};
pub use flexfec::draft03::decoder::{FlexFec03Decoder, ParseError as FlexFecParseError};
pub use flexfec::draft03::encoder::FlexFec03Encoder;
pub use flexfec::draft03::receiver::{FlexFec03ReceiveBuilder, FlexFec03ReceiveInterceptor};
pub use flexfec::draft03::sender::{
    DEFAULT_NUM_FEC_PACKETS, DEFAULT_NUM_MEDIA_PACKETS, FlexFec03SendBuilder,
    FlexFec03SendInterceptor,
};
pub use intervalpli::generator::{
    DEFAULT_INTERVAL as INTERVAL_PLI_DEFAULT_INTERVAL, IntervalPliInterceptor,
};
pub use jitterbuffer::buffer::{
    JitterBuffer, JitterBufferStats, Rejected, State as JitterBufferState,
};
pub use jitterbuffer::receiver::{
    DEFAULT_CAPACITY as JITTER_BUFFER_DEFAULT_CAPACITY,
    DEFAULT_DEPTH as JITTER_BUFFER_DEFAULT_DEPTH, JitterBufferBuilder, JitterBufferInterceptor,
};
pub use nack::generator::{NackGeneratorBuilder, NackGeneratorInterceptor};
pub use nack::responder::{NackResponderBuilder, NackResponderInterceptor};
pub use noop::NoopInterceptor;
pub use pacing::pacer::{MIN_BURST_BITS as PACER_MIN_BURST_BITS, Pacer};
pub use pacing::sender::{
    DEFAULT_BITRATE as PACER_DEFAULT_BITRATE, DEFAULT_QUEUE_LIMIT as PACER_DEFAULT_QUEUE_LIMIT,
    PacerBuilder, PacerInterceptor,
};
pub use packet::{Attribute, AttributedPacket, Packet, TaggedPacket};
pub use registry::Registry;
pub use report::receiver::{ReceiverReportBuilder, ReceiverReportInterceptor};
pub use report::sender::{SenderReportBuilder, SenderReportInterceptor};
pub use rfc8888::recorder::CcFeedbackRecorder;
pub use rfc8888::sender::{
    DEFAULT_INTERVAL as RFC8888_DEFAULT_INTERVAL,
    DEFAULT_MAX_REPORT_SIZE as RFC8888_DEFAULT_MAX_REPORT_SIZE, Rfc8888Builder, Rfc8888Interceptor,
};
pub use rtpfb::acknowledgement::{Acknowledgement, PacketReport, Report};
pub use rtpfb::convert::{convert_ccfb, convert_twcc};
pub use rtpfb::history::History;
pub use stream_info::{RTCPFeedback, RTPHeaderExtension, StreamInfo};
pub use twcc::receiver::{TwccReceiverBuilder, TwccReceiverInterceptor};
pub use twcc::sender::{TwccSenderBuilder, TwccSenderInterceptor};

/// One interceptor of packet processing.
///
/// An interceptor is a [`sansio::Protocol`] like everything else in this stack: packets arrive
/// through `handle_read`/`handle_write` and leave through `poll_read`/`poll_write`. What is
/// different is that nothing is wired to anything — an interceptor does not know what is on either
/// side of it. [`Registry`] builds a flat list and the chain it returns moves packets along it.
///
/// # The contract
///
/// **What `handle_*` takes in, `poll_*` gives back.** The chain hands you a packet, then asks what
/// you have ready; whatever you return is what the next interceptor receives. So an interceptor
/// that passes packets through still needs a queue — take the packet in `handle_read`, hand it
/// back from `poll_read`.
///
/// | To | Do |
/// |---|---|
/// | pass a packet through | queue it in `handle_*`, return it from `poll_*` |
/// | transform it | queue the modified packet |
/// | drop or delay it | queue nothing; a delayed one is queued later, from `handle_timeout` |
/// | generate one | queue it whenever you like; it joins the walk from `poll_*` |
/// | act on a timer | `handle_timeout`, and report the deadline from `poll_timeout` |
///
/// # What you emit continues
///
/// A packet returned from `poll_write` is handed to the next interceptor in the walk and passes
/// through every one still ahead of it. Nothing can bypass an interceptor by being generated past
/// it — which is the class of bug the previous, nested design allowed, and why a retransmission
/// used to escape the pacer, the transport-wide numbering and the send history.
///
/// The same is true in reverse: it also means **nothing reaches the wire or the application except
/// by passing through the interceptors that follow it**. An interceptor that keeps a packet to
/// itself keeps it from everything downstream, deliberately.
///
/// # Direction
///
/// Read walks the list forwards, write walks it in reverse, so one ordering serves both: the first
/// interceptor is closest to the network in both directions.
///
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

/// An interceptor whose concrete type has been erased.
///
/// `Interceptor` is object safe, which is what lets a chain be a flat list of these rather than a
/// tower of nested types. Name it when an application chooses an interceptor at runtime and hands
/// the result to [`Registry::with_boxed`].
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

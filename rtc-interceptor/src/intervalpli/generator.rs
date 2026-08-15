//! Periodic Picture Loss Indication for bound remote streams.

use super::stream_supports_pli;
use crate::stream_info::StreamInfo;
use crate::{Interceptor, Packet, TaggedPacket, interceptor};
use shared::TransportContext;
use shared::error::Error;
use std::collections::{BTreeSet, VecDeque};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

/// How often a keyframe is requested when no interval is configured.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(3);

/// Builder for [`IntervalPliInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{IntervalPliBuilder, Registry};
/// use std::time::Duration;
///
/// let chain = Registry::new()
///     .with(IntervalPliBuilder::new().with_interval(Duration::from_secs(1)).build())
///     .build();
/// ```
pub struct IntervalPliBuilder<P> {
    interval: Duration,
    _phantom: PhantomData<P>,
}

impl<P> Default for IntervalPliBuilder<P> {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            _phantom: PhantomData,
        }
    }
}

impl<P> IntervalPliBuilder<P> {
    /// Create a builder with the default interval.
    pub fn new() -> Self {
        Self::default()
    }

    /// How often each bound stream is asked for a keyframe.
    ///
    /// A zero interval disables periodic requests, leaving only
    /// [`force_pli`](IntervalPliInterceptor::force_pli) — matching upstream, which creates no
    /// ticker when its interval is not positive.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Build the interceptor factory function.
    pub fn build(self) -> impl FnOnce(P) -> IntervalPliInterceptor<P> {
        move |inner| IntervalPliInterceptor::new(inner, self.interval)
    }
}

/// Requests a keyframe from every bound remote stream on a fixed interval.
///
/// - Sans-I/O has no clock of its own: the interval is measured from the first `Instant`
///   the interceptor is handed, whether that arrives via `handle_read` or `handle_timeout`.
#[derive(Interceptor)]
pub struct IntervalPliInterceptor<P> {
    #[next]
    inner: P,
    interval: Duration,
    /// Bound remote streams that negotiated PLI. Ordered so a tick emits deterministically.
    streams: BTreeSet<u32>,
    /// Streams bound but not yet sent their first request.
    ///
    /// Upstream asks immediately on bind, which needs an instant this interceptor does not have
    /// until one is handed to it; these are flushed at the first opportunity.
    pending_immediate: BTreeSet<u32>,
    next_timeout: Option<Instant>,
    write_queue: VecDeque<TaggedPacket>,
}

impl<P> IntervalPliInterceptor<P> {
    fn new(inner: P, interval: Duration) -> Self {
        Self {
            inner,
            interval,
            streams: BTreeSet::new(),
            pending_immediate: BTreeSet::new(),
            next_timeout: None,
            write_queue: VecDeque::new(),
        }
    }

    /// Request a keyframe from every bound stream, now.
    ///
    /// # Why this takes an instant, and why it is not on the trait
    ///
    /// `Ein` is `()` for every interceptor, so there is no typed event to carry an out-of-band
    /// request through a chain — and widening the trait for one interceptor would break every
    /// other. So this is an inherent method, reachable while the concrete type is still in hand
    /// (before [`Registry::boxed`](crate::Registry::boxed) erases it). The instant is a parameter
    /// because a sans-I/O interceptor has no clock to ask.
    pub fn force_pli(&mut self, now: Instant) {
        let ssrcs: Vec<u32> = self.streams.iter().copied().collect();
        self.queue_plis(now, &ssrcs);
    }

    /// Request a keyframe from specific streams, now.
    ///
    /// SSRCs that are not bound are ignored: a PLI for a stream nobody is receiving has no
    /// destination.
    pub fn force_pli_for(&mut self, now: Instant, ssrcs: &[u32]) {
        let bound: Vec<u32> = ssrcs
            .iter()
            .copied()
            .filter(|ssrc| self.streams.contains(ssrc))
            .collect();
        self.queue_plis(now, &bound);
    }

    /// The streams currently being asked for keyframes.
    pub fn bound_streams(&self) -> impl Iterator<Item = u32> + '_ {
        self.streams.iter().copied()
    }

    /// Queue one RTCP packet carrying a PLI per SSRC.
    ///
    /// One compound packet rather than one datagram each, as upstream does: they are all going to
    /// the same peer at the same instant.
    fn queue_plis(&mut self, now: Instant, ssrcs: &[u32]) {
        if ssrcs.is_empty() {
            return;
        }

        let plis: Vec<Box<dyn rtcp::Packet>> = ssrcs
            .iter()
            .map(|&ssrc| {
                Box::new(
                    rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication {
                        sender_ssrc: 0,
                        media_ssrc: ssrc,
                    },
                ) as Box<dyn rtcp::Packet>
            })
            .collect();

        self.write_queue.push_back(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: Packet::Rtcp(plis),
        });
    }

    /// Arm the interval from the first instant this interceptor is handed, and send the first
    /// request for any stream bound since.
    fn observe(&mut self, now: Instant) {
        if !self.pending_immediate.is_empty() {
            let ssrcs: Vec<u32> = self.pending_immediate.iter().copied().collect();
            self.pending_immediate.clear();
            self.queue_plis(now, &ssrcs);
        }

        if self.next_timeout.is_none() && self.is_periodic() && !self.streams.is_empty() {
            self.next_timeout = Some(now + self.interval);
        }
    }

    fn is_periodic(&self) -> bool {
        !self.interval.is_zero()
    }
}

#[interceptor]
impl<P: Interceptor> IntervalPliInterceptor<P> {
    #[overrides]
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        if stream_supports_pli(info) {
            self.streams.insert(info.ssrc);
            self.pending_immediate.insert(info.ssrc);
        }
        self.inner.bind_remote_stream(info);
    }

    #[overrides]
    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
        self.pending_immediate.remove(&info.ssrc);
        if self.streams.is_empty() {
            // Nothing left to ask: stop asking to be woken (delivery rule 3).
            self.next_timeout = None;
        }
        self.inner.unbind_remote_stream(info);
    }

    #[overrides]
    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.observe(msg.now);
        self.inner.handle_read(msg)
    }

    #[overrides]
    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        self.observe(now);

        if let Some(next_timeout) = self.next_timeout
            && now >= next_timeout
        {
            self.next_timeout = Some(now + self.interval);
            let ssrcs: Vec<u32> = self.streams.iter().copied().collect();
            self.queue_plis(now, &ssrcs);
        }

        self.inner.handle_timeout(now)
    }

    #[overrides]
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        match (self.next_timeout, self.inner.poll_timeout()) {
            (Some(mine), Some(theirs)) => Some(mine.min(theirs)),
            (mine, theirs) => mine.or(theirs),
        }
    }

    #[overrides]
    fn poll_write(&mut self) -> Option<Self::Wout> {
        // A generated PLI is terminal (chain contract rule 1): it is complete when built, and
        // nothing below needs to transform it.
        if let Some(packet) = self.write_queue.pop_front() {
            return Some(packet);
        }
        self.inner.poll_write()
    }
}

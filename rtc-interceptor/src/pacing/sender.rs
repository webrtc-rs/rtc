//! Smooths outgoing packets to a target rate.

use super::pacer::Pacer;
use crate::stream_info::StreamInfo;
use crate::{Interceptor, Packet, TaggedPacket, interceptor};
use shared::error::Error;
use shared::marshal::MarshalSize;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::time::Instant;

/// Rate used when none is configured: 1 Mb/s.
pub const DEFAULT_BITRATE: f64 = 1_000_000.0;

/// Packets held before new ones are refused.
pub const DEFAULT_QUEUE_LIMIT: usize = 4096;

/// Builder for [`PacerInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{PacerBuilder, Registry};
///
/// let chain = Registry::new()
///     .with(PacerBuilder::new().with_target_bitrate(2_000_000.0).build())
///     .build();
/// ```
pub struct PacerBuilder<P> {
    bitrate: f64,
    burst_bits: Option<f64>,
    queue_limit: usize,
    _phantom: PhantomData<P>,
}

impl<P> Default for PacerBuilder<P> {
    fn default() -> Self {
        Self {
            bitrate: DEFAULT_BITRATE,
            burst_bits: None,
            queue_limit: DEFAULT_QUEUE_LIMIT,
            _phantom: PhantomData,
        }
    }
}

impl<P> PacerBuilder<P> {
    /// Create a builder with the default rate and queue limit.
    pub fn new() -> Self {
        Self::default()
    }

    /// The rate to pace at, in bits per second.
    pub fn with_target_bitrate(mut self, bits_per_second: f64) -> Self {
        self.bitrate = bits_per_second;
        self
    }

    /// How much may be released at once, in bits.
    ///
    /// Larger bursts smooth less but cost fewer wake-ups.
    pub fn with_burst_bits(mut self, burst_bits: f64) -> Self {
        self.burst_bits = Some(burst_bits);
        self
    }

    /// How many packets may be queued before new ones are refused.
    pub fn with_queue_limit(mut self, queue_limit: usize) -> Self {
        self.queue_limit = queue_limit;
        self
    }

    /// Build the interceptor factory function.
    pub fn build(self) -> impl FnOnce(P) -> PacerInterceptor<P> {
        move |inner| {
            let core = match self.burst_bits {
                Some(burst_bits) => Pacer::new(self.bitrate).with_burst_bits(burst_bits),
                None => Pacer::new(self.bitrate),
            };
            PacerInterceptor::new(inner, core, self.queue_limit)
        }
    }
}

/// Releases queued packets at a target rate rather than as fast as they arrive.
///
/// # Where this belongs in the chain
///
/// **Outermost on write.** Everything below must observe the *release* instant, so nothing that
/// timestamps or records a packet may sit above it — a send history above the pacer would record
/// the enqueue instant and charge this queueing delay to the network (chain contract rule 3).
///
/// # Differences from upstream
///
/// - **No ticker and no goroutine.** Upstream runs a loop on a 5 ms `time.Ticker`; here the
///   budget is a pure function of the instants handed in, so a release schedule is reproducible
///   rather than merely eventually-correct.
/// - **Idle means idle.** `poll_timeout` returns `None` with nothing queued, so an idle
///   connection does not wake the whole chain at the pacing interval.
/// - **The deadline is when the head can afford to go**, not `now + interval`, so it always
///   advances — a deadline at or before the `now` just handed to `handle_timeout` is the
///   webrtc#862 busy-loop.
#[derive(Interceptor)]
pub struct PacerInterceptor<P> {
    #[next]
    inner: P,
    pacer: Pacer,
    queue: VecDeque<TaggedPacket>,
    queue_limit: usize,
    /// Packets refused because the queue was full.
    dropped: u64,
}

impl<P> PacerInterceptor<P> {
    fn new(inner: P, pacer: Pacer, queue_limit: usize) -> Self {
        Self {
            inner,
            pacer,
            queue: VecDeque::new(),
            queue_limit: queue_limit.max(1),
            dropped: 0,
        }
    }

    /// The pacing bucket, for a bandwidth estimator to drive.
    pub fn pacer(&self) -> &Pacer {
        &self.pacer
    }

    /// The pacing bucket, mutably — this is where `set_target_bitrate` is reached.
    pub fn pacer_mut(&mut self) -> &mut Pacer {
        &mut self.pacer
    }

    /// How many packets are waiting to be released.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// How many packets have been refused because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The size of a packet on the wire, in bits — the unit the budget is kept in.
    fn bits_of(packet: &TaggedPacket) -> f64 {
        match &packet.message {
            Packet::Rtp(rtp) => (rtp.marshal_size() * 8) as f64,
            Packet::Rtcp(_) => 0.0,
        }
    }

    /// The instant the head of the queue can next be released.
    fn next_release(&self) -> Option<Instant> {
        let head = self.queue.front()?;
        self.pacer.releasable_at(Self::bits_of(head))
    }
}

#[interceptor]
impl<P: Interceptor> PacerInterceptor<P> {
    #[overrides]
    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // RTCP is control traffic and mostly time-sensitive — feedback is only useful while it is
        // fresh — so it is not paced.
        if matches!(msg.message, Packet::Rtcp(_)) {
            return self.inner.handle_write(msg);
        }

        // Keeping the budget current at enqueue time is what lets `poll_timeout` compute a
        // deadline that is never in the past, even before the first `handle_timeout`.
        self.pacer.refill(msg.now);

        if self.queue.len() >= self.queue_limit {
            // Refuse the arrival rather than evicting something already queued: the queued
            // packets are older, and dropping one of those would put a hole in the middle of a
            // stream that the receiver would have to recover from.
            self.dropped += 1;
            return Ok(());
        }

        self.queue.push_back(msg);
        Ok(())
    }

    #[overrides]
    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        self.pacer.refill(now);

        while let Some(head) = self.queue.front() {
            let bits = Self::bits_of(head);
            if !self.pacer.can_release(bits) {
                break;
            }

            let mut packet = self.queue.pop_front().expect("front just checked");
            self.pacer.consume(bits);
            // Rule 3: the packet departs now. Anything below recording departure — the send
            // history congestion control reads — must see the release instant, not the enqueue
            // instant, or this queueing delay is charged to the network.
            packet.now = now;
            // Rule 2: re-injected through `inner`, so it traverses every outbound layer below
            // exactly as an unpaced packet would.
            self.inner.handle_write(packet)?;
        }

        self.inner.handle_timeout(now)
    }

    #[overrides]
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        match (self.next_release(), self.inner.poll_timeout()) {
            (Some(mine), Some(theirs)) => Some(mine.min(theirs)),
            (mine, theirs) => mine.or(theirs),
        }
    }
}

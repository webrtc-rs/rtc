//! Smooths outgoing packets to a target rate.

use super::pacer::Pacer as LeakyBucket;
use crate::Interceptor;
use crate::StreamInfo;
use crate::{Attribute, Packet, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use shared::marshal::MarshalSize;
use std::collections::VecDeque;
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
pub struct PacerBuilder {
    bitrate: f64,
    burst_bits: Option<f64>,
    queue_limit: usize,
}

impl Default for PacerBuilder {
    fn default() -> Self {
        Self {
            bitrate: DEFAULT_BITRATE,
            burst_bits: None,
            queue_limit: DEFAULT_QUEUE_LIMIT,
        }
    }
}

impl PacerBuilder {
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

    /// Build the interceptor.
    pub fn build(self) -> PacerInterceptor {
        let bucket = match self.burst_bits {
            Some(burst_bits) => LeakyBucket::new(self.bitrate).with_burst_bits(burst_bits),
            None => LeakyBucket::new(self.bitrate),
        };
        PacerInterceptor::new(bucket, self.queue_limit)
    }
}

/// Releases queued packets at a target rate rather than as fast as they arrive.
///
/// # Where this belongs in the chain
///
/// **Close to the wire, with every generator on the application side of it.** Everything after it
/// on the write path observes the *release* instant, so a send history goes there and records what
/// actually left; placed the other way round it would record the enqueue instant and charge this
/// queueing delay to the network.
///
/// Retransmissions, FEC repair packets and generated RTCP are all produced further out and reach
/// the pacer on the belt, so they are metered along with everything else. Under the nested chain
/// they bypassed it entirely.
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
pub struct PacerInterceptor {
    pacer: LeakyBucket,
    queue: VecDeque<TaggedPacket>,
    queue_limit: usize,
    /// Packets refused because the queue was full.
    dropped: u64,
    /// Packets the budget has released, waiting to join the belt.
    released: VecDeque<TaggedPacket>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
    /// Outbound packets ready for the next interceptor: what passed through, plus
    /// anything this one generated.
    write_queue: VecDeque<TaggedPacket>,
}

impl PacerInterceptor {
    fn new(pacer: LeakyBucket, queue_limit: usize) -> Self {
        Self {
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
            released: VecDeque::new(),
            pacer,
            queue: VecDeque::new(),
            queue_limit: queue_limit.max(1),
            dropped: 0,
        }
    }

    /// The pacing bucket, for a bandwidth estimator to drive.
    pub fn pacer(&self) -> &LeakyBucket {
        &self.pacer
    }

    /// The pacing bucket, mutably — this is where `set_target_bitrate` is reached.
    pub fn pacer_mut(&mut self) -> &mut LeakyBucket {
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
        match &packet.message.packet {
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

impl Protocol<TaggedPacket, TaggedPacket, ()> for PacerInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // Follow the congestion controller's estimate. It rides on an outgoing packet because
        // the controller is application-ward of the pacer and nothing else connects the two;
        // observed rather than consumed, so whatever picks the encoder bitrate reads the same
        // number from the same packet.
        if let Some(Attribute::TargetBitrateChanged { bits_per_second }) =
            msg.message.get(&Attribute::TargetBitrateChanged {
                bits_per_second: 0.0,
            })
        {
            self.pacer.set_target_bitrate(*bits_per_second);
        }

        // RTCP is control traffic and mostly time-sensitive — feedback is only useful while it is
        // fresh — so it is not paced.
        if matches!(msg.message.packet, Packet::Rtcp(_)) {
            self.write_queue.push_back(msg);
            return Ok(());
        }

        // Keeping the budget current at enqueue time is what lets `poll_timeout` compute a
        // deadline that is never in the past, even before the first `handle_timeout`.
        self.pacer.refill(msg.now);

        if self.queue.len() >= self.queue_limit {
            // Refuse the arrival rather than evicting something already queued: the queued
            // packets are older, and dropping one of those would put a hole in the middle of a
            // stream that the receiver would have to recover from.
            self.dropped += 1;
            // Refused, so it never leaves.
            return Ok(());
        }

        // Held: it leaves later, from `poll_write`, when the budget allows.
        self.queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        // Unpaced traffic goes first — RTCP is only useful while it is fresh, and holding it
        // behind the budget would be pacing it after all.
        self.write_queue
            .pop_front()
            .or_else(|| self.released.pop_front())
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
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
            // Queued for `poll_write`, which puts it back on the belt so it traverses every
            // interceptor ahead — numbering, and the send history reading the release instant just set.
            self.released.push_back(packet);
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.next_release()
    }
}

impl Interceptor for PacerInterceptor {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

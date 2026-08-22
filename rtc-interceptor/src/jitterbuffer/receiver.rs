//! Receive-side jitter buffer interceptor: a time-based playout policy over [`JitterBufferInterceptor`].
//!
//! # Why this does not follow upstream
//!
//! `pion/interceptor`'s `ReceiverInterceptor` buffers a *packet count* and is pull-driven: its
//! `BindRemoteStream` reader pushes the packet it just read and immediately pops one back, so the
//! buffer is a fixed-length delay line of 50 packets rather than a span of time. webrtc#846 asks
//! for the other thing — a depth measured in milliseconds, drained on a timer — because what a
//! jitter buffer has to absorb is variation in *arrival time*, and a packet count only stands in
//! for that while the bitrate is constant.
//!
//! The differences that follow from that:
//!
//! | | upstream | here |
//! |---|---|---|
//! | depth | 50 packets | a [`Duration`] |
//! | emission | inside the read path, one in one out | on `handle_timeout`, everything now due |
//! | not ready yet | `ErrPopWhileBuffering` | `poll_read` simply yields nothing |
//! | per stream | one buffer for all of them | one per SSRC |
//! | unbind | clears every stream's packets | drops only that stream |

use super::buffer::{JitterBuffer as Buffer, Rejected, State};
use super::sequence::TimestampExtender;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Packet, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Default playout depth: enough to absorb ordinary network jitter without adding audible delay.
pub const DEFAULT_DEPTH: Duration = Duration::from_millis(120);

/// Default cap on packets held per stream, so a stalled or hostile stream cannot grow without
/// bound while its deadline is still in the future.
pub const DEFAULT_CAPACITY: usize = 512;

/// A timestamp jump this large is read as a stream restart rather than a gap to wait out.
///
/// Ten seconds of media: far beyond any real inter-packet spacing, and small enough that a genuine
/// restart is noticed promptly.
const DISCONTINUITY: Duration = Duration::from_secs(10);

/// Builder for [`JitterBufferInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, JitterBufferBuilder, Registry};
/// use std::time::Duration;
///
/// let chain = Registry::new()
///     .with(Slot::JitterBuffer, JitterBufferBuilder::new().with_depth(Duration::from_millis(80)).build())
///     .build();
/// ```
pub struct JitterBufferBuilder {
    depth: Duration,
    capacity: usize,
}

impl Default for JitterBufferBuilder {
    fn default() -> Self {
        Self {
            depth: DEFAULT_DEPTH,
            capacity: DEFAULT_CAPACITY,
        }
    }
}

impl JitterBufferBuilder {
    /// Create a builder with the default depth and capacity.
    pub fn new() -> Self {
        Self::default()
    }

    /// How long a packet is held to absorb arrival-time variation.
    ///
    /// # Its relationship with NACK
    ///
    /// This is the delay the buffer adds, and it is also the window in which a retransmission is
    /// still useful. A lost packet cannot come back before
    ///
    /// ```text
    ///     detection (up to one NACK interval) + round trip + the sender's response
    /// ```
    ///
    /// has elapsed, and the buffer plays a position out one depth after that position is due. So
    /// **a depth shallower than that sum means every retransmission arrives too late** — its slot
    /// has already been played past, so it is dropped rather than emitted out of order, and the
    /// NACK traffic was spent for nothing.
    ///
    /// The two are deliberately not coupled: a mechanism for the jitter buffer and the NACK
    /// generator to negotiate would tie together interceptors that are otherwise independent, and
    /// an application that configures both can honour the inequality itself.
    /// `tests/jitter_buffer_nack_depth.rs` holds it to that — the same loss recovered under a
    /// depth chosen to accommodate it and lost under one chosen not to.
    pub fn with_depth(mut self, depth: Duration) -> Self {
        self.depth = depth;
        self
    }

    /// Maximum packets held per stream, independently of the time depth.
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> JitterBufferInterceptor {
        JitterBufferInterceptor::new(self.depth, self.capacity)
    }
}

/// Where a stream's RTP timeline was pinned to the wall clock.
///
/// Playout instants are derived from this: a packet's deadline is the anchor's arrival instant
/// plus the depth, plus however far the packet's RTP timestamp is beyond the anchor's. Anchoring
/// on the first packet, rather than waiting for the buffered span to reach the full depth, is what
/// lets a single-packet or paused stream start at all.
#[derive(Debug, Clone, Copy)]
struct Anchor {
    arrived: Instant,
    timestamp: u64,
}

/// Everything tracked for one remote stream.
struct Stream {
    buffer: Buffer,
    timestamps: TimestampExtender,
    /// RTP timestamp units per second, from the negotiated codec.
    clock_rate: u32,
    anchor: Option<Anchor>,
    /// Playout instant per held packet, keyed by extended sequence number.
    deadlines: HashMap<u64, Instant>,
}

impl Stream {
    fn new(clock_rate: u32, capacity: usize) -> Self {
        Self {
            buffer: Buffer::new(capacity),
            timestamps: TimestampExtender::new(),
            // A zero clock rate would make every deadline a division by zero; treat an
            // unnegotiated rate as the RTP video default rather than refusing to buffer.
            clock_rate: if clock_rate == 0 { 90_000 } else { clock_rate },
            anchor: None,
            deadlines: HashMap::new(),
        }
    }

    /// How far `timestamp` is beyond the anchor, in wall-clock terms.
    fn offset_from_anchor(&self, anchor: &Anchor, timestamp: u64) -> Duration {
        let ticks = timestamp.saturating_sub(anchor.timestamp);
        Duration::from_secs_f64(ticks as f64 / f64::from(self.clock_rate))
    }

    /// Start the timeline again at this packet, dropping what was held *and* the ordering state.
    ///
    /// Only for a timestamp discontinuity: the old anchor no longer describes where this stream is
    /// in time, and deriving deadlines from it would put every subsequent packet either
    /// immediately overdue or hours away. Resetting the buffer also clears its extended-sequence
    /// origin, which is why running dry must not come through here — a fresh origin measured
    /// against a stale played-out watermark would reject everything.
    fn restart(&mut self, arrived: Instant, timestamp: u64) {
        self.buffer.reset();
        self.deadlines.clear();
        self.anchor = Some(Anchor { arrived, timestamp });
    }
}

/// Holds each stream's packets for a fixed span of time, then releases them in order.
///
/// The `jitterbuffer::receiver` module documentation covers how this differs from upstream.
pub struct JitterBufferInterceptor {
    depth: Duration,
    capacity: usize,
    streams: HashMap<u32, Stream>,
    /// Packets whose playout instant has come, waiting to join the belt.
    due: VecDeque<TaggedPacket>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
    /// Outbound packets ready for the next interceptor: what passed through, plus
    /// anything this one generated.
    write_queue: VecDeque<TaggedPacket>,
}

impl JitterBufferInterceptor {
    fn new(depth: Duration, capacity: usize) -> Self {
        Self {
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
            due: VecDeque::new(),
            depth,
            capacity,
            streams: HashMap::new(),
        }
    }

    /// The playout instant of the packet nearest release on `stream`.
    fn next_deadline(stream: &Stream) -> Option<Instant> {
        let front = stream.buffer.front_sequence()?;
        stream.deadlines.get(&front).copied()
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for JitterBufferInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let Packet::Rtp(rtp) = &msg.message.packet else {
            // RTCP has no sequence number to order by and no playout deadline; it must not be
            // delayed behind media either, since feedback is only useful while it is fresh.
            self.read_queue.push_back(msg);
            return Ok(());
        };

        let ssrc = rtp.header.ssrc;
        let timestamp = rtp.header.timestamp;
        let arrived = msg.now;

        let Some(stream) = self.streams.get_mut(&ssrc) else {
            // Not a stream we were told about: pass it straight through rather than buffering
            // packets nobody will ever come to collect.
            self.read_queue.push_back(msg);
            return Ok(());
        };

        let extended_timestamp = stream.timestamps.extend(timestamp);

        // Anchor the timeline on the first packet, or re-anchor across a discontinuity.
        //
        // Re-anchoring is not the same as restarting: a stream that merely ran dry keeps its
        // ordering state, because `released_through` is what stops a straggler from the previous
        // run being emitted behind packets that already left. Only a discontinuity — where the
        // timeline genuinely no longer relates to the old one — wipes it.
        match stream.anchor {
            None => {
                stream.anchor = Some(Anchor {
                    arrived,
                    timestamp: extended_timestamp,
                })
            }
            Some(anchor) => {
                let ticks = extended_timestamp.abs_diff(anchor.timestamp);
                let elapsed = Duration::from_secs_f64(ticks as f64 / f64::from(stream.clock_rate));
                if elapsed > DISCONTINUITY {
                    stream.restart(arrived, extended_timestamp);
                }
            }
        }

        let anchor = stream.anchor.expect("just anchored");
        let deadline =
            anchor.arrived + self.depth + stream.offset_from_anchor(&anchor, extended_timestamp);

        match stream.buffer.push(msg) {
            Ok(extended) => {
                stream.deadlines.insert(extended, deadline);
                // Held: it leaves later, from `poll_read`, at its playout instant.
                Ok(())
            }
            // Dropped on purpose — a duplicate, a straggler past its position, a foreign SSRC, or
            // the capacity cap. None of these may be forwarded: doing so would emit a packet twice
            // or out of order, which is exactly what this interceptor exists to prevent.
            Err(
                Rejected::Duplicate | Rejected::Late | Rejected::Overflow | Rejected::ForeignSsrc,
            ) => Ok(()),
        }
    }

    fn poll_read(&mut self) -> Option<TaggedPacket> {
        // What passed straight through goes first: RTCP must not wait behind buffered media.
        self.read_queue.pop_front().or_else(|| self.due.pop_front())
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        // Collected first so the borrow of `self.streams` ends before the queue is extended.
        let mut due: Vec<TaggedPacket> = Vec::new();

        for stream in self.streams.values_mut() {
            // The first packet's deadline is what starts playout; before that the stream is still
            // filling, and `pop` yields nothing.
            if stream.buffer.state() == State::Buffering
                && Self::next_deadline(stream).is_some_and(|deadline| deadline <= now)
            {
                stream.buffer.begin_emitting();
            }

            while let Some(front) = stream.buffer.front_sequence() {
                let Some(&deadline) = stream.deadlines.get(&front) else {
                    break;
                };
                if deadline > now {
                    break;
                }
                let Some(mut packet) = stream.buffer.pop() else {
                    break;
                };
                stream.deadlines.remove(&front);
                // Rule 3 of the chain contract: the packet carries the instant it was released,
                // not the instant it arrived, so nothing downstream counts this buffer's own
                // holding time as network delay.
                packet.now = now;
                due.push(packet);
            }

            // Run dry: fill again before playout resumes, so the next packet is not emitted the
            // moment it lands with no cushion behind it.
            if stream.buffer.is_empty() && stream.buffer.state() == State::Emitting {
                stream.buffer.begin_buffering();
                // Timeline anchor only: ordering state survives, so a straggler from the run that
                // just ended is still rejected rather than emitted out of order.
                stream.anchor = None;
            }
        }

        // Queued for `poll_read`, which puts them back on the belt, so a released packet
        // traverses every interceptor ahead of this one exactly as a live one would. The nested design
        // did this by re-injecting through `inner` by hand.
        self.due.extend(due);
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.streams.values().filter_map(Self::next_deadline).min()
    }
}

impl Interceptor for JitterBufferInterceptor {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        // Keyed by SSRC, unlike upstream, whose single buffer interleaves every remote stream
        // into one sequence-number ordering.
        self.streams
            .entry(info.ssrc)
            .or_insert_with(|| Stream::new(info.clock_rate, self.capacity));
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        // Only this stream. Upstream's `UnbindRemoteStream` clears the shared buffer, discarding
        // every other stream's packets along with it.
        self.streams.remove(&info.ssrc);
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}

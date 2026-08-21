//! A deterministic network path, for driving a congestion controller end to end (CC-TEST-01).
//!
//! # Why this exists before any algorithm
//!
//! A bandwidth estimator is a feedback loop, and its parts can each be correct while the loop does
//! not converge. Unit-testing a kalman filter against upstream's vectors proves the filter; it does
//! not prove that the thing built out of it settles on a sensible rate, backs off when a queue
//! builds, or recovers afterwards. Only a closed loop shows that, and writing the algorithm first
//! and the harness afterwards is how a plausible-looking estimator that never converges gets
//! merged.
//!
//! # Determinism
//!
//! There is no clock and no randomness that is not seeded. Every instant is handed in, loss is
//! decided by a counter rather than a coin, and the queue is drained by arithmetic on those
//! instants. The same schedule therefore produces byte-identical [`PacketReport`]s across runs,
//! which is what makes a bitrate *trajectory* assertable rather than merely an eventual outcome.
//!
//! # What it is not
//!
//! Not a network. There is no reordering, no jitter beyond what the queue produces, and one
//! direction only — feedback is generated from what arrived rather than being carried back over a
//! second simulated path. Those are all things a real path does; none of them is what the four
//! fixtures below are for.

#![allow(dead_code)]

use rtc_interceptor::{AttributedPacket, Packet, TaggedPacket};
use shared::TransportContext;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How a path behaves. Fixtures below name the four shapes the plan calls for.
#[derive(Debug, Clone, Copy)]
pub struct PathProfile {
    /// One-way propagation delay, before any queueing.
    pub propagation: Duration,
    /// What the bottleneck can drain, in bits per second.
    pub capacity_bits_per_second: f64,
    /// How much the bottleneck can hold before it drops, in bits.
    pub queue_capacity_bits: f64,
    /// Drop one packet in this many, independent of the queue. `None` for a lossless path.
    ///
    /// A counter rather than a probability: a seeded RNG would be reproducible too, but this is
    /// reproducible *and* legible — "one in twenty" is a property a test can state.
    pub drop_one_in: Option<u32>,
}

impl PathProfile {
    /// Plenty of capacity, no loss: the estimator should settle and stay there.
    pub fn steady() -> Self {
        Self {
            propagation: Duration::from_millis(20),
            capacity_bits_per_second: 3_000_000.0,
            queue_capacity_bits: 3_000_000.0,
            drop_one_in: None,
        }
    }

    /// Capacity below what a sender at 1.2 Mb/s offers, with room to queue: **delay grows, nothing
    /// is lost**. This is what a delay-based estimator exists to notice, and it must notice it
    /// before the queue overflows and turns into loss.
    pub fn queue_building() -> Self {
        Self {
            propagation: Duration::from_millis(20),
            capacity_bits_per_second: 600_000.0,
            queue_capacity_bits: 6_000_000.0,
            drop_one_in: None,
        }
    }

    /// Ample capacity but a lossy link: **loss without queueing**, the wireless shape.
    ///
    /// pion's loss controller cannot move the target on its own here — its `latestBitrate` is only
    /// written from a delay update — so this fixture is what D4's deliberate divergence is tested
    /// against.
    pub fn lossy_without_queueing() -> Self {
        Self {
            propagation: Duration::from_millis(20),
            capacity_bits_per_second: 3_000_000.0,
            queue_capacity_bits: 3_000_000.0,
            drop_one_in: Some(20),
        }
    }

    /// A narrow path that widens: the estimator must climb back rather than stay where the
    /// congestion left it.
    pub fn recovering() -> Self {
        Self::queue_building()
    }

    /// The capacity this path has at `elapsed` since the run began.
    ///
    /// Constant except for [`recovering`](Self::recovering), which triples after two seconds.
    fn capacity_at(&self, elapsed: Duration, widens_after: Option<Duration>) -> f64 {
        match widens_after {
            Some(after) if elapsed >= after => self.capacity_bits_per_second * 5.0,
            _ => self.capacity_bits_per_second,
        }
    }
}

/// One packet in flight, with the instant it will reach the far end.
#[derive(Debug, Clone, Copy)]
struct InFlight {
    /// Transport-wide sequence number, as the TWCC sender assigned it.
    twcc_sequence_number: u16,
    arrival: Instant,
}

/// What the far end observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arrival {
    pub twcc_sequence_number: u16,
    /// `None` if the path dropped it.
    pub at: Option<Instant>,
}

/// A one-way bottleneck: propagation, a drain rate, a finite queue, and optional loss.
pub struct Path {
    profile: PathProfile,
    widens_after: Option<Duration>,
    epoch: Instant,
    /// Bits currently occupying the bottleneck queue.
    queued_bits: f64,
    /// When the bottleneck finishes draining what it already holds.
    drains_at: Instant,
    in_flight: VecDeque<InFlight>,
    /// Counts offered packets, so `drop_one_in` is a deterministic choice.
    offered: u32,
    arrived: Vec<Arrival>,
}

impl Path {
    pub fn new(profile: PathProfile, epoch: Instant) -> Self {
        Self {
            profile,
            widens_after: None,
            epoch,
            queued_bits: 0.0,
            drains_at: epoch,
            in_flight: VecDeque::new(),
            offered: 0,
            arrived: Vec::new(),
        }
    }

    /// A path that widens fivefold after `after`, for the recovery fixture.
    pub fn widening_after(mut self, after: Duration) -> Self {
        self.widens_after = Some(after);
        self
    }

    /// Offer a packet to the path at `now`. Returns whether the path accepted it.
    ///
    /// Refused when the bottleneck queue is full — which is what congestion looks like once delay
    /// has stopped being enough of a signal.
    pub fn offer(&mut self, now: Instant, twcc_sequence_number: u16, size_bits: f64) -> bool {
        self.drain_to(now);
        self.offered += 1;

        if let Some(one_in) = self.profile.drop_one_in
            && self.offered.is_multiple_of(one_in)
        {
            self.arrived.push(Arrival {
                twcc_sequence_number,
                at: None,
            });
            return false;
        }

        if self.queued_bits + size_bits > self.profile.queue_capacity_bits {
            self.arrived.push(Arrival {
                twcc_sequence_number,
                at: None,
            });
            return false;
        }

        let capacity = self
            .profile
            .capacity_at(now.saturating_duration_since(self.epoch), self.widens_after);
        let service = Duration::from_secs_f64(size_bits / capacity);

        // The bottleneck serves one packet at a time: this one leaves when everything ahead of it
        // has, which is where queueing delay comes from.
        let departs = self.drains_at.max(now) + service;
        self.drains_at = departs;
        self.queued_bits += size_bits;

        self.in_flight.push_back(InFlight {
            twcc_sequence_number,
            arrival: departs + self.profile.propagation,
        });
        true
    }

    /// Advance to `now`, moving anything that has arrived out of flight.
    pub fn drain_to(&mut self, now: Instant) {
        while let Some(head) = self.in_flight.front().copied() {
            if head.arrival > now {
                break;
            }
            self.in_flight.pop_front();
            self.arrived.push(Arrival {
                twcc_sequence_number: head.twcc_sequence_number,
                at: Some(head.arrival),
            });
        }

        // The queue is only as full as what has not yet been served.
        if now >= self.drains_at {
            self.queued_bits = 0.0;
        }
    }

    /// Everything the far end has observed since the last call, in the order it observed it.
    pub fn take_arrivals(&mut self) -> Vec<Arrival> {
        std::mem::take(&mut self.arrived)
    }

    /// The one-way delay the most recent arrival experienced, over the bare propagation time.
    ///
    /// This is the signal a delay-based estimator is looking for: on a steady path it stays at
    /// zero, and on a queue-building one it climbs.
    pub fn queueing_delay(&self, sent_at: Instant, arrived_at: Instant) -> Duration {
        arrived_at
            .saturating_duration_since(sent_at)
            .saturating_sub(self.profile.propagation)
    }
}

/// TWCC feedback describing `arrivals`, as the far end would send it.
///
/// Arrival times are quantised to TWCC's 250 µs delta resolution, which is what a real report can
/// express — an estimator that only converges on unquantised times would be lying to itself.
pub fn twcc_feedback_for(
    now: Instant,
    epoch: Instant,
    media_ssrc: u32,
    arrivals: &[Arrival],
) -> Option<TaggedPacket> {
    use rtcp::transport_feedbacks::transport_layer_cc::{
        PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
        TransportLayerCc,
    };

    let base = arrivals.first()?.twcc_sequence_number;

    let mut packet_chunks = Vec::new();
    let mut recv_deltas = Vec::new();
    let mut previous: Option<Instant> = None;

    for arrival in arrivals {
        let symbol = match arrival.at {
            Some(at) => {
                let since = previous.map_or_else(
                    || at.saturating_duration_since(epoch),
                    |last| at.saturating_duration_since(last),
                );
                previous = Some(at);
                // 250 µs ticks, the small-delta resolution.
                let ticks = (since.as_micros() / 250).min(255) as u16;
                recv_deltas.push(RecvDelta {
                    type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                    delta: i64::from(ticks) * 250,
                });
                SymbolTypeTcc::PacketReceivedSmallDelta
            }
            None => SymbolTypeTcc::PacketNotReceived,
        };

        // One run-length chunk per packet: verbose on the wire, unambiguous in a test.
        packet_chunks.push(PacketStatusChunk::RunLengthChunk(RunLengthChunk {
            type_tcc: StatusChunkTypeTcc::RunLengthChunk,
            packet_status_symbol: symbol,
            run_length: 1,
        }));
    }

    let feedback = TransportLayerCc {
        sender_ssrc: 0,
        media_ssrc,
        base_sequence_number: base,
        packet_status_count: arrivals.len() as u16,
        reference_time: (now.saturating_duration_since(epoch).as_millis() / 64) as u32,
        fb_pkt_count: 0,
        packet_chunks,
        recv_deltas,
    };

    Some(TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(feedback)])),
    })
}

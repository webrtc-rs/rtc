//! End-to-end benchmarks for the `rtc` workspace, and the harness they share.
//!
//! Every protocol crate benchmarks its own codecs and ciphers under `rtc-*/benches`. None of them
//! can measure the stack assembled: ICE, DTLS, SCTP, SRTP and the interceptor chain running
//! together inside an [`RTCPeerConnection`](rtc::peer_connection::RTCPeerConnection). This crate
//! fills that gap in two parts:
//!
//! * this library: [`PeerPair`], two peer connections joined by an in-memory wire and driven by a
//!   virtual clock, plus the [`providers`] and [`fixtures`] the benchmarks share;
//! * `benches/`: criterion targets built on it (`peer_connection`, `data_channel`, `media`), and
//!   an allocation report (`allocations`).
//!
//! See `docs/benchmarking.md` at the workspace root for how this fits with the rest of the suite.
//!
//! # In-memory wire, virtual clock
//!
//! The peer connection is sans-I/O: it never opens a socket and never reads the clock. That makes
//! it possible to benchmark it without either, and doing so matters:
//!
//! * Loopback sockets would add syscalls and scheduler wake-ups that are not `rtc`'s cost, and
//!   whose variance would swamp a few-microsecond change in the packet path.
//! * Sleeping to reach a timer would stretch a handshake that costs milliseconds of CPU into
//!   seconds of wall time. Here the clock jumps straight to the next deadline instead.
//!
//! So a run measures CPU spent inside `rtc` and nothing else.
//!
//! The corollary: **these numbers say nothing about protocol dynamics.** The wire is lossless and
//! has zero latency, so congestion control, loss recovery and pacing never engage.
//! `rtc-interceptor`'s `congestion_control` report covers dynamics against a simulated
//! bottleneck.
//!
//! # Two clocks, deliberately separate
//!
//! The protocol only ever sees the *virtual* instant held by [`PeerPair::now`], advanced by
//! arithmetic. CPU cost is measured with a real stopwatch, per peer ([`Peer::busy`]), so a
//! benchmark can attribute work to the sending or receiving side. The two are never compared
//! with each other. Heap allocations are attributed per peer the same way
//! ([`Peer::allocations`]) when a bench binary installs the [`allocations`] counter.

#![warn(rust_2018_idioms)]
#![warn(missing_docs)]

pub mod allocations;
pub mod fixtures;
mod pair;
mod providers;

pub use pair::{
    Direction, LocalTrack, PairBuilder, Peer, PeerPair, Received, WireStats, negotiate,
};
pub use providers::providers;

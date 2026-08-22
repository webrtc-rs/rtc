//! What GCC does on a path that pushes back.
//!
//! Run with `cargo bench --package rtc-interceptor --bench congestion_control`.
//!
//! # Not a criterion benchmark
//!
//! The other benches in this workspace time code — how many nanoseconds a record takes to protect.
//! There is nothing worth timing here: the loop is arithmetic, and how fast it runs says nothing
//! about the estimator. What is worth measuring is a different kind of thing — convergence time,
//! steady-state utilisation, and the response to a step change in available bandwidth — so this is
//! a `harness = false` binary that prints those numbers rather than a criterion target.
//!
//! The pass/fail gate lives in `tests/path_simulation.rs`, which asserts that the estimator climbs
//! on a healthy path, backs off on a queueing one, backs off on loss alone, ignores loss inside the
//! band, and climbs back after a widening. This reports *how well*; those assert *whether*.
//!
//! # Why not loopback
//!
//! A loopback benchmark reports a large number and proves nothing. There is no bottleneck, so no
//! queue builds; nothing is lost, so the loss half never fires. The delay half never leaves its
//! initial state and the "result" is whatever rate the sender happened to offer. Every measurement
//! here runs against `path_simulator`'s bottleneck instead.
//!
//! A real-socket run against an impaired path is not covered here: inducing loss and delay on
//! macOS means `dnctl`/`pfctl` under root, which was not available. Every number is simulated.
//!
//! # Closed loop, unlike the fixtures in `tests/`
//!
//! `path_simulation.rs`'s `gcc_trajectory` offers a packet every 10 ms no matter what the estimator
//! says. That is right for asking "does the target move the correct way" and useless for asking
//! "how well does the sender use the path" — utilisation only means something when the sender
//! actually paces at the estimate. Here the sender is driven *by* the target, so an estimate that
//! runs away shows up as a queue the sender itself built, exactly as on a real path.

// The path simulator is shared with the tests rather than copied; it is the same bottleneck model
// CC-TEST-01 established, and a second copy would be free to drift from it.
#[path = "../tests/path_simulator/mod.rs"]
mod path_simulator;

use path_simulator::{Path, PathProfile};
use rtc_interceptor::{BandwidthEstimator, GCC_MAX_BITRATE, GCC_MIN_BITRATE, Gcc, PacketReport};
use std::time::{Duration, Instant};

const SSRC: u32 = 0x00C0_FFEE;
/// 1200 bytes on the wire, the usual video MTU.
const PACKET_BITS: f64 = 9_600.0;
/// A browser's TWCC cadence.
const FEEDBACK_INTERVAL: Duration = Duration::from_millis(100);
/// Simulation step, fine enough that pacing at 3 Mb/s is not quantised into bursts.
const TICK: Duration = Duration::from_millis(1);

/// One run's worth of measurements.
struct Run {
    /// `(elapsed, target)` each time the estimator produced a new one.
    trajectory: Vec<(Duration, f64)>,
    /// `(elapsed, bits)` the far end received, per feedback round.
    ///
    /// Per round rather than one total, so utilisation can be measured over the tail. Averaged
    /// across a whole run it is dominated by the initial ramp and says more about where the sender
    /// started than about what the estimator settled on.
    delivered: Vec<(Duration, f64)>,
    /// Packets the path did not deliver, of those offered.
    lost: usize,
    offered: usize,
    duration: Duration,
}

impl Run {
    fn final_target(&self) -> f64 {
        self.trajectory.last().map_or(0.0, |(_, target)| *target)
    }

    /// Mean target over the last `fraction` of the run — the rate the loop settled on, rather than
    /// the last sample, which on an AIMD sawtooth is wherever the tooth happened to end.
    fn settled(&self, fraction: f64) -> f64 {
        let from = self.duration.mul_f64(1.0 - fraction);
        let tail: Vec<f64> = self
            .trajectory
            .iter()
            .filter(|(at, _)| *at >= from)
            .map(|(_, target)| *target)
            .collect();
        if tail.is_empty() {
            return self.final_target();
        }
        tail.iter().sum::<f64>() / tail.len() as f64
    }

    /// How long until the target came within `tolerance` of `goal` **and stayed there**, judged on
    /// a two-second rolling mean rather than on individual samples.
    ///
    /// Both halves matter. Without "stayed there", a trajectory that crosses the right value on its
    /// way somewhere else counts as converged. Without the rolling mean, nothing with an AIMD
    /// sawtooth ever converges — the whole point of AIMD is that the target keeps probing upward
    /// and backing off, so single samples leave any band you care to draw while the average sits
    /// exactly where it should.
    fn convergence_time(&self, goal: f64, tolerance: f64) -> Option<Duration> {
        const WINDOW: Duration = Duration::from_secs(2);

        let mut candidate: Option<Duration> = None;
        for (index, (at, _)) in self.trajectory.iter().enumerate() {
            let window: Vec<f64> = self.trajectory[..=index]
                .iter()
                .filter(|(sample_at, _)| *at - *sample_at <= WINDOW)
                .map(|(_, target)| *target)
                .collect();
            let mean = window.iter().sum::<f64>() / window.len() as f64;

            if (mean - goal).abs() / goal <= tolerance {
                candidate.get_or_insert(*at);
            } else {
                candidate = None;
            }
        }
        candidate
    }

    /// Delivered bits over the last `fraction` of the run, against what the path could have carried
    /// in that time. This is the steady-state figure: the ramp from the initial rate is excluded,
    /// so it measures the rate the loop settled on rather than where it started.
    fn utilisation(&self, capacity: f64, fraction: f64) -> f64 {
        let from = self.duration.mul_f64(1.0 - fraction);
        let bits: f64 = self
            .delivered
            .iter()
            .filter(|(at, _)| *at >= from)
            .map(|(_, bits)| *bits)
            .sum();
        bits / (capacity * (self.duration - from).as_secs_f64())
    }

    fn loss_fraction(&self) -> f64 {
        if self.offered == 0 {
            return 0.0;
        }
        self.lost as f64 / self.offered as f64
    }
}

/// Drive a closed loop: the sender paces at whatever the estimator currently believes.
///
/// `widen_after` models a step change in available bandwidth — the bottleneck opens up fivefold,
/// which the estimator has to climb back into rather than merely survive.
fn run(
    profile: PathProfile,
    duration: Duration,
    initial: f64,
    widen_after: Option<Duration>,
) -> Run {
    let epoch = Instant::now();
    let mut path = Path::new(profile, epoch);
    if let Some(after) = widen_after {
        path = path.widening_after(after);
    }

    let mut gcc = Gcc::new(initial, GCC_MIN_BITRATE, GCC_MAX_BITRATE);
    let mut trajectory = vec![(Duration::ZERO, gcc.target_bitrate())];

    // Departure instants, indexed by the sequence number the report will name.
    let mut departures: Vec<Instant> = Vec::new();
    let mut credit_bits = 0.0;
    let mut delivered: Vec<(Duration, f64)> = Vec::new();
    let mut lost = 0usize;
    let mut next_feedback = FEEDBACK_INTERVAL;
    let mut elapsed = Duration::ZERO;

    while elapsed < duration {
        elapsed += TICK;
        let now = epoch + elapsed;

        // The closed half of the loop: the sender releases at the target rate, so an estimate that
        // runs away builds a queue the sender itself created.
        credit_bits += gcc.target_bitrate() * TICK.as_secs_f64();
        while credit_bits >= PACKET_BITS {
            credit_bits -= PACKET_BITS;
            let sequence = departures.len();
            // Wrapping would make two packets share a sequence number and the reports ambiguous.
            assert!(
                sequence <= u16::MAX as usize,
                "run too long for one sequence space"
            );
            departures.push(now);
            path.offer(now, sequence as u16, PACKET_BITS);
        }

        path.drain_to(now);

        if elapsed >= next_feedback {
            next_feedback += FEEDBACK_INTERVAL;
            let mut round_bits = 0.0;

            let reports: Vec<PacketReport> = path
                .take_arrivals()
                .into_iter()
                .map(|arrival| {
                    let index = usize::from(arrival.twcc_sequence_number);
                    if arrival.at.is_some() {
                        round_bits += PACKET_BITS;
                    } else {
                        lost += 1;
                    }
                    PacketReport {
                        ssrc: SSRC,
                        id: index as u64,
                        rtp_sequence_number: arrival.twcc_sequence_number,
                        is_twcc: true,
                        twcc_sequence_number: arrival.twcc_sequence_number,
                        size: (PACKET_BITS / 8.0) as usize,
                        arrived: arrival.at.is_some(),
                        departure: departures[index],
                        arrival: arrival.at.map(|at| at.duration_since(epoch)),
                        ecn: rtcp::transport_feedbacks::cc_feedback_report::Ecn::default(),
                    }
                })
                .collect();

            delivered.push((elapsed, round_bits));

            if !reports.is_empty() {
                gcc.on_reports(now, &reports);
                trajectory.push((elapsed, gcc.target_bitrate()));
            }
        }
    }

    Run {
        trajectory,
        delivered,
        lost,
        offered: departures.len(),
        duration,
    }
}

fn mbps(bits_per_second: f64) -> f64 {
    bits_per_second / 1_000_000.0
}

/// One row per shape, same numbers in the same order.
fn report(name: &str, run: &Run, capacity: f64) {
    let converged = run.convergence_time(capacity, 0.35).map_or_else(
        || "never".to_owned(),
        |at| format!("{:.1}s", at.as_secs_f64()),
    );

    println!(
        "{name:<22} {:>7.2} {:>9.2} {:>9.2} {:>11.1}% {:>7.1}% {:>11}",
        mbps(run.final_target()),
        mbps(run.settled(0.3)),
        mbps(capacity),
        run.utilisation(capacity, 0.3) * 100.0,
        run.loss_fraction() * 100.0,
        converged,
    );
}

fn main() {
    println!("GCC closed-loop behaviour. All rates Mb/s; simulated paths, 30 s each.\n");
    println!(
        "{:<22} {:>7} {:>9} {:>9} {:>12} {:>8} {:>11}",
        "path", "final", "settled", "capacity", "utilisation", "loss", "converged"
    );

    let thirty = Duration::from_secs(30);

    // Plenty of capacity, nothing lost: the estimator should find most of the path.
    let steady = PathProfile::steady();
    report(
        "steady",
        &run(steady, thirty, 300_000.0, None),
        steady.capacity_bits_per_second,
    );

    // Four times oversubscribed with room to queue: delay grows, nothing is lost. This is what the
    // delay half exists to notice, and it must notice it before the queue overflows into loss.
    let queueing = PathProfile::queue_building();
    report(
        "queue building (4x)",
        &run(queueing, thirty, 1_200_000.0, None),
        queueing.capacity_bits_per_second,
    );

    // Ample capacity, one packet in five dropped. The delay half sees nothing, so whatever happens
    // is the loss half acting alone — D4, the divergence from upstream, measured rather than
    // asserted from the source.
    let lossy = PathProfile::lossy_without_queueing();
    report(
        "lossy (1 in 5)",
        &run(lossy, thirty, 1_200_000.0, None),
        lossy.capacity_bits_per_second,
    );

    // Loss inside the 2–10% band GCC ignores on purpose: reacting to a few per cent on a wireless
    // link would give up capacity permanently.
    let mild = PathProfile::mildly_lossy();
    report(
        "mildly lossy (1 in 20)",
        &run(mild, thirty, 1_200_000.0, None),
        mild.capacity_bits_per_second,
    );

    // The step change: a 600 kb/s bottleneck that widens fivefold halfway through. Staying where
    // the congestion left it wastes the new capacity for as long as it takes to notice.
    let widen_after = Duration::from_secs(15);
    let recovering = PathProfile::recovering();
    let stepped = run(
        recovering,
        Duration::from_secs(40),
        1_200_000.0,
        Some(widen_after),
    );
    report(
        "recovering (5x step)",
        &stepped,
        recovering.capacity_bits_per_second * 5.0,
    );

    // The step response deserves its own line: one number for before the widening and one for
    // after, since a row against the *new* capacity alone cannot show that it climbed.
    let before = stepped
        .trajectory
        .iter()
        .filter(|(at, _)| *at < widen_after && *at > widen_after - Duration::from_secs(3))
        .map(|(_, target)| *target)
        .fold(f64::NEG_INFINITY, f64::max);
    let after = stepped.settled(0.25);
    println!(
        "\nstep response: {:.2} Mb/s in the 3 s before the widening → {:.2} Mb/s settled after, \
         into a path that went from {:.2} to {:.2} Mb/s.",
        mbps(before),
        mbps(after),
        mbps(recovering.capacity_bits_per_second),
        mbps(recovering.capacity_bits_per_second * 5.0),
    );

    println!(
        "\nNot covered: a real-socket run against an induced-impairment path. That needs \
         dnctl/pfctl under root."
    );
}

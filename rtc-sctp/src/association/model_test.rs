//! Protocol properties exercised through real endpoint handshakes and public API.

use std::time::Instant;

use crate::fuzzing_state::{CloseKind, Model, Policy, run};

#[test]
fn model_reliability_fragment_loss_matrix() {
    for ordered in [false, true] {
        for length in [32, 1200, 4000] {
            for policy in [
                Policy::Reliable,
                Policy::Timed(100),
                Policy::Rexmit(0),
                Policy::Rexmit(1),
            ] {
                let mut model = Model::new(Instant::now());
                assert!(model.open(0, 1));
                let lost = model.send(0, 1, ordered, policy, length).unwrap();
                model.poll();
                model.drop_packet(0);
                // Hold the surviving fragments until expiry too: delivering
                // their Gap SACKs first could legitimately fast-retransmit the
                // missing head before its deadline.
                model.advance(1100);
                model.deliver_all();
                model.finish();
                if matches!(policy, Policy::Reliable | Policy::Rexmit(1)) {
                    assert!(model.received(lost), "{ordered} {length} {policy:?}");
                } else {
                    assert!(!model.received(lost), "{ordered} {length} {policy:?}");
                }
                let next = model.send(0, 1, ordered, Policy::Reliable, 64).unwrap();
                model.poll();
                model.finish();
                assert!(model.received(next));
            }
        }
    }
}

#[test]
fn model_checks_deadline_at_transmission_not_arrival() {
    let mut model = Model::new(Instant::now());
    assert!(model.open(0, 1));
    let message = model.send(0, 1, true, Policy::Timed(100), 32).unwrap();
    model.poll();
    // The first packet was emitted before its lifetime. It is allowed to arrive
    // after it, even though a new transmission at that time would be forbidden.
    model.advance(101);
    model.deliver_all();
    model.read(1);
    assert!(model.received(message));
    model.finish();
}

#[test]
fn model_duplicate_reordered_data_and_ack_release_once() {
    let mut model = Model::new(Instant::now());
    assert!(model.open(0, 1));
    let first = model.send(0, 1, true, Policy::Reliable, 4000).unwrap();
    let second = model.send(0, 1, true, Policy::Reliable, 32).unwrap();
    model.poll();
    model.duplicate(0);
    model.deliver(model.wire_len() - 1);
    model.deliver(model.wire_len() - 1);
    model.finish();
    assert!(model.received(first));
    assert!(model.received(second));
    assert_eq!(model.buffered(0, 1), Some(0));
}

#[test]
fn model_timed_pending_reset_and_reuse_matrix() {
    for ordered in [false, true] {
        for close in [CloseKind::Stop, CloseKind::Close] {
            let mut model = Model::new(Instant::now());
            assert!(model.open(0, 1));
            model.send(0, 1, ordered, Policy::Timed(100), 8000).unwrap();
            model.poll();
            model.drop_packet(0);
            model.deliver_all();
            model.advance(1100);
            model.close(0, 1, close);
            model.poll();
            // Duplicates and inversion can put a reset request before the TSN
            // advancement that allows the receiver to finish it.
            model.duplicate(0);
            model.deliver(model.wire_len().saturating_sub(1));
            model.finish();
            // The fair exchange includes the peer's reciprocal reset and reads
            // all old messages, so both directions have finished, also for stop.
            assert!(
                model.open(0, 1),
                "completed bidirectional reset did not release SID"
            );
            let fresh = model.send(0, 1, true, Policy::Reliable, 64).unwrap();
            model.poll();
            model.finish();
            assert!(model.received(fresh));
        }
    }
}

#[test]
fn model_stop_preserves_writable_half_before_reciprocal_reset() {
    let mut model = Model::new(Instant::now());
    assert!(model.open(0, 1));
    let first = model.send(0, 1, true, Policy::Reliable, 32).unwrap();
    model.poll();
    model.finish();
    assert!(model.received(first));
    model.close(0, 1, CloseKind::Stop);
    let after_stop = model
        .send(0, 1, true, Policy::Reliable, 64)
        .expect("stop must leave the writable half usable before the peer's reset");
    model.poll();
    model.finish();
    assert!(model.received(after_stop));
}

#[test]
fn model_forward_tsn_before_receiver_stream_exists() {
    let mut model = Model::new(Instant::now());
    assert!(model.open(0, 1));
    // No DATA from this SID has reached the receiver when FORWARD-TSN arrives.
    model.send(0, 1, true, Policy::Timed(100), 32).unwrap();
    model.poll();
    model.drop_packet(0);
    model.advance(1100);
    model.finish();
    let next = model.send(0, 1, true, Policy::Reliable, 64).unwrap();
    model.poll();
    model.finish();
    assert!(model.received(next));
}

#[test]
fn model_stopped_reader_does_not_block_reciprocal_reset() {
    let mut model = Model::new(Instant::now());
    assert!(model.open(0, 1));
    assert!(model.open(1, 1));
    model.close(0, 1, CloseKind::Stop);
    model.poll();
    // The peer has not seen our stop yet. These bytes can be discarded by our
    // application, but must not make reset wait for a now-forbidden read call.
    model.send(1, 1, true, Policy::Reliable, 1200).unwrap();
    model.poll();
    model.finish();
    assert!(model.open(0, 1));
    assert!(model.open(1, 1));
}

#[test]
fn model_old_sack_does_not_release_reused_sid_buffer() {
    let mut model = Model::new(Instant::now());
    assert!(model.open(0, 1));
    model.send(0, 1, true, Policy::Reliable, 32).unwrap();
    model.poll();
    model.deliver_all();
    model.read(1);
    model.advance(200);
    assert_eq!(model.wire_len(), 1, "hold the receiver's delayed SACK");
    model.close(0, 1, CloseKind::Close);
    model.poll();
    // Deliver the complete reset exchange while its earlier cumulative SACK
    // stays at the front of the wire queue.
    for _ in 0..32 {
        if model.wire_len() == 1 {
            break;
        }
        model.deliver(1);
    }
    assert_eq!(
        model.wire_len(),
        1,
        "reset did not finish around the held SACK"
    );
    assert!(
        model.open(0, 1),
        "completed reset must allow reuse before old SACK"
    );
    let fresh = model.send(0, 1, true, Policy::Reliable, 16).unwrap();
    model.poll();
    assert_eq!(model.buffered(0, 1), Some(16));
    model.deliver(0);
    assert_eq!(
        model.buffered(0, 1),
        Some(16),
        "old SACK released the new object's bytes"
    );
    model.finish();
    assert!(model.received(fresh));
}

#[test]
fn model_fair_drain_reads_both_delivery_generations() {
    // Minimized from seed 46. Both messages and both reset directions finish on
    // the wire before the reader drains the old generation. Reading that old
    // message exposes the next generation only after its close event is polled.
    let mut model = Model::new(Instant::now());
    assert!(model.open(0, 2));
    assert!(model.open(1, 2));
    let old = model.send(1, 2, true, Policy::Rexmit(2), 4000).unwrap();
    model.poll();
    model.close(1, 2, CloseKind::Stop);
    model.poll();
    let new = model.send(1, 2, false, Policy::Reliable, 1200).unwrap();
    model.poll();
    model.finish();
    assert!(model.received(old));
    assert!(model.received(new));
}

/// Also provides a subprocess entry for delta reduction without changing a
/// process-global panic hook while the normal suite runs tests in parallel.
#[test]
fn model_replay_input() {
    let input = std::env::var("RTC_SCTP_MODEL_INPUT").unwrap_or_default();
    assert!(
        input.len().is_multiple_of(8),
        "input must contain whole four-byte actions"
    );
    let input: Vec<_> = input
        .as_bytes()
        .chunks_exact(2)
        .map(|byte| u8::from_str_radix(std::str::from_utf8(byte).unwrap(), 16).unwrap())
        .collect();
    run(&input, Instant::now());
}

#[test]
fn model_seeded_event_sequences() {
    for seed in 0..48_u64 {
        let mut state = seed + 1;
        let mut input = [0; 192];
        for byte in &mut input {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        let result = std::panic::catch_unwind(|| run(&input, Instant::now()));
        assert!(
            result.is_ok(),
            "stateful scenario seed={seed}, input={input:02x?}"
        );
    }
}

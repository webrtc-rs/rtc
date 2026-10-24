//! Ports of pion's `stream_test.go` (stream_test.go → stream_test.rs).
//!
//! Only the buffered-amount tests are portable: the other three pion tests
//! exercise I-DATA message identifiers (`MID`/`FSN`, RFC 8260 interleaved
//! delivery), which rtc-sctp's stream and reassembly queue do not implement,
//! so those rows stay gaps.
//!
//! pion's `Stream` is a standalone struct; rtc-sctp's [`Stream`] is a borrow
//! of its [`Association`], so the tests build a minimal association and reach
//! the stream through it, exactly as the association's own tests do.

use super::*;
use crate::chunk::chunk_payload_data::PayloadProtocolIdentifier;

fn stream_association() -> Association {
    let mut a = Association::new(
        None,
        Arc::new(TransportConfig::default()),
        1400,
        0,
        SocketAddr::from_str("0.0.0.0:0").unwrap(),
        SocketAddr::from_str("0.0.0.0:0").unwrap(),
        TransportProtocol::UDP,
        Instant::now(),
    );
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a
}

/// pion: `TestSessionBufferedAmount` / "bufferedAmount".
///
/// A fresh stream reports zero buffered bytes and a zero low threshold; both
/// the counter and the threshold are then readable back after being set.
/// (pion assigns `s.bufferedAmount` directly; the field is reached through the
/// association here, which owns the stream state.)
#[test]
fn session_buffered_amount() -> Result<()> {
    let mut a = stream_association();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?;

    assert_eq!(
        0,
        a.stream(1)?.buffered_amount()?,
        "unexpected bufferedAmount"
    );
    assert_eq!(
        0,
        a.stream(1)?.buffered_amount_low_threshold()?,
        "unexpected threshold"
    );

    a.streams.get_mut(&1).unwrap().buffered_amount = 8192;
    a.stream(1)?.set_buffered_amount_low_threshold(2048)?;
    assert_eq!(
        8192,
        a.stream(1)?.buffered_amount()?,
        "unexpected bufferedAmount"
    );
    assert_eq!(
        2048,
        a.stream(1)?.buffered_amount_low_threshold()?,
        "unexpected threshold"
    );

    Ok(())
}

/// pion: `TestSessionBufferedAmount` / "OnBufferedAmountLow".
///
/// pion counts invocations of the `OnBufferedAmountLow` callback; rtc-sctp
/// replaces the callback with [`StreamState::on_buffer_released`] returning
/// whether the buffered amount crossed from above the low threshold to equal
/// or below it — the association turns exactly that `true` into the
/// `StreamEvent::BufferedAmountLow` event (`release_stream_buffers`). The
/// return value is therefore the callback count.
#[test]
fn session_buffered_amount_on_buffered_amount_low() {
    let mut a = stream_association();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi).unwrap();
    a.streams.get_mut(&1).unwrap().buffered_amount = 4096;
    a.stream(1)
        .unwrap()
        .set_buffered_amount_low_threshold(2048)
        .unwrap();
    let mut callbacks = 0;

    // Negative value should be ignored (by design)
    assert!(!a.streams.get_mut(&1).unwrap().on_buffer_released(-32)); // bufferedAmount = 4096
    assert_eq!(
        4096,
        a.stream(1).unwrap().buffered_amount().unwrap(),
        "unexpected bufferedAmount"
    );
    assert_eq!(0, callbacks, "callback count mismatch");

    // Above to above, no callback
    assert!(!a.streams.get_mut(&1).unwrap().on_buffer_released(1024)); // bufferedAmount = 3072
    assert_eq!(
        3072,
        a.stream(1).unwrap().buffered_amount().unwrap(),
        "unexpected bufferedAmount"
    );
    assert_eq!(0, callbacks, "callback count mismatch");

    // Above to equal, callback should be made
    let fired = a.streams.get_mut(&1).unwrap().on_buffer_released(1024); // bufferedAmount = 2048
    if fired {
        callbacks += 1;
    }
    assert_eq!(
        2048,
        a.stream(1).unwrap().buffered_amount().unwrap(),
        "unexpected bufferedAmount"
    );
    assert_eq!(1, callbacks, "callback count mismatch");

    // Equal to below, no callback
    assert!(!a.streams.get_mut(&1).unwrap().on_buffer_released(1024)); // bufferedAmount = 1024
    assert_eq!(
        1024,
        a.stream(1).unwrap().buffered_amount().unwrap(),
        "unexpected bufferedAmount"
    );
    assert_eq!(1, callbacks, "callback count mismatch");

    // Below to below, no callback
    assert!(!a.streams.get_mut(&1).unwrap().on_buffer_released(1024)); // bufferedAmount = 0
    assert_eq!(
        0,
        a.stream(1).unwrap().buffered_amount().unwrap(),
        "unexpected bufferedAmount"
    );
    assert_eq!(1, callbacks, "callback count mismatch");

    // Capped at 0, no callback
    assert!(!a.streams.get_mut(&1).unwrap().on_buffer_released(1024)); // bufferedAmount = 0
    assert_eq!(
        0,
        a.stream(1).unwrap().buffered_amount().unwrap(),
        "unexpected bufferedAmount"
    );
    assert_eq!(1, callbacks, "callback count mismatch");
}

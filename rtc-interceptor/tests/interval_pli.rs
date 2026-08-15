//! Periodic keyframe requests for bound remote streams.
//!
//! The interceptor exists for bridges to protocols with no receiver feedback: nothing else would
//! ever ask for a keyframe, so it asks on a timer. The properties worth pinning are which streams
//! it asks for, when it stops, and that an idle chain is not woken for nothing.

use rtc_interceptor::{
    Interceptor, IntervalPliBuilder, IntervalPliInterceptor, NoopInterceptor, Packet, RTCPFeedback,
    Registry, StreamInfo,
};
use sansio::Protocol;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_secs(1);

fn chain() -> IntervalPliInterceptor<NoopInterceptor> {
    Registry::new()
        .with(IntervalPliBuilder::new().with_interval(INTERVAL).build())
        .build()
}

/// A stream that negotiated `nack pli`.
fn pli_stream(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_owned(),
            parameter: "pli".to_owned(),
        }],
        ..Default::default()
    }
}

/// A stream with plain `nack` — retransmission but not PLI.
fn nack_only_stream(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_owned(),
            parameter: String::new(),
        }],
        ..Default::default()
    }
}

/// Every media SSRC a PLI was requested for, draining the write side.
fn drain_plis(chain: &mut IntervalPliInterceptor<NoopInterceptor>) -> Vec<u32> {
    let mut ssrcs = Vec::new();
    while let Some(packet) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &packet.message {
            for rtcp_packet in rtcp_packets {
                if let Some(pli) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication>()
                {
                    ssrcs.push(pli.media_ssrc);
                }
            }
        }
    }
    ssrcs
}

// ---------------------------------------------------------------------------------------
// Which streams are asked
// ---------------------------------------------------------------------------------------

/// A newly bound stream is asked for a keyframe straight away — there is no point waiting a full
/// interval to start decoding.
#[test]
fn a_newly_bound_stream_is_asked_immediately() {
    let epoch = Instant::now();
    let mut chain = chain();

    chain.bind_remote_stream(&pli_stream(1));
    assert!(
        drain_plis(&mut chain).is_empty(),
        "binding alone cannot send: a sans-I/O interceptor has no clock until it is given one"
    );

    chain.handle_timeout(epoch).expect("handle_timeout");
    assert_eq!(
        vec![1],
        drain_plis(&mut chain),
        "the first instant handed over is when the request goes out"
    );
}

/// Only streams that negotiated `nack pli` are asked. PLI rides as the `pli` parameter of `nack`,
/// so plain `nack` means retransmission support and nothing about keyframes.
#[test]
fn only_streams_that_negotiated_pli_are_asked() {
    let epoch = Instant::now();
    let mut chain = chain();

    chain.bind_remote_stream(&pli_stream(1));
    chain.bind_remote_stream(&nack_only_stream(2));
    chain.bind_remote_stream(&StreamInfo {
        ssrc: 3,
        ..Default::default()
    });

    chain.handle_timeout(epoch).expect("handle_timeout");
    assert_eq!(
        vec![1],
        drain_plis(&mut chain),
        "2 has nack without pli, 3 has no feedback at all"
    );
    assert_eq!(vec![1], chain.bound_streams().collect::<Vec<_>>());
}

#[test]
fn every_bound_stream_is_asked_on_each_interval() {
    let epoch = Instant::now();
    let mut chain = chain();

    chain.bind_remote_stream(&pli_stream(1));
    chain.bind_remote_stream(&pli_stream(2));

    chain.handle_timeout(epoch).expect("handle_timeout");
    assert_eq!(vec![1, 2], drain_plis(&mut chain), "the immediate request");

    chain
        .handle_timeout(epoch + INTERVAL)
        .expect("handle_timeout");
    assert_eq!(vec![1, 2], drain_plis(&mut chain), "first interval");

    chain
        .handle_timeout(epoch + INTERVAL * 2)
        .expect("handle_timeout");
    assert_eq!(vec![1, 2], drain_plis(&mut chain), "second interval");
}

#[test]
fn nothing_is_asked_before_the_interval_elapses() {
    let epoch = Instant::now();
    let mut chain = chain();

    chain.bind_remote_stream(&pli_stream(1));
    chain.handle_timeout(epoch).expect("handle_timeout");
    drain_plis(&mut chain);

    chain
        .handle_timeout(epoch + INTERVAL / 2)
        .expect("handle_timeout");
    assert!(
        drain_plis(&mut chain).is_empty(),
        "half an interval is not an interval"
    );

    chain
        .handle_timeout(epoch + INTERVAL)
        .expect("handle_timeout");
    assert_eq!(vec![1], drain_plis(&mut chain));
}

// ---------------------------------------------------------------------------------------
// Stopping
// ---------------------------------------------------------------------------------------

/// Unbinding stops the requests. Upstream cannot do this: it registers the stream in
/// `BindRemoteStream` but removes it in `UnbindLocalStream`, so a remote stream is never
/// unregistered and PLIs keep going out for a stream that has gone away.
#[test]
fn unbinding_a_stream_stops_asking_for_it() {
    let epoch = Instant::now();
    let mut chain = chain();

    chain.bind_remote_stream(&pli_stream(1));
    chain.bind_remote_stream(&pli_stream(2));
    chain.handle_timeout(epoch).expect("handle_timeout");
    drain_plis(&mut chain);

    chain.unbind_remote_stream(&pli_stream(1));

    chain
        .handle_timeout(epoch + INTERVAL)
        .expect("handle_timeout");
    assert_eq!(
        vec![2],
        drain_plis(&mut chain),
        "1 is gone; asking it for a keyframe would be shouting into the void"
    );
    assert_eq!(vec![2], chain.bound_streams().collect::<Vec<_>>());
}

#[test]
fn unbinding_the_last_stream_stops_asking_entirely() {
    let epoch = Instant::now();
    let mut chain = chain();

    chain.bind_remote_stream(&pli_stream(1));
    chain.handle_timeout(epoch).expect("handle_timeout");
    drain_plis(&mut chain);

    chain.unbind_remote_stream(&pli_stream(1));

    chain
        .handle_timeout(epoch + INTERVAL * 5)
        .expect("handle_timeout");
    assert!(drain_plis(&mut chain).is_empty());
}

// ---------------------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------------------

/// Delivery rule 3: an interceptor with nothing to do must not ask to be woken, and the instant it
/// reports must be in the future — a repeated past instant is the webrtc#862 busy-loop.
#[test]
fn poll_timeout_is_none_until_a_stream_is_bound_and_running() {
    let epoch = Instant::now();
    let mut chain = chain();

    assert_eq!(None, chain.poll_timeout(), "nothing bound, nothing to do");

    chain.bind_remote_stream(&pli_stream(1));
    assert_eq!(
        None,
        chain.poll_timeout(),
        "bound, but no instant has been handed over yet, so no deadline can exist"
    );

    chain.handle_timeout(epoch).expect("handle_timeout");
    assert_eq!(
        Some(epoch + INTERVAL),
        chain.poll_timeout(),
        "armed one interval out"
    );

    chain
        .handle_timeout(epoch + INTERVAL)
        .expect("handle_timeout");
    assert_eq!(
        Some(epoch + INTERVAL * 2),
        chain.poll_timeout(),
        "and it advances rather than repeating"
    );

    chain.unbind_remote_stream(&pli_stream(1));
    assert_eq!(
        None,
        chain.poll_timeout(),
        "idle again once the last stream goes"
    );
}

/// A zero interval disables the periodic request, leaving only the explicit one — matching
/// upstream, which creates no ticker unless its interval is positive.
#[test]
fn a_zero_interval_disables_periodic_requests() {
    let epoch = Instant::now();
    let mut chain = Registry::new()
        .with(
            IntervalPliBuilder::new()
                .with_interval(Duration::ZERO)
                .build(),
        )
        .build();

    chain.bind_remote_stream(&pli_stream(1));
    chain.handle_timeout(epoch).expect("handle_timeout");
    assert_eq!(
        vec![1],
        drain_plis(&mut chain),
        "the bind-time request still goes out"
    );

    assert_eq!(None, chain.poll_timeout(), "but no interval is armed");
    chain
        .handle_timeout(epoch + Duration::from_secs(60))
        .expect("handle_timeout");
    assert!(drain_plis(&mut chain).is_empty(), "and none ever fires");
}

// ---------------------------------------------------------------------------------------
// The out-of-band request
// ---------------------------------------------------------------------------------------

/// `Ein` is `()` for every interceptor, so an out-of-band request cannot travel through a chain as
/// a typed event. It is an inherent method instead, reachable while the concrete type is in hand.
#[test]
fn a_keyframe_can_be_requested_on_demand() {
    let epoch = Instant::now();
    let mut chain = chain();

    chain.bind_remote_stream(&pli_stream(1));
    chain.bind_remote_stream(&pli_stream(2));
    chain.handle_timeout(epoch).expect("handle_timeout");
    drain_plis(&mut chain);

    chain.force_pli(epoch + Duration::from_millis(10));
    assert_eq!(vec![1, 2], drain_plis(&mut chain), "every bound stream");

    chain.force_pli_for(epoch + Duration::from_millis(20), &[2]);
    assert_eq!(vec![2], drain_plis(&mut chain), "just the one asked for");
}

/// An SSRC nobody is receiving has no destination, so a request for it is dropped rather than
/// emitted against a stream that does not exist.
#[test]
fn forcing_a_keyframe_for_an_unbound_stream_asks_nothing() {
    let epoch = Instant::now();
    let mut chain = chain();

    chain.bind_remote_stream(&pli_stream(1));
    chain.handle_timeout(epoch).expect("handle_timeout");
    drain_plis(&mut chain);

    chain.force_pli_for(epoch, &[99]);
    assert!(drain_plis(&mut chain).is_empty());

    chain.force_pli_for(epoch, &[1, 99]);
    assert_eq!(vec![1], drain_plis(&mut chain), "the bound one only");
}

/// With nothing bound there is nothing to ask, so an explicit request is a no-op rather than an
/// empty RTCP packet on the wire.
#[test]
fn forcing_a_keyframe_with_nothing_bound_sends_nothing() {
    let mut chain = chain();
    chain.force_pli(Instant::now());
    assert!(drain_plis(&mut chain).is_empty());
}

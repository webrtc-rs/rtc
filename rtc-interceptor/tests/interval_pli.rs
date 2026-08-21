//! Periodic keyframe requests for bound remote streams.
//!
//! The interceptor exists for bridges to protocols with no receiver feedback: nothing else would
//! ever ask for a keyframe, so it asks on a timer. The properties worth pinning are which streams
//! it asks for, when it stops, and that an idle chain is not woken for nothing.

use rtc_interceptor::{
    Attribute, AttributedPacket, Interceptor, IntervalPliInterceptor, Packet, RTCPFeedback,
    Registry, StreamInfo, TaggedPacket,
};
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_secs(1);

fn chain() -> Box<dyn Interceptor> {
    Box::new(
        Registry::new()
            .with(IntervalPliInterceptor::new(INTERVAL))
            .build(),
    )
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

/// Ask for a keyframe. With no event channel, an attribute on an inbound packet is how one
/// interceptor asks another for something.
fn force_pli(chain: &mut dyn Interceptor, now: Instant, ssrcs: Option<Vec<u32>>) {
    let mut msg = TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet::default())),
    };
    msg.message.add(Attribute::ForcePli { ssrcs });
    chain.handle_read(msg).expect("handle_read");
    while chain.poll_read().is_some() {}
}

/// Every media SSRC a PLI was requested for, draining the write side.
fn drain_plis(chain: &mut dyn Interceptor) -> Vec<u32> {
    let mut ssrcs = Vec::new();
    while let Some(packet) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &packet.message.packet {
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
        .with(IntervalPliInterceptor::new(Duration::ZERO))
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

/// `Ein` is `()` for every so an out-of-band request cannot travel through a chain as
/// a typed event. It is an inherent method instead, reachable while the concrete type is in hand.
#[test]
fn a_keyframe_can_be_requested_on_demand() {
    let epoch = Instant::now();
    let mut chain = chain();

    chain.bind_remote_stream(&pli_stream(1));
    chain.bind_remote_stream(&pli_stream(2));
    chain.handle_timeout(epoch).expect("handle_timeout");
    drain_plis(&mut chain);

    force_pli(&mut chain, epoch + Duration::from_millis(10), None);
    assert_eq!(vec![1, 2], drain_plis(&mut chain), "every bound stream");

    force_pli(&mut chain, epoch + Duration::from_millis(20), Some(vec![2]));
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

    force_pli(&mut chain, epoch, Some(vec![99]));
    assert!(drain_plis(&mut chain).is_empty());

    force_pli(&mut chain, epoch, Some(vec![1, 99]));
    assert_eq!(vec![1], drain_plis(&mut chain), "the bound one only");
}

/// With nothing bound there is nothing to ask, so an explicit request is a no-op rather than an
/// empty RTCP packet on the wire.
#[test]
fn forcing_a_keyframe_with_nothing_bound_sends_nothing() {
    let mut chain = chain();
    force_pli(&mut chain, Instant::now(), None);
    assert!(drain_plis(&mut chain).is_empty());
}

// ---------------------------------------------------------------------------------------
// CC-PRE-03 — a request is acted on from either leg
// ---------------------------------------------------------------------------------------

/// Ask for a keyframe on the **write** leg, which is where an application's request arrives:
/// `rtc`'s handler turns an `RTCEvent` into an attribute carrier and injects it at the application
/// end of the chain, so it travels application-to-wire.
fn force_pli_on_write(chain: &mut dyn Interceptor, now: Instant, ssrcs: Option<Vec<u32>>) {
    let mut msg = TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet::default())),
    };
    msg.message.add(Attribute::ForcePli { ssrcs });
    chain.handle_write(msg).expect("handle_write");
}

/// The two legs must be indistinguishable. A read-only check would ignore every request an
/// application ever made, silently — there is no error path for "nobody was listening".
#[test]
fn a_request_on_the_write_leg_produces_the_same_plis_as_one_on_the_read_leg() {
    let epoch = Instant::now();

    let mut on_read = chain();
    on_read.bind_remote_stream(&pli_stream(1));
    on_read.bind_remote_stream(&pli_stream(2));
    on_read.handle_timeout(epoch).expect("handle_timeout");
    drain_plis(&mut on_read);

    let mut on_write = chain();
    on_write.bind_remote_stream(&pli_stream(1));
    on_write.bind_remote_stream(&pli_stream(2));
    on_write.handle_timeout(epoch).expect("handle_timeout");
    drain_plis(&mut on_write);

    let at = epoch + Duration::from_millis(10);
    force_pli(&mut on_read, at, None);
    force_pli_on_write(&mut on_write, at, None);

    let from_read = drain_plis(&mut on_read);
    let from_write = drain_plis(&mut on_write);

    assert_eq!(vec![1, 2], from_read, "the read leg is the established behaviour");
    assert_eq!(
        from_read, from_write,
        "a keyframe request must be acted on whichever leg it arrives by — an application's \
         arrives on the write leg"
    );
}

/// And the carrier is not consumed: it continues the walk with its attribute intact, so anything
/// further along sees both the request and the PLIs it produced.
#[test]
fn a_write_leg_request_carries_on_unconsumed() {
    let epoch = Instant::now();
    let mut chain = chain();
    chain.bind_remote_stream(&pli_stream(1));
    chain.handle_timeout(epoch).expect("handle_timeout");
    drain_plis(&mut chain);

    force_pli_on_write(&mut chain, epoch + Duration::from_millis(10), None);

    let mut carriers = 0;
    while let Some(packet) = chain.poll_write() {
        if packet.message.has(&Attribute::ForcePli { ssrcs: None }) {
            carriers += 1;
        }
    }
    assert_eq!(
        1, carriers,
        "the packet that carried the request must carry on, attribute still attached"
    );
}

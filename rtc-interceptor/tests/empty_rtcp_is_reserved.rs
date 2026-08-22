//! `Packet::Rtcp(vec![])` is reserved as an attribute carrier (CC-PRE-01).
//!
//! With `Ein`/`Eout` at `()`, an attribute riding on a packet is the only way information crosses
//! an interceptor boundary — and a connection-level fact often has no packet going its way when it
//! needs to travel. The carrier for those is an RTCP packet with an empty payload: inert to every
//! interceptor that does not look for attributes, because the pacer short-circuits RTCP, the TWCC
//! sender and NACK responder match only `Packet::Rtp`, and a compound-RTCP loop over an empty
//! vector runs zero times.
//!
//! That only works while **nothing else** emits one. `rtc`'s handler drops an empty-RTCP packet
//! after reading its attributes, so an interceptor that emitted a genuinely-empty compound packet
//! would have it silently swallowed — the worst kind of bug, because the packet simply is not
//! there and nothing reports why.
//!
//! Today the invariant holds by construction: `queue_plis` returns early on an empty SSRC list and
//! every other generator emits `vec![one]`. Nothing keeps it true, which is what these tests are
//! for. They drive each generating interceptor through its production path — including the case
//! that would produce an empty compound packet, a timer firing with nothing to report — and fail
//! if any empty RTCP packet reaches the end of the chain.

use rtc_interceptor::{
    Attribute, AttributedPacket, Interceptor, IntervalPliInterceptor, NackGeneratorBuilder, Packet,
    RTCPFeedback, RTPHeaderExtension, ReceiverReportBuilder, Registry, Rfc8888Builder,
    SenderReportBuilder, StreamInfo, TaggedPacket, TwccReceiverBuilder,
};
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

const SSRC: u32 = 0x1234_5678;
const TICK: Duration = Duration::from_millis(50);

/// Every interceptor in the crate that generates RTCP, in one chain.
///
/// `with_rtcp_readable` so inbound RTCP is not dropped at the terminus — this test wants to see
/// everything that reaches either end, not only what an application would normally be shown.
fn generators() -> impl Interceptor {
    Registry::new()
        .with_rtcp_readable()
        .with(NackGeneratorBuilder::new().with_interval(TICK).build())
        .with(TwccReceiverBuilder::new().with_interval(TICK).build())
        .with(Rfc8888Builder::new().with_interval(TICK).build())
        .with(ReceiverReportBuilder::new().with_interval(TICK).build())
        .with(SenderReportBuilder::new().with_interval(TICK).build())
        .with(IntervalPliInterceptor::new(TICK))
        .build()
}

/// A stream that negotiates everything the generators above key off.
fn stream() -> StreamInfo {
    StreamInfo {
        ssrc: SSRC,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        payload_type: 96,
        rtcp_feedback: vec![
            RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: String::new(),
            },
            RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: "pli".to_owned(),
            },
            RTCPFeedback {
                typ: "transport-cc".to_owned(),
                parameter: String::new(),
            },
        ],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: 5,
        }],
        ..Default::default()
    }
}

fn rtp(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                timestamp: u32::from(sequence_number) * 3_000,
                ssrc: SSRC,
                ..Default::default()
            },
            payload: vec![0xAA; 100].into(),
            ..Default::default()
        })),
    }
}

/// Drain both ends, panicking on any empty RTCP packet. Returns how many packets were seen.
fn drain(chain: &mut impl Interceptor, whence: &str) -> usize {
    let mut seen = 0;
    let mut check = |packet: &TaggedPacket| {
        if let Packet::Rtcp(rtcp_packets) = &packet.message.packet {
            assert!(
                !rtcp_packets.is_empty(),
                "{whence}: an interceptor emitted Packet::Rtcp(vec![]), which is reserved as the \
                 attribute carrier and is dropped at the crate boundary — this packet would \
                 vanish with no error"
            );
        }
    };
    while let Some(packet) = chain.poll_write() {
        check(&packet);
        seen += 1;
    }
    while let Some(packet) = chain.poll_read() {
        check(&packet);
        seen += 1;
    }
    seen
}

/// The case that would produce an empty compound packet: every generator's timer fires with
/// nothing recorded to report on.
#[test]
fn generators_ticking_with_nothing_to_report_emit_no_empty_rtcp() {
    let epoch = Instant::now();
    let mut chain = generators();

    // No streams bound, no packets seen — but the timers still fire.
    for tick in 1..=10 {
        chain.handle_timeout(epoch + TICK * tick).expect("timeout");
        drain(&mut chain, "no streams bound");
    }
}

/// The same, with a stream bound but no traffic on it — a connection that negotiated media and
/// then went silent, which is when a report over an empty set is most tempting to construct.
#[test]
fn generators_ticking_on_a_silent_stream_emit_no_empty_rtcp() {
    let epoch = Instant::now();
    let mut chain = generators();
    chain.bind_remote_stream(&stream());
    chain.bind_local_stream(&stream());

    for tick in 1..=10 {
        chain.handle_timeout(epoch + TICK * tick).expect("timeout");
        drain(&mut chain, "stream bound, no traffic");
    }
}

/// And with traffic, so the generators actually produce their reports — the path that proves the
/// two tests above are not passing merely because nothing was emitted at all.
#[test]
fn generators_under_traffic_emit_no_empty_rtcp() {
    let epoch = Instant::now();
    let mut chain = generators();
    chain.bind_remote_stream(&stream());
    chain.bind_local_stream(&stream());

    let mut emitted = 0;
    for tick in 1..=20u32 {
        let now = epoch + TICK * tick;
        // A gap at 5 so the NACK generator has something to ask for.
        let sequence_number = tick as u16;
        if sequence_number != 5 {
            chain.handle_read(rtp(now, sequence_number)).expect("read");
            chain
                .handle_write(rtp(now, sequence_number))
                .expect("write");
        }
        chain.handle_timeout(now).expect("timeout");
        emitted += drain(&mut chain, "under traffic");
    }

    assert!(
        emitted > 0,
        "the generators emitted nothing at all, so this test proves nothing about what they emit"
    );
}

/// The one construction site that builds an RTCP packet from a variable-length list:
/// `IntervalPliInterceptor::queue_plis`. A keyframe request naming only SSRCs nobody is receiving
/// filters down to an empty target list, and without its early return that becomes a compound RTCP
/// packet with no packets in it.
///
/// The tests above do not reach this: with no stream bound the PLI timer never arms, and with one
/// bound the target list is never empty. This is the case that falsifies.
#[test]
fn forcing_a_keyframe_for_unbound_streams_emits_no_empty_rtcp() {
    let epoch = Instant::now();
    let mut chain = generators();
    chain.bind_remote_stream(&stream());

    // Clear the ask-on-bind request, so what follows is only what the forced request produces.
    chain.handle_timeout(epoch).expect("timeout");
    drain(&mut chain, "ask-on-bind");

    let mut carrier = rtp(epoch + TICK, 1);
    carrier.message.add(Attribute::ForcePli {
        ssrcs: Some(vec![SSRC.wrapping_add(1)]),
    });
    chain.handle_read(carrier).expect("read");

    drain(&mut chain, "keyframe request for an unbound stream");
}

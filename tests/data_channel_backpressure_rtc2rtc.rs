//! A receiver that stops consuming must throttle the peer, not lose data.
//!
//! This covers the bounded SCTP drain added for
//! [webrtc#858](https://github.com/webrtc-rs/webrtc/issues/858). The handler stops pulling
//! out of SCTP's reassembly queues once the pipeline is holding more than
//! `SCTP_PIPELINE_READ_BACKLOG_LIMIT` undelivered data-channel messages, which lowers the
//! receiver-window credit advertised in every SACK. Undrained bytes are the mechanism, not a
//! leak — but they only work if the parked stream is later *resumed*.
//!
//! **That resume is the risk this test exists for.** `StreamEvent::Readable` is
//! edge-triggered: it fires when a new DATA chunk arrives, never because unread data remains.
//! So the moment back-pressure succeeds the peer stops sending, nothing arrives to re-trigger
//! the drain, and a stream parked mid-way would stay parked — deadlocking precisely when the
//! feature engages. The resume runs from `poll_read`, and the pipeline walks the handler
//! chain there only when a stream is actually parked; this is the only test that drives that
//! path over a real connection.
//!
//! Shape: the answerer pumps the network but deliberately never calls `poll_read` while the
//! offerer sends far more than the bound, so the backlog builds and streams park. Then it
//! drains and must receive **every** message, **in order**.
//!
//! It is deliberately not a test that "the bound exists" — a core with no bound at all would
//! also deliver everything, just with unbounded memory. It is a test that the bound does not
//! lose or strand anything.
//!
//! The second scenario covers the byte bound (`with_sctp_read_backlog_bytes`), which is what
//! engages first for large messages: two channels of mixed message sizes, a stalled consumer,
//! and an upper bound on the backlog it is handed when it resumes.

use anyhow::Result;
use rtc::data_channel::RTCDataChannelInit;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Well past the 256-message pipeline bound, so parking is structural rather than a matter of
/// timing luck. Small payloads keep SCTP's *send* buffer from being the thing that throttles:
/// the receive side must be the only bottleneck.
const MESSAGE_COUNT: usize = 1_200;

const NEGOTIATED_ID: u16 = 1;

/// How long the answerer refuses to call `poll_read` once the channel is open.
///
/// It must be long enough for messages to actually *arrive* and pile up past the bound.
/// Gating the stall on "the offerer finished sending" is not enough and was the first version
/// of this test: `send_text` only queues into SCTP's send buffer, so that flag flips within a
/// few iterations and the consumer starts before any backlog exists — the test then passes
/// with the resume path entirely disabled, proving nothing.
const CONSUMER_STALL: Duration = Duration::from_secs(3);

struct Peers {
    offer_pc: RTCPeerConnection,
    answer_pc: RTCPeerConnection,
    offer_socket: UdpSocket,
    answer_socket: UdpSocket,
    offer_addr: std::net::SocketAddr,
    answer_addr: std::net::SocketAddr,
}

async fn build_peer(
    role: RTCDtlsRole,
    read_backlog_bytes: Option<usize>,
) -> Result<(RTCPeerConnection, UdpSocket, std::net::SocketAddr)> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;

    let mut setting_engine = SettingEngineBuilder::new().with_answering_dtls_role(role);
    if let Some(bytes) = read_backlog_bytes {
        setting_engine = setting_engine.with_sctp_read_backlog_bytes(bytes);
    }

    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(setting_engine.build())
        .build(Instant::now())?;

    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

    Ok((pc, socket, addr))
}

async fn connect(answerer_read_backlog_bytes: Option<usize>) -> Result<Peers> {
    let (offer_pc, offer_socket, offer_addr) = build_peer(RTCDtlsRole::Server, None).await?;
    let (answer_pc, answer_socket, answer_addr) =
        build_peer(RTCDtlsRole::Client, answerer_read_backlog_bytes).await?;
    Ok(Peers {
        offer_pc,
        answer_pc,
        offer_socket,
        answer_socket,
        offer_addr,
        answer_addr,
    })
}

/// One reliable, ordered channel in a scenario.
struct ChannelPlan {
    /// The SCTP stream id both sides agree on out-of-band.
    negotiated_id: u16,
    messages: usize,
    /// Payload sizes, cycled. Every payload is its index in decimal, space-padded up to the size;
    /// a size shorter than the index is just the index.
    sizes: &'static [usize],
}

impl ChannelPlan {
    fn payload(&self, index: usize) -> String {
        let size = self.sizes[index % self.sizes.len()];
        format!("{index:<size$}")
    }
}

/// What the stalled answerer's application saw.
struct Outcome {
    /// Per channel, the index of every message received, in arrival order.
    received: Vec<Vec<usize>>,
    /// The most data-channel payload bytes the answerer held for its application at once,
    /// sampled every iteration.
    peak_backlog_bytes: usize,
}

/// Opens the planned channels, has the offerer send everything as fast as SCTP accepts it, and
/// has the answerer pump the network but refuse to call `poll_read` for `CONSUMER_STALL` after
/// the channels open — then drain until everything has arrived.
async fn run_stalled_consumer(
    channels: &[ChannelPlan],
    answerer_read_backlog_bytes: Option<usize>,
) -> Result<Outcome> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    let mut p = connect(answerer_read_backlog_bytes).await?;

    // Reliable and ordered on both sides — the contract this test is about. The handle
    // returned is a separate, connection-local identifier from the negotiated stream id — it
    // is what addresses the channel through `data_channel()` and what events carry.
    let mut offer_dcs = vec![];
    let mut answer_dcs = vec![];
    for channel in channels {
        let init = RTCDataChannelInit {
            ordered: true,
            negotiated: Some(channel.negotiated_id),
            ..Default::default()
        };
        let label = format!("backpressure-{}", channel.negotiated_id);
        offer_dcs.push(
            p.offer_pc
                .create_data_channel(&label, Some(init.clone()))?
                .id(),
        );
        answer_dcs.push(p.answer_pc.create_data_channel(&label, Some(init))?.id());
    }

    let offer = p.offer_pc.create_offer(None)?;
    p.offer_pc
        .set_local_description(Instant::now(), offer.clone())?;
    p.answer_pc.set_remote_description(Instant::now(), offer)?;
    let answer = p.answer_pc.create_answer(None)?;
    p.answer_pc
        .set_local_description(Instant::now(), answer.clone())?;
    p.offer_pc.set_remote_description(Instant::now(), answer)?;

    let mut offer_connected = false;
    let mut dc_open = false;
    let mut sent = vec![0usize; channels.len()];
    let mut received: Vec<Vec<usize>> = channels
        .iter()
        .map(|channel| Vec::with_capacity(channel.messages))
        .collect();
    let mut peak_backlog_bytes = 0usize;

    // The stall: until this instant the answerer pumps the network but never calls
    // `poll_read`, so its pipeline backlog grows past the bound and the SCTP handler parks
    // the stream. Set when the channel opens, since nothing arrives before that.
    let mut stall_until: Option<Instant> = None;
    let mut answerer_consuming = false;

    let mut offer_buf = vec![0u8; 2048];
    let mut answer_buf = vec![0u8; 2048];

    let start = Instant::now();
    let deadline = Duration::from_secs(60);
    let done = |received: &[Vec<usize>]| {
        received
            .iter()
            .zip(channels)
            .all(|(got, channel)| got.len() >= channel.messages)
    };

    while start.elapsed() < deadline {
        while let Some(msg) = p.offer_pc.poll_write() {
            p.offer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }
        while let Some(msg) = p.answer_pc.poll_write() {
            p.answer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await?;
        }

        while let Some(event) = p.offer_pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => offer_connected = true,
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_)) => {
                    dc_open = true;
                    stall_until.get_or_insert_with(|| Instant::now() + CONSUMER_STALL);
                }
                _ => {}
            }
        }
        while p.answer_pc.poll_event().is_some() {}

        // The offerer receives nothing on this connection; drain so it cannot back up.
        while p.offer_pc.poll_read().is_some() {}

        // The answerer consumes only once the stall is over. Before that, messages pile up in
        // its pipeline — which is exactly what drives the backlog past the bound.
        peak_backlog_bytes = peak_backlog_bytes.max(p.answer_pc.data_read_backlog_bytes());
        if answerer_consuming {
            while let Some(TaggedRTCMessage { message, .. }) = p.answer_pc.poll_read() {
                if let RTCMessage::DataChannelMessage(id, msg) = message {
                    let channel = answer_dcs
                        .iter()
                        .position(|dc| *dc == id)
                        .expect("message on a planned channel");
                    let text = String::from_utf8_lossy(&msg.data);
                    let index: usize = text
                        .trim_end()
                        .parse()
                        .expect("message payload is its index");
                    assert_eq!(
                        msg.data.len(),
                        channels[channel].payload(index).len(),
                        "message {index} arrived at the wrong size"
                    );
                    received[channel].push(index);
                }
            }
        }

        // Push as fast as SCTP will take it, keeping at most 1 MiB unacknowledged per channel
        // so the offerer's own queue is not what absorbs the workload. A refusal here is the
        // send buffer, not a failure: retry on the next iteration.
        if offer_connected && dc_open {
            for (index, channel) in channels.iter().enumerate() {
                if sent[index] < channel.messages
                    && let Some(mut dc) = p.offer_pc.data_channel(offer_dcs[index])
                    && dc.outstanding_bytes() < 1 << 20
                    && dc
                        .send_text(Instant::now(), channel.payload(sent[index]))
                        .is_ok()
                {
                    sent[index] += 1;
                }
            }
        }

        // Let the consumer start only once it has been stalled long enough for the backlog to
        // build. Whatever has not been handed over by then is parked in — or behind — the
        // answerer's SCTP reassembly queue, and only the resume path can get it out.
        if !answerer_consuming
            && let Some(until) = stall_until
            && Instant::now() >= until
        {
            answerer_consuming = true;
        }

        if answerer_consuming && done(&received) {
            break;
        }

        let next = p
            .offer_pc
            .poll_timeout()
            .unwrap_or(Instant::now() + Duration::from_secs(1))
            .min(
                p.answer_pc
                    .poll_timeout()
                    .unwrap_or(Instant::now() + Duration::from_secs(1)),
            );
        let delay = next
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(5));

        if delay.is_zero() {
            p.offer_pc.handle_timeout(Instant::now()).ok();
            p.answer_pc.handle_timeout(Instant::now()).ok();
            continue;
        }

        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);

        tokio::select! {
            _ = sleep => {
                p.offer_pc.handle_timeout(Instant::now()).ok();
                p.answer_pc.handle_timeout(Instant::now()).ok();
            }
            r = p.offer_socket.recv_from(&mut offer_buf) => {
                if let Ok((n, peer)) = r {
                    p.offer_pc.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: p.offer_addr,
                            peer_addr: peer,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: bytes::BytesMut::from(&offer_buf[..n]),
                    }).ok();
                }
            }
            r = p.answer_socket.recv_from(&mut answer_buf) => {
                if let Ok((n, peer)) = r {
                    p.answer_pc.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: p.answer_addr,
                            peer_addr: peer,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: bytes::BytesMut::from(&answer_buf[..n]),
                    }).ok();
                }
            }
        }
    }

    assert!(
        offer_connected && dc_open,
        "peers never established a channel"
    );
    for (index, channel) in channels.iter().enumerate() {
        assert_eq!(
            sent[index], channel.messages,
            "offerer could not put all messages on the wire, so the receive side was never \
             the bottleneck and this test proved nothing"
        );
    }

    p.offer_pc.close()?;
    p.answer_pc.close()?;
    Ok(Outcome {
        received,
        peak_backlog_bytes,
    })
}

/// The property. A parked stream that is never resumed shows up here as a short tail:
/// everything up to the bound arrives and the rest is stranded in the reassembly queue
/// forever, because the peer has been throttled and no new chunk will re-trigger the drain.
fn assert_complete_and_ordered(received: &[usize], messages: usize) {
    let expected: Vec<usize> = (0..messages).collect();
    assert_eq!(
        received.len(),
        messages,
        "receiver got {} of {} messages — a stream parked by back-pressure was never \
         resumed (delivery stops at index {})",
        received.len(),
        messages,
        received
            .iter()
            .enumerate()
            .find(|(i, got)| **got != *i)
            .map(|(i, _)| i)
            .unwrap_or(received.len()),
    );
    assert_eq!(received, expected, "ordered channel delivered out of order");
}

#[tokio::test]
async fn test_slow_consumer_throttles_the_peer_without_losing_data() -> Result<()> {
    let channel = ChannelPlan {
        negotiated_id: NEGOTIATED_ID,
        messages: MESSAGE_COUNT,
        sizes: &[0],
    };
    let outcome = run_stalled_consumer(std::slice::from_ref(&channel), None).await?;
    assert_complete_and_ordered(&outcome.received[0], MESSAGE_COUNT);
    Ok(())
}

/// The byte bound, over a real connection: large messages would let 256 of them hold megabytes,
/// so a stalled consumer must instead see the backlog stop near the configured byte budget —
/// overshooting by at most one message — with two channels of different sizes sharing it, and
/// then everything delivered once it resumes.
#[tokio::test]
async fn test_slow_consumer_backlog_is_bounded_by_bytes_with_mixed_sizes() -> Result<()> {
    const BUDGET: usize = 64 * 1024;
    const LARGEST: usize = 60_000;
    let channels = [
        ChannelPlan {
            negotiated_id: NEGOTIATED_ID,
            messages: 120,
            sizes: &[1_000, 16_000, LARGEST],
        },
        ChannelPlan {
            negotiated_id: NEGOTIATED_ID + 2,
            messages: 120,
            sizes: &[200, 8_000],
        },
    ];

    let outcome = run_stalled_consumer(&channels, Some(BUDGET)).await?;

    for (received, channel) in outcome.received.iter().zip(&channels) {
        assert_complete_and_ordered(received, channel.messages);
    }
    assert!(
        outcome.peak_backlog_bytes <= BUDGET + LARGEST,
        "the stalled backlog held {} bytes, over the {BUDGET}-byte budget plus one \
         {LARGEST}-byte message",
        outcome.peak_backlog_bytes
    );
    // Without this the bound could pass by never being reached — a consumer that was never
    // really stalled would also stay under it.
    assert!(
        outcome.peak_backlog_bytes >= BUDGET,
        "the backlog peaked at {} bytes and never reached the {BUDGET}-byte budget, so the \
         bound was never exercised",
        outcome.peak_backlog_bytes
    );
    Ok(())
}

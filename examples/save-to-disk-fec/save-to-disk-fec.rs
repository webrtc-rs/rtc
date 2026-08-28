//! save-to-disk-fec: receive a FlexFEC-03 protected stream, rebuild what the path lost, save it.
//!
//! The receiving half of [`play-from-disk-fec`](../play-from-disk-fec). That example protects a VP8
//! stream with FlexFEC-03 and then deliberately drops media packets at the wire; this one accepts
//! the offer, rebuilds the dropped packets from the repair stream, and writes the result to an IVF
//! file. Run the two together and the file on this side should be whole despite the loss on that
//! one.
//!
//! Unlike the other examples here there is no pion counterpart — pion has no FlexFEC *receiver*.
//!
//! # What makes it work
//!
//! Two things, and neither is code:
//!
//! - **`video/flexfec-03` in the `MediaEngine`.** As the answerer this endpoint can only select
//!   payload types the offer listed, so the repair codec has to be registered here for the
//!   `a=rtpmap:49 flexfec-03/90000` in the offer to be answered. Without it the repair stream is
//!   never negotiated, `bind_remote_stream` never sees a `ssrc_fec`, and the decoder sits idle
//!   while the holes go straight to disk.
//! - **`FlexFec03Receive` at [`Slot::FecDecoder`]**, which is wire-ward of everything that inspects
//!   sequence numbers. A rebuilt packet has to be indistinguishable from one that arrived, so it
//!   must rejoin the stream before the NACK generator (which would otherwise ask the sender for a
//!   packet already being rebuilt here) and before the jitter buffer (which has to order it along
//!   with the rest).
//!
//! [`RecoveryCounter`] adds nothing to that — it only reports, so you can see the recovery happen.

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::{error, trace};
use rtc::interceptor::{
    Attribute, FlexFec03ReceiveBuilder, Interceptor, Packet, Registry, Slot, StreamInfo,
    TaggedPacket,
};
use rtc::media::io::Writer;
use rtc::media::io::ivf_reader::IVFFileHeader;
use rtc::media::io::ivf_writer::IVFWriter;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_FLEX_FEC03, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::event::RTCTrackEvent;
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpTransceiverInit, SSRC};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::time::{Duration, Instant};
use std::{fs, fs::OpenOptions, io::Write as IoWrite, str::FromStr};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, channel};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day duration

/// The FlexFEC-03 payload type, matching what `play-from-disk-fec` offers.
const FLEX_FEC_PAYLOAD_TYPE: u8 = 49;

/// Where [`RecoveryCounter`] sits: immediately application-ward of `Slot::FecDecoder` (6_000).
///
/// The read walk runs from the wire up to the application, so this is the first thing a packet
/// meets after the decoder has had its say — the earliest point at which
/// [`Attribute::RecoveredByFec`] exists to be counted. Anywhere wire-ward of the decoder it would
/// count nothing and report a recovery rate of zero on a connection that was recovering fine.
const RECOVERY_COUNTER_SLOT: usize = 6_500;

#[derive(Parser)]
#[command(name = "save-to-disk-fec")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "Receive a FlexFEC-03 protected stream and save the recovered video.")]
struct Cli {
    #[arg(short, long)]
    client: bool,
    #[arg(short, long)]
    debug: bool,
    #[arg(short, long, default_value_t = format!("INFO"))]
    log_level: String,
    #[arg(short, long, default_value_t = format!(""))]
    input_sdp_file: String,
    #[arg(short, long, default_value_t = format!(""))]
    output_log_file: String,
    #[arg(long, default_value_t = format!("127.0.0.1"))]
    host: String,
    #[arg(long, default_value_t = 0)]
    port: u16,
    #[arg(short, long, default_value = "output.ivf")]
    video: String,
}

/// Counts inbound media, separating what arrived from what the FEC decoder rebuilt.
///
/// Purely an observer: every packet is passed through untouched. It exists because recovery is
/// invisible from the outside — a rebuilt packet is deliberately indistinguishable from one that
/// arrived, which is what makes FEC work and also what makes it impossible to tell whether it is
/// working at all. The attribute is the one place that distinction survives, and it survives only
/// inside the chain.
///
/// The counts are reported from here rather than handed to the application. Attributes do not
/// cross into `poll_read` — `RTCMessage::RtpPacket` carries the packet and nothing else — so an
/// application that wants them either does this, or has the interceptor publish through a channel
/// as `bandwidth-estimation-from-disk` does with its estimate.
struct RecoveryCounter {
    /// Repair SSRCs, so repair traffic is not counted as media.
    fec_ssrcs: Vec<SSRC>,
    arrived: u64,
    recovered: u64,
    /// Repair packets that reached this far. Expected to stay at zero — see [`Self::report`].
    fec_packets: u64,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl RecoveryCounter {
    fn new() -> Self {
        Self {
            fec_ssrcs: Vec::new(),
            arrived: 0,
            recovered: 0,
            fec_packets: 0,
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }

    /// `Unrouted FEC` is expected to read 0: the decoder is wire-ward of here and consumes repair
    /// packets it has a decoder for. A non-zero value means repair packets arrived for a stream
    /// that never bound — negotiated but unusable — which otherwise looks identical to a path that
    /// simply lost nothing.
    fn report(&self) {
        let media = self.arrived + self.recovered;
        let rate = if media == 0 {
            0.0
        } else {
            self.recovered as f64 / media as f64
        };
        println!(
            "Stats: Media: {media} (arrived: {}, recovered: {}), Unrouted FEC: {}, Recovered: {:.4}%",
            self.arrived,
            self.recovered,
            self.fec_packets,
            rate * 100.0
        );
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for RecoveryCounter {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet {
            if self.fec_ssrcs.contains(&rtp_packet.header.ssrc) {
                // Repair packets are consumed by the decoder wire-ward of here, so seeing one
                // means it was not routed to a decoder — worth counting separately rather than
                // silently folding into the media total.
                self.fec_packets += 1;
            } else {
                if msg.message.has(&Attribute::RecoveredByFec) {
                    self.recovered += 1;
                } else {
                    self.arrived += 1;
                }

                if (self.arrived + self.recovered).is_multiple_of(100) {
                    self.report();
                }
            }
        }

        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for RecoveryCounter {
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        // The repair flow is bound in its own right, as a real RTP stream with its own SSRC and
        // sequence-number space — so this runs twice per protected stream. The repair flow's own
        // bind carries no `ssrc_fec` (it repairs nothing), and must not be mistaken for a media
        // stream that failed to negotiate FEC.
        if info.payload_type == FLEX_FEC_PAYLOAD_TYPE {
            return;
        }

        if let Some(ssrc_fec) = info.ssrc_fec {
            println!(
                "FEC negotiated: media SSRC {} protected by repair SSRC {ssrc_fec}",
                info.ssrc
            );
            self.fec_ssrcs.push(ssrc_fec);
        } else {
            // Worth saying out loud. Everything still runs, the file still fills up, and the loss
            // the sender induced goes straight to disk — a silent no-op is the failure mode this
            // example is most likely to hit.
            println!(
                "no FEC for media SSRC {} — nothing will be recovered",
                info.ssrc
            );
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        if let Some(ssrc_fec) = info.ssrc_fec {
            self.fec_ssrcs.retain(|ssrc| *ssrc != ssrc_fec);
        }
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let host = cli.host;
    let port = cli.port;
    let is_client = cli.client;
    let input_sdp_file = cli.input_sdp_file;
    let output_log_file = cli.output_log_file;
    let log_level = log::LevelFilter::from_str(&cli.log_level)?;
    let video_file = cli.video;
    if cli.debug {
        env_logger::Builder::new()
            .target(if !output_log_file.is_empty() {
                Target::Pipe(Box::new(
                    OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(output_log_file)?,
                ))
            } else {
                Target::Stdout
            })
            .format(|buf, record| {
                writeln!(
                    buf,
                    "{}:{} [{}] {} - {}",
                    record.file().unwrap_or("unknown"),
                    record.line().unwrap_or(0),
                    record.level(),
                    chrono::Local::now().format("%H:%M:%S.%6f"),
                    record.args()
                )
            })
            .filter(None, log_level)
            .init();
    }

    let (stop_tx, stop_rx) = channel::<()>(1);

    println!("Press Ctrl-C to stop");
    std::thread::spawn(move || {
        let mut stop_tx = Some(stop_tx);
        ctrlc::set_handler(move || {
            if let Some(stop_tx) = stop_tx.take() {
                let _ = stop_tx.try_send(());
            }
        })
        .expect("Error setting Ctrl-C handler");
    });

    if let Err(err) = run(stop_rx, host, port, input_sdp_file, is_client, video_file).await {
        eprintln!("run got error: {}", err);
    }

    Ok(())
}

async fn run(
    mut stop_rx: Receiver<()>,
    host: String,
    port: u16,
    input_sdp_file: String,
    is_client: bool,
    video_file: String,
) -> Result<()> {
    // Everything below is the RTC API! Thanks for using it ❤️.
    let socket = UdpSocket::bind(format!("{host}:{port}")).await?;
    let local_addr = socket.local_addr()?;

    let setting_engine = SettingEngineBuilder::new()
        .with_answering_dtls_role(if is_client {
            RTCDtlsRole::Client
        } else {
            RTCDtlsRole::Server
        })
        .build();

    // Create a MediaEngine object to configure the supported codec
    let mut media_engine = MediaEngine::default();

    let video_codec = RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_VP8.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "".to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: 96,
    };
    media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;

    // The repair codec. An answerer selects from what the offer listed, so this has to be here for
    // the offer's `a=rtpmap:49 flexfec-03/90000` to be answered — and if it is not, everything
    // still runs and nothing is ever recovered.
    let fec_codec = RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_FLEX_FEC03.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "repair-window=10000000".to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: FLEX_FEC_PAYLOAD_TYPE,
    };
    media_engine.register_codec(fec_codec, RtpCodecKind::Video)?;

    // The interceptor chain. Slots decide the order, not the sequence of these calls. On the read
    // walk, from the wire up to the application:
    //
    //   6_000  FlexFec03Receive — rebuilds media from the repair stream
    //   6_500  RecoveryCounter  — reports what was rebuilt
    //   …             everything `register_default_interceptors` adds
    let registry = Registry::new()
        .with(Slot::FecDecoder, FlexFec03ReceiveBuilder::new().build())
        .with(Slot::from(RECOVERY_COUNTER_SLOT), RecoveryCounter::new());

    // Use the default set of Interceptors
    let registry = register_default_interceptors(registry, &mut media_engine)?;

    // Create RTC peer connection configuration
    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_string()],
            ..Default::default()
        }])
        .build();

    // Create a new RTCPeerConnection
    let mut peer_connection = RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?;

    // Allow us to receive 1 video track
    peer_connection.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            ..Default::default()
        }),
    )?;

    // Wait for the offer to be pasted
    print!("Paste offer from play-from-disk-fec and press Enter: ");

    let line = if input_sdp_file.is_empty() {
        signal::must_read_stdin()?
    } else {
        fs::read_to_string(&input_sdp_file)?
    };
    let desc_data = signal::decode(line.as_str())?;
    let offer = serde_json::from_str::<RTCSessionDescription>(&desc_data)?;
    println!("Offer received: {}", offer);

    // Set the remote SessionDescription
    peer_connection.set_remote_description(Instant::now(), offer)?;

    // Add local candidate
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: local_addr.ip().to_string(),
            port: local_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    let local_candidate_init = RTCIceCandidate::from(&candidate).to_json()?;
    peer_connection.add_local_candidate(local_candidate_init)?;

    // Create an answer
    let answer = peer_connection.create_answer(None)?;

    // Sets the LocalDescription
    peer_connection.set_local_description(Instant::now(), answer)?;

    // Output the answer in base64 so we can paste it into play-from-disk-fec
    if let Some(local_desc) = peer_connection.local_description() {
        println!("answer created: {}", local_desc);
        let json_str = serde_json::to_string(&local_desc)?;
        let b64 = signal::encode(&json_str);
        println!("{b64}");
    } else {
        println!("generate local_description failed!");
        return Err(Error::ErrPeerConnLocalDescriptionNil.into());
    }

    println!("listening {}...", socket.local_addr()?);

    let mut video_writer = IVFWriter::new(
        File::create(&video_file)?,
        &IVFFileHeader {
            signature: *b"DKIF",      // 0-3
            version: 0,               // 4-5
            header_size: 32,          // 6-7
            four_cc: *b"VP80",        // 8-11
            width: 640,               // 12-13
            height: 480,              // 14-15
            timebase_denominator: 30, // 16-19
            timebase_numerator: 1,    // 20-23
            num_frames: 900,          // 24-27
            unused: 0,                // 28-31
        },
    )?;

    let mut track_id2_receiver_id = HashMap::new();
    let mut announced = false;

    let mut buf = vec![0; 2000];
    'EventLoop: loop {
        while let Some(msg) = peer_connection.poll_write() {
            match socket.send_to(&msg.message, msg.transport.peer_addr).await {
                Ok(n) => {
                    trace!(
                        "socket write to {} with bytes {}",
                        msg.transport.peer_addr, n
                    );
                }
                Err(err) => {
                    error!(
                        "socket write to {} with error {}",
                        msg.transport.peer_addr, err
                    );
                }
            }
        }

        while let Some(event) = peer_connection.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(ice_connection_state) => {
                    println!("ICE Connection State has changed: {ice_connection_state}");
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(peer_connection_state) => {
                    println!("Peer Connection State has changed: {peer_connection_state}");
                    if peer_connection_state == RTCPeerConnectionState::Failed {
                        eprintln!("Peer Connection State has gone to failed! Exiting...");
                        break 'EventLoop;
                    } else if peer_connection_state == RTCPeerConnectionState::Connected {
                        println!("Ctrl-C play-from-disk-fec, or this side, to stop the demo");
                    }
                }
                RTCPeerConnectionEvent::OnTrack(track_event) => match track_event {
                    RTCTrackEvent::OnOpen(init) => {
                        track_id2_receiver_id.insert(init.track_id, init.receiver_id);
                    }
                    RTCTrackEvent::OnClose(_track_id) => {}
                    _ => {}
                },
                _ => {}
            }
        }

        while let Some(TaggedRTCMessage { message, .. }) = peer_connection.poll_read() {
            match message {
                RTCMessage::RtpPacket(track_id, rtp_packet) => {
                    if !announced {
                        let receiver_id = *track_id2_receiver_id
                            .get(&track_id)
                            .ok_or(Error::ErrRTPReceiverNotExisted)?;
                        let rtp_receiver = peer_connection
                            .rtp_receiver(receiver_id)
                            .ok_or(Error::ErrRTPReceiverNotExisted)?;
                        let track = rtp_receiver.track();
                        let codec = track
                            .codec(
                                track
                                    .ssrcs()
                                    .next()
                                    .ok_or(Error::ErrRTPReceiverForSSRCTrackStreamNotFound)?,
                            )
                            .ok_or(Error::ErrCodecNotFound)?;
                        println!(
                            "Got {} track, saving to disk as {video_file}",
                            codec.mime_type
                        );
                        announced = true;
                    }

                    // Recovered packets arrive here exactly like any other: by the time a packet
                    // reaches the application the FEC decoder has already put it back in the
                    // stream, so there is nothing to do differently. That is the whole point.
                    video_writer.write_rtp(&rtp_packet)?;
                }
                RTCMessage::RtcpPacket(_, _) => {}
                RTCMessage::DataChannelMessage(_, _) => {}
                _ => {}
            }
        }

        // Poll peer_connection to get next timeout
        let eto = peer_connection
            .poll_timeout()
            .unwrap_or(Instant::now() + DEFAULT_TIMEOUT_DURATION);

        let delay_from_now = eto
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_secs(0));
        if delay_from_now.is_zero() {
            peer_connection.handle_timeout(Instant::now())?;
            continue;
        }

        let timer = tokio::time::sleep(delay_from_now);
        tokio::pin!(timer);

        tokio::select! {
            biased;

            _ = stop_rx.recv() => {
                trace!("pipeline socket exit loop");
                break 'EventLoop;
            }
            _ = timer.as_mut() => {
                peer_connection.handle_timeout(Instant::now())?;
            }
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((n, peer_addr)) => {
                        trace!("socket read {} bytes", n);
                        peer_connection.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr,
                                peer_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message: BytesMut::from(&buf[..n]),
                        })?;
                    }
                    Err(err) => {
                        eprintln!("socket read error {}", err);
                        break 'EventLoop;
                    }
                }
            }
        }
    }

    video_writer.close()?;
    println!("Done writing {video_file}");

    peer_connection.close()?;

    Ok(())
}

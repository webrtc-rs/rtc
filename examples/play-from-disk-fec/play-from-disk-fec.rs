//! play-from-disk-fec: send video to a browser with FlexFEC-03 repair, over a path that drops
//! packets on purpose.
//!
//! A port of pion's `play-from-disk-fec`. The point of the example is not that video plays — that
//! is `play-from-disk-vpx` — but that it *keeps* playing while a fraction of the media packets are
//! discarded on the way out. A `DropFilter` interceptor stands at the wire end of the chain and
//! throws media away after everything else has run, which is what makes the recovery visible: the
//! browser receives a stream with holes in it and reconstructs the missing packets from the repair
//! stream.
//!
//! The drop sits at [`DROP_FILTER_SLOT`], below every built-in interceptor, because it is standing
//! in for the network. Anywhere higher and some sender-side mechanism would be told about a loss
//! the network caused: above the FEC encoder, nothing would ever be protected and the example would
//! recover nothing; above the NACK responder, dropped packets would never enter the retransmission
//! buffer; above congestion control, the estimator would not count the bytes that were sent.

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::{error, trace};
use rtc::interceptor::{
    FlexFec03SendBuilder, Interceptor, Packet, Registry, Slot, StreamInfo, TaggedPacket,
};
use rtc::media::io::ivf_reader::IVFReader;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_FLEX_FEC03, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp;
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters, RTCRtpFecParameters,
};
use rtc::rtp_transceiver::{RTCRtpSenderId, SSRC};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{
    fs,
    fs::{File, OpenOptions},
    io::{BufReader, Write},
    str::FromStr,
};
use tokio::net::UdpSocket;
use tokio::sync::{
    Notify,
    mpsc::{Receiver, Sender, channel},
};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day duration
const RTP_OUTBOUND_MTU: usize = 1200;

/// The FlexFEC-03 payload type, matching pion's `ConfigureFlexFEC03(49, …)`.
const FLEX_FEC_PAYLOAD_TYPE: u8 = 49;

/// One repair packet per ten media packets: it recovers a single loss anywhere in the block.
///
/// The example drops far more than that — see [`DropFilter`] — so the browser will still see gaps.
/// That is the honest picture: FEC narrows the loss it is sized for and no more, and a block that
/// loses two of ten is not recoverable however the repair is arranged.
const NUM_MEDIA_PACKETS: u32 = 10;
const NUM_FEC_PACKETS: u32 = 1;

/// Where [`DropFilter`] sits: below `Slot::CongestionControl` (1_000), the lowest built-in slot.
///
/// The write walk runs from the application down to the wire, so this is the last thing a
/// departing packet meets — which is exactly where a network loss belongs. It matches where pion's
/// `packetDropInterceptorFactory` ends up, since pion's chain puts the first-registered interceptor
/// closest to the wire.
const DROP_FILTER_SLOT: usize = 500;

#[derive(Parser)]
#[command(name = "play-from-disk-fec")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "An example of play-from-disk with FlexFEC-03 over a lossy path.")]
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
    #[arg(short, long)]
    video: String,
    /// Drop one media packet in this many. `0` disables dropping, which is the way to see what the
    /// stream looks like without the loss this example exists to survive.
    #[arg(long, default_value_t = 5)]
    drop_one_in: u32,
}

/// Discards outgoing media packets to simulate a lossy path, and counts what it did.
///
/// # Where it sits, and why that matters
///
/// At [`DROP_FILTER_SLOT`], below every built-in interceptor. The write walk runs from the
/// application down to the wire, so this is the last thing a departing packet meets: the FEC
/// encoder has already built its repair block from the complete stream, the NACK responder has
/// already buffered the packet for retransmission, and congestion control has already counted it.
/// Then this throws some of that media away — which is precisely what a lossy path does, and why
/// the repair packets still go out for the receiver to rebuild from.
///
/// Every slot above changes what is being demonstrated rather than how much is lost. Above the FEC
/// encoder, nothing is ever protected and the example recovers nothing while appearing to run
/// correctly. Above the NACK responder, dropped packets never enter the retransmission buffer, so
/// the sender cannot answer a NACK for a packet the network lost. Above congestion control, the
/// estimator undercounts what was actually sent.
///
/// Repair packets are never dropped: they are identified by the FEC SSRC the stream negotiated and
/// pass through untouched. Dropping them too would only add a second, uninteresting variable.
struct DropFilter {
    /// Drop one media packet in this many; `0` disables.
    drop_one_in: u32,
    /// The repair SSRC for each protected stream, so repair traffic is exempt.
    fec_ssrcs: Vec<SSRC>,
    media_packets: u64,
    fec_packets: u64,
    dropped_packets: u64,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl DropFilter {
    fn new(drop_one_in: u32) -> Self {
        Self {
            drop_one_in,
            fec_ssrcs: Vec::new(),
            media_packets: 0,
            fec_packets: 0,
            dropped_packets: 0,
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }

    fn report(&self) {
        let ratio = if self.media_packets == 0 {
            0.0
        } else {
            self.dropped_packets as f64 / self.media_packets as f64
        };
        println!(
            "Stats: Media: {}, FEC: {}, Dropped: {}, Drop ratio: {:.4}%",
            self.media_packets,
            self.fec_packets,
            self.dropped_packets,
            ratio * 100.0
        );
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for DropFilter {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let Packet::Rtp(ref rtp_packet) = msg.message.packet else {
            // RTCP is control traffic; dropping it would break feedback rather than demonstrate
            // recovery.
            self.write_queue.push_back(msg);
            return Ok(());
        };

        // Repair packets travel on their own SSRC and are never dropped.
        if self.fec_ssrcs.contains(&rtp_packet.header.ssrc) {
            self.fec_packets += 1;
            self.write_queue.push_back(msg);
            return Ok(());
        }

        if self.media_packets % 100 == 0 {
            self.report();
        }
        self.media_packets += 1;

        if self.drop_one_in != 0 && self.media_packets % self.drop_one_in as u64 == 0 {
            self.dropped_packets += 1;
            // Swallowed: the packet is not queued, so nothing below this interceptor — the pacer,
            // the TWCC sender, the send history — ever sees it, exactly as if the path had lost it.
            return Ok(());
        }

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

impl Interceptor for DropFilter {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        // Learn the repair SSRC from the stream that negotiated FEC, so `handle_write` can tell
        // repair from media without guessing.
        if let Some(ssrc_fec) = info.ssrc_fec {
            self.fec_ssrcs.push(ssrc_fec);
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        if let Some(ssrc_fec) = info.ssrc_fec {
            self.fec_ssrcs.retain(|ssrc| *ssrc != ssrc_fec);
        }
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
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
    let drop_one_in = cli.drop_one_in;
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

    if !Path::new(&video_file).exists() {
        return Err(anyhow::anyhow!("video file: '{}' not exist", video_file));
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

    if let Err(err) = run(
        stop_rx,
        host,
        port,
        input_sdp_file,
        is_client,
        video_file,
        drop_one_in,
    )
    .await
    {
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
    drop_one_in: u32,
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
        ..Default::default()
    };
    media_engine.register_codec(video_codec.clone(), RtpCodecKind::Video)?;

    // The repair stream is a codec in its own right, and both halves of the association have to be
    // negotiated: a FEC SSRC with no payload type is not a usable repair flow, and the encoder
    // declines to bind without both.
    let fec_codec = RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_FLEX_FEC03.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "repair-window=10000000".to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: FLEX_FEC_PAYLOAD_TYPE,
        ..Default::default()
    };
    media_engine.register_codec(fec_codec, RtpCodecKind::Video)?;

    // The interceptor chain. Slots decide the order, not the sequence of these calls. On the write
    // walk, from the application down to the wire:
    //
    //   5_000  FlexFec03Send  — builds the repair block from the complete media stream
    //   …             everything `register_default_interceptors` adds, plus congestion control
    //     500  DropFilter     — the "network", discarding media last of all
    let registry = Registry::new()
        .with(
            Slot::FecEncoder,
            FlexFec03SendBuilder::new()
                .with_num_media_packets(NUM_MEDIA_PACKETS)
                .with_num_fec_packets(NUM_FEC_PACKETS)
                .build(),
        )
        .with(Slot::from(DROP_FILTER_SLOT), DropFilter::new(drop_one_in));

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

    let ssrc: SSRC = rand::random::<u32>();
    let fec_ssrc: SSRC = rand::random::<u32>();

    let output_track = MediaStreamTrack::new(
        "webrtc-rs-stream-id-video".to_owned(),
        "webrtc-rs-track-id-video".to_owned(),
        "webrtc-rs-track-label-video".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                // The other half of the repair association: the SSRC the encoder sends repair
                // packets on, and the one `DropFilter` exempts. Naming it here rather than
                // letting one be minted keeps every SSRC this example puts on the wire explicit.
                fec: Some(RTCRtpFecParameters { ssrc: fec_ssrc }),
                ..Default::default()
            },
            codec: video_codec.rtp_codec.clone(),
            ..Default::default()
        }],
    );

    // Add this newly created track to the PeerConnection
    let video_sender_id = peer_connection.add_track(output_track)?;

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

    // Unlike most examples here, this one *offers* rather than answers, and the direction is not
    // cosmetic: it is the only way the repair stream gets negotiated with Chrome.
    //
    // Chrome accepts `video/flexfec-03` when it is offered to it, but does not put it in its own
    // offers. As the answerer we could only choose among the payload types the browser listed, so
    // there would be no FEC to select, the encoder would never bind, and the example would run to
    // completion showing dropped video and no recovery.
    let offer = peer_connection.create_offer(None)?;

    // Sets the LocalDescription, and starts our UDP listeners
    peer_connection.set_local_description(Instant::now(), offer)?;

    // Output the offer in base64 so we can paste it in browser
    if let Some(local_desc) = peer_connection.local_description() {
        println!("offer created: {}", local_desc);
        let json_str = serde_json::to_string(&local_desc)?;
        let b64 = signal::encode(&json_str);
        println!("{b64}");
    } else {
        println!("generate local_description failed!");
        return Err(Error::ErrPeerConnLocalDescriptionNil.into());
    }

    // Wait for the answer to be pasted
    let line = if input_sdp_file.is_empty() {
        println!("Paste answer from browser and press Enter:");
        signal::must_read_stdin()?
    } else {
        // The file is read on Enter, not at startup: the browser has not produced the answer yet
        // when this process begins, so there would be nothing there to read.
        println!("Save answer from browser to {input_sdp_file} and press Enter:");
        signal::must_read_stdin()?;
        fs::read_to_string(&input_sdp_file)?
    };
    let desc_data = signal::decode(line.as_str())?;
    let answer = serde_json::from_str::<RTCSessionDescription>(&desc_data)?;
    println!("answer received: {}", answer);

    // Apply the answer as the remote description
    peer_connection.set_remote_description(Instant::now(), answer)?;

    println!("listening {}...", socket.local_addr()?);
    if drop_one_in == 0 {
        println!("dropping disabled: this is play-from-disk with FEC and no induced loss");
    } else {
        println!(
            "dropping 1 media packet in {drop_one_in} at the wire; \
             repair is {NUM_FEC_PACKETS} per {NUM_MEDIA_PACKETS}"
        );
    }

    let (message_tx, mut message_rx) = channel::<(RTCRtpSenderId, rtp::Packet)>(8);
    let notify_tx = Arc::new(Notify::new());
    let video_notify_rx = notify_tx.clone();

    // Spawn video streaming task
    let (video_done_tx, mut video_done_rx) = channel::<()>(1);
    let video_message_tx = message_tx.clone();
    let video_codec_for_task = video_codec.clone();
    tokio::spawn(async move {
        if let Err(err) = stream_video(
            (ssrc, video_codec_for_task),
            video_file,
            video_sender_id,
            video_notify_rx,
            video_done_tx,
            video_message_tx,
        )
        .await
        {
            eprintln!("video streaming error: {}", err);
        }
    });

    let mut connection_established = false;
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
                        println!("Peer Connection State has gone to connected!");
                        connection_established = true;
                        notify_tx.notify_waiters();
                    }
                }
                _ => {}
            }
        }

        if connection_established && video_done_rx.try_recv().is_ok() {
            println!("All video frames parsed and sent");
            break 'EventLoop;
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
            res = message_rx.recv() => {
                match res {
                    Some((rtp_sender_id, mut packet)) => {
                        let mut rtp_sender = peer_connection
                            .rtp_sender(rtp_sender_id)
                            .ok_or(Error::ErrRTPReceiverNotExisted)?;

                        packet.header.ssrc = rtp_sender
                            .track()
                            .ssrcs()
                            .next()
                            .ok_or(Error::ErrSenderWithNoSSRCs)?;
                        // The disk file was packetized with a fixed local payload type, and
                        // write_rtp requires the packet's PT to match a negotiated codec. Take the
                        // media codec's — not the repair codec's, which is also on this sender's
                        // list and would send the frame as if it were FEC.
                        packet.header.payload_type = rtp_sender
                            .get_parameters()
                            .rtp_parameters
                            .codecs
                            .iter()
                            .find(|codec| {
                                !codec
                                    .rtp_codec
                                    .mime_type
                                    .to_lowercase()
                                    .contains("flexfec")
                            })
                            .map(|codec| codec.payload_type)
                            .ok_or(Error::ErrRTPTransceiverCodecUnsupported)?;
                        rtp_sender.write_rtp(Instant::now(), packet)?;
                    }
                    None => {
                        eprintln!("message_rx.recv() is closed");
                        break 'EventLoop;
                    }
                }
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

    peer_connection.close()?;

    Ok(())
}

async fn stream_video(
    (ssrc, codec): (SSRC, RTCRtpCodecParameters),
    video_file_name: String,
    video_sender_id: RTCRtpSenderId,
    video_notify_rx: Arc<Notify>,
    video_done_tx: Sender<()>,
    video_message_tx: Sender<(RTCRtpSenderId, rtp::Packet)>,
) -> Result<()> {
    // Wait for connection established
    video_notify_rx.notified().await;

    println!("play video from disk file {video_file_name}");

    let mut packetizer = rtp::packetizer::new_packetizer(
        Instant::now(),
        RTP_OUTBOUND_MTU,
        codec.payload_type,
        ssrc,
        codec.rtp_codec.payloader()?,
        Box::new(rtp::sequence::new_random_sequencer()),
        codec.rtp_codec.clock_rate,
    );

    // Open a IVF file and start reading using our IVFReader
    let file = File::open(&video_file_name)?;
    let reader = BufReader::new(file);
    let (mut ivf, header) = IVFReader::new(reader)?;

    // Send the file a frame at a time, paced at playback speed. Sending it all at once would
    // produce loss of its own and confuse the loss this example induces on purpose.
    let sleep_time = Duration::from_millis(
        ((1000 * header.timebase_numerator) / header.timebase_denominator) as u64,
    );
    let mut ticker = tokio::time::interval(sleep_time);

    loop {
        let frame = match ivf.parse_next_frame() {
            Ok((frame, _)) => frame,
            Err(err) => {
                println!("All video frames parsed and sent: {err}");
                break;
            }
        };

        let sample_duration = Duration::from_millis(40);
        let samples = (sample_duration.as_secs_f64() * codec.rtp_codec.clock_rate as f64) as u32;
        let packets = packetizer.packetize(Instant::now(), &frame.freeze(), samples)?;
        for packet in packets {
            video_message_tx.send((video_sender_id, packet)).await?;
        }

        let _ = ticker.tick().await;
    }

    let _ = video_done_tx.try_send(());

    Ok(())
}

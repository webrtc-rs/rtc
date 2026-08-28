//! bandwidth-estimation-from-disk: switch between three pre-encoded renditions as the estimate moves.
//!
//! A port of pion's `bandwidth-estimation-from-disk`. Send-side congestion control produces one
//! number — how many bits per second the path looks willing to carry — and it is the sender's job
//! to meet it. This example meets it the crudest way that works: three IVF files encoded at 300
//! kbps, 1 Mbps and 2.5 Mbps, and a switch to whichever one fits.
//!
//! # Getting the estimate out
//!
//! The estimator is a plain object behind [`BandwidthEstimator`], but `configure_congestion_control`
//! takes it by value and it ends up boxed inside the chain, where the application cannot reach it.
//! So the number has to be pushed rather than pulled: [`ReportingEstimator`] wraps the real
//! estimator, delegates every call, and publishes the target on a `watch` channel that the
//! streaming task reads.
//!
//! That wrapper is the whole of the integration, and it is worth noticing what it is *not*. There
//! is no callback registration, no event variant, no new peer-connection API — a
//! `BandwidthEstimator` is a function from acknowledgements to a number, and anything that wants to
//! observe that number can sit in the same place the algorithm does.

use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Target;
use log::{error, trace};
use rtc::interceptor::{BandwidthEstimator, EstimatorStats, Gcc, PacketReport, Registry};
use rtc::media::io::ivf_reader::IVFReader;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::{
    CongestionFeedback, configure_congestion_control, register_default_interceptors,
};
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceServer;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::rtp;
use rtc::rtp::packetizer::Packetizer;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
};
use rtc::rtp_transceiver::{RTCRtpSenderId, SSRC};
use rtc::sansio::Protocol;
use rtc::shared::error::Error;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::io::{Seek, SeekFrom};
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
    watch,
};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day duration
const RTP_OUTBOUND_MTU: usize = 1200;

/// The IVF file header, which `reset_reader` does not re-parse — a reader handed to it must
/// already be positioned past it.
const IVF_HEADER_SIZE: u64 = 32;

/// The renditions, cheapest first. Each entry is the file and the bitrate it was encoded at; the
/// estimate is compared against these numbers to decide which one to send.
const QUALITY_LEVELS: [(&str, f64); 3] = [
    ("low.ivf", 300_000.0),
    ("med.ivf", 1_000_000.0),
    ("high.ivf", 2_500_000.0),
];

/// Where the estimator starts. The lowest rendition, so the first seconds of the call are
/// deliverable on a path that turns out to be poor, and probing climbs from there. Starting at the
/// highest instead would open the call by congesting the path it is still measuring.
const INITIAL_BITRATE: f64 = 300_000.0;
const MIN_BITRATE: f64 = 100_000.0;
const MAX_BITRATE: f64 = 5_000_000.0;

#[derive(Parser)]
#[command(name = "bandwidth-estimation-from-disk")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(version = "0.1.0")]
#[command(about = "An example of bandwidth estimation driving quality selection.")]
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
    /// Directory holding `low.ivf`, `med.ivf` and `high.ivf`.
    #[arg(short, long, default_value_t = format!("."))]
    video_dir: String,
}

/// Delegates to `inner` and publishes its target bitrate after every update.
///
/// The estimator is where an application belongs if it wants to watch the estimate: it is the one
/// object in the congestion control loop that is application-supplied, so wrapping it costs nothing
/// and reaches into no internals. Every method forwards; the only addition is the `send_replace`
/// after each call that can move the number.
///
/// `target_bitrate` takes `&self`, so publishing cannot happen there. It happens after
/// [`on_reports`](BandwidthEstimator::on_reports) and
/// [`handle_timeout`](BandwidthEstimator::handle_timeout), which the interceptor's own contract
/// names as the two points where the estimate can change.
struct ReportingEstimator<E: BandwidthEstimator> {
    inner: E,
    target: watch::Sender<f64>,
}

impl<E: BandwidthEstimator> ReportingEstimator<E> {
    fn new(inner: E) -> (Self, watch::Receiver<f64>) {
        let (target, target_rx) = watch::channel(inner.target_bitrate());
        (Self { inner, target }, target_rx)
    }

    fn publish(&self) {
        // `send_replace` rather than `send`: a dropped receiver is not an error here, and the
        // estimator must not start failing because the streaming task has finished.
        self.target.send_replace(self.inner.target_bitrate());
    }
}

impl<E: BandwidthEstimator> BandwidthEstimator for ReportingEstimator<E> {
    fn on_reports(&mut self, now: Instant, reports: &[PacketReport]) {
        self.inner.on_reports(now, reports);
        self.publish();
    }

    fn target_bitrate(&self) -> f64 {
        self.inner.target_bitrate()
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.inner.handle_timeout(now);
        self.publish();
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.inner.poll_timeout()
    }

    fn stats(&self) -> EstimatorStats {
        self.inner.stats()
    }
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
    let video_dir = cli.video_dir;
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

    // All three renditions have to exist before the call starts: discovering a missing file at the
    // moment the estimate says to switch would fail mid-stream, long after the mistake was made.
    for (file_name, _) in QUALITY_LEVELS {
        let path = Path::new(&video_dir).join(file_name);
        if !path.exists() {
            return Err(anyhow::anyhow!("video file '{}' not found", path.display()));
        }
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

    if let Err(err) = run(stop_rx, host, port, input_sdp_file, is_client, video_dir).await {
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
    video_dir: String,
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

    // Send-side congestion control, around Google Congestion Control. `configure_congestion_control`
    // places the send history, the pacer, the TWCC sender and the TWCC receiver at the slots the
    // chain reserves for them, and registers the `transport-cc` feedback and header extension the
    // remote needs in order to report arrivals at all — without which the estimator holds its
    // initial rate forever and never says anything is wrong.
    let (estimator, target_rx) =
        ReportingEstimator::new(Gcc::new(INITIAL_BITRATE, MIN_BITRATE, MAX_BITRATE));
    let registry = configure_congestion_control(
        Registry::new(),
        estimator,
        CongestionFeedback::Twcc,
        &mut media_engine,
    )?;

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

    let output_track = MediaStreamTrack::new(
        "webrtc-rs-stream-id-video".to_owned(),
        "webrtc-rs-track-id-video".to_owned(),
        "webrtc-rs-track-label-video".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: video_codec.rtp_codec.clone(),
            ..Default::default()
        }],
    );

    // Add this newly created track to the PeerConnection
    let video_sender_id = peer_connection.add_track(output_track)?;

    // Wait for the offer to be pasted
    print!("Paste offer from browser and press Enter: ");

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

    // Output the answer in base64 so we can paste it in browser
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
    println!(
        "starting at {} kbps; switching between {}",
        (INITIAL_BITRATE / 1000.0) as u64,
        QUALITY_LEVELS
            .iter()
            .map(|(file_name, _)| *file_name)
            .collect::<Vec<_>>()
            .join(", ")
    );

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
            video_dir,
            video_sender_id,
            video_notify_rx,
            video_done_tx,
            video_message_tx,
            target_rx.clone(),
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
            println!("video streaming stopped");
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

/// Opens one rendition, positioned past the IVF file header so `reset_reader` can use it directly.
fn open_rendition(video_dir: &str, file_name: &str) -> Result<BufReader<File>> {
    let mut file = File::open(Path::new(video_dir).join(file_name))?;
    file.seek(SeekFrom::Start(IVF_HEADER_SIZE))?;
    Ok(BufReader::new(file))
}

/// Whether a VP8 payload is a keyframe.
///
/// Bit 0 of the first byte of the uncompressed data chunk is the frame type (RFC 6386 §9.1): 0 for
/// a key frame, 1 for an interframe. This is what makes a mid-stream switch decodable — an
/// interframe from a file the receiver has not been watching references a reference frame it does
/// not have, and produces a smear until the next keyframe arrives.
fn is_keyframe(frame: &[u8]) -> bool {
    frame.first().is_some_and(|byte| byte & 0x1 == 0)
}

#[allow(clippy::too_many_arguments)]
async fn stream_video(
    (ssrc, codec): (SSRC, RTCRtpCodecParameters),
    video_dir: String,
    video_sender_id: RTCRtpSenderId,
    video_notify_rx: Arc<Notify>,
    video_done_tx: Sender<()>,
    video_message_tx: Sender<(RTCRtpSenderId, rtp::Packet)>,
    target_rx: watch::Receiver<f64>,
) -> Result<()> {
    // Wait for connection established
    video_notify_rx.notified().await;

    let mut current_quality = 0usize;
    println!("starting with {}", QUALITY_LEVELS[current_quality].0);

    // One packetizer across every rendition. Switching files must not restart the sequence numbers
    // or the timestamps: to the receiver this is one continuous stream whose content happens to
    // change resolution, and a discontinuity would look like the stream had been replaced.
    let mut packetizer = rtp::packetizer::new_packetizer(
        Instant::now(),
        RTP_OUTBOUND_MTU,
        codec.payload_type,
        ssrc,
        codec.rtp_codec.payloader()?,
        Box::new(rtp::sequence::new_random_sequencer()),
        codec.rtp_codec.clock_rate,
    );

    // The header comes from the first rendition; all three are encoded from the same source, so
    // they share a timebase.
    let first = File::open(Path::new(&video_dir).join(QUALITY_LEVELS[current_quality].0))?;
    let (mut ivf, header) = IVFReader::new(BufReader::new(first))?;

    // Pace at playback speed. Sending the file as fast as it parses would saturate the path and
    // make the estimator measure this example's own impatience rather than the network.
    let frame_duration = Duration::from_millis(
        ((1000 * header.timebase_numerator) / header.timebase_denominator) as u64,
    );
    let samples = (frame_duration.as_secs_f64() * codec.rtp_codec.clock_rate as f64) as u32;
    let mut ticker = tokio::time::interval(frame_duration);

    let mut current_timestamp = 0u64;

    loop {
        ticker.tick().await;

        let target_bitrate = *target_rx.borrow();

        // Two comparisons, and note they use different levels. Dropping down is judged against the
        // rendition being sent — if the path will not carry what is already going out, that is a
        // problem now. Climbing is judged against the *next* rendition, because there is no point
        // moving up until the estimate covers what the move would cost.
        let new_quality =
            if current_quality != 0 && target_bitrate < QUALITY_LEVELS[current_quality].1 {
                println!("target_bitrate is changed to {}", target_bitrate);
                Some(current_quality - 1)
            } else if current_quality + 1 < QUALITY_LEVELS.len()
                && target_bitrate > QUALITY_LEVELS[current_quality + 1].1
            {
                println!("target_bitrate is changed to {}", target_bitrate);
                Some(current_quality + 1)
            } else {
                None
            };

        let frame = match new_quality {
            Some(new_quality) => {
                let frame = switch_quality_level(
                    &video_dir,
                    &mut ivf,
                    current_quality,
                    new_quality,
                    current_timestamp,
                );
                // Committed even if the scan below found nothing usable: the reader is already on
                // the new file, so leaving `current_quality` behind would make the next reset
                // reopen a rendition that is not the one being read.
                current_quality = new_quality;
                frame
            }
            None => ivf.parse_next_frame().ok(),
        };

        let Some((frame, frame_header)) = frame else {
            // End of file — loop the rendition rather than stopping. The example is about the
            // estimate, and it needs a stream that outlives the file.
            ivf.reset_reader(reset_to(&video_dir, QUALITY_LEVELS[current_quality].0));
            current_timestamp = 0;
            continue;
        };

        current_timestamp = frame_header.timestamp;

        let packets = packetizer.packetize(Instant::now(), &frame.freeze(), samples)?;
        for packet in packets {
            if video_message_tx
                .send((video_sender_id, packet))
                .await
                .is_err()
            {
                let _ = video_done_tx.try_send(());
                return Ok(());
            }
        }
    }
}

/// A reset closure for [`IVFReader::reset_reader`], opening `file_name` past its header.
fn reset_to(video_dir: &str, file_name: &str) -> rtc::media::io::ResetFn<BufReader<File>> {
    let video_dir = video_dir.to_owned();
    let file_name = file_name.to_owned();
    Box::new(move |_bytes_read| open_rendition(&video_dir, &file_name).expect("reopen rendition"))
}

/// Switches to `new_quality` and returns the first frame that can be decoded from it.
///
/// Two conditions have to hold for that frame, and dropping either one produces a switch that
/// looks like it worked. It must be a **keyframe**, or the receiver decodes it against reference
/// frames from a file it was never sent. And its timestamp must be at or after the last one sent,
/// or the stream jumps backwards in time and the receiver discards everything until it catches up.
fn switch_quality_level(
    video_dir: &str,
    ivf: &mut IVFReader<BufReader<File>>,
    current_quality: usize,
    new_quality: usize,
    current_timestamp: u64,
) -> Option<(BytesMut, rtc::media::io::ivf_reader::IVFFrameHeader)> {
    println!(
        "Switching from {} to {}",
        QUALITY_LEVELS[current_quality].0, QUALITY_LEVELS[new_quality].0
    );

    ivf.reset_reader(reset_to(video_dir, QUALITY_LEVELS[new_quality].0));

    loop {
        let (frame, frame_header) = ivf.parse_next_frame().ok()?;
        if frame_header.timestamp >= current_timestamp && is_keyframe(&frame) {
            return Some((frame, frame_header));
        }
    }
}

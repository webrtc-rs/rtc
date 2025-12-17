use anyhow::Result;
use bytes::BytesMut;
use clap::Parser;
use log::{error, info, trace, warn};
use sansio_executor::LocalExecutorBuilder;
use shared::{Protocol, TaggedBytesMut, TransportContext, TransportProtocol};
use std::time::{Duration, Instant};
use std::{io::Write, str::FromStr};
use tokio::{net::UdpSocket, sync::broadcast};

use rtc::configuration::RTCConfigurationBuilder;
use rtc::data_channel::event::RTCDataChannelEvent;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::message::{RTCEvent, RTCMessage};
use rtc::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use rtc::peer_connection::RTCPeerConnection;
use rtc::{
    peer_connection::sdp::session_description::RTCSessionDescription,
    transport::ice::server::RTCIceServer,
};
use shared::error::Error;

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day duration

#[derive(Parser)]
#[command(name = "data-channels-create")]
#[command(author = "Rusty Rain <y@liu.mx>")]
#[command(version = "0.0.0")]
#[command(about = "An example of Data-Channels-Create", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
    #[arg(long, default_value_t = format!("127.0.0.1"))]
    host: String,
    #[arg(long, default_value_t = 8080)]
    port: u16,
    #[arg(long, default_value_t = format!("INFO"))]
    log_level: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let host = cli.host;
    let port = cli.port;
    let log_level = log::LevelFilter::from_str(&cli.log_level)?;
    if cli.debug {
        env_logger::Builder::new()
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

    let (stop_tx, stop_rx) = broadcast::channel::<()>(1);
    let (_message_tx, message_rx) = broadcast::channel::<RTCMessage>(8);
    let (_event_tx, event_rx) = broadcast::channel::<RTCEvent>(8);

    info!("Press Ctrl-C to stop");
    std::thread::spawn(move || {
        let mut stop_tx = Some(stop_tx);
        ctrlc::set_handler(move || {
            if let Some(stop_tx) = stop_tx.take() {
                let _ = stop_tx.send(());
            }
        })
        .expect("Error setting Ctrl-C handler");
    });

    LocalExecutorBuilder::default().run(async move {
        if let Err(err) = run(stop_rx, message_rx, event_rx, host, port).await {
            error!("run got error: {}", err);
        }
    });

    Ok(())
}

async fn run(
    mut stop_rx: broadcast::Receiver<()>,
    mut message_rx: broadcast::Receiver<RTCMessage>,
    mut event_rx: broadcast::Receiver<RTCEvent>,
    host: String,
    port: u16,
) -> Result<()> {
    // Everything below is the RTC API! Thanks for using it ❤️.

    let config = RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }])
        .build();

    // Create a new RTCPeerConnection
    let mut peer_connection = RTCPeerConnection::new(config)?;

    // Create a datachannel with label 'data'
    let _data_channel = peer_connection.create_data_channel("data", None)?;

    // Create an offer to send to the browser
    let offer = peer_connection.create_offer(None)?;

    // Sets the LocalDescription, and starts our UDP listeners
    peer_connection.set_local_description(offer)?;

    // Output the answer in base64 so we can paste it in browser
    if let Some(local_desc) = peer_connection.local_description() {
        let json_str = serde_json::to_string(local_desc)?;
        let b64 = signal::encode(&json_str);
        println!("{b64}");
    } else {
        println!("generate local_description failed!");
        return Err(Error::ErrPeerConnLocalDescriptionNil.into());
    }

    // Wait for the answer to be pasted
    let line = signal::must_read_stdin()?;
    let desc_data = signal::decode(line.as_str())?;
    let answer = serde_json::from_str::<RTCSessionDescription>(&desc_data)?;

    // Apply the answer as the remote description
    peer_connection.set_remote_description(answer)?;

    let socket = UdpSocket::bind(format!("{host}:{port}")).await?;
    let local_addr = socket.local_addr()?;

    println!("listening {}...", socket.local_addr()?);

    let mut buf = vec![0; 2000];
    loop {
        while let Some(msg) = peer_connection.poll_write() {
            match socket.send_to(&msg.message, msg.transport.peer_addr).await {
                Ok(n) => {
                    trace!(
                        "socket write to {} with bytes {}",
                        msg.transport.peer_addr,
                        n
                    );
                }
                Err(err) => {
                    warn!(
                        "socket write to {} with error {}",
                        msg.transport.peer_addr, err
                    );
                    break;
                }
            }
        }

        while let Some(event) = peer_connection.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(peer_connection_state) => {
                    info!("Peer Connection State has changed: {peer_connection_state}");
                    if peer_connection_state == RTCPeerConnectionState::Failed {
                        warn!("Peer Connection State has gone to failed! Exiting...");
                        break;
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(data_channel_event) => {
                    match data_channel_event {
                        RTCDataChannelEvent::OnOpen(channel_id) => {
                            let dc = peer_connection
                                .data_channel(channel_id)
                                .ok_or(Error::ErrDataChannelClosed)?;
                            info!("Data channel '{}'-'{}' open", dc.label()?, dc.id());
                        }
                        RTCDataChannelEvent::OnMessage(channel_id, message) => {
                            let mut dc = peer_connection
                                .data_channel(channel_id)
                                .ok_or(Error::ErrDataChannelClosed)?;
                            let msg_str = String::from_utf8(message.data.to_vec())?;
                            info!(
                                "Message from DataChannel '{}': '{}', Echoing back",
                                dc.label()?,
                                msg_str
                            );
                            dc.send(&message.data)?;
                        }
                        _ => {}
                    }
                }
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
                break;
            }
            res = message_rx.recv() => {
                match res {
                    Ok(message) => {
                        peer_connection.handle_write(message)?;
                    }
                    Err(err) => {
                        warn!("write_rx error: {}", err);
                        break;
                    }
                }
            }
            res = event_rx.recv() => {
                match res {
                    Ok(event) => {
                        peer_connection.handle_event(event)?;
                    }
                    Err(err) => {
                        warn!("event_rx error: {}", err);
                        break;
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
                        warn!("socket read error {}", err);
                        break;
                    }
                }
            }
        }
    }

    peer_connection.close()?;

    Ok(())
}

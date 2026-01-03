use bytes::BytesMut;
use clap::Parser;
use futures::StreamExt;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Method, Request, Response, Server, StatusCode};
use rtc_ice::agent::Agent;
use rtc_ice::agent::agent_config::AgentConfig;
use rtc_ice::candidate::candidate_host::CandidateHostConfig;
use rtc_ice::candidate::*;
use rtc_ice::state::*;
use rtc_ice::{Credentials, Event};
use sansio::Protocol;
use shared::error::Error;
use shared::{TransportContext, TransportMessage, TransportProtocol};
use std::io;
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, watch};

#[macro_use]
extern crate lazy_static;

type SenderType = Arc<Mutex<mpsc::Sender<String>>>;
type ReceiverType = Arc<Mutex<mpsc::Receiver<String>>>;

lazy_static! {
    // ErrUnknownType indicates an error with Unknown info.
    static ref REMOTE_AUTH_CHANNEL: (SenderType, ReceiverType ) = {
        let (tx, rx) = mpsc::channel::<String>(3);
        (Arc::new(Mutex::new(tx)), Arc::new(Mutex::new(rx)))
    };

    static ref REMOTE_CAND_CHANNEL: (SenderType, ReceiverType) = {
        let (tx, rx) = mpsc::channel::<String>(10);
        (Arc::new(Mutex::new(tx)), Arc::new(Mutex::new(rx)))
    };
}

// HTTP Listener to get ICE Credentials/Candidate from remote Peer
async fn remote_handler(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    //println!("received {:?}", req);
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/remoteAuth") => {
            let full_body =
                match std::str::from_utf8(&hyper::body::to_bytes(req.into_body()).await?) {
                    Ok(s) => s.to_owned(),
                    Err(err) => panic!("{}", err),
                };
            let tx = REMOTE_AUTH_CHANNEL.0.lock().await;
            //println!("body: {:?}", full_body);
            let _ = tx.send(full_body).await;

            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::OK;
            Ok(response)
        }

        (&Method::POST, "/remoteCandidate") => {
            let full_body =
                match std::str::from_utf8(&hyper::body::to_bytes(req.into_body()).await?) {
                    Ok(s) => s.to_owned(),
                    Err(err) => panic!("{}", err),
                };
            let tx = REMOTE_CAND_CHANNEL.0.lock().await;
            //println!("body: {:?}", full_body);
            let _ = tx.send(full_body).await;

            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::OK;
            Ok(response)
        }

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

// Controlled Agent:
//      cargo run --color=always --package webrtc-ice --example ping_pong
// Controlling Agent:
//      cargo run --color=always --package webrtc-ice --example ping_pong -- --controlling

#[derive(Parser)]
#[command(name = "ICE Ping Pong")]
#[command(author = "Rusty Rain <y@ngr.tc>")]
#[command(version = "0.1.0")]
#[command(about = "An example of ICE", long_about = None)]
struct Cli {
    #[arg(short, long)]
    controlling: bool,

    #[arg(short, long)]
    debug: bool,
    #[arg(long, default_value_t = format!("INFO"))]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    if cli.debug {
        let log_level = log::LevelFilter::from_str(&cli.log_level).unwrap();
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

    let (local_http_port, remote_http_port) = if cli.controlling {
        (9000, 9001)
    } else {
        (9001, 9000)
    };

    let (done_tx, mut done_rx) = watch::channel(());

    println!("Listening on http://localhost:{local_http_port}");
    let mut done_http_server = done_rx.clone();
    tokio::spawn(async move {
        let addr = ([0, 0, 0, 0], local_http_port).into();
        let service =
            make_service_fn(|_| async { Ok::<_, hyper::Error>(service_fn(remote_handler)) });
        let server = Server::bind(&addr).serve(service);
        tokio::select! {
            _ = done_http_server.changed() => {
                println!("receive cancel http server!");
            }
            result = server => {
                // Run this server for... forever!
                if let Err(e) = result {
                    eprintln!("server error: {e}");
                }
                println!("exit http server!");
            }
        };
    });

    if cli.controlling {
        println!("Local Agent is controlling");
    } else {
        println!("Local Agent is controlled");
    };
    println!("Press 'Enter' when both processes have started");
    let mut input = String::new();
    let _ = io::stdin().read_line(&mut input)?;

    let port = if cli.controlling { 4000 } else { 4001 };
    let udp_socket = UdpSocket::bind(("0.0.0.0", port)).await?;
    let mut ice_agent = Agent::new(Arc::new(AgentConfig {
        disconnected_timeout: Some(Duration::from_secs(5)),
        failed_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    }))?;

    let client = Arc::new(Client::new());

    // When we have gathered a new ICE Candidate send it to the remote peer
    let client2 = Arc::clone(&client);
    let on_candidate = |c: Candidate| {
        let client3 = Arc::clone(&client2);
        Box::pin(async move {
            println!("posting remoteCandidate with {}", c.marshal());

            let req = match Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "http://localhost:{remote_http_port}/remoteCandidate"
                ))
                .body(Body::from(c.marshal()))
            {
                Ok(req) => req,
                Err(err) => {
                    println!("{err}");
                    return;
                }
            };
            let resp = match client3.request(req).await {
                Ok(resp) => resp,
                Err(err) => {
                    println!("{err}");
                    return;
                }
            };
            println!("Response from remoteCandidate: {}", resp.status());
        })
    };

    // Get the local auth details and send to remote peer
    let Credentials {
        ufrag: local_ufrag,
        pwd: local_pwd,
    } = ice_agent.get_local_credentials();

    println!("posting remoteAuth with {local_ufrag}:{local_pwd}");
    let req = match Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:{remote_http_port}/remoteAuth"))
        .body(Body::from(format!("{local_ufrag}:{local_pwd}")))
    {
        Ok(req) => req,
        Err(err) => return Err(Error::Other(format!("{err}"))),
    };
    let resp = match client.request(req).await {
        Ok(resp) => resp,
        Err(err) => return Err(Error::Other(format!("{err}"))),
    };
    println!("Response from remoteAuth: {}", resp.status());

    let (remote_ufrag, remote_pwd) = {
        let mut rx = REMOTE_AUTH_CHANNEL.1.lock().await;
        if let Some(s) = rx.recv().await {
            println!("received: {s}");
            let fields: Vec<String> = s.split(':').map(|s| s.to_string()).collect();
            (fields[0].clone(), fields[1].clone())
        } else {
            panic!("rx.recv() empty");
        }
    };
    println!("remote_ufrag: {remote_ufrag}, remote_pwd: {remote_pwd}");

    // gather_candidates
    println!("gathering candidates...");
    let local_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: udp_socket.local_addr()?.ip().to_string(),
            port: udp_socket.local_addr()?.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    on_candidate(local_candidate.clone()).await;
    ice_agent.add_local_candidate(local_candidate)?;

    let remote_candidate = {
        let mut rx = REMOTE_CAND_CHANNEL.1.lock().await;
        if let Some(s) = rx.recv().await {
            println!("received remote_candidate: {s}");
            unmarshal_candidate(&s)?
        } else {
            panic!("rx.recv() empty");
        }
    };
    let peer_addr = remote_candidate.addr();
    ice_agent.add_remote_candidate(remote_candidate)?;

    ice_agent.start_connectivity_checks(cli.controlling, remote_ufrag, remote_pwd)?;

    println!("Enter bye to stop");
    let (mut tx, mut rx) = futures::channel::mpsc::channel(8);
    std::thread::spawn(move || {
        let mut buffer = String::new();
        while io::stdin().read_line(&mut buffer).is_ok() {
            match buffer.trim_end() {
                "" => break,
                line => {
                    if line == "bye" {
                        let _ = done_tx.send(());
                        break;
                    }
                    if tx.try_send(line.to_string()).is_err() {
                        break;
                    }
                }
            };
            buffer.clear();
        }
    });

    // Start the ICE Agent. One side must be controlled, and the other must be controlling
    let mut buf = vec![0u8; 2048];
    loop {
        while let Some(transmit) = ice_agent.poll_write() {
            udp_socket
                .send_to(&transmit.message[..], transmit.transport.peer_addr)
                .await?;
        }
        let mut is_failed = false;
        while let Some(event) = ice_agent.poll_event() {
            match event {
                Event::ConnectionStateChange(cs) => {
                    println!("ConnectionStateChange with {}", cs);
                    match cs {
                        ConnectionState::Failed => {
                            is_failed = true;
                            break;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        if is_failed {
            break;
        }

        let d = if let Some(eto) = ice_agent.poll_timeout() {
            eto.duration_since(Instant::now())
        } else {
            Duration::from_millis(100)
        };
        let timeout = tokio::time::sleep(d);
        tokio::pin!(timeout);

        tokio::select! {
            _ = done_rx.changed() => {
                println!("exit ICE loop");
                break;
            }
            _ = timeout.as_mut() => {
                ice_agent.handle_timeout(Instant::now())?;
            }
            res = udp_socket.recv_from(&mut buf) => {
                if let Ok((n, remote_addr)) = res {
                    if n == 0 {
                        break;
                    }

                    if stun::message::is_stun_message(&buf[0..n]) {
                        ice_agent.handle_read(TransportMessage::<BytesMut>{
                            now: Instant::now(),
                            transport: TransportContext{
                                local_addr: udp_socket.local_addr()?,
                                peer_addr: remote_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message:BytesMut::from(&buf[0..n]),
                        })?;
                    } else {
                        println!("{}", String::from_utf8((&buf[0..n]).to_vec())?);
                    }
                }
            }
            res = rx.next() => {
                if let Some(line) = res {
                    udp_socket.send_to(line.as_bytes(), peer_addr).await?;
                }
            }
        };
    }

    ice_agent.close()?;

    Ok(())
}

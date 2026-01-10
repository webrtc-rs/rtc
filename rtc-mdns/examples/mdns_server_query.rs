//! mDNS Server + Query Example
//!
//! This example demonstrates how to use the sans-I/O rtc-mdns library
//! to run both an mDNS server and client together. It starts a server
//! with some local names and then queries for those names.
//!
//! # Usage
//!
//! ```
//! cargo run --package rtc-mdns --example mdns_server_query
//! ```
//!
//! With custom timeout and interval:
//! ```
//! cargo run --package rtc-mdns --example mdns_server_query -- --timeout 5 --interval 500
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use clap::Parser;
use rtc_mdns::{MDNS_MULTICAST_IPV4, MDNS_PORT, Mdns, MdnsConfig, MdnsEvent, MulticastSocket};
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use tokio::net::UdpSocket;

#[derive(Parser, Debug)]
#[command(name = "mDNS Server + Query")]
#[command(version = "0.1.0")]
#[command(author = "Rain Liu <yuliu@webrtc.rs>")]
#[command(about = "An example of mDNS Server + Query using sans-I/O rtc-mdns")]
struct Args {
    /// Query timeout in seconds
    #[arg(long, default_value = "10")]
    timeout: u64,

    /// Query retry interval in milliseconds
    #[arg(long, default_value = "1000")]
    interval: u64,
}

fn get_local_ip() -> IpAddr {
    /*if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                if let IpAddr::V4(ip) = addr.ip() {
                    return ip.into();
                }
            }
        }
    }*/
    Ipv4Addr::new(127, 0, 0, 1).into()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    let multicast_local_ip = if cfg!(target_os = "linux") {
        IpAddr::V4(MDNS_MULTICAST_IPV4)
    } else {
        // DNS_MULTICAST_IPV4 doesn't work on Mac/Win,
        // only 0.0.0.0 works fine, even 127.0.0.1 doesn't work
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    };
    let multicast_local_addr = SocketAddr::new(multicast_local_ip, MDNS_PORT);

    log::info!("Creating mDNS server with local names and local ip");

    // Server: has local names and responds to queries
    let config_server = MdnsConfig::default()
        .with_local_names(vec![
            "webrtc-rs-mdns-1.local".to_string(),
            "webrtc-rs-mdns-2.local".to_string(),
        ])
        .with_local_ip(get_local_ip());
    let mut mdns_server = Mdns::new(config_server);

    // Client: queries for names with timeout
    let config_client = MdnsConfig::default()
        .with_query_interval(Duration::from_millis(args.interval))
        .with_query_timeout(Duration::from_secs(args.timeout));
    let mut mdns_client = Mdns::new(config_client);

    // Create a shared multicast UDP socket using the builder
    // In a real application, you might use separate sockets
    let multicast_udp_socket =
        UdpSocket::from_std(MulticastSocket::new(multicast_local_addr).into_std()?)?;

    // Query 1: webrtc-rs-mdns-1.local
    let query_id_1 = mdns_client.query("webrtc-rs-mdns-1.local");
    log::info!(
        "Started query for webrtc-rs-mdns-1.local (query_id={}, timeout={}s, interval={}ms)",
        query_id_1,
        args.timeout,
        args.interval
    );

    let mut query_1_answered = false;
    let mut query_2_answered = false;
    let mut query_id_2: Option<u64> = None;

    let mut buf = vec![0u8; 1500];

    loop {
        // Send any queued packets from both connections
        while let Some(packet) = mdns_server.poll_write() {
            log::trace!("server_a sending {} bytes", packet.message.len());
            multicast_udp_socket
                .send_to(&packet.message, packet.transport.peer_addr)
                .await?;
        }
        while let Some(packet) = mdns_client.poll_write() {
            log::trace!("server_b sending {} bytes", packet.message.len());
            multicast_udp_socket
                .send_to(&packet.message, packet.transport.peer_addr)
                .await?;
        }

        // Check if we still have pending queries
        if mdns_client.pending_query_count() == 0 {
            if query_1_answered && query_2_answered {
                log::info!("All queries answered successfully");
            } else {
                log::debug!("No more pending queries, exiting");
            }
            break;
        }

        // Calculate how long to wait
        let wait_duration = mdns_client
            .poll_timeout()
            .map(|t| t.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_millis(100));

        tokio::select! {
            result = multicast_udp_socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, peer_addr)) => {
                        log::trace!("Received {} bytes from {}", len, peer_addr);
                        let now = Instant::now();
                        let msg = TaggedBytesMut {
                            now,
                            transport: TransportContext {
                                local_addr: multicast_local_addr,
                                peer_addr,
                                transport_protocol: TransportProtocol::UDP,
                                ecn: None,
                            },
                            message: BytesMut::from(&buf[..len]),
                        };

                        // Feed packet to both connections
                        // Server A will respond to questions, Server B will receive answers
                        let msg_clone = TaggedBytesMut {
                            now,
                            transport: msg.transport.clone(),
                            message: msg.message.clone(),
                        };

                        if let Err(e) = mdns_server.handle_read(msg) {
                            log::trace!("server_a handle_read: {}", e);
                        }
                        if let Err(e) = mdns_client.handle_read(msg_clone) {
                            log::trace!("server_b handle_read: {}", e);
                        }
                    }
                    Err(e) => {
                        log::warn!("Socket recv error: {}", e);
                    }
                }
            }
            _ = tokio::time::sleep(wait_duration) => {
                // Handle timeout - this triggers query retries and timeout events
                let now = Instant::now();
                let _ = mdns_server.handle_timeout(now);
                if let Err(e) = mdns_client.handle_timeout(now) {
                    log::warn!("Failed to handle timeout: {}", e);
                }
            }
        }

        // Check for events from server_b (query answers and timeouts)
        while let Some(event) = mdns_client.poll_event() {
            match event {
                MdnsEvent::QueryAnswered(id, addr) => {
                    if id == query_id_1 {
                        println!("query_id = {}, addr = {}", id, addr);
                        query_1_answered = true;

                        // Start query 2 after query 1 is answered
                        if query_id_2.is_none() {
                            let id = mdns_client.query("webrtc-rs-mdns-2.local");
                            query_id_2 = Some(id);
                            log::info!(
                                "Started query for webrtc-rs-mdns-2.local (query_id={}, timeout={}s, interval={}ms)",
                                id,
                                args.timeout,
                                args.interval
                            );
                        }
                    } else if query_id_2 == Some(id) {
                        println!("query_id = {}, addr = {}", id, addr);
                        query_2_answered = true;
                    }
                }
                MdnsEvent::QueryTimeout(id) => {
                    log::error!("Query {} timed out after {} seconds", id, args.timeout);
                    mdns_server.close()?;
                    mdns_client.close()?;
                    return Err(
                        format!("Query {} timed out after {} seconds", id, args.timeout).into(),
                    );
                }
            }
        }
    }

    mdns_server.close()?;
    mdns_client.close()?;

    Ok(())
}

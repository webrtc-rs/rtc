//! mDNS Server Example
//!
//! This example demonstrates how to use the sans-I/O rtc-mdns library
//! to run an mDNS server that responds to queries for configured local names.
//!
//! # Usage
//!
//! For interop with webrtc-rs/mdns_query:
//! ```
//! cargo run --package rtc-mdns --example mdns_server
//! ```
//!
//! For interop with pion/mdns_client:
//! ```
//! cargo run --package rtc-mdns --example mdns_server -- --local-name pion-test.local
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use bytes::BytesMut;
use clap::Parser;
use rtc_mdns::{Mdns, MdnsConfig, MulticastSocket};
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use tokio::net::UdpSocket;

#[derive(Parser, Debug)]
#[command(name = "mDNS Server")]
#[command(version = "0.1.0")]
#[command(author = "Rain Liu <yliu@webrtc.rs>")]
#[command(about = "An example of mDNS Server using sans-I/O rtc-mdns")]
struct Args {
    /// mDNS server bind address
    #[arg(long, default_value = "0.0.0.0:5353")]
    server: String,

    /// Local name to respond for
    #[arg(long, default_value = "webrtc-rs-test.local")]
    local_name: String,

    /// Local IP address to advertise (if not specified, uses bind address)
    #[arg(long)]
    local_ip: Option<String>,
}

fn get_local_ip() -> Option<Ipv4Addr> {
    // Try to get a reasonable local IP address
    // This is a simple heuristic - in production you'd want to be more careful
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        // Connect to a public address to determine the local interface
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                if let IpAddr::V4(ip) = addr.ip() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let bind_addr: SocketAddr = args.server.parse()?;

    // Determine the local address to advertise
    let local_ip = if let Some(ip_str) = &args.local_ip {
        ip_str.parse::<Ipv4Addr>()?
    } else {
        get_local_ip().unwrap_or(Ipv4Addr::new(127, 0, 0, 1))
    };
    let local_addr = SocketAddr::new(IpAddr::V4(local_ip), 5353);

    log::info!("Starting mDNS server");
    log::info!("  Bind address: {}", bind_addr);
    log::info!("  Local name: {}", args.local_name);
    log::info!("  Advertised IP: {}", local_ip);

    // Create the sans-I/O mDNS connection
    let config = MdnsConfig::default()
        .with_local_names(vec![args.local_name.clone()])
        .with_local_ip(local_addr.ip());
    let mut conn = Mdns::new(config);

    // Create a multicast UDP socket using the builder
    let multicast_local_ip = match bind_addr.ip() {
        IpAddr::V4(local_ip) => local_ip,
        IpAddr::V6(_) => return Ok(()),
    };
    let std_socket = MulticastSocket::new()
        .with_multicast_local_ipv4(multicast_local_ip)
        .with_multicast_local_port(bind_addr.port())
        .into_std()?;
    let socket = UdpSocket::from_std(std_socket)?;

    println!("mDNS server running. Press Ctrl+C to stop.");

    let mut buf = vec![0u8; 1500];

    loop {
        tokio::select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, src)) => {
                        log::trace!("Received {} bytes from {}", len, src);
                        let msg = TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr: bind_addr,
                                peer_addr: src,
                                transport_protocol: TransportProtocol::UDP,
                                ecn: None,
                            },
                            message: BytesMut::from(&buf[..len]),
                        };
                        if let Err(e) = conn.handle_read(msg) {
                            log::warn!("Failed to handle packet: {}", e);
                        }

                        // Send any response packets
                        while let Some(packet) = conn.poll_write() {
                            log::debug!(
                                "Sending {} bytes to {}",
                                packet.message.len(),
                                packet.transport.peer_addr
                            );
                            if let Err(e) = socket.send_to(&packet.message, packet.transport.peer_addr).await {
                                log::warn!("Failed to send packet: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("Socket recv error: {}", e);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                log::info!("Received Ctrl+C, shutting down");
                break;
            }
        }
    }

    conn.close()?;
    Ok(())
}

//! mDNS Query Example
//!
//! This example demonstrates how to use the sans-I/O rtc-mdns library
//! to send an mDNS query and receive an answer.
//!
//! # Usage
//!
//! For interop with webrtc-rs/mdns_server:
//! ```
//! cargo run --package rtc-mdns --example mdns_query
//! ```
//!
//! For interop with pion/mdns_server:
//! ```
//! cargo run --package rtc-mdns --example mdns_query -- --local-name pion-test.local
//! ```

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use clap::Parser;
use rtc_mdns::{Mdns, MdnsConfig, MdnsEvent, MulticastSocket};
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use tokio::net::UdpSocket;

#[derive(Parser, Debug)]
#[command(name = "mDNS Query")]
#[command(version = "0.1.0")]
#[command(author = "Rain Liu <yuliu@webrtc.rs>")]
#[command(about = "An example of mDNS Query using sans-I/O rtc-mdns")]
struct Args {
    /// mDNS server bind address
    #[arg(long, default_value = "0.0.0.0:5353")]
    server: String,

    /// Local name to query for
    #[arg(long, default_value = "webrtc-rs-test.local")]
    local_name: String,

    /// Query timeout in seconds
    #[arg(long, default_value = "10")]
    timeout: u64,

    /// Query retry interval in milliseconds
    #[arg(long, default_value = "1000")]
    interval: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let bind_addr: SocketAddr = args.server.parse()?;

    // Create the sans-I/O mDNS connection with query timeout
    let config = MdnsConfig::default()
        .with_query_interval(Duration::from_millis(args.interval))
        .with_query_timeout(Duration::from_secs(args.timeout));
    let mut conn = Mdns::new(config);

    let multicast_local_ip = match bind_addr.ip() {
        IpAddr::V4(local_ip) => local_ip,
        IpAddr::V6(_) => return Ok(()),
    };

    // Create a multicast UDP socket using the builder
    let std_socket = MulticastSocket::new()
        .with_multicast_local_ipv4(multicast_local_ip)
        .with_multicast_local_port(bind_addr.port())
        .into_std()?;
    let socket = UdpSocket::from_std(std_socket)?;

    // Start the query
    let query_id = conn.query(&args.local_name);
    log::info!(
        "Querying for '{}' (query_id={}, timeout={}s, interval={}ms)",
        args.local_name,
        query_id,
        args.timeout,
        args.interval
    );

    let mut buf = vec![0u8; 1500];

    loop {
        // Send any queued packets
        while let Some(packet) = conn.poll_write() {
            log::trace!(
                "Sending {} bytes to {}",
                packet.message.len(),
                packet.transport.peer_addr
            );
            socket
                .send_to(&packet.message, packet.transport.peer_addr)
                .await?;
        }

        // Check if we still have pending queries
        if conn.pending_query_count() == 0 {
            log::debug!("No more pending queries, exiting");
            break;
        }

        // Calculate how long to wait
        let wait_duration = conn
            .poll_timeout()
            .map(|t| t.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_millis(100));

        // Wait for incoming packets or timeout
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
                    }
                    Err(e) => {
                        log::warn!("Socket recv error: {}", e);
                    }
                }
            }
            _ = tokio::time::sleep(wait_duration) => {
                // Handle timeout - this triggers query retries and timeout events
                if let Err(e) = conn.handle_timeout(Instant::now()) {
                    log::warn!("Failed to handle timeout: {}", e);
                }
            }
        }

        // Check for events (query answers and timeouts)
        while let Some(event) = conn.poll_event() {
            match event {
                MdnsEvent::QueryAnswered(id, addr) => {
                    log::info!("Query answered!");
                    println!("query_id = {}, addr = {}", id, addr);
                    conn.close()?;
                    return Ok(());
                }
                MdnsEvent::QueryTimeout(id) => {
                    log::error!("Query {} timed out after {} seconds", id, args.timeout);
                    conn.close()?;
                    return Err(format!("Query timed out after {} seconds", args.timeout).into());
                }
            }
        }
    }

    conn.close()?;
    Ok(())
}

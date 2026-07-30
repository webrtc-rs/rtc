#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! Signaling helpers for the WebRTC.rs examples.
//!
//! The examples in this workspace exchange SDP by hand: one side prints a base64 blob, you
//! paste it into the other. This crate holds the few functions that make that work, so the
//! examples can stay focused on the WebRTC parts.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let json = r#"{"type":"offer","sdp":"v=0\r\n"}"#;
//!
//! // The examples print this blob for you to paste into the other peer.
//! let blob = rtc_signal::encode(json);
//! assert_eq!(rtc_signal::decode(&blob)?, json);
//! # Ok(())
//! # }
//! ```
//!
//! It is a support crate for the examples, not part of the WebRTC API — nothing here is
//! needed to use [`rtc`](https://docs.rs/rtc) or [`webrtc`](https://docs.rs/webrtc).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use tokio::sync::{Mutex, mpsc};

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref SDP_CHAN_TX_MUTEX: Arc<Mutex<Option<mpsc::Sender<String>>>> =
        Arc::new(Mutex::new(None));
}

// HTTP Listener to get sdp
async fn remote_handler(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // A HTTP handler that processes a SessionDescription given to us from the other WebRTC-rs or Pion process
        (&Method::POST, "/sdp") => {
            //println!("remote_handler receive from /sdp");
            let sdp_str = match std::str::from_utf8(&hyper::body::to_bytes(req.into_body()).await?)
            {
                Ok(s) => s.to_owned(),
                Err(err) => panic!("{}", err),
            };

            {
                let sdp_chan_tx = SDP_CHAN_TX_MUTEX.lock().await;
                if let Some(tx) = &*sdp_chan_tx {
                    let _ = tx.send(sdp_str).await;
                }
            }

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

/// http_sdp_server starts a HTTP Server that consumes SDPs
pub async fn http_sdp_server(port: u16) -> mpsc::Receiver<String> {
    let (sdp_chan_tx, sdp_chan_rx) = mpsc::channel::<String>(1);
    {
        let mut tx = SDP_CHAN_TX_MUTEX.lock().await;
        *tx = Some(sdp_chan_tx);
    }

    tokio::spawn(async move {
        let addr = SocketAddr::from_str(&format!("0.0.0.0:{port}")).unwrap();
        let service =
            make_service_fn(|_| async { Ok::<_, hyper::Error>(service_fn(remote_handler)) });
        let server = Server::bind(&addr).serve(service);
        // Run this server for... forever!
        if let Err(e) = server.await {
            eprintln!("server error: {e}");
        }
    });

    sdp_chan_rx
}

/// Note that macOS Terminal may have issue to paste large size of SDP line
/// How to fix it? echo $BROWSER_SDP | ./target/debug/examples/$example
/// must_read_stdin blocks until input is received from stdin
#[allow(clippy::assigning_clones)]
pub fn must_read_stdin() -> Result<String> {
    let mut line = String::new();

    std::io::stdin().read_line(&mut line)?;
    line = line.trim().to_owned();
    println!();

    Ok(line)
}

/// encode encodes the input in base64
/// It can optionally zip the input before encoding
pub fn encode(b: &str) -> String {
    BASE64_STANDARD.encode(b)
}

/// decode decodes the input from base64
/// It can optionally unzip the input after decoding
pub fn decode(s: &str) -> Result<String> {
    let b = BASE64_STANDARD.decode(s)?;
    let s = String::from_utf8(b)?;
    Ok(s)
}

/// Best-effort discovery of this host's primary local IPv4 address.
///
/// Opens a UDP socket toward a public address and reads back the local address the OS
/// picked — no packet is sent. Falls back to `127.0.0.1` if that fails, which is what the
/// examples want when running offline.
pub fn get_local_ip() -> IpAddr {
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0")
        && socket.connect("8.8.8.8:80").is_ok()
        && let Ok(addr) = socket.local_addr()
        && let IpAddr::V4(ip) = addr.ip()
    {
        ip.into()
    } else {
        Ipv4Addr::new(127, 0, 0, 1).into()
    }
}

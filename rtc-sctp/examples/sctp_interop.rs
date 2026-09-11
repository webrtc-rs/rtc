//! Test-only line-protocol adapter for exchanges with independent SCTP stacks.
//!
//! Uses public rtc-sctp APIs, stdin/stdout and a caller-driven virtual clock.
//! See `rtc-sctp/interop/README.md` for the protocol and scenario driver.

use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rtc_sctp::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig, Event,
    Payload, PayloadProtocolIdentifier, ReliabilityType, ServerConfig, TransportConfig,
};
use shared::TransportProtocol;

const MAX_MESSAGE: usize = 1 << 20;
const MAX_DRIVE: usize = 100_000;

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

fn unhex(value: &str) -> Result<Bytes, String> {
    if value == "-" {
        return Ok(Bytes::new());
    }
    if !value.len().is_multiple_of(2) || value.len() > 2 * MAX_MESSAGE + 4096 {
        return Err("invalid hex length".into());
    }
    let bytes: Result<Vec<_>, _> = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |c: u8| (c as char).to_digit(16).ok_or("invalid hex digit");
            Ok::<_, &str>((digit(pair[0])? * 16 + digit(pair[1])?) as u8)
        })
        .collect();
    bytes.map(Bytes::from).map_err(String::from)
}

fn transport() -> TransportConfig {
    TransportConfig::default()
        .with_sctp_port(5000)
        .with_max_message_size(MAX_MESSAGE as u32)
        .with_max_receive_buffer_size(4 * MAX_MESSAGE as u32)
        .with_max_num_inbound_streams(1024)
        .with_max_num_outbound_streams(1024)
}

struct Peer {
    endpoint: Endpoint,
    peer_addr: SocketAddr,
    handle: Option<AssociationHandle>,
    association: Option<Association>,
    now: Instant,
    passive: bool,
}

impl Peer {
    fn new(role: &str) -> Result<Self, String> {
        let passive = match role {
            "client" => false,
            "server" => true,
            _ => return Err("expected INIT client or server".into()),
        };
        let local_addr = "127.0.0.1:5000".parse().unwrap();
        let peer_addr = "127.0.0.2:5000".parse().unwrap();
        let mut config = EndpointConfig::default();
        // The same packet budget as the external adapters. No IP socket is used.
        config.max_payload_size(rtc_sctp::max_payload_size_for_mtu(1200));
        Ok(Self {
            endpoint: Endpoint::new(
                local_addr,
                TransportProtocol::UDP,
                Arc::new(config),
                passive.then(|| Arc::new(ServerConfig::new(transport()))),
            ),
            peer_addr,
            handle: None,
            association: None,
            now: Instant::now(),
            passive,
        })
    }

    fn pump(&mut self) -> Result<(), String> {
        let Some(association) = self.association.as_mut() else {
            return Ok(());
        };
        // Reading can produce window updates or finish application close. Drain
        // those outputs in the same command, with an explicit runaway bound.
        for _ in 0..MAX_DRIVE {
            let mut progress = false;
            if let Some(transmit) = association.poll_transmit(self.now) {
                if let Payload::RawEncode(packets) = transmit.message {
                    for packet in packets {
                        println!("PACKET {}", hex(&packet));
                    }
                }
                progress = true;
            }
            while let Some(event) = association.poll() {
                match event {
                    Event::Connected => println!("EVENT ready"),
                    Event::HandshakeFailed { reason } => {
                        println!("EVENT error:handshake:{reason}")
                    }
                    Event::AssociationLost { reason, id } => {
                        if association.is_closed() {
                            println!("EVENT error:association:{reason}");
                            println!("EVENT closed");
                        } else {
                            println!("EVENT stream_closed:{id}");
                        }
                    }
                    _ => {}
                }
                progress = true;
            }
            for sid in association.stream_ids() {
                // Reacquire the public handle: reading the final old message
                // may retire the API object or make a later generation visible.
                while let Ok(mut stream) = association.stream(sid) {
                    match stream.read_sctp() {
                        Ok(Some(message)) => {
                            let payload = message
                                .to_payload(MAX_MESSAGE)
                                .map_err(|error| error.to_string())?;
                            println!("MESSAGE {sid} {} {}", message.ppi as u32, hex(&payload));
                            progress = true;
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
            }
            while let Some(event) = association.poll_endpoint_event() {
                if let Some(handle) = self.handle {
                    self.endpoint.handle_event(handle, event);
                }
                progress = true;
            }
            if !progress {
                return Ok(());
            }
        }
        Err("drive iteration limit".into())
    }

    fn advance(&mut self, delta_ms: u64) -> Result<(), String> {
        if delta_ms > 3_600_000 {
            return Err("TICK exceeds one hour".into());
        }
        let target = self.now + Duration::from_millis(delta_ms);
        for _ in 0..MAX_DRIVE {
            let next = self
                .association
                .as_ref()
                .and_then(Association::poll_timeout);
            if let Some(deadline) = next
                && deadline <= target
            {
                self.now = self.now.max(deadline);
                self.association.as_mut().unwrap().handle_timeout(self.now);
                self.pump()?;
            } else {
                self.now = target;
                return self.pump();
            }
        }
        Err("timeout iteration limit".into())
    }

    fn command(&mut self, words: &[&str]) -> Result<(), String> {
        match words {
            ["CONNECT"] if !self.passive && self.association.is_none() => {
                let (handle, association) = self
                    .endpoint
                    .connect(self.now, ClientConfig::new(transport()), self.peer_addr)
                    .map_err(|error| error.to_string())?;
                self.handle = Some(handle);
                self.association = Some(association);
            }
            ["INPUT", packet] => {
                let packet = unhex(packet)?;
                if let Some((handle, event)) =
                    self.endpoint.handle(self.now, self.peer_addr, None, packet)
                {
                    match event {
                        DatagramEvent::NewAssociation(association) => {
                            self.handle = Some(handle);
                            self.association = Some(association);
                        }
                        DatagramEvent::AssociationEvent(event) => {
                            if let Some(association) = self.association.as_mut() {
                                association.handle_event(event);
                            }
                        }
                        _ => {}
                    }
                }
            }
            ["SEND", sid, order, policy, ppid, payload] => {
                let sid = sid.parse::<u16>().map_err(|e| e.to_string())?;
                let ppid = ppid.parse::<u32>().map_err(|e| e.to_string())?;
                let ppi = PayloadProtocolIdentifier::from(ppid);
                if ppi == PayloadProtocolIdentifier::Unknown {
                    return Err("rtc public API supports WebRTC PPIDs only".into());
                }
                let unordered = match *order {
                    "ordered" => false,
                    "unordered" => true,
                    _ => return Err("invalid ordering".into()),
                };
                let (kind, value) = if *policy == "reliable" {
                    (ReliabilityType::Reliable, 0)
                } else if let Some(value) = policy.strip_prefix("timed:") {
                    (
                        ReliabilityType::Timed,
                        value.parse::<u32>().map_err(|e| e.to_string())?,
                    )
                } else if let Some(value) = policy.strip_prefix("rexmit:") {
                    (
                        ReliabilityType::Rexmit,
                        value.parse::<u32>().map_err(|e| e.to_string())?,
                    )
                } else {
                    return Err("invalid policy".into());
                };
                let payload = unhex(payload)?;
                if payload.is_empty() || payload.len() > MAX_MESSAGE {
                    return Err("payload must contain 1..1048576 bytes".into());
                }
                let association = self.association.as_mut().ok_or("no association")?;
                if !association.stream_ids().contains(&sid) {
                    association
                        .open_stream(sid, ppi)
                        .map_err(|e| e.to_string())?;
                }
                let mut stream = association.stream(sid).map_err(|e| e.to_string())?;
                stream
                    .set_reliability_params(unordered, kind, value)
                    .map_err(|e| e.to_string())?;
                stream
                    .write_sctp(self.now, &payload, ppi)
                    .map_err(|e| e.to_string())?;
            }
            ["RESET", list] => {
                let association = self.association.as_mut().ok_or("no association")?;
                for sid in list.split(',') {
                    let sid = sid.parse::<u16>().map_err(|e| e.to_string())?;
                    if !association.stream_ids().contains(&sid) {
                        association
                            .open_stream(sid, PayloadProtocolIdentifier::Binary)
                            .map_err(|e| e.to_string())?;
                    }
                    // stop() is the public API that initiates an outgoing reset
                    // while allowing writes after the eventual reset result.
                    association
                        .stream(sid)
                        .map_err(|e| e.to_string())?
                        .stop(self.now)
                        .map_err(|e| e.to_string())?;
                }
            }
            ["TICK", elapsed] => {
                return self.advance(elapsed.parse::<u64>().map_err(|e| e.to_string())?);
            }
            ["POLL"] => return self.advance(0),
            _ => return Err("unknown command or invalid arguments".into()),
        }
        self.pump()
    }
}

fn main() -> io::Result<()> {
    let mut peer = None;
    for line in io::stdin().lock().lines() {
        let line = line?;
        let words: Vec<_> = line.split_whitespace().collect();
        let result = match words.as_slice() {
            ["QUIT"] => {
                println!("DONE");
                io::stdout().flush()?;
                break;
            }
            ["INIT", role] if peer.is_none() => Peer::new(role).map(|p| peer = Some(p)),
            _ => match peer.as_mut() {
                Some(peer) => peer.command(&words),
                None => Err("INIT required".into()),
            },
        };
        if let Err(error) = result {
            println!("ERROR {}", error.replace(['\r', '\n'], " "));
        }
        println!("DONE");
        io::stdout().flush()?;
    }
    Ok(())
}

//! mDNS work, at the level pion does it: build a query for a name, and answer a query for a
//! local name (parse the question, pack the A record). Pion packs and unpacks with
//! `golang.org/x/net/dns/dnsmessage`; the Go half is `go/mdns.go`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use bytes::BytesMut;
use rtc_mdns::{Mdns, MdnsConfig};
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};

const NAME: &str = "7a1f6e3c-0b2d-4c5e-9f10-aabbccddeeff.local";

pub struct Client {
    conn: Mdns,
}

impl Client {
    pub fn new() -> Self {
        Self { conn: Mdns::new(Instant::now(), MdnsConfig::default()) }
    }

    /// Builds the query packets for `NAME` and returns the first.
    pub fn query(&mut self) -> BytesMut {
        let now = Instant::now();
        let id = self.conn.query_now(now, NAME);
        let packet = self.conn.poll_write().expect("a query packet");
        while self.conn.poll_write().is_some() {}
        self.conn.cancel_query(id);
        packet.message
    }
}

pub struct Server {
    conn: Mdns,
    query: BytesMut,
    from: SocketAddr,
    to: SocketAddr,
}

impl Server {
    pub fn new() -> Self {
        let query = Client::new().query();
        let conn = Mdns::new(
            Instant::now(),
            MdnsConfig::default()
                .with_local_names(vec![NAME.to_owned()])
                .with_local_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
        );
        Self {
            conn,
            query,
            from: "192.168.1.7:5353".parse().unwrap(),
            to: rtc_mdns::MDNS_DEST_ADDR,
        }
    }

    /// Answers one query; returns the response bytes.
    pub fn answer(&mut self) -> BytesMut {
        self.conn
            .handle_read(TaggedBytesMut {
                now: Instant::now(),
                transport: TransportContext {
                    local_addr: self.to,
                    peer_addr: self.from,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: BytesMut::from(&self.query[..]),
            })
            .expect("handle_read");
        let response = self.conn.poll_write().expect("a response");
        while self.conn.poll_write().is_some() {}
        response.message
    }
}

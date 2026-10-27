#![no_main]

//! Arbitrary datagrams into the mDNS connection: as a responder for a local name, with a query in
//! flight for another. Nothing may panic, whatever the packet claims about its sections, names and
//! compression pointers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use rtc_mdns::{Mdns, MdnsConfig};
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};

fuzz_target!(|data: &[u8]| {
    let now = Instant::now();
    let mut mdns = Mdns::new(
        now,
        MdnsConfig::default()
            .with_local_names(vec!["host.local".to_owned()])
            .with_local_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
    );
    mdns.query_now(now, "peer.local");
    while mdns.poll_write().is_some() {}

    let _ = mdns.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: rtc_mdns::MDNS_DEST_ADDR,
            peer_addr: SocketAddr::from(([192, 168, 1, 7], 5353)),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(data),
    });
    let _ = mdns.handle_timeout(now + Duration::from_secs(2));
    while mdns.poll_write().is_some() {}
    while mdns.poll_event().is_some() {}
});

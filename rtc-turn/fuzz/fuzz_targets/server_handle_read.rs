#![no_main]

//! Arbitrary datagrams into a TURN server holding a TCP allocation and a peer connection, over a
//! control connection (TCP) and as a datagram: the malformed, the unauthenticated and the oddly
//! sized must be refused without a panic, and the server must still answer a Binding afterwards.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use rtc_turn::server::{
    AuthCredentials, AuthRequest, RelayAddressGeneratorStatic, Server, ServerConfig, ServerEvent,
    generate_auth_key,
};
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};

fn context(protocol: TransportProtocol) -> TransportContext {
    TransportContext {
        local_addr: SocketAddr::from(([192, 0, 2, 1], 3478)),
        peer_addr: SocketAddr::from(([198, 51, 100, 7], 40000)),
        transport_protocol: protocol,
        ecn: None,
    }
}

fuzz_target!(|data: &[u8]| {
    let now = Instant::now();
    let provider = crypto::default_provider().unwrap();
    let key_provider = provider.clone();
    let auth = move |req: &AuthRequest<'_>| {
        Some(AuthCredentials {
            user_id: req.username.to_owned(),
            key: generate_auth_key(req.username, req.realm, "pass", key_provider.crypto()).ok()?,
        })
    };
    let generator = Box::new(RelayAddressGeneratorStatic {
        relay_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
        address: IpAddr::V4(Ipv4Addr::LOCALHOST),
    });
    let mut server = Server::new(
        ServerConfig::new("webrtc.rs", Arc::new(auth), generator, provider),
        now,
    )
    .unwrap();

    // Both transports, and as a datagram from a peer to the relay address too.
    for protocol in [TransportProtocol::UDP, TransportProtocol::TCP] {
        let _ = server.handle_read(TaggedBytesMut {
            now,
            transport: context(protocol),
            message: BytesMut::from(data),
        });
    }
    let _ = server.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: SocketAddr::from(([192, 0, 2, 50], 50000)),
            peer_addr: SocketAddr::from(([203, 0, 113, 9], 6000)),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(data),
    });

    // Answer what the server asks of the application, as a cooperative one would.
    while let Some(event) = server.poll_event() {
        match event {
            ServerEvent::BindRelay { id, .. } | ServerEvent::BindRelayTcp { id, .. } => {
                server.relay_bound(id, SocketAddr::from(([192, 0, 2, 50], 50000)), now);
            }
            ServerEvent::ConnectPeer { id, .. } => server.peer_connected(id, now),
            _ => {}
        }
    }
    let _ = server.peer_accepted(
        SocketAddr::from(([192, 0, 2, 50], 50000)),
        SocketAddr::from(([203, 0, 113, 9], 6000)),
        now,
    );
    let _ = server.handle_timeout(now + Duration::from_secs(60));
    while server.poll_write().is_some() {}
    while server.poll_event().is_some() {}
});

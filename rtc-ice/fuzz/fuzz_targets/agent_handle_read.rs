#![no_main]

//! Arbitrary datagrams into a connected ICE agent's receive path, and then time passing.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use rtc_ice::agent::Agent;
use rtc_ice::agent::agent_config::AgentConfig;
use rtc_ice::candidate::candidate_host::CandidateHostConfig;
use rtc_ice::candidate::{Candidate, CandidateConfig};
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};

fn host(ip: &str, port: u16) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: ip.to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap()
}

fuzz_target!(|data: &[u8]| {
    let now = Instant::now();
    let provider = crypto::default_provider().unwrap();
    let mut agent = Agent::new(now, Arc::new(AgentConfig::default()), provider).unwrap();
    let (local, remote) = (host("10.0.0.1", 1000), host("10.0.0.2", 2000));
    agent.add_local_candidate(local).unwrap();
    agent.add_remote_candidate(remote).unwrap();
    agent
        .start_connectivity_checks(
            now,
            true,
            "remote".to_owned(),
            "remotepassword0123456789".to_owned(),
        )
        .unwrap();
    while agent.poll_write().is_some() {}

    let _ = agent.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: SocketAddr::from(([10, 0, 0, 1], 1000)),
            peer_addr: SocketAddr::from(([10, 0, 0, 2], 2000)),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(data),
    });
    let _ = agent.handle_timeout(now + Duration::from_millis(500));
    while agent.poll_write().is_some() {}
    while agent.poll_event().is_some() {}
});

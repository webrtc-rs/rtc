//! One ICE session between two in-memory agents with a host candidate each, as
//! `rtc-ice/src/agent/selection_test.rs` wires them: a lossless link and a hand-advanced clock.
//! An operation builds both agents, exchanges credentials and candidates, and runs the checks
//! until both are connected. The Go half is `go/ice.go` (pion/ice over loopback UDP, CPU time).

use std::sync::Arc;
use std::time::{Duration, Instant};

use rtc_ice::agent::Agent;
use rtc_ice::agent::agent_config::AgentConfig;
use rtc_ice::candidate::candidate_host::CandidateHostConfig;
use rtc_ice::candidate::{Candidate, CandidateConfig};
use rtc_ice::state::ConnectionState;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext};

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

fn forward(from: &mut Agent, to: &mut Agent, now: Instant) -> bool {
    let mut moved = false;
    while let Some(packet) = from.poll_write() {
        moved = true;
        let inbound = TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: packet.transport.peer_addr,
                peer_addr: packet.transport.local_addr,
                ecn: None,
                transport_protocol: packet.transport.transport_protocol,
            },
            message: packet.message,
        };
        let _ = to.handle_read(inbound);
    }
    moved
}

pub fn connect(provider: &Arc<dyn rtc_ice::crypto::RTCCryptoProvider>) -> (Agent, Agent) {
    let mut clock = Instant::now();
    let cfg = |controlling| {
        Arc::new(AgentConfig {
            is_controlling: controlling,
            check_interval: Duration::from_millis(20),
            ..Default::default()
        })
    };
    let mut a = Agent::new(clock, cfg(true), provider.clone()).unwrap();
    let mut b = Agent::new(clock, cfg(false), provider.clone()).unwrap();
    let (ca, cb) = (host("10.0.0.1", 1000), host("10.0.0.2", 2000));
    a.add_local_candidate(ca.clone()).unwrap();
    b.add_remote_candidate(ca).unwrap();
    b.add_local_candidate(cb.clone()).unwrap();
    a.add_remote_candidate(cb).unwrap();
    let (au, ap) = {
        let c = a.get_local_credentials();
        (c.ufrag.clone(), c.pwd.clone())
    };
    let (bu, bp) = {
        let c = b.get_local_credentials();
        (c.ufrag.clone(), c.pwd.clone())
    };
    a.start_connectivity_checks(clock, true, bu, bp).unwrap();
    b.start_connectivity_checks(clock, false, au, ap).unwrap();
    for _ in 0..2000 {
        clock += Duration::from_millis(10);
        a.handle_timeout(clock).unwrap();
        b.handle_timeout(clock).unwrap();
        while forward(&mut a, &mut b, clock) | forward(&mut b, &mut a, clock) {}
        while a.poll_event().is_some() {}
        while b.poll_event().is_some() {}
        if a.state() == ConnectionState::Connected && b.state() == ConnectionState::Connected {
            return (a, b);
        }
    }
    panic!("ICE did not connect");
}

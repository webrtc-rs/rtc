//! Ports of pion/ice v4.4.8 `agent_test.go` cases that exercise one agent in isolation:
//! inbound message validation, peer-reflexive discovery, the IP policies, aggressive
//! nomination, keepalive and connection-state transitions.
//!
//! pion calls its unexported `handleInbound` with a hand-built STUN message; so does this module,
//! through the agent's own `handle_inbound`.

use super::selection_test::*;
use super::*;
use crate::attributes::{
    control::AttrControlling, priority::PriorityAttr, use_candidate::UseCandidateAttr,
};
use crate::candidate::candidate_host::CandidateHostConfig;
use sansio::Protocol;
use stun::attributes::*;
use stun::fingerprint::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;

const REMOTE: &str = "172.17.0.3:999";

fn remote_addr() -> SocketAddr {
    REMOTE.parse().unwrap()
}

/// pion's `buildMsg`: a Binding message of `class` for `username`, signed with `key`.
fn build_msg(class: MessageClass, username: &str, key: &str) -> Message {
    let crypto_provider = provider();
    let mut m = Message::new();
    m.build(&[
        Box::new(MessageType::new(METHOD_BINDING, class)),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username.to_owned())),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            key.to_owned(),
            crypto_provider.crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    m
}

/// An agent with one local host candidate, as the tests of `handleInbound` set up.
fn agent_with_local(config: AgentConfig) -> Agent {
    let mut agent = Agent::new(Instant::now(), Arc::new(config), provider()).unwrap();
    agent
        .add_local_candidate(
            CandidateHostConfig {
                base_config: CandidateConfig {
                    network: "udp".to_owned(),
                    address: "192.168.0.2".to_owned(),
                    port: 777,
                    component: 1,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()
            .unwrap(),
        )
        .unwrap();
    agent
}

fn credentials_of(agent: &Agent) -> (String, String) {
    let c = agent.get_local_credentials();
    (c.ufrag.clone(), c.pwd.clone())
}

// ---------------------------------------------------------------------------------------------
// TestInboundValidity
// ---------------------------------------------------------------------------------------------

#[test]
fn test_inbound_validity() {
    let now = Instant::now();

    // Invalid Binding requests should be discarded
    {
        let mut agent = agent_with_local(AgentConfig::default());
        agent
            .set_remote_credentials(
                "remoteufrag".to_owned(),
                "remotepwd0123456789012345".to_owned(),
            )
            .unwrap();
        let (ufrag, pwd) = credentials_of(&agent);

        let mut m = build_msg(CLASS_REQUEST, "invalid", &pwd);
        assert!(agent.handle_inbound(now, &mut m, 0, remote_addr()).is_err());
        assert!(agent.get_remote_candidates().is_empty());

        let mut m = build_msg(CLASS_REQUEST, &format!("{ufrag}:remoteufrag"), "Invalid");
        assert!(agent.handle_inbound(now, &mut m, 0, remote_addr()).is_err());
        assert!(agent.get_remote_candidates().is_empty());
    }

    // Invalid Binding success responses should be discarded
    {
        let mut agent = agent_with_local(AgentConfig::default());
        agent
            .set_remote_credentials(
                "remoteufrag".to_owned(),
                "remotepwd0123456789012345".to_owned(),
            )
            .unwrap();
        let (ufrag, _) = credentials_of(&agent);
        let mut m = build_msg(
            CLASS_SUCCESS_RESPONSE,
            &format!("{ufrag}:remoteufrag"),
            "Invalid",
        );
        assert!(agent.handle_inbound(now, &mut m, 0, remote_addr()).is_err());
        assert!(agent.get_remote_candidates().is_empty());
    }

    // Discard non-binding messages: an error response that is not a role conflict adds nothing
    {
        let mut agent = agent_with_local(AgentConfig::default());
        agent
            .set_remote_credentials(
                "remoteufrag".to_owned(),
                "remotepwd0123456789012345".to_owned(),
            )
            .unwrap();
        let (ufrag, _) = credentials_of(&agent);
        let mut m = build_msg(
            CLASS_ERROR_RESPONSE,
            &format!("{ufrag}:remoteufrag"),
            "Invalid",
        );
        let _ = agent.handle_inbound(now, &mut m, 0, remote_addr());
        assert!(agent.get_remote_candidates().is_empty());
    }

    // Valid bind request: the sender is learned as a peer-reflexive remote candidate
    {
        let mut agent = agent_with_local(AgentConfig {
            is_controlling: true,
            ..Default::default()
        });
        agent
            .set_remote_credentials(
                "remoteufrag".to_owned(),
                "remotepwd0123456789012345".to_owned(),
            )
            .unwrap();
        let (ufrag, pwd) = credentials_of(&agent);
        let mut m = build_msg(CLASS_REQUEST, &format!("{ufrag}:remoteufrag"), &pwd);
        agent.handle_inbound(now, &mut m, 0, remote_addr()).unwrap();
        assert_eq!(1, agent.get_remote_candidates().len());
    }

    // Valid bind without fingerprint
    {
        let mut agent = agent_with_local(AgentConfig {
            is_controlling: true,
            ..Default::default()
        });
        agent
            .set_remote_credentials(
                "remoteufrag".to_owned(),
                "remotepwd0123456789012345".to_owned(),
            )
            .unwrap();
        let (ufrag, pwd) = credentials_of(&agent);
        let mut m = Message::new();
        m.build(&[
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId::new()),
            Box::new(Username::new(ATTR_USERNAME, format!("{ufrag}:remoteufrag"))),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                pwd,
                provider().crypto(),
            )),
        ])
        .unwrap();
        agent.handle_inbound(now, &mut m, 0, remote_addr()).unwrap();
        assert_eq!(1, agent.get_remote_candidates().len());
    }

    // Success with invalid TransactionID
    {
        let mut agent = agent_with_local(AgentConfig::default());
        agent
            .set_remote_credentials(
                "remoteufrag".to_owned(),
                "remotepwd0123456789012345".to_owned(),
            )
            .unwrap();
        let mut tid = TransactionId::default();
        tid.0[..3].copy_from_slice(b"ABC");
        let mut m = Message::new();
        m.build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(tid),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                "remotepwd0123456789012345".to_owned(),
                provider().crypto(),
            )),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
        let _ = agent.handle_inbound(now, &mut m, 0, remote_addr());
        assert!(agent.get_remote_candidates().is_empty());
    }
}

// ---------------------------------------------------------------------------------------------
// TestHandleInboundAdditionalCases
// ---------------------------------------------------------------------------------------------

#[test]
fn test_binding_indication_updates_last_received() {
    let mut agent = agent_with_local(AgentConfig::default());
    let remote = host("192.0.2.1", 4242);
    agent.add_remote_candidate(remote.clone()).unwrap();
    assert!(agent.get_remote_candidates()[0].last_received().is_none());

    let mut m = Message::new();
    m.build(&[
        Box::new(MessageType::new(METHOD_BINDING, CLASS_INDICATION)),
        Box::new(TransactionId::new()),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    let now = Instant::now();
    agent.handle_inbound(now, &mut m, 0, remote.addr()).unwrap();
    assert_eq!(
        Some(now),
        agent.get_remote_candidates()[0].last_received(),
        "an indication proves the sender is alive"
    );
}

#[test]
fn test_role_conflict_prevents_binding_handling() {
    // Both sides controlling with the same tiebreaker: the local side keeps its role and the
    // request is answered with an error, not handled as a check.
    let mut agent = agent_with_local(AgentConfig {
        is_controlling: true,
        ..Default::default()
    });
    agent
        .set_remote_credentials(
            "remoteufrag".to_owned(),
            "remotepwd0123456789012345".to_owned(),
        )
        .unwrap();
    let (ufrag, pwd) = credentials_of(&agent);
    let tie_breaker = agent.tie_breaker;
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, format!("{ufrag}:remoteufrag"))),
        Box::new(AttrControlling(tie_breaker)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            pwd,
            provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    agent
        .handle_inbound(Instant::now(), &mut m, 0, remote_addr())
        .unwrap();

    assert!(agent.role(), "still controlling");
    let packet = agent.poll_write().expect("a role conflict answer");
    let mut answer = Message {
        raw: packet.message.to_vec(),
        ..Default::default()
    };
    answer.decode().unwrap();
    assert_eq!(CLASS_ERROR_RESPONSE, answer.typ.class);
    assert!(
        agent.poll_write().is_none(),
        "nothing else: no check was triggered"
    );
}

#[test]
fn test_success_response_for_known_transaction_marks_pair_succeeded() {
    let mut agent = agent_with_local(AgentConfig {
        is_controlling: true,
        ..Default::default()
    });
    let remote = host("192.0.2.2", 5555);
    agent.add_remote_candidate(remote.clone()).unwrap();
    agent
        .set_remote_credentials(
            "remoteufrag".to_owned(),
            "remotekey0123456789012345".to_owned(),
        )
        .unwrap();

    let mut tid = TransactionId::default();
    tid.0[..3].copy_from_slice(b"ABC");
    let now = Instant::now();
    agent.pending_binding_requests = vec![BindingRequest {
        timestamp: now,
        transaction_id: tid,
        destination: remote.addr(),
        is_use_candidate: false,
        is_controlling: true,
        nomination_value: None,
    }];

    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(tid),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            "remotekey0123456789012345".to_owned(),
            provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    agent.handle_inbound(now, &mut m, 0, remote.addr()).unwrap();

    let pair = agent.find_pair(0, 0).expect("the pair exists");
    assert_eq!(
        CandidatePairState::Succeeded,
        agent.candidate_pairs[pair].state
    );
    assert!(agent.pending_binding_requests.is_empty());
}

#[test]
fn test_requests_from_blocked_addresses_are_discarded() {
    let blocked: IpAddr = "172.17.0.44".parse().unwrap();
    let mut agent = agent_with_local(AgentConfig {
        remote_ip_filter: Some(IpFilter::new(move |ip| *ip != blocked)),
        ..Default::default()
    });
    agent
        .set_remote_credentials(
            "remoteufrag".to_owned(),
            "remotepwd0123456789012345".to_owned(),
        )
        .unwrap();
    let (ufrag, pwd) = credentials_of(&agent);

    let mut m = build_msg(CLASS_REQUEST, &format!("{ufrag}:remoteufrag"), &pwd);
    let _ = agent.handle_inbound(
        Instant::now(),
        &mut m,
        0,
        "172.17.0.44:9999".parse().unwrap(),
    );
    assert!(agent.get_remote_candidates().is_empty());
    assert!(agent.poll_write().is_none(), "the request is not answered");

    // another address is fine
    let mut m = build_msg(CLASS_REQUEST, &format!("{ufrag}:remoteufrag"), &pwd);
    let _ = agent.handle_inbound(
        Instant::now(),
        &mut m,
        0,
        "172.17.0.45:9999".parse().unwrap(),
    );
    assert_eq!(1, agent.get_remote_candidates().len());
}

#[test]
fn test_prflx_filter_is_called_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let mut agent = agent_with_local(AgentConfig {
        remote_ip_filter: Some(IpFilter::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst) + 1 > 1
        })),
        ..Default::default()
    });
    agent
        .set_remote_credentials(
            "remoteufrag".to_owned(),
            "remotepwd0123456789012345".to_owned(),
        )
        .unwrap();
    let (ufrag, pwd) = credentials_of(&agent);
    let mut m = build_msg(CLASS_REQUEST, &format!("{ufrag}:remoteufrag"), &pwd);
    let _ = agent.handle_inbound(
        Instant::now(),
        &mut m,
        0,
        "172.17.0.45:9999".parse().unwrap(),
    );

    assert_eq!(1, calls.load(Ordering::SeqCst));
    assert!(agent.get_remote_candidates().is_empty());
}

// pion TestRemoteIPFilterInAddRemoteCandidate / TestAddRemoteCandidateHonorsRemoteIPFilter,
// and the local filter (WithIPFilter).
#[test]
fn test_ip_filters_apply_to_added_candidates() {
    let blocked: IpAddr = "192.0.2.9".parse().unwrap();
    let mut agent = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig {
            remote_ip_filter: Some(IpFilter::new(move |ip| *ip != blocked)),
            ip_filter: Some(IpFilter::new(|ip| !ip.is_loopback())),
            ..Default::default()
        }),
        provider(),
    )
    .unwrap();

    assert!(!agent.add_remote_candidate(host("192.0.2.9", 1000)).unwrap());
    assert!(
        agent
            .add_remote_candidate(host("192.0.2.10", 1000))
            .unwrap()
    );
    assert_eq!(1, agent.get_remote_candidates().len());

    assert!(!agent.add_local_candidate(host("127.0.0.1", 2000)).unwrap());
    assert!(agent.add_local_candidate(host("192.0.2.1", 2000)).unwrap());
    assert_eq!(1, agent.get_local_candidates().len());
}

// ---------------------------------------------------------------------------------------------
// TestHandlePeerReflexive
// ---------------------------------------------------------------------------------------------

fn controlling_with_credentials() -> (Agent, String, String) {
    let mut agent = agent_with_local(AgentConfig {
        is_controlling: true,
        ..Default::default()
    });
    agent
        .set_remote_credentials(
            "remoteufrag".to_owned(),
            "remotepwd0123456789012345".to_owned(),
        )
        .unwrap();
    let (ufrag, pwd) = credentials_of(&agent);
    (agent, ufrag, pwd)
}

fn use_candidate_request(ufrag: &str, pwd: &str, tie_breaker: u64, priority: u32) -> Message {
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, format!("{ufrag}:remoteufrag"))),
        Box::<UseCandidateAttr>::default(),
        Box::new(AttrControlling(tie_breaker)),
        Box::new(PriorityAttr(priority)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            pwd.to_owned(),
            provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    m
}

/// A controlled agent (as in pion's tests, which feed it requests that carry
/// `ICE-CONTROLLING`) with credentials for a remote it has not been given a candidate for.
fn controlled_with_credentials() -> (Agent, String, String) {
    let mut agent = agent_with_local(AgentConfig::default());
    agent
        .set_remote_credentials(
            "remoteufrag".to_owned(),
            "remotepwd0123456789012345".to_owned(),
        )
        .unwrap();
    let (ufrag, pwd) = credentials_of(&agent);
    (agent, ufrag, pwd)
}

#[test]
fn test_udp_prflx_candidate_from_handle_inbound() {
    let (mut agent, ufrag, pwd) = controlled_with_credentials();
    let local_priority = agent.get_local_candidates()[0].priority();
    let mut m = use_candidate_request(&ufrag, &pwd, 5, local_priority);
    agent
        .handle_inbound(Instant::now(), &mut m, 0, remote_addr())
        .unwrap();

    assert_eq!(1, agent.get_remote_candidates().len());
    let c = &agent.get_remote_candidates()[0];
    assert_eq!(CandidateType::PeerReflexive, c.candidate_type());
    assert_eq!("172.17.0.3", c.address());
    assert_eq!(999, c.port());
}

#[test]
fn test_prflx_candidate_priority_comes_from_inbound_priority() {
    let (mut agent, ufrag, pwd) = controlled_with_credentials();
    let mut m = use_candidate_request(&ufrag, &pwd, 5, 123456);
    agent
        .handle_inbound(Instant::now(), &mut m, 0, remote_addr())
        .unwrap();
    let c = &agent.get_remote_candidates()[0];
    assert_eq!(CandidateType::PeerReflexive, c.candidate_type());
    assert_eq!(123456, c.priority());
}

#[test]
fn test_resolved_mdns_candidate_is_matched_instead_of_creating_prflx() {
    let (mut agent, ufrag, pwd) = controlled_with_credentials();

    let mut mdns = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1f4712db-ea17-4bcf-a596-105139dfd8bf.local".to_owned(),
            port: 999,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap();
    mdns.set_ip(&"172.17.0.3".parse().unwrap()).unwrap();
    // what the agent does when the mDNS query comes back
    agent.trigger_request_connectivity_check(vec![mdns]);

    let mut m = use_candidate_request(&ufrag, &pwd, 5, 1000);
    agent
        .handle_inbound(Instant::now(), &mut m, 0, remote_addr())
        .unwrap();

    // The inbound traffic matches the resolved candidate by transport address rather than
    // surfacing a duplicate prflx candidate (RFC 8445 §7.3.1.3).
    assert_eq!(1, agent.get_remote_candidates().len());
    assert_eq!(
        "1f4712db-ea17-4bcf-a596-105139dfd8bf.local",
        agent.get_remote_candidates()[0].address()
    );
    assert_eq!(
        CandidateType::Host,
        agent.get_remote_candidates()[0].candidate_type()
    );
}

// pion "Signaled srflx candidate replaces existing remote prflx candidate"
#[test]
fn test_signaled_srflx_candidate_replaces_prflx_and_keeps_the_pair() {
    use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;

    let (mut agent, ufrag, pwd) = controlled_with_credentials();
    let mut m = use_candidate_request(&ufrag, &pwd, 5, 99999);
    agent
        .handle_inbound(Instant::now(), &mut m, 0, remote_addr())
        .unwrap();
    assert_eq!(
        CandidateType::PeerReflexive,
        agent.get_remote_candidates()[0].candidate_type()
    );
    assert_eq!(1, agent.candidate_pairs.len());
    let old_priority = agent.candidate_pairs[0].priority();
    agent.set_selected_pair(Some(Instant::now()), Some(0));

    let srflx = CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "172.17.0.3".to_owned(),
            port: 999,
            component: 1,
            ..Default::default()
        },
        rel_addr: "10.0.0.5".to_owned(),
        rel_port: 5000,
        ..Default::default()
    }
    .new_candidate_server_reflexive()
    .unwrap();
    agent.add_remote_candidate(srflx).unwrap();

    assert_eq!(1, agent.get_remote_candidates().len());
    assert_eq!(
        CandidateType::ServerReflexive,
        agent.get_remote_candidates()[0].candidate_type()
    );
    assert_eq!(1, agent.candidate_pairs.len());
    assert_eq!(
        old_priority,
        agent.candidate_pairs[0].priority(),
        "the pair keeps the rank it had"
    );
    assert_eq!(Some(0), agent.get_selected_pair());
}

// ---------------------------------------------------------------------------------------------
// TestAcceptAggressiveNomination
// ---------------------------------------------------------------------------------------------

#[test]
fn test_accept_aggressive_nomination() {
    // (name, lite, check priority, higher priority, expected to switch)
    let cases = [
        ("higher priority - full agent", false, false, true, true),
        ("lower priority - full agent", false, false, false, false),
        ("higher priority - lite agent", true, false, true, true),
        (
            "lower priority - lite agent, no check",
            true,
            false,
            false,
            true,
        ),
        (
            "higher priority - lite agent, check",
            true,
            true,
            true,
            true,
        ),
        (
            "lower priority - lite agent, check",
            true,
            true,
            false,
            false,
        ),
    ];

    for (name, lite, check, higher, expect_switch) in cases {
        let remotes = {
            let mut first = host("10.0.0.1", 1000);
            first.priority_override = 100_000;
            let mut second = host("10.0.0.1", 1001);
            second.priority_override = if higher { 101_000 } else { 99_500 };
            [first, second]
        };
        let (mut peer, local) = agent_with_pairs(
            false,
            AgentConfig {
                lite,
                candidate_types: if lite {
                    vec![CandidateType::Host]
                } else {
                    vec![]
                },
                enable_use_candidate_check_priority: check,
                ..Default::default()
            },
            &remotes,
        );

        let m = nomination_request(&peer, true, None);
        deliver_from(&mut peer, &local, &remotes[0], &m);
        assert_eq!(
            Some(remotes[0].addr()),
            selected_remote(&peer),
            "{name}: first"
        );

        let m = nomination_request(&peer, true, None);
        deliver_from(&mut peer, &local, &remotes[1], &m);
        let expected = if expect_switch {
            &remotes[1]
        } else {
            &remotes[0]
        };
        assert_eq!(Some(expected.addr()), selected_remote(&peer), "{name}");
    }
}

// ---------------------------------------------------------------------------------------------
// Keepalive and connection-state transitions
// ---------------------------------------------------------------------------------------------

// pion TestAlwaysSentKeepAlive: once connected, a consent check goes out every keepalive
// interval for as long as the connection lives.
#[test]
fn test_keepalive_is_always_sent() {
    let mut clock = Instant::now();
    let mut a = Peer::new(clock, AgentConfig::default());
    let mut b = Peer::new(clock, AgentConfig::default());
    start(
        &mut a,
        &[host("10.0.0.1", 1000)],
        true,
        &mut b,
        &[host("10.0.0.2", 2000)],
        false,
        clock,
    );
    run(&mut a, &mut b, &mut clock, 2000);
    assert_eq!(ConnectionState::Connected, a.agent.state());

    let checks = |peer: &Peer| {
        peer.sent
            .iter()
            .filter(|raw| {
                let mut m = Message {
                    raw: (*raw).clone(),
                    ..Default::default()
                };
                m.decode().is_ok() && m.typ.class == CLASS_REQUEST
            })
            .count()
    };
    let mut previous = checks(&a);
    for _ in 0..5 {
        run(&mut a, &mut b, &mut clock, 2100);
        let now = checks(&a);
        assert!(now > previous, "a consent check every keepalive interval");
        previous = now;
    }
    assert_eq!(ConnectionState::Connected, a.agent.state());
    assert_eq!(ConnectionState::Connected, b.agent.state());
}

// pion TestValidateSelectedPairTransitions
#[test]
fn test_validate_selected_pair_transitions() {
    let now = Instant::now();
    let mut agent = Agent::new(
        now,
        Arc::new(AgentConfig {
            disconnected_timeout: Some(Duration::from_secs(1)),
            failed_timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        }),
        provider(),
    )
    .unwrap();
    agent.add_local_candidate(host("1.1.1.1", 1000)).unwrap();
    agent.add_remote_candidate(host("2.2.2.2", 2000)).unwrap();
    agent.set_selected_pair(Some(now), Some(0));
    assert_eq!(ConnectionState::Connected, agent.state());

    let later = now + Duration::from_secs(10);
    agent.remote_candidates[0].set_last_received(later - Duration::from_secs(3));

    assert!(agent.validate_selected_pair(later));
    assert_eq!(ConnectionState::Disconnected, agent.state());
    assert!(agent.validate_selected_pair(later));
    assert_eq!(ConnectionState::Failed, agent.state());
}

// pion TestAddRemoteCandidateStoresCandidatesIndependentlyOfNetworkTypes
#[test]
fn test_remote_candidates_are_stored_independently_of_network_types() {
    let mut agent = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig {
            network_types: vec![NetworkType::Udp4],
            ..Default::default()
        }),
        provider(),
    )
    .unwrap();

    let tcp =
        unmarshal_candidate("1052353102 1 tcp 1675624447 192.0.2.1 8080 typ host tcptype passive")
            .unwrap();
    let udp = unmarshal_candidate("1052353102 1 udp 1675624447 192.0.2.2 8080 typ host").unwrap();
    agent.add_remote_candidate(tcp).unwrap();
    agent.add_remote_candidate(udp).unwrap();

    let addresses: Vec<&str> = agent
        .get_remote_candidates()
        .iter()
        .map(Candidate::address)
        .collect();
    assert_eq!(vec!["192.0.2.1", "192.0.2.2"], addresses);
}

// pion "prflx candidate is stored even when network type is disabled"
#[test]
fn test_prflx_candidate_is_stored_even_when_its_network_type_is_disabled() {
    let mut agent = agent_with_local(AgentConfig::default());
    // the agent only enables TCP, yet UDP traffic arrived
    agent.network_types = vec![NetworkType::Tcp4];
    agent
        .set_remote_credentials(
            "remoteufrag".to_owned(),
            "remotepwd0123456789012345".to_owned(),
        )
        .unwrap();
    let (ufrag, pwd) = credentials_of(&agent);
    let mut m = use_candidate_request(&ufrag, &pwd, 5, 1000);
    agent
        .handle_inbound(Instant::now(), &mut m, 0, remote_addr())
        .unwrap();
    assert_eq!(1, agent.get_remote_candidates().len());
    assert_eq!(
        NetworkType::Udp4,
        agent.get_remote_candidates()[0].network_type()
    );
}

// pion "Success from unknown remote, prflx candidate MUST only be created via Binding Request"
#[test]
fn test_success_from_unknown_remote_creates_no_prflx_candidate() {
    let (mut agent, _, _) = controlled_with_credentials();
    let mut tid = TransactionId::default();
    tid.0[..3].copy_from_slice(b"ABC");
    agent.pending_binding_requests = vec![BindingRequest {
        timestamp: Instant::now(),
        transaction_id: tid,
        destination: "0.0.0.0:0".parse().unwrap(),
        is_use_candidate: false,
        is_controlling: false,
        nomination_value: None,
    }];
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(tid),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            "remotepwd0123456789012345".to_owned(),
            provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    let _ = agent.handle_inbound(Instant::now(), &mut m, 0, remote_addr());
    assert!(agent.get_remote_candidates().is_empty());
}

// pion "AcceptanceMinWait: prflx not accepted until replaced": a pair to a peer-reflexive
// candidate waits out the (long) prflx acceptance time, but once the signaled candidate for the
// same address replaces it, the host's (no) wait applies.
#[test]
fn test_prflx_acceptance_wait_ends_when_the_signaled_candidate_replaces_it() {
    use crate::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig;

    let clock = Instant::now();
    let mut agent = Agent::new(
        clock,
        Arc::new(AgentConfig {
            is_controlling: true,
            host_acceptance_min_wait: Some(Duration::ZERO),
            prflx_acceptance_min_wait: Some(Duration::from_secs(3600)),
            ..Default::default()
        }),
        provider(),
    )
    .unwrap();
    agent.add_local_candidate(host("192.168.0.2", 777)).unwrap();
    agent
        .start_connectivity_checks(
            clock,
            true,
            "remoteufrag".to_owned(),
            "remotepwd0123456789012345".to_owned(),
        )
        .unwrap();

    let prflx = CandidatePeerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.4".to_owned(),
            port: 999,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_peer_reflexive()
    .unwrap();
    agent.add_remote_candidate(prflx).unwrap();
    let pair = agent.find_pair(0, 0).unwrap();
    assert_eq!(
        CandidateType::Host,
        agent.local_candidates[0].candidate_type()
    );
    assert_eq!(
        CandidateType::PeerReflexive,
        agent.remote_candidates[0].candidate_type()
    );
    agent.candidate_pairs[pair].state = CandidatePairState::Succeeded;

    // prflx acceptance wait is an hour: not nominatable yet
    agent.contact_candidates(clock + Duration::from_secs(1));
    assert_eq!(None, agent.nominated_pair);
    assert!(!agent.candidate_pairs[pair].nominated);

    // the signaled candidate for that address replaces the prflx one
    agent.add_remote_candidate(host("1.2.3.4", 999)).unwrap();
    assert_eq!(
        CandidateType::Host,
        agent.remote_candidates[0].candidate_type()
    );

    agent.contact_candidates(clock + Duration::from_secs(2));
    assert_eq!(Some(pair), agent.nominated_pair);
    assert!(agent.candidate_pairs[pair].nominated);
}

// pion "Signaled relay candidate replaces existing remote prflx candidate"
#[test]
fn test_signaled_relay_candidate_replaces_prflx() {
    let (mut agent, ufrag, pwd) = controlled_with_credentials();
    let mut m = use_candidate_request(&ufrag, &pwd, 5, 99999);
    agent
        .handle_inbound(Instant::now(), &mut m, 0, remote_addr())
        .unwrap();
    let old_priority = agent.candidate_pairs[0].priority();

    agent
        .add_remote_candidate(relay("172.17.0.3", 999))
        .unwrap();

    assert_eq!(1, agent.get_remote_candidates().len());
    assert_eq!(
        CandidateType::Relay,
        agent.get_remote_candidates()[0].candidate_type()
    );
    assert_eq!(1, agent.candidate_pairs.len());
    assert_eq!(old_priority, agent.candidate_pairs[0].priority());
}

// pion TestRoleConflictErrorResponse: `b` answers `a`'s check with a 487, and with `b`'s own
// requests withheld, `a` has to switch roles purely because of that 487; afterwards both connect.
#[test]
fn test_role_conflict_error_response_alone_resolves_the_conflict() {
    for (name, controlling, a_tie, b_tie) in [
        ("controlled", false, 2u64, 1u64),
        ("controlling", true, 1, 2),
    ] {
        let mut clock = Instant::now();
        let mut a = Peer::new(clock, AgentConfig::default());
        let mut b = Peer::new(clock, AgentConfig::default());
        a.agent.tie_breaker = a_tie;
        b.agent.tie_breaker = b_tie;

        // wire the peers up by hand, `b` first (its role is established before `a`'s request)
        let a_candidate = host("192.168.0.1", 1000);
        let b_candidate = host("192.168.0.2", 2000);
        a.agent.add_local_candidate(a_candidate.clone()).unwrap();
        a.agent.add_remote_candidate(b_candidate.clone()).unwrap();
        b.agent.add_local_candidate(b_candidate.clone()).unwrap();
        b.agent.add_remote_candidate(a_candidate.clone()).unwrap();
        let (a_ufrag, a_pwd) = credentials(&a);
        let (b_ufrag, b_pwd) = credentials(&b);
        b.agent
            .start_connectivity_checks(clock, controlling, a_ufrag, a_pwd)
            .unwrap();
        a.agent
            .start_connectivity_checks(clock, controlling, b_ufrag, b_pwd)
            .unwrap();

        let is_request = |raw: &[u8]| {
            let mut m = Message {
                raw: raw.to_vec(),
                ..Default::default()
            };
            m.decode().is_ok() && m.typ.class == CLASS_REQUEST
        };
        let mut saw_role_conflict = false;
        let mut withhold_b_requests = true;

        for _ in 0..200 {
            clock += Duration::from_millis(50);
            a.agent.handle_timeout(clock).unwrap();
            b.agent.handle_timeout(clock).unwrap();
            loop {
                let mut moved = false;
                while let Some(packet) = a.agent.poll_write() {
                    moved = true;
                    let _ = b.agent.handle_read(reverse(&packet, clock));
                }
                while let Some(packet) = b.agent.poll_write() {
                    moved = true;
                    if withhold_b_requests && is_request(&packet.message) {
                        continue;
                    }
                    let mut m = Message {
                        raw: packet.message.to_vec(),
                        ..Default::default()
                    };
                    if m.decode().is_ok() && m.typ.class == CLASS_ERROR_RESPONSE {
                        saw_role_conflict = true;
                    }
                    let _ = a.agent.handle_read(reverse(&packet, clock));
                }
                a.drain_events();
                b.drain_events();
                if !moved {
                    break;
                }
            }

            if withhold_b_requests && saw_role_conflict && a.agent.role() == !controlling {
                withhold_b_requests = false;
            }
        }

        assert!(saw_role_conflict, "{name}: b answered with a 487");
        assert_eq!(!controlling, a.agent.role(), "{name}: a switched");
        assert_eq!(controlling, b.agent.role(), "{name}: b held its role");
        assert_eq!(ConnectionState::Connected, a.agent.state(), "{name}");
        assert_eq!(ConnectionState::Connected, b.agent.state(), "{name}");
    }
}

/// The datagram as the receiving end sees it.
fn reverse(packet: &TaggedBytesMut, now: Instant) -> TaggedBytesMut {
    TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: packet.transport.peer_addr,
            peer_addr: packet.transport.local_addr,
            ecn: None,
            transport_protocol: packet.transport.transport_protocol,
        },
        message: packet.message.clone(),
    }
}

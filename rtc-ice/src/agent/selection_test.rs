//! Scenario tests for pair selection, nomination and renomination, ported from pion/ice
//! v4.4.8 (`selection_test.go`, `renomination_test.go`, `role_test.go`).
//!
//! pion drives its agents over real or virtual sockets; here two sans-I/O agents are wired
//! back to back in memory under a hand-advanced clock, so every scenario is deterministic.

use super::*;
use crate::attributes::nomination::{
    DEFAULT_NOMINATION_ATTRIBUTE, NominationAttribute, NominationSetter,
};
use crate::attributes::{
    control::AttrControlling, priority::PriorityAttr, use_candidate::UseCandidateAttr,
};
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig;
use crate::candidate::candidate_relay::CandidateRelayConfig;
use sansio::Protocol;
use std::str::FromStr;
use stun::attributes::*;
use stun::fingerprint::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;

pub(super) fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

pub(super) fn host(ip: &str, port: u16) -> Candidate {
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

pub(super) fn relay(ip: &str, port: u16) -> Candidate {
    CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: ip.to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        rel_addr: ip.to_owned(),
        rel_port: port,
        ..Default::default()
    }
    .new_candidate_relay()
    .unwrap()
}

/// One end of the in-memory link: an agent plus what it reported.
pub(super) struct Peer {
    pub(super) agent: Agent,
    pub(super) selected: Vec<(SocketAddr, SocketAddr)>,
    pub(super) states: Vec<ConnectionState>,
    pub(super) roles: Vec<bool>,
    /// Every packet the agent sent, for inspection.
    pub(super) sent: Vec<Vec<u8>>,
}

impl Peer {
    pub(super) fn new(now: Instant, config: AgentConfig) -> Peer {
        Peer {
            agent: Agent::new(now, Arc::new(config), provider()).unwrap(),
            selected: vec![],
            states: vec![],
            roles: vec![],
            sent: vec![],
        }
    }

    pub(super) fn selected_pair(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.agent
            .get_selected_candidate_pair()
            .map(|(local, remote)| (local.addr(), remote.addr()))
    }

    pub(super) fn drain_events(&mut self) {
        while let Some(event) = self.agent.poll_event() {
            match event.event {
                Event::ConnectionStateChange(state) => self.states.push(state),
                Event::SelectedCandidatePairChange(local, remote) => {
                    self.selected.push((local.addr(), remote.addr()))
                }
                Event::RoleChange(controlling) => self.roles.push(controlling),
            }
        }
    }
}

/// Moves everything `from` has queued to `to`; whether anything moved.
pub(super) fn forward(from: &mut Peer, to: &mut Peer, now: Instant) -> bool {
    let mut moved = false;
    while let Some(packet) = from.agent.poll_write() {
        moved = true;
        from.sent.push(packet.message.to_vec());
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
        let _ = to.agent.handle_read(inbound);
    }
    moved
}

/// Delivers every pending datagram between the two peers until the link is quiet.
pub(super) fn pump(a: &mut Peer, b: &mut Peer, now: Instant) {
    loop {
        let moved_a = forward(a, b, now);
        let moved_b = forward(b, a, now);
        a.drain_events();
        b.drain_events();
        if !moved_a && !moved_b {
            break;
        }
    }
}

/// Advances the clock in 50 ms steps, running both agents and the link.
pub(super) fn run(a: &mut Peer, b: &mut Peer, clock: &mut Instant, millis: u64) {
    for _ in 0..millis / 50 {
        *clock += Duration::from_millis(50);
        a.agent.handle_timeout(*clock).unwrap();
        b.agent.handle_timeout(*clock).unwrap();
        pump(a, b, *clock);
    }
}

pub(super) fn credentials(peer: &Peer) -> (String, String) {
    let c = peer.agent.get_local_credentials();
    (c.ufrag.clone(), c.pwd.clone())
}

/// Wires two peers together: each learns the other's candidates and credentials, and starts
/// checking in the given role.
pub(super) fn start(
    a: &mut Peer,
    a_candidates: &[Candidate],
    a_controlling: bool,
    b: &mut Peer,
    b_candidates: &[Candidate],
    b_controlling: bool,
    now: Instant,
) {
    for c in a_candidates {
        a.agent.add_local_candidate(c.clone()).unwrap();
        b.agent.add_remote_candidate(c.clone()).unwrap();
    }
    for c in b_candidates {
        b.agent.add_local_candidate(c.clone()).unwrap();
        a.agent.add_remote_candidate(c.clone()).unwrap();
    }
    let (a_ufrag, a_pwd) = credentials(a);
    let (b_ufrag, b_pwd) = credentials(b);
    a.agent
        .start_connectivity_checks(now, a_controlling, b_ufrag, b_pwd)
        .unwrap();
    b.agent
        .start_connectivity_checks(now, b_controlling, a_ufrag, a_pwd)
        .unwrap();
}

pub(super) fn addr(ip: &str, port: u16) -> SocketAddr {
    SocketAddr::from_str(&format!("{ip}:{port}")).unwrap()
}

pub(super) fn renominating(generator: NominationValueGenerator) -> AgentConfig {
    AgentConfig {
        is_controlling: true,
        renomination: Some(generator),
        ..Default::default()
    }
}

/// Two connected peers with two host candidates each, controlling side renomination-enabled.
fn connected_with_two_pairs(
    generator: NominationValueGenerator,
) -> (Peer, Peer, Instant, [Candidate; 2], [Candidate; 2]) {
    let mut clock = Instant::now();
    let mut a = Peer::new(clock, renominating(generator));
    let mut b = Peer::new(clock, AgentConfig::default());
    let a_candidates = [host("10.0.0.1", 1000), host("10.0.0.1", 1001)];
    let b_candidates = [host("10.0.0.2", 2000), host("10.0.0.2", 2001)];
    start(
        &mut a,
        &a_candidates,
        true,
        &mut b,
        &b_candidates,
        false,
        clock,
    );
    run(&mut a, &mut b, &mut clock, 3000);
    (a, b, clock, a_candidates, b_candidates)
}

// ---------------------------------------------------------------------------------------------
// Connection and ordinary nomination
// ---------------------------------------------------------------------------------------------

#[test]
fn test_two_agents_connect_and_select_the_same_pair() {
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
    assert_eq!(ConnectionState::Connected, b.agent.state());
    assert_eq!(
        Some((addr("10.0.0.1", 1000), addr("10.0.0.2", 2000))),
        a.selected_pair()
    );
    assert_eq!(
        Some((addr("10.0.0.2", 2000), addr("10.0.0.1", 1000))),
        b.selected_pair()
    );
    // exactly one selection each: nothing flapped
    assert_eq!(1, a.selected.len());
    assert_eq!(1, b.selected.len());
}

// pion TestBindingRequestPriorityAttr, RFC 8445 §7.1.1: a check carries the priority a
// peer-reflexive candidate would have, and the peer that learns the address takes it.
#[test]
fn test_binding_request_priority_attr() {
    let mut clock = Instant::now();
    let mut a = Peer::new(clock, AgentConfig::default());
    let mut b = Peer::new(clock, AgentConfig::default());

    // `b` is told nothing about `a`'s candidate, so it must learn it from the check.
    let a_candidate = host("10.0.0.1", 1000);
    a.agent.add_local_candidate(a_candidate.clone()).unwrap();
    a.agent
        .add_remote_candidate(host("10.0.0.2", 2000))
        .unwrap();
    b.agent.add_local_candidate(host("10.0.0.2", 2000)).unwrap();
    let (a_ufrag, a_pwd) = credentials(&a);
    let (b_ufrag, b_pwd) = credentials(&b);
    a.agent
        .start_connectivity_checks(clock, true, b_ufrag, b_pwd)
        .unwrap();
    b.agent
        .start_connectivity_checks(clock, false, a_ufrag, a_pwd)
        .unwrap();
    run(&mut a, &mut b, &mut clock, 500);

    let learned = b
        .agent
        .get_remote_candidates()
        .iter()
        .find(|c| c.addr() == addr("10.0.0.1", 1000))
        .expect("b learned a peer-reflexive candidate");
    assert_eq!(CandidateType::PeerReflexive, learned.candidate_type());
    assert_eq!(a_candidate.prflx_priority(), learned.priority());
    assert_ne!(
        a_candidate.priority(),
        learned.priority(),
        "the check must not advertise the host priority"
    );
}

// ---------------------------------------------------------------------------------------------
// Renomination
// ---------------------------------------------------------------------------------------------

// pion TestAgentRenominateCandidate / TestControllingSideRenomination: the controlling agent
// moves the call to another pair and the controlled agent follows.
#[test]
fn test_renomination_moves_both_sides_to_the_new_pair() {
    let (mut a, mut b, mut clock, a_candidates, b_candidates) =
        connected_with_two_pairs(NominationValueGenerator::incrementing());
    let first = a.selected_pair().expect("a selected a pair");
    assert_eq!(b.selected_pair(), Some((first.1, first.0)));

    // renominate towards the pair that is not selected
    let (local, remote) = if first.0 == a_candidates[0].addr() {
        (&a_candidates[1], &b_candidates[1])
    } else {
        (&a_candidates[0], &b_candidates[0])
    };
    a.agent.renominate_candidate(clock, local, remote).unwrap();
    run(&mut a, &mut b, &mut clock, 500);

    assert_eq!(Some((local.addr(), remote.addr())), a.selected_pair());
    assert_eq!(Some((remote.addr(), local.addr())), b.selected_pair());
    assert_eq!(2, a.selected.len(), "one switch, no flapping");
    assert_eq!(2, b.selected.len());
    assert_eq!(ConnectionState::Connected, a.agent.state());
    assert_eq!(ConnectionState::Connected, b.agent.state());
}

#[test]
fn test_renomination_errors() {
    let clock = Instant::now();
    let local = host("10.0.0.1", 1000);
    let remote = host("10.0.0.2", 2000);

    // controlled agents cannot renominate
    let mut controlled = Peer::new(clock, AgentConfig::default());
    assert_eq!(
        Err(Error::ErrOnlyControllingAgentCanRenominate),
        controlled
            .agent
            .renominate_candidate(clock, &local, &remote)
    );

    // not enabled
    let mut disabled = Peer::new(
        clock,
        AgentConfig {
            is_controlling: true,
            ..Default::default()
        },
    );
    assert_eq!(
        Err(Error::ErrRenominationNotEnabled),
        disabled.agent.renominate_candidate(clock, &local, &remote)
    );

    // enabled, but no such pair
    let mut enabled = Peer::new(
        clock,
        renominating(NominationValueGenerator::incrementing()),
    );
    assert_eq!(
        Err(Error::ErrCandidatePairNotFound),
        enabled.agent.renominate_candidate(clock, &local, &remote)
    );
}

// pion TestSendNominationRequest: the request is a USE-CANDIDATE check carrying the nomination
// value under the configured attribute type, and PRIORITY is the prflx priority.
#[test]
fn test_nomination_request_wire_format() {
    for (attribute, expected_type) in [
        (None, DEFAULT_NOMINATION_ATTRIBUTE),
        (Some(0xC123), AttrType(0xC123)),
    ] {
        let clock = Instant::now();
        let mut a = Peer::new(
            clock,
            AgentConfig {
                is_controlling: true,
                renomination: Some(NominationValueGenerator::new(|| 42)),
                nomination_attribute: attribute,
                ..Default::default()
            },
        );
        let mut b = Peer::new(clock, AgentConfig::default());
        let a_candidate = host("10.0.0.1", 1000);
        start(
            &mut a,
            &[a_candidate.clone()],
            true,
            &mut b,
            &[host("10.0.0.2", 2000)],
            false,
            clock,
        );

        let remote = a.agent.get_remote_candidates()[0].clone();
        a.agent
            .renominate_candidate(clock, &a_candidate, &remote)
            .unwrap();
        let packet = a.agent.poll_write().expect("a nomination request");

        let mut m = Message {
            raw: packet.message.to_vec(),
            ..Default::default()
        };
        m.decode().unwrap();
        assert!(m.contains(ATTR_USE_CANDIDATE));
        assert!(m.contains(ATTR_ICE_CONTROLLING));
        assert!(m.contains(expected_type));
        let mut nomination = NominationAttribute::default();
        nomination.get_from_with_type(&m, expected_type).unwrap();
        assert_eq!(42, nomination.value);
        let mut priority = PriorityAttr::default();
        priority.get_from(&m).unwrap();
        assert_eq!(a_candidate.prflx_priority(), priority.0);
    }
}

// A zero value is "no renomination value": it is not sent, so the request is an ordinary
// nomination (pion `nominationValue > 0`).
#[test]
fn test_zero_nomination_value_is_not_sent() {
    let clock = Instant::now();
    let mut a = Peer::new(
        clock,
        AgentConfig {
            is_controlling: true,
            renomination: Some(NominationValueGenerator::new(|| 0)),
            ..Default::default()
        },
    );
    let mut b = Peer::new(clock, AgentConfig::default());
    let a_candidate = host("10.0.0.1", 1000);
    start(
        &mut a,
        &[a_candidate.clone()],
        true,
        &mut b,
        &[host("10.0.0.2", 2000)],
        false,
        clock,
    );
    let remote = a.agent.get_remote_candidates()[0].clone();
    a.agent
        .renominate_candidate(clock, &a_candidate, &remote)
        .unwrap();
    let packet = a.agent.poll_write().unwrap();
    let mut m = Message {
        raw: packet.message.to_vec(),
        ..Default::default()
    };
    m.decode().unwrap();
    assert!(m.contains(ATTR_USE_CANDIDATE));
    assert!(!m.contains(DEFAULT_NOMINATION_ATTRIBUTE));
}

#[test]
fn test_invalid_nomination_attribute_is_rejected() {
    let config = AgentConfig {
        nomination_attribute: Some(0),
        ..Default::default()
    };
    assert!(matches!(
        Agent::new(Instant::now(), Arc::new(config), provider()),
        Err(Error::ErrInvalidNominationAttribute)
    ));
}

// pion TestNominationValueGenerator / DefaultNominationValueGenerator
#[test]
fn test_incrementing_nomination_value_generator() {
    let g = NominationValueGenerator::incrementing();
    assert_eq!(1, g.generate());
    assert_eq!(2, g.generate());
    assert_eq!(3, g.generate());
}

// pion TestControlledSelectorNominationAcceptance / ...Disabled: "last nomination wins",
// whatever the local configuration says.
#[test]
fn test_controlled_nomination_acceptance_is_last_wins() {
    for config in [
        AgentConfig::default(),
        AgentConfig {
            renomination: Some(NominationValueGenerator::incrementing()),
            ..Default::default()
        },
    ] {
        let mut peer = Peer::new(Instant::now(), config);
        let agent = &mut peer.agent;
        agent.start(Instant::now());

        assert!(agent.should_accept_nomination(Some(5)), "first is accepted");
        assert!(
            agent.should_accept_nomination(Some(10)),
            "higher is accepted"
        );
        assert!(
            !agent.should_accept_nomination(Some(7)),
            "lower is rejected"
        );
        assert!(
            !agent.should_accept_nomination(Some(10)),
            "equal is rejected"
        );
        assert!(
            agent.should_accept_nomination(None),
            "plain ICE is accepted"
        );
        // a restart of the selector forgets the history
        agent.start(Instant::now());
        assert!(agent.should_accept_nomination(Some(1)));
    }
}

// pion shouldSwitchSelectedPair, with and without the lite opt-in to the priority rule.
#[test]
fn test_should_switch_selected_pair() {
    let clock = Instant::now();
    for (lite, check_priority, ordinary_switch_requires_better) in [
        (false, false, true),
        (true, false, false),
        (true, true, true),
    ] {
        let mut peer = Peer::new(
            clock,
            AgentConfig {
                lite,
                candidate_types: if lite {
                    vec![CandidateType::Host]
                } else {
                    vec![]
                },
                enable_use_candidate_check_priority: check_priority,
                ..Default::default()
            },
        );
        let agent = &mut peer.agent;
        // pair 0: host-host; pair 1: host-relay (lower priority)
        agent.add_local_candidate(host("10.0.0.1", 1000)).unwrap();
        agent.add_remote_candidate(host("10.0.0.2", 2000)).unwrap();
        agent.add_remote_candidate(relay("10.0.0.3", 3000)).unwrap();
        assert!(agent.candidate_pairs[0].priority() > agent.candidate_pairs[1].priority());

        // no selection: anything goes; same pair: no switch
        assert!(agent.should_switch_selected_pair(1, None, None));
        assert!(!agent.should_switch_selected_pair(0, Some(0), None));
        // a renomination value overrides priority
        assert!(agent.should_switch_selected_pair(1, Some(0), Some(1)));
        // ordinary nomination of a worse pair
        assert_eq!(
            !ordinary_switch_requires_better,
            agent.should_switch_selected_pair(1, Some(0), None),
            "lite={lite} check_priority={check_priority}"
        );
        // ordinary nomination of a better pair always switches
        assert!(agent.should_switch_selected_pair(0, Some(1), None));
    }
}

// pion TestAutomaticRenomination: a clearly better path appears after the call is up on a
// relayed one; the controlling agent moves to it without being asked.
#[test]
fn test_automatic_renomination_prefers_direct_over_relay() {
    let mut clock = Instant::now();
    let mut a = Peer::new(
        clock,
        AgentConfig {
            is_controlling: true,
            renomination: Some(NominationValueGenerator::incrementing()),
            automatic_renomination: Some(Duration::from_secs(1)),
            ..Default::default()
        },
    );
    let mut b = Peer::new(clock, AgentConfig::default());

    // The call starts on a relayed path only.
    let a_relay = relay("10.0.0.9", 9000);
    let b_host = host("10.0.0.2", 2000);
    start(
        &mut a,
        &[a_relay.clone()],
        true,
        &mut b,
        &[b_host.clone()],
        false,
        clock,
    );
    run(&mut a, &mut b, &mut clock, 3000);
    assert_eq!(
        Some((a_relay.addr(), b_host.addr())),
        a.selected_pair(),
        "connected over the relay first"
    );

    // A direct path shows up (trickle).
    let a_host = host("10.0.0.1", 1000);
    a.agent.add_local_candidate(a_host.clone()).unwrap();
    b.agent.add_remote_candidate(a_host.clone()).unwrap();
    run(&mut a, &mut b, &mut clock, 6000);

    assert_eq!(
        Some((a_host.addr(), b_host.addr())),
        a.selected_pair(),
        "controlling moved to the direct pair"
    );
    assert_eq!(
        Some((b_host.addr(), a_host.addr())),
        b.selected_pair(),
        "controlled followed"
    );
}

// Without the opt-in, nothing renominates by itself.
#[test]
fn test_no_automatic_renomination_unless_enabled() {
    let mut clock = Instant::now();
    let mut a = Peer::new(
        clock,
        AgentConfig {
            is_controlling: true,
            renomination: Some(NominationValueGenerator::incrementing()),
            ..Default::default()
        },
    );
    let mut b = Peer::new(clock, AgentConfig::default());
    let a_relay = relay("10.0.0.9", 9000);
    let b_host = host("10.0.0.2", 2000);
    start(
        &mut a,
        &[a_relay.clone()],
        true,
        &mut b,
        &[b_host.clone()],
        false,
        clock,
    );
    run(&mut a, &mut b, &mut clock, 3000);

    let a_host = host("10.0.0.1", 1000);
    a.agent.add_local_candidate(a_host.clone()).unwrap();
    b.agent.add_remote_candidate(a_host).unwrap();
    run(&mut a, &mut b, &mut clock, 6000);
    assert_eq!(Some((a_relay.addr(), b_host.addr())), a.selected_pair());
}

// pion shouldRenominate: type, RTT and quality-score rules.
#[test]
fn test_should_renominate_rules() {
    let clock = Instant::now();
    let mut peer = Peer::new(
        clock,
        renominating(NominationValueGenerator::incrementing()),
    );
    let agent = &mut peer.agent;
    agent.add_local_candidate(host("10.0.0.1", 1000)).unwrap();
    agent.add_local_candidate(relay("10.0.0.9", 9000)).unwrap();
    agent.add_remote_candidate(host("10.0.0.2", 2000)).unwrap();
    agent.add_remote_candidate(host("10.0.0.2", 2001)).unwrap();
    // the agent pairs candidates itself as they are added
    let pair = |agent: &Agent, l, r| agent.find_pair(l, r).expect("pair exists");
    let direct = pair(agent, 0, 0);
    let via_relay = pair(agent, 1, 0);
    let other_direct = pair(agent, 0, 1);

    // pairs that have not succeeded are never candidates, and a pair never replaces itself
    assert!(!agent.should_renominate(clock, via_relay, direct));
    for p in [direct, via_relay, other_direct] {
        agent.candidate_pairs[p].state = CandidatePairState::Succeeded;
    }
    assert!(!agent.should_renominate(clock, direct, direct));

    // relay -> direct switches whatever the RTTs
    assert!(agent.should_renominate(clock, via_relay, direct));
    assert!(!agent.should_renominate(clock, direct, via_relay));

    // RTT: switch only when better by more than 10 ms, and only with both measured
    agent.candidate_pairs[direct].current_round_trip_time = Duration::from_millis(50);
    agent.candidate_pairs[other_direct].current_round_trip_time = Duration::from_millis(41);
    assert!(!agent.should_renominate(clock, direct, other_direct));
    agent.candidate_pairs[other_direct].current_round_trip_time = Duration::from_millis(30);
    assert!(agent.should_renominate(clock, direct, other_direct));
    agent.candidate_pairs[other_direct].current_round_trip_time = Duration::ZERO;
    agent.candidate_pairs[direct].current_round_trip_time = Duration::ZERO;
    assert!(
        !agent.should_renominate(clock, direct, other_direct),
        "unmeasured RTTs are not compared; equal scores do not switch"
    );
}

// pion evaluateCandidatePairQuality
#[test]
fn test_pair_quality_score() {
    let clock = Instant::now();
    let mut peer = Peer::new(clock, AgentConfig::default());
    let agent = &mut peer.agent;
    agent.add_local_candidate(host("10.0.0.1", 1000)).unwrap();
    agent.add_remote_candidate(host("10.0.0.2", 2000)).unwrap();

    assert_eq!(
        0.0,
        agent.evaluate_candidate_pair_quality(clock, 0),
        "not succeeded"
    );
    agent.candidate_pairs[0].state = CandidatePairState::Succeeded;
    // host/host averages to 100, no RTT costs 30
    assert_eq!(70.0, agent.evaluate_candidate_pair_quality(clock, 0));
    // 100 ms costs 10 * log10(100) = 20
    agent.candidate_pairs[0].current_round_trip_time = Duration::from_millis(100);
    assert!((80.0 - agent.evaluate_candidate_pair_quality(clock, 0)).abs() < 1e-9);
    // a recent answer adds a stability bonus, a stale one does not
    agent.candidate_pairs[0].responses_received = 1;
    agent.candidate_pairs[0].last_response_received_at = Some(clock);
    assert!((100.0 - agent.evaluate_candidate_pair_quality(clock, 0)).abs() < 1e-9);
    assert!(
        (80.0 - agent.evaluate_candidate_pair_quality(clock + Duration::from_secs(6), 0)).abs()
            < 1e-9
    );
    // an RTT under 1 ms is floored at 1 ms (no log of zero)
    agent.candidate_pairs[0].current_round_trip_time = Duration::from_micros(10);
    assert!((100.0 - agent.evaluate_candidate_pair_quality(clock, 0) + 20.0).abs() < 1e-9);
}

// ---------------------------------------------------------------------------------------------
// Lite agents
// ---------------------------------------------------------------------------------------------

pub(super) fn lite_config(controlling: bool) -> AgentConfig {
    AgentConfig {
        lite: true,
        is_controlling: controlling,
        candidate_types: vec![CandidateType::Host],
        ..Default::default()
    }
}

// pion TestLiteMode_FullToLite_Integration: a full controlling agent connects to a lite one;
// the lite agent never sends a check of its own.
#[test]
fn test_full_agent_connects_to_lite_agent() {
    let mut clock = Instant::now();
    let mut full = Peer::new(clock, AgentConfig::default());
    let mut lite = Peer::new(clock, lite_config(false));
    start(
        &mut full,
        &[host("10.0.0.1", 1000)],
        true,
        &mut lite,
        &[host("10.0.0.2", 2000)],
        false,
        clock,
    );
    run(&mut full, &mut lite, &mut clock, 2000);

    assert_eq!(ConnectionState::Connected, full.agent.state());
    assert_eq!(ConnectionState::Connected, lite.agent.state());
    assert_eq!(
        Some((addr("10.0.0.2", 2000), addr("10.0.0.1", 1000))),
        lite.selected_pair()
    );

    // every packet the lite agent sent is a response
    assert!(!lite.sent.is_empty());
    for packet in &lite.sent {
        let mut m = Message {
            raw: packet.clone(),
            ..Default::default()
        };
        m.decode().unwrap();
        assert_eq!(
            CLASS_SUCCESS_RESPONSE, m.typ.class,
            "a lite agent only ever answers"
        );
    }
}

// pion TestLiteControlledSelector_NoPingCandidate
#[test]
fn test_lite_agent_never_pings() {
    let clock = Instant::now();
    let mut peer = Peer::new(clock, lite_config(false));
    peer.agent
        .add_local_candidate(host("10.0.0.1", 1000))
        .unwrap();
    peer.agent
        .add_remote_candidate(host("10.0.0.2", 2000))
        .unwrap();
    peer.agent.ping_candidate(clock, 0, 0);
    assert!(peer.agent.poll_write().is_none());
}

// pion TestLiteMode_LiteControlling_Integration: with a lite agent facing a lite agent,
// nobody sends checks, so each side takes the best available pair itself.
#[test]
fn test_two_lite_agents_select_a_pair_without_checks() {
    let mut clock = Instant::now();
    let mut a = Peer::new(clock, lite_config(true));
    let mut b = Peer::new(clock, lite_config(false));
    a.agent.set_remote_ice_lite(true);
    b.agent.set_remote_ice_lite(true);
    start(
        &mut a,
        &[host("10.0.0.1", 1000)],
        true,
        &mut b,
        &[host("10.0.0.2", 2000)],
        false,
        clock,
    );
    run(&mut a, &mut b, &mut clock, 1000);

    assert_eq!(
        Some((addr("10.0.0.1", 1000), addr("10.0.0.2", 2000))),
        a.selected_pair()
    );
    assert_eq!(
        Some((addr("10.0.0.2", 2000), addr("10.0.0.1", 1000))),
        b.selected_pair()
    );
    assert!(a.sent.is_empty() && b.sent.is_empty(), "no checks at all");
}

// A lite agent that is not told its peer is lite keeps waiting for the peer's checks.
#[test]
fn test_lite_agent_waits_when_peer_is_not_lite() {
    let mut clock = Instant::now();
    let mut lite = Peer::new(clock, lite_config(false));
    let mut other = Peer::new(clock, lite_config(true));
    start(
        &mut lite,
        &[host("10.0.0.1", 1000)],
        false,
        &mut other,
        &[host("10.0.0.2", 2000)],
        true,
        clock,
    );
    run(&mut lite, &mut other, &mut clock, 1000);
    assert_eq!(None, lite.selected_pair());
}

// ---------------------------------------------------------------------------------------------
// Nomination before the pair's own check succeeded
// ---------------------------------------------------------------------------------------------

// RFC 8445 §7.3.1.5 / pion `nominateOnBindingSuccess`: a nomination that arrives before the
// controlled agent's own check on that pair has succeeded selects the pair as soon as it does.
#[test]
fn test_controlled_nominates_on_binding_success() {
    let clock = Instant::now();
    let mut controlled = Peer::new(clock, AgentConfig::default());
    let local = host("10.0.0.2", 2000);
    let remote = host("10.0.0.1", 1000);
    controlled.agent.add_local_candidate(local.clone()).unwrap();
    controlled
        .agent
        .add_remote_candidate(remote.clone())
        .unwrap();
    controlled
        .agent
        .start_connectivity_checks(
            clock,
            false,
            "remoteufrag".to_owned(),
            "remotepassword01234567890".to_owned(),
        )
        .unwrap();

    // The controlling side's nomination arrives first.
    let local_ufrag = controlled.agent.get_local_credentials().ufrag.clone();
    let local_pwd = controlled.agent.get_local_credentials().pwd.clone();
    let mut nomination = Message::new();
    nomination
        .build(&[
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId::new()),
            Box::new(Username::new(
                ATTR_USERNAME,
                format!("{local_ufrag}:remoteufrag"),
            )),
            Box::<UseCandidateAttr>::default(),
            Box::new(AttrControlling(7)),
            Box::new(PriorityAttr(remote.prflx_priority())),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                local_pwd,
                provider().crypto(),
            )),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
    controlled
        .agent
        .handle_read(TaggedBytesMut {
            now: clock,
            transport: TransportContext {
                local_addr: local.addr(),
                peer_addr: remote.addr(),
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(&nomination.raw[..]),
        })
        .unwrap();
    assert_eq!(
        None,
        controlled.selected_pair(),
        "own check has not succeeded"
    );
    assert!(controlled.agent.candidate_pairs[0].nominate_on_binding_success);

    // Its own check goes out (as the triggered check and/or the first scheduled one)...
    let mut check = None;
    let mut c = clock;
    for _ in 0..4 {
        c += Duration::from_millis(250);
        controlled.agent.handle_timeout(c).unwrap();
        while let Some(packet) = controlled.agent.poll_write() {
            let mut m = Message {
                raw: packet.message.to_vec(),
                ..Default::default()
            };
            m.decode().unwrap();
            if m.typ.class == CLASS_REQUEST {
                check = Some(m);
            }
        }
    }
    let check = check.expect("the controlled agent sent its own check");

    // ... and when the answer arrives the pair is selected.
    let mut answer = Message::new();
    answer
        .build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(check.transaction_id),
            Box::new(XorMappedAddress {
                ip: local.addr().ip(),
                port: local.addr().port(),
            }),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                "remotepassword01234567890".to_owned(),
                provider().crypto(),
            )),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
    controlled
        .agent
        .handle_read(TaggedBytesMut {
            now: c,
            transport: TransportContext {
                local_addr: local.addr(),
                peer_addr: remote.addr(),
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(&answer.raw[..]),
        })
        .unwrap();
    controlled.drain_events();
    assert_eq!(
        Some((local.addr(), remote.addr())),
        controlled.selected_pair()
    );
    assert_eq!(ConnectionState::Connected, controlled.agent.state());
}

// pion TestControlledSelector_NoTriggeredCheckAfterConnected / ...DuringChecking
#[test]
fn test_controlled_triggered_checks_stop_once_connected() {
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
    assert_eq!(ConnectionState::Connected, b.agent.state());

    // Once the pair is established and selected, an inbound request is only answered; it does
    // not trigger another check (that would make the two sides ping each other forever).
    let before = b.sent.len();
    let remote = b.agent.get_remote_candidates()[0].clone();
    let local = b.agent.get_local_candidates()[0].clone();
    a.agent.ping_candidate(clock, 0, 0);
    pump(&mut a, &mut b, clock);
    let after: Vec<_> = b.sent[before..]
        .iter()
        .map(|p| {
            let mut m = Message {
                raw: p.clone(),
                ..Default::default()
            };
            m.decode().unwrap();
            m.typ.class
        })
        .collect();
    assert_eq!(vec![CLASS_SUCCESS_RESPONSE], after);
    let _ = (remote, local);
}

// ---------------------------------------------------------------------------------------------
// Role conflicts
// ---------------------------------------------------------------------------------------------

fn conflict_scenario(
    a_controlling: bool,
    b_controlling: bool,
    a_tie: u64,
    b_tie: u64,
) -> (Peer, Peer) {
    let mut clock = Instant::now();
    let mut a = Peer::new(clock, AgentConfig::default());
    let mut b = Peer::new(clock, AgentConfig::default());
    a.agent.tie_breaker = a_tie;
    b.agent.tie_breaker = b_tie;
    start(
        &mut a,
        &[host("10.0.0.1", 1000)],
        a_controlling,
        &mut b,
        &[host("10.0.0.2", 2000)],
        b_controlling,
        clock,
    );
    run(&mut a, &mut b, &mut clock, 4000);
    (a, b)
}

// RFC 8445 §7.3.1.1 / pion handleRoleConflict: whichever way the tiebreakers fall, exactly one
// agent ends up controlling and the connection comes up.
#[test]
fn test_role_conflict_resolves_to_one_controlling_agent() {
    for (a_controlling, b_controlling) in [(true, true), (false, false)] {
        for (a_tie, b_tie) in [(100, 200), (200, 100)] {
            let (a, b) = conflict_scenario(a_controlling, b_controlling, a_tie, b_tie);
            assert_ne!(
                a.agent.role(),
                b.agent.role(),
                "roles must differ (controlling={a_controlling}, ties={a_tie}/{b_tie})"
            );
            assert_eq!(ConnectionState::Connected, a.agent.state());
            assert_eq!(ConnectionState::Connected, b.agent.state());
            assert_eq!(a.selected_pair().map(|(l, r)| (r, l)), b.selected_pair());

            // the controlling side keeps its role when its tiebreaker is the larger (and the
            // controlled side when it is the smaller)
            let a_keeps = if a_controlling {
                a_tie > b_tie
            } else {
                a_tie < b_tie
            };
            assert_eq!(a_keeps, a.agent.role() == a_controlling);
        }
    }
}

// pion handleRoleConflict at equal tiebreakers: the "greater or equal" side holds.
#[test]
fn test_role_conflict_equal_tiebreakers() {
    let (a, b) = conflict_scenario(true, true, 500, 500);
    // both are "greater or equal", so both answer 487 and then each switches on the 487 it
    // receives... which must still leave a usable pair of roles after the next exchange.
    assert_ne!(a.agent.role(), b.agent.role());
}

// pion handleInboundErrorResponse: a 487 to one of our checks makes us take the opposite of the
// role the check advertised, with a fresh tiebreaker, and re-queues the pair.
#[test]
fn test_487_role_conflict_response_switches_role_and_requeues_pair() {
    let mut clock = Instant::now();
    let mut peer = Peer::new(clock, AgentConfig::default());
    let local = host("10.0.0.1", 1000);
    let remote = host("10.0.0.2", 2000);
    peer.agent.add_local_candidate(local.clone()).unwrap();
    peer.agent.add_remote_candidate(remote.clone()).unwrap();
    peer.agent
        .start_connectivity_checks(
            clock,
            true,
            "ruf".to_owned(),
            "remotepassword01234567890".to_owned(),
        )
        .unwrap();
    peer.agent.tie_breaker = 1234;

    clock += Duration::from_millis(250);
    peer.agent.handle_timeout(clock).unwrap();
    let packet = peer.agent.poll_write().expect("a check");
    let mut check = Message {
        raw: packet.message.to_vec(),
        ..Default::default()
    };
    check.decode().unwrap();
    assert!(check.contains(ATTR_ICE_CONTROLLING));
    peer.agent.candidate_pairs[0].state = CandidatePairState::InProgress;
    peer.agent.candidate_pairs[0].binding_request_count = 5;

    let mut error = Message::new();
    error
        .build(&[
            Box::new(BINDING_ERROR),
            Box::new(check.transaction_id),
            Box::new(stun::error_code::CODE_ROLE_CONFLICT),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                "remotepassword01234567890".to_owned(),
                provider().crypto(),
            )),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
    peer.agent
        .handle_read(TaggedBytesMut {
            now: clock,
            transport: TransportContext {
                local_addr: local.addr(),
                peer_addr: remote.addr(),
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(&error.raw[..]),
        })
        .unwrap();
    peer.drain_events();

    assert!(!peer.agent.role(), "switched to controlled");
    assert_eq!(vec![false], peer.roles);
    assert_ne!(1234, peer.agent.tie_breaker, "fresh tiebreaker");
    assert_eq!(
        CandidatePairState::Waiting,
        peer.agent.candidate_pairs[0].state
    );
    assert_eq!(0, peer.agent.candidate_pairs[0].binding_request_count);

    // the same 487 again is for an unknown transaction now and changes nothing
    peer.agent
        .handle_read(TaggedBytesMut {
            now: clock,
            transport: TransportContext {
                local_addr: local.addr(),
                peer_addr: remote.addr(),
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(&error.raw[..]),
        })
        .unwrap();
    assert!(!peer.agent.role());
    assert_eq!(1, peer.roles.len());
}

// Other error codes are not role conflicts.
#[test]
fn test_other_error_responses_are_ignored() {
    let mut clock = Instant::now();
    let mut peer = Peer::new(clock, AgentConfig::default());
    let local = host("10.0.0.1", 1000);
    let remote = host("10.0.0.2", 2000);
    peer.agent.add_local_candidate(local.clone()).unwrap();
    peer.agent.add_remote_candidate(remote.clone()).unwrap();
    peer.agent
        .start_connectivity_checks(
            clock,
            true,
            "ruf".to_owned(),
            "remotepassword01234567890".to_owned(),
        )
        .unwrap();
    clock += Duration::from_millis(250);
    peer.agent.handle_timeout(clock).unwrap();
    let packet = peer.agent.poll_write().unwrap();
    let mut check = Message {
        raw: packet.message.to_vec(),
        ..Default::default()
    };
    check.decode().unwrap();

    let mut error = Message::new();
    error
        .build(&[
            Box::new(BINDING_ERROR),
            Box::new(check.transaction_id),
            Box::new(stun::error_code::CODE_BAD_REQUEST),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                "remotepassword01234567890".to_owned(),
                provider().crypto(),
            )),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
    peer.agent
        .handle_read(TaggedBytesMut {
            now: clock,
            transport: TransportContext {
                local_addr: local.addr(),
                peer_addr: remote.addr(),
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(&error.raw[..]),
        })
        .unwrap();
    assert!(peer.agent.role(), "still controlling");
}

// ---------------------------------------------------------------------------------------------
// More of pion's renomination_test.go
// ---------------------------------------------------------------------------------------------

// pion TestSendNominationRequest: the nomination value goes in before MESSAGE-INTEGRITY, which
// comes before FINGERPRINT, or the integrity check would not cover it.
#[test]
fn test_nomination_attribute_precedes_integrity_and_fingerprint() {
    let clock = Instant::now();
    let mut a = Peer::new(clock, renominating(NominationValueGenerator::new(|| 123)));
    let mut b = Peer::new(clock, AgentConfig::default());
    let a_candidate = host("10.0.0.1", 1000);
    start(
        &mut a,
        &[a_candidate.clone()],
        true,
        &mut b,
        &[host("10.0.0.2", 2000)],
        false,
        clock,
    );
    let remote = a.agent.get_remote_candidates()[0].clone();
    a.agent
        .renominate_candidate(clock, &a_candidate, &remote)
        .unwrap();
    let packet = a.agent.poll_write().unwrap();
    let mut m = Message {
        raw: packet.message.to_vec(),
        ..Default::default()
    };
    m.decode().unwrap();

    let index = |t: AttrType| m.iter_attributes().position(|a| a.typ == t).unwrap();
    assert!(index(DEFAULT_NOMINATION_ATTRIBUTE) < index(ATTR_MESSAGE_INTEGRITY));
    assert!(index(ATTR_MESSAGE_INTEGRITY) < index(ATTR_FINGERPRINT));
}

// pion TestRenominationErrorCases / TestInvalidRenominationConfig: without a generator the
// value is 0, and constant and counting generators behave as written.
#[test]
fn test_nomination_value_generators() {
    let none = Peer::new(Instant::now(), AgentConfig::default());
    assert_eq!(0, none.agent.next_nomination_value());

    let constant = Peer::new(
        Instant::now(),
        renominating(NominationValueGenerator::new(|| 42)),
    );
    assert_eq!(42, constant.agent.next_nomination_value());
    assert_eq!(42, constant.agent.next_nomination_value());

    let counting = Peer::new(
        Instant::now(),
        renominating(NominationValueGenerator::incrementing()),
    );
    assert_eq!(1, counting.agent.next_nomination_value());
    assert_eq!(2, counting.agent.next_nomination_value());
}

// pion TestAgentWithCustomNominationAttribute
#[test]
fn test_nomination_attribute_configuration() {
    let default = Peer::new(Instant::now(), AgentConfig::default());
    assert_eq!(
        DEFAULT_NOMINATION_ATTRIBUTE,
        default.agent.nomination_attribute
    );
    assert_eq!(AttrType(0xC001), default.agent.nomination_attribute);

    for custom in [0x0042, 0x0055] {
        let peer = Peer::new(
            Instant::now(),
            AgentConfig {
                renomination: Some(NominationValueGenerator::new(|| 100)),
                nomination_attribute: Some(custom),
                ..Default::default()
            },
        );
        assert_eq!(AttrType(custom), peer.agent.nomination_attribute);
    }
}

/// An authenticated Binding request from the controlling side towards `controlled`.
pub(super) fn nomination_request(
    controlled: &Peer,
    use_candidate: bool,
    value: Option<u32>,
) -> Message {
    let crypto_provider = provider();
    let creds = controlled.agent.get_local_credentials();
    let mut setters: Vec<Box<dyn Setter>> = vec![
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(
            ATTR_USERNAME,
            format!("{}:remoteufrag", creds.ufrag),
        )),
        Box::new(AttrControlling(7)),
    ];
    if use_candidate {
        setters.push(Box::<UseCandidateAttr>::default());
    }
    if let Some(value) = value {
        setters.push(Box::new(NominationSetter {
            value,
            attr_type: DEFAULT_NOMINATION_ATTRIBUTE,
        }));
    }
    setters.push(Box::new(
        MessageIntegrity::new_short_term_integrity_with_provider(
            creds.pwd.clone(),
            crypto_provider.crypto(),
        ),
    ));
    setters.push(Box::new(FINGERPRINT));
    let mut m = Message::new();
    m.build(&setters).unwrap();
    m
}

// pion TestControlledSelectorWithActualSTUNMessages: nomination values arriving in real
// Binding requests are tracked, and lower ones are answered but not honoured.
#[test]
fn test_controlled_selector_with_actual_stun_messages() {
    let clock = Instant::now();
    let mut peer = Peer::new(clock, AgentConfig::default());
    let local = host("10.0.0.2", 2000);
    let remote = host("10.0.0.1", 1000);
    peer.agent.add_local_candidate(local.clone()).unwrap();
    peer.agent.add_remote_candidate(remote.clone()).unwrap();
    peer.agent
        .start_connectivity_checks(
            clock,
            false,
            "remoteufrag".to_owned(),
            "remotepassword01234567890".to_owned(),
        )
        .unwrap();

    let deliver = |peer: &mut Peer, m: &Message| {
        peer.agent
            .handle_read(TaggedBytesMut {
                now: clock,
                transport: TransportContext {
                    local_addr: local.addr(),
                    peer_addr: remote.addr(),
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: BytesMut::from(&m.raw[..]),
            })
            .unwrap();
    };

    let first = nomination_request(&peer, true, Some(5));
    deliver(&mut peer, &first);
    assert_eq!(Some(5), peer.agent.last_nomination);

    let higher = nomination_request(&peer, true, Some(10));
    deliver(&mut peer, &higher);
    assert_eq!(Some(10), peer.agent.last_nomination);

    // rejected, but still answered with a success response
    let before = peer.agent.write_outs.len();
    let lower = nomination_request(&peer, true, Some(7));
    deliver(&mut peer, &lower);
    assert_eq!(Some(10), peer.agent.last_nomination, "lower value rejected");
    let answered = peer.agent.write_outs.iter().skip(before).any(|p| {
        let mut m = Message {
            raw: p.message.to_vec(),
            ..Default::default()
        };
        m.decode().is_ok() && m.typ.class == CLASS_SUCCESS_RESPONSE
    });
    assert!(answered, "a rejected nomination is still answered");

    // without a nomination value the history is untouched
    let mut fresh = Peer::new(clock, AgentConfig::default());
    fresh.agent.add_local_candidate(local.clone()).unwrap();
    fresh.agent.add_remote_candidate(remote.clone()).unwrap();
    fresh
        .agent
        .start_connectivity_checks(
            clock,
            false,
            "remoteufrag".to_owned(),
            "remotepassword01234567890".to_owned(),
        )
        .unwrap();
    let plain = nomination_request(&fresh, true, None);
    deliver(&mut fresh, &plain);
    assert_eq!(None, fresh.agent.last_nomination);
}

// A nomination value alone, without USE-CANDIDATE, is a nomination too (pion
// `hasValidNomination`).
#[test]
fn test_nomination_value_without_use_candidate_nominates() {
    let clock = Instant::now();
    let mut peer = Peer::new(clock, AgentConfig::default());
    let local = host("10.0.0.2", 2000);
    let remote = host("10.0.0.1", 1000);
    peer.agent.add_local_candidate(local.clone()).unwrap();
    peer.agent.add_remote_candidate(remote.clone()).unwrap();
    peer.agent
        .start_connectivity_checks(
            clock,
            false,
            "remoteufrag".to_owned(),
            "remotepassword01234567890".to_owned(),
        )
        .unwrap();
    let m = nomination_request(&peer, false, Some(3));
    peer.agent
        .handle_read(TaggedBytesMut {
            now: clock,
            transport: TransportContext {
                local_addr: local.addr(),
                peer_addr: remote.addr(),
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(&m.raw[..]),
        })
        .unwrap();
    assert_eq!(Some(3), peer.agent.last_nomination);
    assert!(peer.agent.candidate_pairs[0].nominate_on_binding_success);
}

// pion TestKeepAliveCandidatesForRenomination: with automatic renomination on, every pair that
// has not failed keeps being pinged, succeeded ones included and with no request limit.
#[test]
fn test_keep_alive_candidates_for_renomination() {
    let clock = Instant::now();
    let mut peer = Peer::new(
        clock,
        renominating(NominationValueGenerator::incrementing()),
    );
    let agent = &mut peer.agent;
    agent.add_local_candidate(host("10.0.0.1", 1000)).unwrap();
    for port in [2000, 2001, 2002, 2003] {
        agent.add_remote_candidate(host("10.0.0.2", port)).unwrap();
    }
    agent
        .start_connectivity_checks(
            clock,
            true,
            "ruf".to_owned(),
            "remotepassword01234567890".to_owned(),
        )
        .unwrap();
    agent.candidate_pairs[0].state = CandidatePairState::Succeeded;
    agent.candidate_pairs[1].state = CandidatePairState::Failed;
    agent.candidate_pairs[2].state = CandidatePairState::InProgress;
    agent.candidate_pairs[2].binding_request_count = 1000; // far past the limit
    agent.candidate_pairs[3].state = CandidatePairState::Waiting;

    agent.keep_alive_candidates_for_renomination(clock);
    let mut pinged = vec![];
    while let Some(p) = agent.poll_write() {
        pinged.push(p.transport.peer_addr.port());
    }
    pinged.sort();
    assert_eq!(
        vec![2000, 2002, 2003],
        pinged,
        "everything but the failed pair"
    );
    assert_eq!(
        CandidatePairState::InProgress,
        agent.candidate_pairs[3].state,
        "waiting pairs start"
    );
    assert_eq!(CandidatePairState::Failed, agent.candidate_pairs[1].state);
}

// ---------------------------------------------------------------------------------------------
// pion TestRenominationAcceptance / TestControllingSideRenomination: one agent, several pairs
// that have already succeeded, driven with crafted Binding requests and responses.
// ---------------------------------------------------------------------------------------------

pub(super) const REMOTE_PWD: &str = "remotepassword01234567890";

/// An agent in the given role with one local host candidate and a pair (already succeeded) to
/// each of `remotes`.
pub(super) fn agent_with_pairs(
    controlling: bool,
    config: AgentConfig,
    remotes: &[Candidate],
) -> (Peer, Candidate) {
    let clock = Instant::now();
    let mut peer = Peer::new(
        clock,
        AgentConfig {
            is_controlling: controlling,
            ..config
        },
    );
    let local = host("10.0.0.2", 2000);
    peer.agent.add_local_candidate(local.clone()).unwrap();
    for remote in remotes {
        peer.agent.add_remote_candidate(remote.clone()).unwrap();
    }
    peer.agent
        .start_connectivity_checks(
            clock,
            controlling,
            "remoteufrag".to_owned(),
            REMOTE_PWD.to_owned(),
        )
        .unwrap();
    for pair in &mut peer.agent.candidate_pairs {
        pair.state = CandidatePairState::Succeeded;
    }
    (peer, local)
}

pub(super) fn deliver_from(peer: &mut Peer, local: &Candidate, remote: &Candidate, m: &Message) {
    peer.agent
        .handle_read(TaggedBytesMut {
            now: Instant::now(),
            transport: TransportContext {
                local_addr: local.addr(),
                peer_addr: remote.addr(),
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(&m.raw[..]),
        })
        .unwrap();
    peer.drain_events();
}

pub(super) fn selected_remote(peer: &Peer) -> Option<SocketAddr> {
    peer.selected_pair().map(|(_, remote)| remote)
}

#[test]
fn test_controlled_accepts_nomination_attribute_without_use_candidate() {
    let remotes = [host("10.0.0.1", 1000), host("10.0.0.1", 1001)];
    let (mut peer, local) = agent_with_pairs(false, AgentConfig::default(), &remotes);

    let m = nomination_request(&peer, true, None);
    deliver_from(&mut peer, &local, &remotes[0], &m);
    assert_eq!(Some(remotes[0].addr()), selected_remote(&peer));

    let m = nomination_request(&peer, false, Some(1));
    deliver_from(&mut peer, &local, &remotes[1], &m);
    assert_eq!(
        Some(remotes[1].addr()),
        selected_remote(&peer),
        "a nomination value alone switches the pair"
    );
}

#[test]
fn test_controlled_renomination_ignores_priority_but_plain_nomination_does_not() {
    // pair 0 is host-host; pair 1 is host-relay and ranks lower
    let remotes = [host("10.0.0.1", 1000), relay("10.0.0.9", 9000)];
    let (mut peer, local) = agent_with_pairs(false, AgentConfig::default(), &remotes);
    assert!(peer.agent.candidate_pairs[0].priority() > peer.agent.candidate_pairs[1].priority());

    let m = nomination_request(&peer, true, None);
    deliver_from(&mut peer, &local, &remotes[0], &m);
    assert_eq!(Some(remotes[0].addr()), selected_remote(&peer));
    assert!(peer.agent.candidate_pairs[0].nominated);

    // a plain nomination of the worse pair is ignored
    let m = nomination_request(&peer, true, None);
    deliver_from(&mut peer, &local, &remotes[1], &m);
    assert_eq!(Some(remotes[0].addr()), selected_remote(&peer));

    // a renomination of the worse pair is honoured
    let m = nomination_request(&peer, true, Some(1));
    deliver_from(&mut peer, &local, &remotes[1], &m);
    assert_eq!(Some(remotes[1].addr()), selected_remote(&peer));
    assert!(peer.agent.candidate_pairs[1].nominated);
}

#[test]
fn test_controlled_plain_nomination_needs_strictly_higher_priority() {
    // two pairs of equal priority
    let remotes = [host("10.0.0.1", 1000), host("10.0.0.1", 1001)];
    let (mut peer, local) = agent_with_pairs(false, AgentConfig::default(), &remotes);
    assert_eq!(
        peer.agent.candidate_pairs[0].priority(),
        peer.agent.candidate_pairs[1].priority()
    );

    let m = nomination_request(&peer, true, None);
    deliver_from(&mut peer, &local, &remotes[0], &m);
    let m = nomination_request(&peer, true, None);
    deliver_from(&mut peer, &local, &remotes[1], &m);
    assert_eq!(
        Some(remotes[0].addr()),
        selected_remote(&peer),
        "an equal-priority pair does not replace the selected one"
    );
}

#[test]
fn test_controlled_higher_nomination_values_override_lower_ones() {
    let remotes = [
        host("10.0.0.1", 1000),
        host("10.0.0.1", 1001),
        host("10.0.0.1", 1002),
    ];
    let (mut peer, local) = agent_with_pairs(false, AgentConfig::default(), &remotes);

    let m = nomination_request(&peer, true, Some(5));
    deliver_from(&mut peer, &local, &remotes[0], &m);
    assert_eq!(Some(remotes[0].addr()), selected_remote(&peer));

    let m = nomination_request(&peer, true, Some(3));
    deliver_from(&mut peer, &local, &remotes[1], &m);
    assert_eq!(
        Some(remotes[0].addr()),
        selected_remote(&peer),
        "a lower value is rejected"
    );

    let m = nomination_request(&peer, true, Some(8));
    deliver_from(&mut peer, &local, &remotes[2], &m);
    assert_eq!(
        Some(remotes[2].addr()),
        selected_remote(&peer),
        "a higher value is accepted"
    );
}

/// The Binding success an authenticated peer would send for `request`.
pub(super) fn success_for(request: &Message, mapped: SocketAddr) -> Message {
    let crypto_provider = provider();
    let mut answer = Message::new();
    answer
        .build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(request.transaction_id),
            Box::new(XorMappedAddress {
                ip: mapped.ip(),
                port: mapped.port(),
            }),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                REMOTE_PWD.to_owned(),
                crypto_provider.crypto(),
            )),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
    answer
}

pub(super) fn take_request(peer: &mut Peer) -> Message {
    let packet = peer.agent.poll_write().expect("a request");
    let mut m = Message {
        raw: packet.message.to_vec(),
        ..Default::default()
    };
    m.decode().unwrap();
    m
}

#[test]
fn test_controlling_switches_on_renomination_success_only() {
    let remotes = [host("10.0.0.1", 1000), host("10.0.0.1", 1001)];
    let (mut peer, local) = agent_with_pairs(
        true,
        AgentConfig {
            renomination: Some(NominationValueGenerator::new(|| 9)),
            ..Default::default()
        },
        &remotes,
    );
    peer.agent.set_selected_pair(Some(Instant::now()), Some(0));
    peer.drain_events();
    assert_eq!(Some(remotes[0].addr()), selected_remote(&peer));

    // a plain nomination answered successfully does not move a selected pair
    peer.agent.nominated_pair = Some(1);
    peer.agent.nominate_pair(Instant::now());
    let request = take_request(&mut peer);
    assert!(
        request.contains(ATTR_USE_CANDIDATE) && !request.contains(DEFAULT_NOMINATION_ATTRIBUTE)
    );
    let answer = success_for(&request, local.addr());
    deliver_from(&mut peer, &local, &remotes[1], &answer);
    assert_eq!(
        Some(remotes[0].addr()),
        selected_remote(&peer),
        "standard nomination success leaves the selected pair alone"
    );

    // a renomination answered successfully does
    peer.agent
        .renominate_candidate(Instant::now(), &local, &remotes[1])
        .unwrap();
    let request = take_request(&mut peer);
    assert!(request.contains(DEFAULT_NOMINATION_ATTRIBUTE));
    assert_eq!(
        Some(9),
        peer.agent
            .pending_binding_requests
            .last()
            .unwrap()
            .nomination_value,
        "the pending request remembers its nomination value"
    );
    let answer = success_for(&request, local.addr());
    deliver_from(&mut peer, &local, &remotes[1], &answer);
    assert_eq!(Some(remotes[1].addr()), selected_remote(&peer));
    assert!(peer.agent.candidate_pairs[1].nominated);
}

// pion TestControlledSelector_TriggeredCheckDuringChecking: while a pair is still being
// established, an inbound request is answered and also triggers a check of our own.
#[test]
fn test_controlled_triggered_check_during_checking() {
    let remotes = [host("10.0.0.1", 1000)];
    let (mut peer, local) = agent_with_pairs(false, AgentConfig::default(), &remotes);
    peer.agent.candidate_pairs[0].state = CandidatePairState::Waiting;

    let m = nomination_request(&peer, false, None);
    deliver_from(&mut peer, &local, &remotes[0], &m);

    let mut classes = vec![];
    while let Some(packet) = peer.agent.poll_write() {
        let mut m = Message {
            raw: packet.message.to_vec(),
            ..Default::default()
        };
        m.decode().unwrap();
        classes.push(m.typ.class);
    }
    assert!(classes.contains(&CLASS_SUCCESS_RESPONSE), "answered");
    assert!(classes.contains(&CLASS_REQUEST), "triggered a check");
}

// pion TestAutomaticRenomination configuration and quality subtests.
#[test]
fn test_automatic_renomination_configuration() {
    let on = Peer::new(
        Instant::now(),
        AgentConfig {
            renomination: Some(NominationValueGenerator::incrementing()),
            automatic_renomination: Some(Duration::from_secs(5)),
            ..Default::default()
        },
    );
    assert!(on.agent.automatic_renomination);
    assert_eq!(Duration::from_secs(5), on.agent.renomination_interval);

    let zero = Peer::new(
        Instant::now(),
        AgentConfig {
            renomination: Some(NominationValueGenerator::incrementing()),
            automatic_renomination: Some(Duration::ZERO),
            ..Default::default()
        },
    );
    assert!(zero.agent.automatic_renomination);
    assert_eq!(Duration::from_secs(3), zero.agent.renomination_interval);

    let off = Peer::new(Instant::now(), AgentConfig::default());
    assert!(!off.agent.automatic_renomination);
}

#[test]
fn test_quality_and_best_pair_selection() {
    let now = Instant::now();
    let remotes = [
        host("10.0.0.1", 1000),
        relay("10.0.0.9", 9000),
        host("10.0.0.1", 1001),
    ];
    let (mut peer, _) = agent_with_pairs(true, AgentConfig::default(), &remotes);
    let agent = &mut peer.agent;
    let rtt = |agent: &mut Agent, pair: usize, ms: u64| {
        agent.candidate_pairs[pair].current_round_trip_time = Duration::from_millis(ms);
    };

    // host scores higher than relay at the same RTT
    rtt(agent, 0, 20);
    rtt(agent, 1, 20);
    assert!(
        agent.evaluate_candidate_pair_quality(now, 0)
            > agent.evaluate_candidate_pair_quality(now, 1)
    );
    // lower RTT scores higher
    rtt(agent, 2, 5);
    assert!(
        agent.evaluate_candidate_pair_quality(now, 2)
            > agent.evaluate_candidate_pair_quality(now, 0)
    );

    // the best pair is the host pair with the lowest latency; non-succeeded pairs never win
    assert_eq!(Some(2), agent.find_best_candidate_pair(now));
    agent.candidate_pairs[2].state = CandidatePairState::Failed;
    assert_eq!(Some(0), agent.find_best_candidate_pair(now));
    for pair in &mut agent.candidate_pairs {
        pair.state = CandidatePairState::Waiting;
    }
    assert_eq!(None, agent.find_best_candidate_pair(now));

    // a small RTT improvement (< 10 ms) does not justify renominating
    for pair in &mut agent.candidate_pairs {
        pair.state = CandidatePairState::Succeeded;
    }
    rtt(agent, 0, 50);
    rtt(agent, 2, 41);
    assert!(!agent.should_renominate(now, 0, 2));
    rtt(agent, 2, 30);
    assert!(agent.should_renominate(now, 0, 2));
}

// pion TestLiteControllingSelectorContactCandidates: facing a lite peer, a lite agent
// selects the best available pair itself and keeps upgrading to a better one.
#[test]
fn test_lite_agent_facing_lite_peer_tracks_the_best_pair() {
    let clock = Instant::now();
    let mut peer = Peer::new(clock, lite_config(true));
    peer.agent.set_remote_ice_lite(true);
    let agent = &mut peer.agent;

    agent.contact_candidates(clock);
    assert_eq!(None, agent.get_selected_pair(), "nothing to select yet");

    let with_priority = |priority: u32, port: u16| {
        let mut c = host("10.0.0.1", port);
        c.priority_override = priority;
        c
    };
    let mut remote = host("10.0.0.2", 2000);
    remote.priority_override = 100;
    agent.add_remote_candidate(remote.clone()).unwrap();
    agent.add_local_candidate(with_priority(100, 1000)).unwrap();
    let first = agent.find_pair(0, 0).unwrap();

    agent.contact_candidates(clock);
    assert_eq!(Some(first), agent.get_selected_pair());
    assert_eq!(
        CandidatePairState::Succeeded,
        agent.candidate_pairs[first].state
    );
    assert!(
        agent.remote_candidates[0].last_received().is_some(),
        "the pair's liveness window has started"
    );
    assert_eq!(0, agent.candidate_pairs[first].requests_sent);

    // a worse pair is left waiting
    agent.add_local_candidate(with_priority(50, 1001)).unwrap();
    let worse = agent.find_pair(1, 0).unwrap();
    agent.contact_candidates(clock);
    assert_eq!(Some(first), agent.get_selected_pair());
    assert_eq!(
        CandidatePairState::Waiting,
        agent.candidate_pairs[worse].state
    );

    // a better one takes over
    agent.add_local_candidate(with_priority(200, 1002)).unwrap();
    let better = agent.find_pair(2, 0).unwrap();
    agent.contact_candidates(clock);
    assert_eq!(Some(better), agent.get_selected_pair());
    assert_eq!(
        CandidatePairState::Succeeded,
        agent.candidate_pairs[better].state
    );
}

// pion TestBindingRequestPriorityAttr: every kind of check carries the peer-reflexive priority
// of the candidate it is sent from, never the candidate's own.
#[test]
fn test_every_check_carries_the_prflx_priority() {
    fn priority_of(packet: &TaggedBytesMut) -> u32 {
        let mut m = Message {
            raw: packet.message.to_vec(),
            ..Default::default()
        };
        m.decode().unwrap();
        let mut priority = PriorityAttr::default();
        priority.get_from(&m).unwrap();
        priority.0
    }

    for controlling in [true, false] {
        let remotes = [host("10.0.0.1", 1000)];
        let (mut peer, local) = agent_with_pairs(
            controlling,
            AgentConfig {
                renomination: Some(NominationValueGenerator::incrementing()),
                ..Default::default()
            },
            &remotes,
        );
        let expected = local.prflx_priority();
        assert_ne!(
            local.priority(),
            expected,
            "the host priority must not be sent"
        );

        peer.agent.ping_candidate(Instant::now(), 0, 0);
        assert_eq!(expected, priority_of(&peer.agent.poll_write().unwrap()));
    }

    // nomination and renomination (controlling only)
    let remotes = [host("10.0.0.1", 1000)];
    let (mut peer, local) = agent_with_pairs(
        true,
        AgentConfig {
            renomination: Some(NominationValueGenerator::incrementing()),
            ..Default::default()
        },
        &remotes,
    );
    let expected = local.prflx_priority();
    peer.agent.nominated_pair = Some(0);
    peer.agent.nominate_pair(Instant::now());
    peer.agent
        .renominate_candidate(Instant::now(), &local, &remotes[0])
        .unwrap();
    let mut seen = 0;
    while let Some(packet) = peer.agent.poll_write() {
        assert_eq!(expected, priority_of(&packet));
        seen += 1;
    }
    assert_eq!(2, seen);
}

// pion TestBindingRequestHandler: the application's hook sees every Binding request, and when it
// says so, the pair the request came in on becomes the selected one.
#[test]
fn test_binding_request_handler_takes_over_selection() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let switch = Arc::new(AtomicBool::new(false));
    let controlling_fired = Arc::new(AtomicBool::new(false));

    let mut clock = Instant::now();
    let controlling_flag = controlling_fired.clone();
    let mut a = Peer::new(
        clock,
        AgentConfig {
            is_controlling: true,
            binding_request_handler: Some(BindingRequestHandler::new(move |_, _, _, _| {
                controlling_flag.store(true, Ordering::SeqCst);
                false
            })),
            ..Default::default()
        },
    );
    let switch_flag = switch.clone();
    let mut b = Peer::new(
        clock,
        AgentConfig {
            binding_request_handler: Some(BindingRequestHandler::new(move |_, _, _, _| {
                // Don't switch candidate pair until we are ready
                switch_flag.load(Ordering::SeqCst)
            })),
            ..Default::default()
        },
    );
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
    assert!(a.selected_pair().is_some() && b.selected_pair().is_some());

    // Unset the selection on the controlled side only.
    b.agent.set_selected_pair(Some(clock), None);
    assert!(b.selected_pair().is_none());
    assert!(a.selected_pair().is_some());

    // The controlling side keeps checking consent, but the handler is not ready.
    run(&mut a, &mut b, &mut clock, 5000);
    assert!(b.selected_pair().is_none(), "the handler declined");

    // Once the handler agrees, the next request selects the pair again.
    switch.store(true, Ordering::SeqCst);
    run(&mut a, &mut b, &mut clock, 5000);
    assert_eq!(
        Some((addr("10.0.0.2", 2000), addr("10.0.0.1", 1000))),
        b.selected_pair()
    );
    assert!(
        controlling_fired.load(Ordering::SeqCst),
        "fired on the controlling side too"
    );
}

// On a lite agent a pair the handler approves is valid straight away.
#[test]
fn test_binding_request_handler_on_a_lite_agent() {
    let clock = Instant::now();
    let mut lite = Peer::new(
        clock,
        AgentConfig {
            binding_request_handler: Some(BindingRequestHandler::new(|_, _, _, _| true)),
            ..lite_config(false)
        },
    );
    let remotes = [host("10.0.0.1", 1000)];
    let local = host("10.0.0.2", 2000);
    lite.agent.add_local_candidate(local.clone()).unwrap();
    lite.agent.add_remote_candidate(remotes[0].clone()).unwrap();
    lite.agent
        .start_connectivity_checks(
            clock,
            false,
            "remoteufrag".to_owned(),
            REMOTE_PWD.to_owned(),
        )
        .unwrap();
    assert_eq!(
        CandidatePairState::Waiting,
        lite.agent.candidate_pairs[0].state
    );

    let m = nomination_request(&lite, false, None);
    deliver_from(&mut lite, &local, &remotes[0], &m);
    assert_eq!(Some(remotes[0].addr()), selected_remote(&lite));
    assert_eq!(
        CandidatePairState::Succeeded,
        lite.agent.candidate_pairs[0].state
    );
}

// RFC 8838 §11.4 / pion replaceRedundantPeerReflexiveCandidates: a candidate signaled after the
// peer was already discovered at that address (peer-reflexive) replaces it, and the running call
// is undisturbed.
#[test]
fn test_signaled_candidate_replaces_peer_reflexive_one() {
    let mut clock = Instant::now();
    let mut a = Peer::new(clock, AgentConfig::default());
    let mut b = Peer::new(clock, AgentConfig::default());

    // `b` has not been told about `a`'s candidate, so it learns it from a check.
    let a_candidate = host("10.0.0.1", 1000);
    let b_candidate = host("10.0.0.2", 2000);
    a.agent.add_local_candidate(a_candidate.clone()).unwrap();
    a.agent.add_remote_candidate(b_candidate.clone()).unwrap();
    b.agent.add_local_candidate(b_candidate.clone()).unwrap();
    let (a_ufrag, a_pwd) = credentials(&a);
    let (b_ufrag, b_pwd) = credentials(&b);
    a.agent
        .start_connectivity_checks(clock, true, b_ufrag, b_pwd)
        .unwrap();
    b.agent
        .start_connectivity_checks(clock, false, a_ufrag, a_pwd)
        .unwrap();
    run(&mut a, &mut b, &mut clock, 2000);

    assert_eq!(ConnectionState::Connected, b.agent.state());
    assert_eq!(
        CandidateType::PeerReflexive,
        b.agent.get_remote_candidates()[0].candidate_type()
    );
    let pairs_before = b.agent.candidate_pairs.len();
    let selected_before = b.agent.selected_pair;
    let events_before = b.selected.len();
    let requests_before = b.agent.candidate_pairs[selected_before.unwrap()].requests_received;

    // The signaling catches up.
    b.agent.add_remote_candidate(a_candidate.clone()).unwrap();
    run(&mut a, &mut b, &mut clock, 500);

    let remotes = b.agent.get_remote_candidates();
    assert_eq!(1, remotes.len(), "replaced, not added");
    assert_eq!(CandidateType::Host, remotes[0].candidate_type());
    assert_eq!(
        pairs_before,
        b.agent.candidate_pairs.len(),
        "no duplicate pair"
    );
    assert_eq!(
        selected_before, b.agent.selected_pair,
        "same pair stays selected"
    );
    assert_eq!(ConnectionState::Connected, b.agent.state());
    assert!(
        b.agent.candidate_pairs[selected_before.unwrap()].requests_received >= requests_before,
        "the pair keeps its history"
    );
    assert_eq!(
        events_before + 1,
        b.selected.len(),
        "the selected pair is reported again, now with the host candidate"
    );
    let (_, remote) = b.agent.get_selected_candidate_pair().unwrap();
    assert_eq!(CandidateType::Host, remote.candidate_type());

    // signaling the same candidate again changes nothing
    b.agent.add_remote_candidate(a_candidate).unwrap();
    assert_eq!(1, b.agent.get_remote_candidates().len());
}

// A peer-reflexive candidate never replaces anything.
#[test]
fn test_peer_reflexive_candidate_does_not_replace_a_signaled_one() {
    let clock = Instant::now();
    let mut peer = Peer::new(clock, AgentConfig::default());
    peer.agent
        .add_local_candidate(host("10.0.0.2", 2000))
        .unwrap();
    peer.agent
        .add_remote_candidate(host("10.0.0.1", 1000))
        .unwrap();
    let prflx = CandidatePeerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.0.0.1".to_owned(),
            port: 1000,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_peer_reflexive()
    .unwrap();
    peer.agent.add_remote_candidate(prflx).unwrap();
    assert_eq!(
        CandidateType::Host,
        peer.agent.get_remote_candidates()[0].candidate_type()
    );
}

// pion TestLiteLocalCandidatePrioritiesAreUnique
#[test]
fn test_lite_local_candidate_priorities_are_unique() {
    let mut peer = Peer::new(Instant::now(), lite_config(false));
    let mut previous = None;
    for i in 0..3u16 {
        peer.agent
            .add_local_candidate(host(&format!("192.0.2.{}", i + 1), 10000 + i))
            .unwrap();
        let priority = peer.agent.get_local_candidates()[i as usize].priority();
        if let Some(previous) = previous {
            assert_eq!(previous - (1 << 8), priority);
        }
        previous = Some(priority);
    }

    // a full agent leaves priorities alone
    let mut full = Peer::new(Instant::now(), AgentConfig::default());
    for i in 0..3u16 {
        full.agent
            .add_local_candidate(host(&format!("192.0.2.{}", i + 1), 10000 + i))
            .unwrap();
    }
    let priorities: Vec<u32> = full
        .agent
        .get_local_candidates()
        .iter()
        .map(Candidate::priority)
        .collect();
    assert_eq!(vec![priorities[0]; 3], priorities);
}

// A candidate's relay protocol is reported for local relay candidates only.
#[test]
fn test_candidate_stats_report_the_relay_protocol() {
    let now = Instant::now();
    let mut peer = Peer::new(now, AgentConfig::default());
    let mut tls_relay = relay("10.0.0.9", 9000);
    tls_relay.relay_protocol = "tls".to_owned();
    peer.agent
        .add_local_candidate(host("10.0.0.1", 1000))
        .unwrap();
    peer.agent.add_local_candidate(tls_relay).unwrap();
    peer.agent
        .add_remote_candidate(relay("10.0.0.8", 8000))
        .unwrap();

    let local = peer.agent.get_local_candidates_stats(now);
    assert_eq!("", local[0].relay_protocol);
    assert_eq!("tls", local[1].relay_protocol);
    let remote = peer.agent.get_remote_candidates_stats(now);
    assert_eq!("", remote[0].relay_protocol);
    assert_eq!("udp", relay("10.0.0.9", 9000).relay_protocol());
}

// pion connectionStateForDisconnection: when a long silence has already passed both thresholds,
// the agent still reports Disconnected before Failed.
#[test]
fn test_disconnected_is_reported_before_failed() {
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
    let seen = a.states.len();

    // total silence for far longer than disconnected (5 s) + failed (25 s)
    clock += Duration::from_secs(120);
    a.agent.handle_timeout(clock).unwrap();
    a.drain_events();
    assert_eq!(
        vec![ConnectionState::Disconnected],
        a.states[seen..].to_vec(),
        "disconnected is reported first, although failed is already due"
    );

    // the next tick carries on to failed
    clock += Duration::from_secs(1);
    a.agent.handle_timeout(clock).unwrap();
    a.drain_events();
    assert_eq!(
        vec![ConnectionState::Disconnected, ConnectionState::Failed],
        a.states[seen..].to_vec()
    );
}

// pion applyICELiteDisconnectedTimeoutDefault / initialCheckingTimeout
#[test]
fn test_lite_agent_gets_the_longer_default_disconnect_timeout() {
    let lite = Peer::new(Instant::now(), lite_config(false));
    assert_eq!(Duration::from_secs(10), lite.agent.disconnected_timeout);
    // while still checking, the ordinary default counts toward the initial deadline
    assert_eq!(
        Duration::from_secs(5 + 25),
        lite.agent.initial_checking_timeout()
    );

    let explicit = Peer::new(
        Instant::now(),
        AgentConfig {
            disconnected_timeout: Some(Duration::from_secs(3)),
            ..lite_config(false)
        },
    );
    assert_eq!(Duration::from_secs(3), explicit.agent.disconnected_timeout);
    assert_eq!(
        Duration::from_secs(3 + 25),
        explicit.agent.initial_checking_timeout()
    );

    let full = Peer::new(Instant::now(), AgentConfig::default());
    assert_eq!(Duration::from_secs(5), full.agent.disconnected_timeout);

    let no_failure = Peer::new(
        Instant::now(),
        AgentConfig {
            failed_timeout: Some(Duration::ZERO),
            ..Default::default()
        },
    );
    assert_eq!(Duration::ZERO, no_failure.agent.initial_checking_timeout());
}

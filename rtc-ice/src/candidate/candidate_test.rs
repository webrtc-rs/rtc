use super::*;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_pair::CandidatePairState;
use crate::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig;
use crate::candidate::candidate_relay::CandidateRelayConfig;
use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use crate::candidate::{Candidate, unmarshal_candidate};
use std::time::Instant;

// A Binding request's PRIORITY is the candidate's own priority with the peer-reflexive type
// preference (RFC 8445 §7.1.1), and the TCP offset applies to TCP transports only.
#[test]
fn test_prflx_priority_and_tcp_offset() {
    let host = Candidate {
        candidate_type: CandidateType::Host,
        component: COMPONENT_RTP,
        ..Default::default()
    };
    assert_eq!(2130706431, host.priority());
    // 110 << 24 | host's low 24 bits
    assert_eq!(
        110 * (1 << 24) + 2130706431 % (1 << 24),
        host.prflx_priority()
    );

    let tcp = Candidate {
        network_type: NetworkType::Tcp4,
        tcp_type: TcpType::Active,
        ..host.clone()
    };
    // 126 - 27 for TCP host, 110 - 27 for TCP prflx
    assert_eq!(99, tcp.type_preference_for(CandidateType::Host));
    assert_eq!(83, tcp.type_preference_for(CandidateType::PeerReflexive));
    assert_eq!(0, tcp.type_preference_for(CandidateType::Relay));
    assert_eq!(
        83 * (1 << 24) + tcp.priority() % (1 << 24),
        tcp.prflx_priority()
    );

    let wide_gap = Candidate {
        tcp_priority_offset: 50,
        ..tcp
    };
    assert_eq!(76, wide_gap.type_preference_for(CandidateType::Host));
}

#[test]
fn test_relay_protocol_from_url() {
    use candidate_relay::relay_protocol_from_url as f;
    assert_eq!("udp", f("turn:example.com:3478"));
    assert_eq!("tcp", f("turn:example.com:3478?transport=tcp"));
    assert_eq!("tls", f("turns:example.com:5349?transport=tcp"));
    assert_eq!("dtls", f("turns:example.com:5349?transport=udp"));
    assert_eq!("udp", f("garbage"));
}

#[test]
fn test_candidate_priority() -> Result<()> {
    let tests = vec![
        (
            Candidate {
                candidate_type: CandidateType::Host,
                component: COMPONENT_RTP,
                ..Default::default()
            },
            2130706431,
        ),
        (
            Candidate {
                candidate_type: CandidateType::Host,
                component: COMPONENT_RTP,
                network_type: NetworkType::Tcp4,
                tcp_type: TcpType::Active,
                ..Default::default()
            },
            1675624447,
        ),
        (
            Candidate {
                candidate_type: CandidateType::Host,
                component: COMPONENT_RTP,
                network_type: NetworkType::Tcp4,
                tcp_type: TcpType::Passive,
                ..Default::default()
            },
            1671430143,
        ),
        (
            Candidate {
                candidate_type: CandidateType::Host,
                component: COMPONENT_RTP,
                network_type: NetworkType::Tcp4,
                tcp_type: TcpType::SimultaneousOpen,
                ..Default::default()
            },
            1667235839,
        ),
        (
            Candidate {
                candidate_type: CandidateType::PeerReflexive,
                component: COMPONENT_RTP,
                ..Default::default()
            },
            1862270975,
        ),
        (
            Candidate {
                candidate_type: CandidateType::PeerReflexive,
                component: COMPONENT_RTP,
                network_type: NetworkType::Tcp6,
                tcp_type: TcpType::SimultaneousOpen,
                ..Default::default()
            },
            1407188991,
        ),
        (
            Candidate {
                candidate_type: CandidateType::PeerReflexive,
                component: COMPONENT_RTP,
                network_type: NetworkType::Tcp6,
                tcp_type: TcpType::Active,
                ..Default::default()
            },
            1402994687,
        ),
        (
            Candidate {
                candidate_type: CandidateType::PeerReflexive,
                component: COMPONENT_RTP,
                network_type: NetworkType::Tcp6,
                tcp_type: TcpType::Passive,
                ..Default::default()
            },
            1398800383,
        ),
        (
            Candidate {
                candidate_type: CandidateType::ServerReflexive,
                component: COMPONENT_RTP,
                ..Default::default()
            },
            1694498815,
        ),
        // The relay's local preference follows the protocol used to reach the relay.
        (
            Candidate {
                candidate_type: CandidateType::Relay,
                component: COMPONENT_RTP,
                relay_local_preference: relay_protocol_preference("udp"),
                ..Default::default()
            },
            1023,
        ),
        (
            Candidate {
                candidate_type: CandidateType::Relay,
                component: COMPONENT_RTP,
                relay_local_preference: relay_protocol_preference("tcp"),
                ..Default::default()
            },
            511,
        ),
    ];

    for (candidate, want) in tests {
        let got = candidate.priority();
        assert_eq!(
            got, want,
            "Candidate({candidate}).Priority() = {got}, want {want}"
        );
    }

    Ok(())
}

#[test]
fn test_candidate_last_sent() -> Result<()> {
    let mut candidate = Candidate::default();
    assert_eq!(
        candidate.last_sent(),
        None,
        "a fresh candidate has sent nothing"
    );

    let now = Instant::now();
    candidate.set_last_sent(now);
    assert_eq!(candidate.last_sent(), Some(now));

    Ok(())
}

#[test]
fn test_candidate_last_received() -> Result<()> {
    let mut candidate = Candidate::default();
    assert_eq!(
        candidate.last_received(),
        None,
        "a fresh candidate has received nothing"
    );

    let now = Instant::now();
    candidate.set_last_received(now);
    assert_eq!(candidate.last_received(), Some(now));

    Ok(())
}

#[test]
fn test_candidate_foundation() -> Result<()> {
    // All fields are the same
    assert_eq!(
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation(),
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation()
    );

    // Different Address
    assert_ne!(
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation(),
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "B".to_owned(),
            ..Default::default()
        })
        .foundation(),
    );

    // Different networkType
    assert_ne!(
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation(),
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp6,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation(),
    );

    // Different candidateType
    assert_ne!(
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation(),
        (Candidate {
            candidate_type: CandidateType::PeerReflexive,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            ..Default::default()
        })
        .foundation(),
    );

    // Port has no effect
    assert_eq!(
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            port: 8080,
            ..Default::default()
        })
        .foundation(),
        (Candidate {
            candidate_type: CandidateType::Host,
            network_type: NetworkType::Udp4,
            address: "A".to_owned(),
            port: 80,
            ..Default::default()
        })
        .foundation()
    );

    Ok(())
}

#[test]
fn test_candidate_pair_state_serialization() {
    let tests = vec![
        (CandidatePairState::Unspecified, "\"unspecified\""),
        (CandidatePairState::Waiting, "\"waiting\""),
        (CandidatePairState::InProgress, "\"in-progress\""),
        (CandidatePairState::Failed, "\"failed\""),
        (CandidatePairState::Succeeded, "\"succeeded\""),
    ];

    for (candidate_pair_state, expected_string) in tests {
        assert_eq!(
            expected_string.to_string(),
            serde_json::to_string(&candidate_pair_state).unwrap()
        );
    }
}

#[test]
fn test_candidate_pair_state_to_string() {
    let tests = vec![
        (CandidatePairState::Unspecified, "unspecified"),
        (CandidatePairState::Waiting, "waiting"),
        (CandidatePairState::InProgress, "in-progress"),
        (CandidatePairState::Failed, "failed"),
        (CandidatePairState::Succeeded, "succeeded"),
    ];

    for (candidate_pair_state, expected_string) in tests {
        assert_eq!(candidate_pair_state.to_string(), expected_string);
    }
}

#[test]
fn test_candidate_type_serialization() {
    let tests = vec![
        (CandidateType::Unspecified, "\"unspecified\""),
        (CandidateType::Host, "\"host\""),
        (CandidateType::ServerReflexive, "\"srflx\""),
        (CandidateType::PeerReflexive, "\"prflx\""),
        (CandidateType::Relay, "\"relay\""),
    ];

    for (candidate_type, expected_string) in tests {
        assert_eq!(
            serde_json::to_string(&candidate_type).unwrap(),
            expected_string.to_string()
        );
    }
}

#[test]
fn test_candidate_type_to_string() {
    let tests = vec![
        (CandidateType::Unspecified, "Unknown candidate type"),
        (CandidateType::Host, "host"),
        (CandidateType::ServerReflexive, "srflx"),
        (CandidateType::PeerReflexive, "prflx"),
        (CandidateType::Relay, "relay"),
    ];

    for (candidate_type, expected_string) in tests {
        assert_eq!(candidate_type.to_string(), expected_string);
    }
}

#[test]
fn test_candidate_marshal() -> Result<()> {
    let host = |network: &str,
                address: &str,
                port: u16,
                priority: u32,
                foundation: &str,
                tcp_type: TcpType| {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: network.to_owned(),
                address: address.to_owned(),
                port,
                component: COMPONENT_RTP,
                priority,
                foundation: foundation.to_owned(),
                ..CandidateConfig::default()
            },
            tcp_type,
        }
        .new_candidate_host()
    };

    // (candidate, marshaled, expect_error): pion v4.4.8 TestCandidateMarshal, verbatim.
    let tests: Vec<(Option<Candidate>, &str, bool)> = vec![
        (
            Some(host(
                "udp6",
                "fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a",
                53987,
                500,
                "750",
                TcpType::Unspecified,
            )?),
            "750 1 udp 500 fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a 53987 typ host",
            false,
        ),
        (
            Some(host(
                "udp4",
                "10.0.75.1",
                53634,
                0,
                "",
                TcpType::Unspecified,
            )?),
            "4273957277 1 udp 2130706431 10.0.75.1 53634 typ host",
            false,
        ),
        (
            Some(
                CandidateServerReflexiveConfig {
                    base_config: CandidateConfig {
                        network: "udp4".to_owned(),
                        address: "191.228.238.68".to_owned(),
                        port: 53991,
                        component: COMPONENT_RTP,
                        ..CandidateConfig::default()
                    },
                    rel_addr: "192.168.0.274".to_owned(),
                    rel_port: 53991,
                    url: None,
                }
                .new_candidate_server_reflexive()?,
            ),
            "647372371 1 udp 1694498815 191.228.238.68 53991 typ srflx raddr 192.168.0.274 rport 53991",
            false,
        ),
        (
            {
                let mut cand = CandidatePeerReflexiveConfig {
                    base_config: CandidateConfig {
                        network: "tcp4".to_owned(),
                        address: "192.0.2.15".to_owned(),
                        port: 50000,
                        component: COMPONENT_RTP,
                        ..CandidateConfig::default()
                    },
                    rel_addr: "10.0.0.1".to_owned(),
                    rel_port: 12345,
                }
                .new_candidate_peer_reflexive()?;
                cand.set_extensions(vec![
                    CandidateExtension::new("generation", "0"),
                    CandidateExtension::new("network-id", "2"),
                    CandidateExtension::new("network-cost", "10"),
                ]);
                Some(cand)
            },
            "4207374052 1 tcp 1685790463 192.0.2.15 50000 typ prflx raddr 10.0.0.1 rport 12345 generation 0 network-id 2 network-cost 10",
            false,
        ),
        (
            Some(
                CandidateRelayConfig {
                    base_config: CandidateConfig {
                        network: "udp4".to_owned(),
                        address: "50.0.0.1".to_owned(),
                        port: 5000,
                        component: COMPONENT_RTP,
                        ..CandidateConfig::default()
                    },
                    rel_addr: "192.168.0.1".to_owned(),
                    rel_port: 5001,
                    url: None,
                    relay_protocol: String::new(),
                }
                .new_candidate_relay()?,
            ),
            "848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1 rport 5001",
            false,
        ),
        (
            Some(host("tcp4", "192.168.0.196", 0, 0, "", TcpType::Active)?),
            "1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype active",
            false,
        ),
        (
            Some(host(
                "udp4",
                "e2494022-4d9a-4c1e-a750-cc48d4f8d6ee.local",
                60542,
                0,
                "",
                TcpType::Unspecified,
            )?),
            "1380287402 1 udp 2130706431 e2494022-4d9a-4c1e-a750-cc48d4f8d6ee.local 60542 typ host",
            false,
        ),
        (
            Some(host(
                "udp4",
                "redacted-ip.invalid",
                60542,
                0,
                "",
                TcpType::Unspecified,
            )?),
            "1380287402 1 udp 2130706431 redacted-ip.invalid 60542 typ host",
            false,
        ),
        // Missing foundation
        (
            Some(host(
                "udp4",
                "127.0.0.1",
                80,
                500,
                " ",
                TcpType::Unspecified,
            )?),
            " 1 udp 500 127.0.0.1 80 typ host",
            false,
        ),
        // Missing foundation, candidate: prefix
        (
            Some(host(
                "udp4",
                "127.0.0.1",
                80,
                500,
                " ",
                TcpType::Unspecified,
            )?),
            "candidate: 1 udp 500 127.0.0.1 80 typ host",
            false,
        ),
        (
            Some(host(
                "udp4",
                "127.0.0.1",
                80,
                500,
                "+/3713fhi",
                TcpType::Unspecified,
            )?),
            "+/3713fhi 1 udp 500 127.0.0.1 80 typ host",
            false,
        ),
        (
            Some(host(
                "tcp4",
                "172.28.142.173",
                7686,
                1671430143,
                "+/3713fhi",
                TcpType::Unspecified,
            )?),
            "3359356140 1 tcp 1671430143 172.28.142.173 7686 typ host",
            false,
        ),
        (
            Some(host(
                "tcp4",
                "172.28.142.173",
                7686,
                1671430143,
                "+/3713fhi",
                TcpType::Unspecified,
            )?),
            "candidate:3359356140 1 tcp 1671430143 172.28.142.173 7686 typ host",
            false,
        ),
        // Invalid candidates
        (None, "", true),
        (None, "1938809241", true),
        (
            None,
            "1986380506 99999999 udp 2122063615 10.0.75.1 53634 typ host generation 0 network-id 2",
            true,
        ),
        (
            None,
            "1986380506 1 udp 99999999999 10.0.75.1 53634 typ host",
            true,
        ),
        (
            None,
            "4207374051 1 udp 1685790463 191.228.238.68 99999999 typ srflx raddr 192.168.0.278 rport 53991 generation 0 network-id 3",
            true,
        ),
        (
            None,
            "4207374051 1 udp 1685790463 191.228.238.68 53991 typ srflx raddr",
            true,
        ),
        (
            None,
            "4207374051 1 udp 1685790463 191.228.238.68 53991 typ srflx raddr 192.168.0.278 rport 99999999 generation 0 network-id 3",
            true,
        ),
        (
            None,
            "4207374051 INVALID udp 2130706431 10.0.75.1 53634 typ host",
            true,
        ),
        (
            None,
            "4207374051 1 udp INVALID 10.0.75.1 53634 typ host",
            true,
        ),
        (
            None,
            "4207374051 INVALID udp 2130706431 10.0.75.1 INVALID typ host",
            true,
        ),
        (
            None,
            "4207374051 1 udp 2130706431 10.0.75.1 53634 typ INVALID",
            true,
        ),
        (
            None,
            "4207374051 1 INVALID 2130706431 10.0.75.1 53634 typ host",
            true,
        ),
        (
            None,
            "4207374051 1 INVALID 2130706431 10.0.75.1 53634 typ",
            true,
        ),
        (
            None,
            "4207374051 1 INVALID 2130706431 10.0.75.1 53634",
            true,
        ),
        (
            None,
            "848194626 1 udp 16777215 50.0.0.^^1 5000 typ relay raddr 192.168.0.1 rport 5001",
            true,
        ),
        (
            None,
            "4207374052 1 tcp 1685790463 192.0#.2.15 50000 typ prflx raddr 10.0.0.1 rport 12345 rport 5001",
            true,
        ),
        (
            None,
            "647372371 1 udp 1694498815 191.228.2@338.68 53991 typ srflx raddr 192.168.0.274 rport 53991",
            true,
        ),
        // invalid foundation; longer than 32 characters
        (
            None,
            "111111111111111111111111111111111 1 udp 500 127.0.0.1 80 typ host",
            true,
        ),
        // Invalid ice-char
        (None, "3$3 1 udp 500 127.0.0.1 80 typ host", true),
        // invalid component; longer than 5 digits
        (None, "4207374051 123456 udp 500 127.0.0.1 0 typ host", true),
        // invalid component; does not fit in a uint16
        (None, "4207374051 65536 udp 500 127.0.0.1 80 typ host", true),
        // invalid priority; longer than 10 digits
        (
            None,
            "4207374051 1 udp 12345678910 127.0.0.1 99999 typ host",
            true,
        ),
        // invalid priority; does not fit in a uint32
        (
            None,
            "4207374051 1 udp 4294967296 127.0.0.1 80 typ host",
            true,
        ),
        // invalid port
        (None, "4207374051 1 udp 500 127.0.0.1 65536 typ host", true),
        (None, "4207374051 1 udp 500 127.0.0.1 999999 typ host", true),
        (
            None,
            "848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1 rport 999999",
            true,
        ),
        // bad byte-string in extension value
        (
            None,
            "750 1 udp 500 fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a 53987 typ host ext valu\nu",
            true,
        ),
        (
            None,
            "848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1 rport 654 ext valu\nu",
            true,
        ),
        (
            None,
            "848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1 rport 654 ext valu\u{0}e",
            true,
        ),
        // bad byte-string in extension key
        (
            None,
            "848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1 rport 654 ext\r value",
            true,
        ),
        // invalid tcptype
        (
            None,
            "1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype INVALID",
            true,
        ),
        // expect rport after raddr
        (
            None,
            "848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1 extension 322",
            true,
        ),
        (
            None,
            "848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1 rport",
            true,
        ),
        (
            None,
            "848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1",
            true,
        ),
        (
            None,
            "848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr",
            true,
        ),
        (None, "4207374051 1 udp 500 127.0.0.1 80 typ", true),
        (None, "4207374051 1 udp 500 127.0.0.1 80", true),
        (None, "4207374051 1 udp 500 127.0.0.1", true),
        (None, "4207374051 1 udp 500 ", true),
        (None, "4207374051 1 udp", true),
        (None, "4207374051 1", true),
        (None, "4207374051", true),
    ];

    for (candidate, marshaled, expect_error) in tests {
        let actual = unmarshal_candidate(marshaled);
        if expect_error {
            assert!(actual.is_err(), "expected error: {marshaled}");
            continue;
        }
        let candidate = candidate.expect("non-error rows carry a candidate");
        let actual = actual.unwrap_or_else(|e| panic!("expected ok: {marshaled}: {e}"));
        assert!(
            candidate.equal(&actual),
            "{} != {}",
            candidate.marshal(),
            actual.marshal()
        );

        let expected = marshaled.strip_prefix("candidate:").unwrap_or(marshaled);
        assert_eq!(expected, actual.marshal());
    }

    Ok(())
}

/// pion TestUnmarshalCandidateNumericBounds: the 1*5DIGIT and 1*10DIGIT length limits still
/// admit values that do not fit in the u16 and u32 the candidate API exposes.
#[test]
fn test_unmarshal_candidate_numeric_bounds() -> Result<()> {
    let tests = [
        ("4207374051 65535 udp 500 127.0.0.1 80 typ host", false),
        ("4207374051 65536 udp 500 127.0.0.1 80 typ host", true),
        ("4207374051 1 udp 4294967295 127.0.0.1 80 typ host", false),
        ("4207374051 1 udp 4294967296 127.0.0.1 80 typ host", true),
    ];

    for (raw, expected_error) in tests {
        let candidate = unmarshal_candidate(raw);
        if expected_error {
            assert!(candidate.is_err(), "expected error: {raw}");
            continue;
        }
        let candidate = candidate.unwrap_or_else(|e| panic!("expected ok: {raw}: {e}"));
        assert_eq!(raw, candidate.marshal());
    }

    Ok(())
}

/// pion TestMarshalUnmarshalCandidateWithZoneID: an IPv6 zone ID never survives into a
/// candidate; marshaling and parsing both drop it.
#[test]
fn test_marshal_unmarshal_candidate_with_zone_id() -> Result<()> {
    let candidate_with_zone_id = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp6".to_owned(),
            address: "fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a%Local Connection".to_owned(),
            port: 53987,
            priority: 500,
            foundation: "750".to_owned(),
            ..CandidateConfig::default()
        },
        tcp_type: TcpType::Unspecified,
    }
    .new_candidate_host()?;
    let candidate_str = "750 0 udp 500 fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a 53987 typ host";
    assert_eq!(candidate_str, candidate_with_zone_id.marshal());

    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp6".to_owned(),
            address: "fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a".to_owned(),
            port: 53987,
            priority: 500,
            foundation: "750".to_owned(),
            ..CandidateConfig::default()
        },
        tcp_type: TcpType::Unspecified,
    }
    .new_candidate_host()?;

    let candidate_with_zone_id_str =
        "750 0 udp 500 fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a%eth0 53987 typ host";
    let candidate2 = unmarshal_candidate(candidate_with_zone_id_str)?;
    assert!(
        candidate.equal(&candidate2),
        "{} != {}",
        candidate.marshal(),
        candidate2.marshal()
    );

    let candidate_with_zone_id_str2 =
        "750 0 udp 500 fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a%eth0%eth1 53987 typ host";
    let candidate2 = unmarshal_candidate(candidate_with_zone_id_str2)?;
    assert!(
        candidate.equal(&candidate2),
        "{} != {}",
        candidate.marshal(),
        candidate2.marshal()
    );

    Ok(())
}

/// Regression test: a candidate's base address must be the local (bound)
/// transport address. For server/peer-reflexive candidates that is the
/// related address, not the NAT-mapped candidate address (RFC 8445 §5.1.1).
#[test]
fn test_candidate_base_addr() -> Result<()> {
    let host = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 5000,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    assert_eq!(host.base_addr(), host.addr(), "host base is itself");

    let srflx = CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.79.12.1".to_owned(),
            port: 60823,
            component: 1,
            ..Default::default()
        },
        rel_addr: "192.168.0.2".to_owned(),
        rel_port: 5000,
        ..Default::default()
    }
    .new_candidate_server_reflexive()?;
    assert_eq!(
        srflx.base_addr(),
        "192.168.0.2:5000".parse().unwrap(),
        "srflx base must be the related (host) address"
    );
    assert_ne!(srflx.base_addr(), srflx.addr());

    let prflx = CandidatePeerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.79.12.1".to_owned(),
            port: 60824,
            component: 1,
            ..Default::default()
        },
        rel_addr: "192.168.0.2".to_owned(),
        rel_port: 5000,
        ..Default::default()
    }
    .new_candidate_peer_reflexive()?;
    assert_eq!(
        prflx.base_addr(),
        "192.168.0.2:5000".parse().unwrap(),
        "prflx base must be the related (host) address"
    );

    // Missing/unparseable related address falls back to the candidate address.
    let prflx_no_rel = CandidatePeerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.79.12.1".to_owned(),
            port: 60825,
            component: 1,
            ..Default::default()
        },
        rel_addr: "".to_owned(),
        rel_port: 0,
        ..Default::default()
    }
    .new_candidate_peer_reflexive()?;
    assert_eq!(prflx_no_rel.base_addr(), prflx_no_rel.addr());

    let relay = CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "50.0.0.1".to_owned(),
            port: 5000,
            component: 1,
            ..Default::default()
        },
        rel_addr: "192.168.0.2".to_owned(),
        rel_port: 5001,
        ..Default::default()
    }
    .new_candidate_relay()?;
    assert_eq!(
        relay.base_addr(),
        relay.addr(),
        "relay base is the relayed address itself"
    );

    Ok(())
}

/// pion TestCandidateExtensionsMarshal: extensions round-trip through unmarshal and marshal.
#[test]
fn test_candidate_extensions_marshal() -> Result<()> {
    let exts = |pairs: &[(&str, &str)]| -> Vec<CandidateExtension> {
        pairs
            .iter()
            .map(|(k, v)| CandidateExtension::new(k, v))
            .collect()
    };

    let test_cases = vec![
        (
            exts(&[("generation", "0"), ("ufrag", "QNvE"), ("network-id", "4")]),
            "1299692247 1 udp 2122134271 fdc8:cc8:c835:e400:343c:feb:32c8:17b9 58240 typ host generation 0 ufrag QNvE network-id 4",
        ),
        (
            exts(&[
                ("generation", "1"),
                ("network-id", "2"),
                ("network-cost", "50"),
            ]),
            "647372371 1 udp 1694498815 191.228.238.68 53991 typ srflx raddr 192.168.0.274 rport 53991 generation 1 network-id 2 network-cost 50",
        ),
        (
            exts(&[
                ("generation", "0"),
                ("network-id", "2"),
                ("network-cost", "10"),
            ]),
            "4207374052 1 tcp 1685790463 192.0.2.15 50000 typ prflx raddr 10.0.0.1 rport 12345 generation 0 network-id 2 network-cost 10",
        ),
        (
            exts(&[
                ("generation", "0"),
                ("network-id", "1"),
                ("network-cost", "20"),
                ("ufrag", "frag42abcdef"),
                ("password", "abc123exp123"),
            ]),
            "848194626 1 udp 16777215 50.0.0.1 5000 typ relay raddr 192.168.0.1 rport 5001 generation 0 network-id 1 network-cost 20 ufrag frag42abcdef password abc123exp123",
        ),
        (
            exts(&[("tcptype", "active"), ("generation", "0")]),
            "1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype active generation 0",
        ),
        (
            exts(&[("tcptype", "active"), ("generation", "0")]),
            "1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype active generation 0",
        ),
        (
            exts(&[]),
            "1052353102 1 tcp 2128609279 192.168.0.196 0 typ host",
        ),
        (
            exts(&[
                ("tcptype", "active"),
                ("empty-value-1", ""),
                ("empty-value-2", ""),
            ]),
            "1052353102 1 tcp 2128609279 192.168.0.196 0 typ host tcptype active empty-value-1  empty-value-2",
        ),
    ];

    for (extensions, candidate_str) in test_cases {
        let candidate = unmarshal_candidate(candidate_str)?;
        assert_eq!(
            extensions,
            candidate.extensions(),
            "Extensions should be equal: {candidate_str}"
        );

        let value_str = candidate.marshal();
        let candidate2 = unmarshal_candidate(&value_str)?;

        assert_eq!(
            extensions,
            candidate2.extensions(),
            "Marshal() should preserve extensions: {value_str}"
        );
    }

    Ok(())
}

/// pion TestCandidateExtensionsDeepEqual: `equal` ignores extensions, `deep_equal` compares
/// them as multisets.
#[test]
fn test_candidate_extensions_deep_equal() -> Result<()> {
    let no_ext =
        unmarshal_candidate("750 0 udp 500 fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a 53987 typ host")?;

    let extensions = vec![
        CandidateExtension::new("generation", "0"),
        CandidateExtension::new("ufrag", "QNvE"),
        CandidateExtension::new("network-id", "4"),
    ];

    let candidate = unmarshal_candidate(
        "750 0 udp 500 fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a 53987 typ host generation 0 ufrag QNvE network-id 4",
    )?;

    let host_config = || CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp4".to_owned(),
            address: "fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a".to_owned(),
            port: 53987,
            priority: 500,
            foundation: "750".to_owned(),
            ..CandidateConfig::default()
        },
        tcp_type: TcpType::Unspecified,
    };
    let relay_config = || CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp4".to_owned(),
            address: "10.0.0.10".to_owned(),
            port: 5000,
            ..CandidateConfig::default()
        },
        rel_addr: "10.0.0.2".to_owned(),
        rel_port: 5001,
        url: None,
        relay_protocol: String::new(),
    };
    let prflx_config = || CandidatePeerReflexiveConfig {
        base_config: CandidateConfig {
            network: "tcp4".to_owned(),
            address: "192.0.2.15".to_owned(),
            port: 50000,
            ..CandidateConfig::default()
        },
        rel_addr: "10.0.0.1".to_owned(),
        rel_port: 12345,
    };
    let srflx_config = || CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp4".to_owned(),
            address: "191.228.238.68".to_owned(),
            port: 53991,
            ..CandidateConfig::default()
        },
        rel_addr: "192.168.0.274".to_owned(),
        rel_port: 53991,
        url: None,
    };
    let host_with = |extensions: Vec<CandidateExtension>| -> Result<Candidate> {
        let mut cand = host_config().new_candidate_host()?;
        cand.set_extensions(extensions);
        Ok(cand)
    };
    let relay_with = |extensions: Vec<CandidateExtension>| -> Result<Candidate> {
        let mut cand = relay_config().new_candidate_relay()?;
        cand.set_extensions(extensions);
        Ok(cand)
    };
    let prflx_with = |extensions: Vec<CandidateExtension>| -> Result<Candidate> {
        let mut cand = prflx_config().new_candidate_peer_reflexive()?;
        cand.set_extensions(extensions);
        Ok(cand)
    };
    let srflx_with = |extensions: Vec<CandidateExtension>| -> Result<Candidate> {
        let mut cand = srflx_config().new_candidate_server_reflexive()?;
        cand.set_extensions(extensions);
        Ok(cand)
    };

    let host_no_ext = host_config().new_candidate_host()?;
    let test_cases = vec![
        // A candidate with no extensions equals one parsed without them.
        (host_no_ext.clone(), no_ext.clone(), true),
        (host_with(vec![])?, no_ext.clone(), true),
        (host_with(extensions.clone())?, candidate.clone(), true),
        // Extension order does not matter for deep equality.
        (
            relay_with(vec![
                CandidateExtension::new("generation", "0"),
                CandidateExtension::new("network-id", "1"),
            ])?,
            relay_with(vec![
                CandidateExtension::new("network-id", "1"),
                CandidateExtension::new("generation", "0"),
            ])?,
            true,
        ),
        (
            prflx_with(vec![
                CandidateExtension::new("generation", "0"),
                CandidateExtension::new("network-id", "2"),
                CandidateExtension::new("network-cost", "10"),
            ])?,
            prflx_with(vec![
                CandidateExtension::new("generation", "0"),
                CandidateExtension::new("network-id", "2"),
                CandidateExtension::new("network-cost", "10"),
            ])?,
            true,
        ),
        (
            srflx_with(vec![
                CandidateExtension::new("generation", "0"),
                CandidateExtension::new("network-id", "2"),
                CandidateExtension::new("network-cost", "10"),
            ])?,
            srflx_with(vec![
                CandidateExtension::new("generation", "0"),
                CandidateExtension::new("network-id", "2"),
                CandidateExtension::new("network-cost", "10"),
            ])?,
            true,
        ),
        // Different extension values.
        (
            host_with(vec![
                CandidateExtension::new("generation", "5"),
                CandidateExtension::new("ufrag", "QNvE"),
                CandidateExtension::new("network-id", "4"),
            ])?,
            candidate.clone(),
            false,
        ),
        // Different addresses.
        (
            {
                let mut cand = CandidateHostConfig {
                    base_config: CandidateConfig {
                        network: "tcp4".to_owned(),
                        address: "192.168.0.196".to_owned(),
                        port: 0,
                        priority: 2128609279,
                        foundation: "1052353102".to_owned(),
                        ..CandidateConfig::default()
                    },
                    tcp_type: TcpType::Active,
                }
                .new_candidate_host()?;
                cand.set_extensions(vec![
                    CandidateExtension::new("tcptype", "active"),
                    CandidateExtension::new("generation", "0"),
                ]);
                cand
            },
            {
                let mut cand = CandidateHostConfig {
                    base_config: CandidateConfig {
                        network: "tcp4".to_owned(),
                        address: "192.168.0.197".to_owned(),
                        port: 0,
                        priority: 2128609279,
                        foundation: "1052353102".to_owned(),
                        ..CandidateConfig::default()
                    },
                    tcp_type: TcpType::Active,
                }
                .new_candidate_host()?;
                cand.set_extensions(vec![
                    CandidateExtension::new("tcptype", "active"),
                    CandidateExtension::new("generation", "0"),
                ]);
                cand
            },
            false,
        ),
    ];

    for (a, b, expected) in test_cases {
        assert_eq!(
            a.deep_equal(&b),
            expected,
            "a: {}, b: {}",
            a.marshal(),
            b.marshal()
        );
    }

    Ok(())
}

/// pion TestUnmarshalCandidateExtensions: byte-string pairs, empty values tolerated, leading
/// space rejected.
#[test]
fn test_unmarshal_candidate_extensions() -> Result<()> {
    let exts = |pairs: &[(&str, &str)]| -> Vec<CandidateExtension> {
        pairs
            .iter()
            .map(|(k, v)| CandidateExtension::new(k, v))
            .collect()
    };

    let test_cases = vec![
        ("empty string", "", exts(&[]), false),
        (
            "valid extension string",
            "a b c d",
            exts(&[("a", "b"), ("c", "d")]),
            false,
        ),
        (
            "empty value",
            "a b empty  c d",
            exts(&[("a", "b"), ("empty", ""), ("c", "d")]),
            false,
        ),
        // A leading space means the first key would be empty.
        (
            "invalid extension",
            " a b d",
            exts(&[("", "a"), ("b", "d")]),
            true,
        ),
    ];

    for (name, value, expected, fail) in test_cases {
        let actual = unmarshal_candidate_extensions(value);
        if fail {
            assert!(actual.is_err(), "{name}: expected error");
        } else {
            let (actual, tcp_type_raw) =
                actual.unwrap_or_else(|e| panic!("{name}: expected ok: {e}"));
            assert_eq!(
                expected, actual,
                "{name}: UnmarshalCandidateExtensions() did not return the expected value"
            );
            assert_eq!(tcp_type_raw, None, "{name}: no tcptype expected");
        }
    }

    Ok(())
}

/// pion TestCandidateGetExtension: lookup by key, first duplicate wins, a manually-set TCP
/// type answers for `tcptype`.
#[test]
fn test_candidate_get_extension() -> Result<()> {
    let new_candidate = || {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp4".to_owned(),
                address: "fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a".to_owned(),
                port: 53987,
                priority: 500,
                foundation: "750".to_owned(),
                ..CandidateConfig::default()
            },
            tcp_type: TcpType::Unspecified,
        }
        .new_candidate_host()
    };

    // Get extension
    {
        let mut candidate = new_candidate()?;
        candidate.set_extensions(vec![
            CandidateExtension::new("a", "b"),
            CandidateExtension::new("c", "d"),
        ]);

        assert_eq!(
            candidate.get_extension("c"),
            Some(CandidateExtension::new("c", "d"))
        );
        assert_eq!(
            candidate.get_extension("a"),
            Some(CandidateExtension::new("a", "b"))
        );
        assert_eq!(candidate.get_extension("b"), None);
    }

    // Extension with multiple values: the first one wins.
    {
        let mut candidate = new_candidate()?;
        candidate.set_extensions(vec![
            CandidateExtension::new("a", "1"),
            CandidateExtension::new("a", "2"),
        ]);
        assert_eq!(
            candidate.get_extension("a"),
            Some(CandidateExtension::new("a", "1"))
        );
    }

    // TCPType extension: the manual TCP type answers until an explicit extension overrides it.
    {
        let mut candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp4".to_owned(),
                address: "fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a".to_owned(),
                port: 53987,
                priority: 500,
                foundation: "750".to_owned(),
                ..CandidateConfig::default()
            },
            tcp_type: TcpType::Active,
        }
        .new_candidate_host()?;

        assert_eq!(
            candidate.get_extension("tcptype"),
            Some(CandidateExtension::new("tcptype", "active"))
        );

        candidate.set_extensions(vec![CandidateExtension::new("tcptype", "passive")]);
        assert_eq!(
            candidate.get_extension("tcptype"),
            Some(CandidateExtension::new("tcptype", "passive"))
        );

        let candidate2 = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp4".to_owned(),
                address: "fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a".to_owned(),
                port: 53987,
                priority: 500,
                foundation: "750".to_owned(),
                ..CandidateConfig::default()
            },
            tcp_type: TcpType::Unspecified,
        }
        .new_candidate_host()?;
        assert_eq!(candidate2.get_extension("tcptype"), None);
    }

    Ok(())
}

/// pion TestBaseCandidateMarshalExtensions: the wire form of the extensions, with a manual
/// TCP type included.
#[test]
fn test_base_candidate_marshal_extensions() -> Result<()> {
    let new_candidate = |tcp_type: TcpType| {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp4".to_owned(),
                address: "fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a".to_owned(),
                port: 53987,
                priority: 500,
                foundation: "750".to_owned(),
                ..CandidateConfig::default()
            },
            tcp_type,
        }
        .new_candidate_host()
    };

    // Marshal extension
    {
        let mut candidate = new_candidate(TcpType::Unspecified)?;
        candidate.set_extensions(vec![
            CandidateExtension::new("generation", "0"),
            CandidateExtension::new("ValuE", "KeE"),
            CandidateExtension::new("empty", ""),
            CandidateExtension::new("another", "value"),
        ]);
        assert_eq!(
            candidate.marshal_extensions(),
            "generation 0 ValuE KeE empty  another value"
        );
    }

    // Marshal Empty
    {
        let candidate = new_candidate(TcpType::Unspecified)?;
        assert_eq!(candidate.marshal_extensions(), "");
    }

    // Marshal TCPType no extension
    {
        let candidate = new_candidate(TcpType::Active)?;
        assert_eq!(candidate.marshal_extensions(), "tcptype active");
    }

    Ok(())
}

/// pion TestBaseCandidateExtensionsEqual: multiset comparison of extension lists.
#[test]
fn test_base_candidate_extensions_equal() -> Result<()> {
    let exts = |pairs: &[(&str, &str)]| -> Vec<CandidateExtension> {
        pairs
            .iter()
            .map(|(k, v)| CandidateExtension::new(k, v))
            .collect()
    };

    let test_cases = vec![
        ("Empty extensions", exts(&[]), exts(&[]), true),
        (
            "Single value extensions",
            exts(&[("a", "b")]),
            exts(&[("a", "b")]),
            true,
        ),
        (
            "multiple value extensions",
            exts(&[("a", "b"), ("c", "d")]),
            exts(&[("a", "b"), ("c", "d")]),
            true,
        ),
        (
            "unsorted extensions",
            exts(&[("c", "d"), ("a", "b")]),
            exts(&[("a", "b"), ("c", "d")]),
            true,
        ),
        (
            "different values",
            exts(&[("a", "b"), ("c", "d")]),
            exts(&[("a", "b"), ("c", "e")]),
            false,
        ),
        (
            "different size",
            exts(&[("a", "b"), ("c", "d")]),
            exts(&[("a", "b")]),
            false,
        ),
        (
            "different keys",
            exts(&[("a", "b"), ("c", "d")]),
            exts(&[("a", "b"), ("e", "d")]),
            false,
        ),
    ];

    for (name, extensions1, extensions2, expected) in test_cases {
        let mut cand = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp4".to_owned(),
                address: "fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a".to_owned(),
                port: 53987,
                priority: 500,
                foundation: "750".to_owned(),
                ..CandidateConfig::default()
            },
            tcp_type: TcpType::Unspecified,
        }
        .new_candidate_host()?;
        cand.set_extensions(extensions1);

        assert_eq!(cand.extensions_equal(&extensions2), expected, "{name}");
    }

    Ok(())
}

/// pion TestCandidateAddExtension: adding, replacing, `tcptype` handling and empty keys.
#[test]
fn test_candidate_add_extension() -> Result<()> {
    let new_candidate = |tcp_type: TcpType| {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp4".to_owned(),
                address: "fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a".to_owned(),
                port: 53987,
                priority: 500,
                foundation: "750".to_owned(),
                ..CandidateConfig::default()
            },
            tcp_type,
        }
        .new_candidate_host()
    };

    // Add extension
    {
        let mut candidate = new_candidate(TcpType::Unspecified)?;
        candidate.add_extension(CandidateExtension::new("a", "b"))?;
        candidate.add_extension(CandidateExtension::new("c", "d"))?;
        assert_eq!(
            candidate.extensions(),
            vec![
                CandidateExtension::new("a", "b"),
                CandidateExtension::new("c", "d")
            ]
        );
    }

    // Add extension with existing key: replaces it.
    {
        let mut candidate = new_candidate(TcpType::Unspecified)?;
        candidate.add_extension(CandidateExtension::new("a", "b"))?;
        candidate.add_extension(CandidateExtension::new("a", "d"))?;
        assert_eq!(
            candidate.extensions(),
            vec![CandidateExtension::new("a", "d")]
        );
    }

    // Keep tcptype extension: a manual TCP type stays first.
    {
        let mut candidate = new_candidate(TcpType::Active)?;
        assert_eq!(
            candidate.get_extension("tcptype"),
            Some(CandidateExtension::new("tcptype", "active"))
        );
        assert_eq!(
            candidate.extensions(),
            vec![CandidateExtension::new("tcptype", "active")]
        );

        candidate.add_extension(CandidateExtension::new("a", "b"))?;
        assert_eq!(
            candidate.get_extension("tcptype"),
            Some(CandidateExtension::new("tcptype", "active"))
        );
        assert_eq!(
            candidate.extensions(),
            vec![
                CandidateExtension::new("tcptype", "active"),
                CandidateExtension::new("a", "b")
            ]
        );
    }

    // TcpType change extension: adding tcptype sets the TCP type; an invalid one is an error.
    {
        let mut candidate = new_candidate(TcpType::Unspecified)?;
        candidate.add_extension(CandidateExtension::new("tcptype", "active"))?;
        assert_eq!(
            candidate.extensions(),
            vec![CandidateExtension::new("tcptype", "active")]
        );
        assert_eq!(candidate.tcp_type(), TcpType::Active);

        assert!(
            candidate
                .add_extension(CandidateExtension::new("tcptype", "INVALID"))
                .is_err()
        );
    }

    // Add empty extension: an empty key errors, an empty value is fine.
    {
        let mut candidate = new_candidate(TcpType::Unspecified)?;
        assert!(
            candidate
                .add_extension(CandidateExtension::new("", ""))
                .is_err()
        );
        candidate.add_extension(CandidateExtension::new("a", ""))?;
        assert_eq!(
            candidate.extensions(),
            vec![CandidateExtension::new("a", "")]
        );
    }

    Ok(())
}

/// pion TestCandidateRemoveExtension: removal by key, missing keys, and `tcptype`.
#[test]
fn test_candidate_remove_extension() -> Result<()> {
    let new_candidate = |tcp_type: TcpType| {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp4".to_owned(),
                address: "fcd9:e3b8:12ce:9fc5:74a5:c6bb:d8b:e08a".to_owned(),
                port: 53987,
                priority: 500,
                foundation: "750".to_owned(),
                ..CandidateConfig::default()
            },
            tcp_type,
        }
        .new_candidate_host()
    };

    // Remove extension
    {
        let mut candidate = new_candidate(TcpType::Unspecified)?;
        candidate.add_extension(CandidateExtension::new("a", "b"))?;
        candidate.add_extension(CandidateExtension::new("c", "d"))?;

        assert!(candidate.remove_extension("a"));
        assert_eq!(
            candidate.extensions(),
            vec![CandidateExtension::new("c", "d")]
        );
    }

    // Remove extension that does not exist
    {
        let mut candidate = new_candidate(TcpType::Unspecified)?;
        candidate.add_extension(CandidateExtension::new("a", "b"))?;
        candidate.add_extension(CandidateExtension::new("c", "d"))?;

        assert!(!candidate.remove_extension("b"));
        assert_eq!(
            candidate.extensions(),
            vec![
                CandidateExtension::new("a", "b"),
                CandidateExtension::new("c", "d")
            ]
        );
    }

    // Remove tcptype extension: clears the manual TCP type even when unparsed.
    {
        let mut candidate = new_candidate(TcpType::Active)?;
        assert!(candidate.remove_extension("tcptype"));
        assert_eq!(candidate.tcp_type(), TcpType::Unspecified);
        assert!(candidate.extensions().is_empty());

        candidate.add_extension(CandidateExtension::new("tcptype", "passive"))?;
        assert_eq!(candidate.tcp_type(), TcpType::Passive);
        assert!(candidate.remove_extension("tcptype"));
        assert_eq!(candidate.tcp_type(), TcpType::Unspecified);
        assert!(candidate.extensions().is_empty());
    }

    Ok(())
}

/// pion TestCandidateTypePreference: the RFC 8445 type preference per candidate type and
/// transport, lowered by the agent's TCP priority offset for TCP candidates.
#[test]
fn test_candidate_type_preference() {
    const HOST_DEFAULT_PREFERENCE: u16 = 126;
    const PRFLX_DEFAULT_PREFERENCE: u16 = 110;
    const SRFLX_DEFAULT_PREFERENCE: u16 = 100;
    const RELAY_DEFAULT_PREFERENCE: u16 = 0;

    let supported_network_types = [
        NetworkType::Udp4,
        NetworkType::Udp6,
        NetworkType::Tcp4,
        NetworkType::Tcp6,
    ];

    for tcp_offset in [0u16, 10] {
        for network_type in supported_network_types {
            let make = |candidate_type: CandidateType| Candidate {
                candidate_type,
                network_type,
                tcp_priority_offset: tcp_offset,
                ..Default::default()
            };

            let host = make(CandidateType::Host);
            let prflx = make(CandidateType::PeerReflexive);
            let srflx = make(CandidateType::ServerReflexive);
            let relay = make(CandidateType::Relay);

            if network_type.is_tcp() {
                assert_eq!(host.type_preference(), HOST_DEFAULT_PREFERENCE - tcp_offset);
                assert_eq!(
                    prflx.type_preference(),
                    PRFLX_DEFAULT_PREFERENCE - tcp_offset
                );
                assert_eq!(
                    srflx.type_preference(),
                    SRFLX_DEFAULT_PREFERENCE - tcp_offset
                );
            } else {
                assert_eq!(host.type_preference(), HOST_DEFAULT_PREFERENCE);
                assert_eq!(prflx.type_preference(), PRFLX_DEFAULT_PREFERENCE);
                assert_eq!(srflx.type_preference(), SRFLX_DEFAULT_PREFERENCE);
            }

            assert_eq!(relay.type_preference(), RELAY_DEFAULT_PREFERENCE);
        }
    }
}

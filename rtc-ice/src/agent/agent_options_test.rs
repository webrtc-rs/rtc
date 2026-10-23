use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::mdns::MulticastDnsMode;

fn test_crypto_provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

fn new_agent(config: AgentConfig) -> Result<Agent> {
    Agent::new(Instant::now(), Arc::new(config), test_crypto_provider())
}

/// pion TestWithLite: config sets lite; the default is not lite; lite with non-host candidate
/// types is rejected.
#[test]
fn test_with_lite() -> Result<()> {
    // Config sets lite (host candidates only, as a lite agent must).
    let mut agent = new_agent(AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        ..AgentConfig::default()
    })?;
    assert!(agent.lite);
    agent.close()?;

    // Default is not lite.
    let mut agent = new_agent(AgentConfig::default())?;
    assert!(!agent.lite);
    agent.close()?;

    // Default candidate types include srflx/relay: lite with them is an error.
    let err = match new_agent(AgentConfig {
        lite: true,
        ..AgentConfig::default()
    }) {
        Err(err) => err,
        Ok(_) => panic!("expected ErrLiteUsingNonHostCandidates"),
    };
    assert_eq!(err, Error::ErrLiteUsingNonHostCandidates);

    Ok(())
}

/// pion TestWithUrls: the configured servers reach the agent verbatim.
#[test]
fn test_with_urls() -> Result<()> {
    let stun_url = crate::url::Url::parse_url("stun:example.com:3478")?;
    let config = AgentConfig {
        urls: vec![stun_url.clone()],
        ..AgentConfig::default()
    };
    let mut agent = new_agent(config)?;
    assert_eq!(agent.urls.len(), 1);
    assert_eq!(agent.urls[0].to_string(), stun_url.to_string());
    agent.close()
}

/// pion TestWithTimeoutOptions: the four timers all take their configured values.
#[test]
fn test_with_timeout_options() -> Result<()> {
    let mut agent = new_agent(AgentConfig {
        disconnected_timeout: Some(Duration::from_secs(10)),
        failed_timeout: Some(Duration::from_secs(20)),
        keepalive_interval: Some(Duration::from_secs(3)),
        check_interval: Duration::from_millis(150),
        ..AgentConfig::default()
    })?;

    assert_eq!(agent.disconnected_timeout, Duration::from_secs(10));
    assert_eq!(agent.failed_timeout, Duration::from_secs(20));
    assert_eq!(agent.keepalive_interval, Duration::from_secs(3));
    assert_eq!(agent.check_interval, Duration::from_millis(150));
    agent.close()
}

/// pion TestICELiteDisconnectedTimeoutDefault: a lite agent that did not set a disconnected
/// timeout uses the longer lite default, but computes its initial checking deadline from the
/// full agent's default; explicit values always win, and a zero failed timeout disables the
/// initial checking timeout.
#[test]
fn test_ice_lite_disconnected_timeout_default() -> Result<()> {
    let explicit_disconnected_timeout = Duration::from_secs(10);
    let explicit_failed_timeout = Duration::from_secs(10);

    struct Case {
        name: &'static str,
        lite: bool,
        disconnected_timeout: Option<Duration>,
        failed_timeout: Option<Duration>,
        expected_disconnected_timeout: Duration,
        expected_failed_timeout: Duration,
        expected_checking_timeout: Duration,
    }

    let cases = vec![
        // Full agent keeps the full defaults.
        Case {
            name: "full agent keeps full default",
            lite: false,
            disconnected_timeout: None,
            failed_timeout: None,
            expected_disconnected_timeout: DEFAULT_DISCONNECTED_TIMEOUT,
            expected_failed_timeout: DEFAULT_FAILED_TIMEOUT,
            expected_checking_timeout: DEFAULT_DISCONNECTED_TIMEOUT + DEFAULT_FAILED_TIMEOUT,
        },
        // Lite uses the lite default for disconnected...
        Case {
            name: "lite agent uses lite default",
            lite: true,
            disconnected_timeout: None,
            failed_timeout: None,
            expected_disconnected_timeout: DEFAULT_LITE_DISCONNECTED_TIMEOUT,
            expected_failed_timeout: DEFAULT_FAILED_TIMEOUT,
            // ...but the initial checking deadline still sums from the full default.
            expected_checking_timeout: DEFAULT_DISCONNECTED_TIMEOUT + DEFAULT_FAILED_TIMEOUT,
        },
        Case {
            name: "lite agent preserves explicit timeout",
            lite: true,
            disconnected_timeout: Some(explicit_disconnected_timeout),
            failed_timeout: None,
            expected_disconnected_timeout: explicit_disconnected_timeout,
            expected_failed_timeout: DEFAULT_FAILED_TIMEOUT,
            expected_checking_timeout: explicit_disconnected_timeout + DEFAULT_FAILED_TIMEOUT,
        },
        Case {
            name: "explicit lite default uses explicit checking deadline",
            lite: true,
            disconnected_timeout: Some(DEFAULT_LITE_DISCONNECTED_TIMEOUT),
            failed_timeout: None,
            expected_disconnected_timeout: DEFAULT_LITE_DISCONNECTED_TIMEOUT,
            expected_failed_timeout: DEFAULT_FAILED_TIMEOUT,
            expected_checking_timeout: DEFAULT_LITE_DISCONNECTED_TIMEOUT + DEFAULT_FAILED_TIMEOUT,
        },
        Case {
            name: "lite default combines with explicit failed timeout",
            lite: true,
            disconnected_timeout: None,
            failed_timeout: Some(explicit_failed_timeout),
            expected_disconnected_timeout: DEFAULT_LITE_DISCONNECTED_TIMEOUT,
            expected_failed_timeout: explicit_failed_timeout,
            expected_checking_timeout: DEFAULT_DISCONNECTED_TIMEOUT + explicit_failed_timeout,
        },
        Case {
            name: "explicit zero is preserved",
            lite: true,
            disconnected_timeout: Some(Duration::ZERO),
            failed_timeout: None,
            expected_disconnected_timeout: Duration::ZERO,
            expected_failed_timeout: DEFAULT_FAILED_TIMEOUT,
            expected_checking_timeout: DEFAULT_FAILED_TIMEOUT,
        },
        Case {
            name: "zero failed timeout disables initial checking timeout",
            lite: false,
            disconnected_timeout: None,
            failed_timeout: Some(Duration::ZERO),
            expected_disconnected_timeout: DEFAULT_DISCONNECTED_TIMEOUT,
            expected_failed_timeout: Duration::ZERO,
            expected_checking_timeout: Duration::ZERO,
        },
        Case {
            name: "zero disconnected and failed timeouts disable initial checking timeout",
            lite: false,
            disconnected_timeout: Some(Duration::ZERO),
            failed_timeout: Some(Duration::ZERO),
            expected_disconnected_timeout: Duration::ZERO,
            expected_failed_timeout: Duration::ZERO,
            expected_checking_timeout: Duration::ZERO,
        },
    ];

    for case in cases {
        let mut agent = new_agent(AgentConfig {
            lite: case.lite,
            candidate_types: if case.lite {
                vec![CandidateType::Host]
            } else {
                vec![]
            },
            disconnected_timeout: case.disconnected_timeout,
            failed_timeout: case.failed_timeout,
            ..AgentConfig::default()
        })?;
        assert_eq!(
            agent.disconnected_timeout, case.expected_disconnected_timeout,
            "{}: disconnected timeout",
            case.name
        );
        assert_eq!(
            agent.initial_checking_timeout(),
            case.expected_checking_timeout,
            "{}: initial checking timeout",
            case.name
        );
        assert_eq!(
            agent.failed_timeout, case.expected_failed_timeout,
            "{}: failed timeout",
            case.name
        );
        assert_eq!(
            agent.keepalive_interval, DEFAULT_KEEPALIVE_INTERVAL,
            "{}: keepalive interval keeps its default",
            case.name
        );
        agent.close()?;
    }

    Ok(())
}

/// pion TestWithAcceptanceWaitOptions: the four acceptance waits take their configured values.
#[test]
fn test_with_acceptance_wait_options() -> Result<()> {
    let mut agent = new_agent(AgentConfig {
        host_acceptance_min_wait: Some(Duration::from_secs(1)),
        srflx_acceptance_min_wait: Some(Duration::from_secs(2)),
        prflx_acceptance_min_wait: Some(Duration::from_secs(3)),
        relay_acceptance_min_wait: Some(Duration::from_secs(4)),
        ..AgentConfig::default()
    })?;

    assert_eq!(agent.host_acceptance_min_wait, Duration::from_secs(1));
    assert_eq!(agent.srflx_acceptance_min_wait, Duration::from_secs(2));
    assert_eq!(agent.prflx_acceptance_min_wait, Duration::from_secs(3));
    assert_eq!(agent.relay_acceptance_min_wait, Duration::from_secs(4));
    agent.close()
}

/// pion TestWithMaxBindingRequests.
#[test]
fn test_with_max_binding_requests() -> Result<()> {
    let mut agent = new_agent(AgentConfig {
        max_binding_requests: Some(3),
        ..AgentConfig::default()
    })?;
    assert_eq!(agent.max_binding_requests, 3);
    agent.close()
}

/// pion TestWithMulticastDNSOptions: mode and host name applied; an invalid host name is
/// rejected.
#[test]
fn test_with_multicast_dns_options() -> Result<()> {
    let mut agent = new_agent(AgentConfig {
        multicast_dns_mode: MulticastDnsMode::Disabled,
        multicast_dns_local_name: "pion-test.local".to_owned(),
        ..AgentConfig::default()
    })?;
    assert_eq!(agent.mdns_mode, MulticastDnsMode::Disabled);
    assert_eq!(agent.mdns_local_name, "pion-test.local");
    agent.close()?;

    let err = match new_agent(AgentConfig {
        multicast_dns_local_name: "invalid-host".to_owned(),
        ..AgentConfig::default()
    }) {
        Err(err) => err,
        Ok(_) => panic!("expected ErrInvalidMulticastDnshostName"),
    };
    assert_eq!(err, Error::ErrInvalidMulticastDnshostName);

    Ok(())
}

/// pion TestWithLocalCredentials: credentials are installed; too-short ones are rejected.
#[test]
fn test_with_local_credentials() -> Result<()> {
    let password = "p".repeat(22); // 22 chars * 8 = 176 bits >= 128
    let mut agent = new_agent(AgentConfig {
        local_ufrag: "abcd".to_owned(),
        local_pwd: password.clone(),
        ..AgentConfig::default()
    })?;
    assert_eq!(agent.get_local_credentials().ufrag, "abcd");
    assert_eq!(agent.get_local_credentials().pwd, password);
    agent.close()?;

    let err = match new_agent(AgentConfig {
        local_ufrag: "ab".to_owned(),
        local_pwd: password,
        ..AgentConfig::default()
    }) {
        Err(err) => err,
        Ok(_) => panic!("expected ErrLocalUfragInsufficientBits"),
    };
    assert_eq!(err, Error::ErrLocalUfragInsufficientBits);

    let err = match new_agent(AgentConfig {
        local_ufrag: "abcd".to_owned(),
        local_pwd: "p".repeat(10),
        ..AgentConfig::default()
    }) {
        Err(err) => err,
        Ok(_) => panic!("expected ErrLocalPwdInsufficientBits"),
    };
    assert_eq!(err, Error::ErrLocalPwdInsufficientBits);

    Ok(())
}

/// pion TestLocalCredentialsLength: the minimum lengths at construction and on restart; empty
/// credentials are generated, not rejected.
#[test]
fn test_local_credentials_length() -> Result<()> {
    let ufrag = "u".repeat(4);
    let short_ufrag = "u".repeat(3);
    let pwd = "p".repeat(22);
    let short_pwd = "p".repeat(21);

    struct Case {
        name: &'static str,
        ufrag: String,
        pwd: String,
        expected: Option<Error>,
    }

    let cases = vec![
        Case {
            name: "ufrag too short",
            ufrag: short_ufrag,
            pwd: pwd.clone(),
            expected: Some(Error::ErrLocalUfragInsufficientBits),
        },
        Case {
            name: "ufrag at minimum",
            ufrag: ufrag.clone(),
            pwd: pwd.clone(),
            expected: None,
        },
        Case {
            name: "pwd too short",
            ufrag: ufrag.clone(),
            pwd: short_pwd,
            expected: Some(Error::ErrLocalPwdInsufficientBits),
        },
        Case {
            name: "stateless token",
            ufrag: "u".repeat(24),
            pwd: "p".repeat(32),
            expected: None,
        },
        Case {
            name: "both empty",
            ufrag: String::new(),
            pwd: String::new(),
            expected: None,
        },
    ];

    for case in cases {
        // At construction.
        let result = new_agent(AgentConfig {
            local_ufrag: case.ufrag.clone(),
            local_pwd: case.pwd.clone(),
            ..AgentConfig::default()
        });
        match &case.expected {
            Some(expected) => {
                let err = result
                    .err()
                    .unwrap_or_else(|| panic!("{}: expected error at construction", case.name));
                assert_eq!(&err, expected, "{}: construction", case.name);
            }
            None => {
                let mut agent = result.unwrap_or_else(|e| panic!("{}: {e}", case.name));
                assert!(
                    agent.get_local_credentials().ufrag.len() * 8 >= 24,
                    "{}: generated ufrag too short",
                    case.name
                );
                assert!(
                    agent.get_local_credentials().pwd.len() * 8 >= 128,
                    "{}: generated pwd too short",
                    case.name
                );
                agent.close()?;
            }
        }

        // On restart of an existing agent.
        let mut agent = new_agent(AgentConfig::default())?;
        let result = agent.restart(Instant::now(), case.ufrag.clone(), case.pwd.clone(), false);
        match &case.expected {
            Some(expected) => {
                let err = result
                    .err()
                    .unwrap_or_else(|| panic!("{}: expected error on restart", case.name));
                assert_eq!(&err, expected, "{}: restart", case.name);
            }
            None => {
                result.unwrap_or_else(|e| panic!("{}: restart: {e}", case.name));
                assert!(
                    agent.get_local_credentials().ufrag.len() * 8 >= 24,
                    "{}: restarted ufrag too short",
                    case.name
                );
                assert!(
                    agent.get_local_credentials().pwd.len() * 8 >= 128,
                    "{}: restarted pwd too short",
                    case.name
                );
            }
        }
        agent.close()?;
    }

    Ok(())
}

/// pion TestWithTCPPriorityOffset: custom value, config path, and the libwebrtc default of 27.
#[test]
fn test_with_tcp_priority_offset() -> Result<()> {
    let mut agent = new_agent(AgentConfig {
        tcp_priority_offset: Some(50),
        ..AgentConfig::default()
    })?;
    assert_eq!(agent.tcp_priority_offset, 50);
    agent.close()?;

    let mut agent = new_agent(AgentConfig::default())?;
    assert_eq!(agent.tcp_priority_offset, 27);
    agent.close()?;

    let mut agent = new_agent(AgentConfig {
        tcp_priority_offset: Some(100),
        ..AgentConfig::default()
    })?;
    assert_eq!(agent.tcp_priority_offset, 100);
    agent.close()
}

/// pion TestMultipleConfigOptions (the parts with a Rust counterpart): several independent
/// settings applied at once.
#[test]
fn test_multiple_config_options() -> Result<()> {
    let mut agent = new_agent(AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        tcp_priority_offset: Some(100),
        ..AgentConfig::default()
    })?;

    assert!(agent.lite);
    assert_eq!(agent.tcp_priority_offset, 100);
    agent.close()
}

/// pion TestWithNetworkTypes: applied, deduplicated, and unsupported values rejected.
#[test]
fn test_with_network_types() -> Result<()> {
    let mut agent = new_agent(AgentConfig {
        network_types: vec![NetworkType::Udp4, NetworkType::Tcp4],
        ..AgentConfig::default()
    })?;
    assert_eq!(
        agent.network_types,
        vec![NetworkType::Udp4, NetworkType::Tcp4]
    );
    agent.close()?;

    // Deduplicates values.
    let mut agent = new_agent(AgentConfig {
        network_types: vec![NetworkType::Udp4, NetworkType::Udp4, NetworkType::Tcp4],
        ..AgentConfig::default()
    })?;
    assert_eq!(
        agent.network_types,
        vec![NetworkType::Udp4, NetworkType::Tcp4]
    );
    agent.close()?;

    // Rejects an unsupported value.
    let err = match new_agent(AgentConfig {
        network_types: vec![NetworkType::Unspecified],
        ..AgentConfig::default()
    }) {
        Err(err) => err,
        Ok(_) => panic!("expected ErrProtoType"),
    };
    assert_eq!(err, Error::ErrProtoType);

    Ok(())
}

/// pion TestWithCandidateTypesAffectsURLValidation: URLs are only useful when srflx or relay
/// gathering is enabled; host-only candidate types reject them.
#[test]
fn test_with_candidate_types_affects_url_validation() -> Result<()> {
    // Default candidate types (host, srflx, relay) accept URLs.
    let stun_url = crate::url::Url::parse_url("stun:example.com:3478")?;
    let mut agent = new_agent(AgentConfig {
        urls: vec![stun_url],
        ..AgentConfig::default()
    })?;
    agent.close()?;

    // Host-only candidate types reject URLs.
    let stun_url = crate::url::Url::parse_url("stun:example.com:3478")?;
    let err = match new_agent(AgentConfig {
        urls: vec![stun_url],
        candidate_types: vec![CandidateType::Host],
        ..AgentConfig::default()
    }) {
        Err(err) => err,
        Ok(_) => panic!("expected ErrUselessUrlsProvided"),
    };
    assert_eq!(err, Error::ErrUselessUrlsProvided);

    Ok(())
}

use std::str::FromStr;
use stun::message::*;
use stun::textattrs::Username;

use super::*;
use crate::attributes::{
    control::AttrControlling, priority::PriorityAttr, use_candidate::UseCandidateAttr,
};
use crate::candidate::candidate_host::*;
use crate::candidate::candidate_peer_reflexive::*;
use crate::candidate::candidate_relay::CandidateRelayConfig;
use crate::candidate::candidate_server_reflexive::*;
use crate::candidate::*;

#[test]
fn test_pair_search() -> Result<()> {
    let config = AgentConfig::default();
    let mut a = Agent::new(config)?;

    assert!(
        a.candidate_pairs.is_empty(),
        "TestPairSearch is only a valid test if a.validPairs is empty on construction"
    );

    let cp = a.get_best_available_candidate_pair();
    assert!(cp.is_none(), "No Candidate pairs should exist");

    a.close()?;

    Ok(())
}

#[test]
fn test_pair_priority() -> Result<()> {
    let mut a = Agent::new(AgentConfig::default())?;

    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.1".to_owned(),
            port: 19216,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let host_local = host_config.new_candidate_host()?;
    a.local_candidates.push(host_local);

    let relay_config = CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.4".to_owned(),
            port: 12340,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43210,
        ..Default::default()
    };

    let relay_remote = relay_config.new_candidate_relay()?;

    let srflx_config = CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.10.10.2".to_owned(),
            port: 19218,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43212,
    };

    let srflx_remote = srflx_config.new_candidate_server_reflexive()?;

    let prflx_config = CandidatePeerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.10.10.2".to_owned(),
            port: 19217,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43211,
    };

    let prflx_remote = prflx_config.new_candidate_peer_reflexive()?;

    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.5".to_owned(),
            port: 12350,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let host_remote = host_config.new_candidate_host()?;

    let remotes: Vec<Candidate> = vec![relay_remote, srflx_remote, prflx_remote, host_remote];
    for remote in remotes {
        a.remote_candidates.push(remote);
    }

    {
        let local = 0;
        for remote in 0..a.remote_candidates.len() {
            if a.find_pair(local, remote).is_none() {
                a.add_pair(local, remote);
            }

            if let Some(p) = a.find_pair(local, remote) {
                a.candidate_pairs[p].state = CandidatePairState::Succeeded;
            }

            if let Some(best_pair) = a.get_best_available_candidate_pair() {
                assert_eq!(
                    a.candidate_pairs[best_pair].to_string(),
                    CandidatePair::new(
                        local,
                        remote,
                        a.local_candidates[local].priority(),
                        a.remote_candidates[remote].priority(),
                        a.is_controlling,
                    )
                    .to_string(),
                    "Unexpected bestPair {best_pair} (expected remote: {remote})",
                );
            } else {
                panic!("expected Some, but got None");
            }
        }
    }

    a.close()?;
    Ok(())
}

fn pipe(
    default_config0: Option<AgentConfig>,
    default_config1: Option<AgentConfig>,
) -> Result<(Agent, Agent)> {
    let mut cfg0 = if let Some(cfg) = default_config0 {
        cfg
    } else {
        AgentConfig::default()
    };
    cfg0.urls = vec![];

    let a_agent = Agent::new(cfg0)?;

    let mut cfg1 = if let Some(cfg) = default_config1 {
        cfg
    } else {
        AgentConfig::default()
    };
    cfg1.urls = vec![];

    let b_agent = Agent::new(cfg1)?;

    Ok((a_agent, b_agent))
}

#[test]
fn test_on_selected_candidate_pair_change() -> Result<()> {
    let mut a = Agent::new(AgentConfig::default())?;

    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.1".to_owned(),
            port: 19216,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let host_local = host_config.new_candidate_host()?;
    a.add_local_candidate(host_local)?;

    let relay_config = CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.4".to_owned(),
            port: 12340,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43210,
        ..Default::default()
    };
    let relay_remote = relay_config.new_candidate_relay()?;
    a.add_remote_candidate(relay_remote)?;

    // select the pair
    let (local, remote) = (0, 0);
    a.add_pair(local, remote);
    a.set_selected_pair(Some(0));

    // ensure that the callback fired on setting the pair
    let mut is_selected_candidate_pair_change_event_fired = false;
    while let Some(event) = a.poll_event() {
        if let Event::SelectedCandidatePairChange(_, _) = event {
            is_selected_candidate_pair_change_event_fired = true;
        }
    }

    assert!(is_selected_candidate_pair_change_event_fired);

    a.close()?;
    Ok(())
}

#[test]
fn test_handle_peer_reflexive_udp_pflx_candidate() -> Result<()> {
    let mut a = Agent::new(AgentConfig::default())?;

    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };

    let local_candidate = host_config.new_candidate_host()?;
    let local = 0;
    let local_priority = local_candidate.priority();
    let local_network_type = local_candidate.network_type();
    a.add_local_candidate(local_candidate)?;

    let remote_addr = SocketAddr::from_str("172.17.0.3:999")?;

    let (username, local_pwd, tie_breaker) = {
        a.ufrag_pwd.remote_credentials = Some(Credentials {
            ufrag: "".to_string(),
            pwd: "".to_string(),
        });
        (
            a.ufrag_pwd.local_credentials.ufrag.to_owned() + ":",
            a.ufrag_pwd.local_credentials.pwd.clone(),
            a.tie_breaker,
        )
    };

    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(UseCandidateAttr::new()),
        Box::new(AttrControlling(tie_breaker)),
        Box::new(PriorityAttr(local_priority)),
        Box::new(MessageIntegrity::new_short_term_integrity(local_pwd)),
        Box::new(FINGERPRINT),
    ])?;

    {
        a.handle_inbound(&mut msg, local, remote_addr)?;

        // length of remote candidate list must be one now
        assert_eq!(
            a.remote_candidates.len(),
            1,
            "failed to add a network type to the remote candidate list"
        );

        // length of remote candidate list for a network type must be 1
        if let Some(remote_index) = a.find_remote_candidate(remote_addr) {
            let c = &a.remote_candidates[remote_index];

            assert_eq!(
                c.candidate_type(),
                CandidateType::PeerReflexive,
                "candidate type must be prflx"
            );

            assert_eq!(c.address(), "172.17.0.3", "IP address mismatch");

            assert_eq!(c.port(), 999, "Port number mismatch");
        } else {
            assert!(
                false,
                "expected non-empty remote candidate for network type {}",
                local_network_type,
            );
        }
    }

    a.close()?;
    Ok(())
}

#[test]
fn test_handle_peer_reflexive_unknown_remote() -> Result<()> {
    let mut a = Agent::new(AgentConfig::default())?;

    let mut tid = TransactionId::default();
    tid.0[..3].copy_from_slice("ABC".as_bytes());

    let remote_pwd = {
        a.pending_binding_requests = vec![BindingRequest {
            timestamp: Instant::now(),
            transaction_id: tid,
            destination: SocketAddr::from_str("0.0.0.0:0")?,
            is_use_candidate: false,
        }];
        a.ufrag_pwd.remote_credentials = Some(Credentials {
            ufrag: "".to_string(),
            pwd: "".to_string(),
        });
        "".to_string()
    };

    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };

    let local = host_config.new_candidate_host()?;
    let local_index = 0;
    a.add_local_candidate(local)?;
    let remote_addr = SocketAddr::from_str("172.17.0.3:999")?;

    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(tid),
        Box::new(MessageIntegrity::new_short_term_integrity(remote_pwd)),
        Box::new(FINGERPRINT),
    ])?;

    let result = a.handle_inbound(&mut msg, local_index, remote_addr);
    assert!(result.is_err());

    assert_eq!(
        a.remote_candidates.len(),
        0,
        "unknown remote was able to create a candidate"
    );

    a.close()?;
    Ok(())
}

/* TODO:
fn gather_and_exchange_candidates(a_agent: &mut Agent, b_agent: &mut Agent) -> Result<()> {
    let wg = WaitGroup::new();

    let w1 = Arc::new(Mutex::new(Some(wg.worker())));
    a_agent.on_candidate(Box::new(
        move |candidate: Option<Arc<dyn Candidate + Send + Sync>>| {
            let w3 = Arc::clone(&w1);
            Box::pin(async move {
                if candidate.is_none() {
                    let mut w = w3.lock().await;
                    w.take();
                }
            })
        },
    ));
    a_agent.gather_candidates()?;

    let w2 = Arc::new(Mutex::new(Some(wg.worker())));
    b_agent.on_candidate(Box::new(
        move |candidate: Option<Arc<dyn Candidate + Send + Sync>>| {
            let w3 = Arc::clone(&w2);
            Box::pin(async move {
                if candidate.is_none() {
                    let mut w = w3.lock().await;
                    w.take();
                }
            })
        },
    ));
    b_agent.gather_candidates()?;

    wg.wait().await;

    let candidates = a_agent.get_local_candidates().await?;
    for c in candidates {
        let c2: Arc<dyn Candidate + Send + Sync> =
            Arc::new(unmarshal_candidate(c.marshal().as_str())?);
        b_agent.add_remote_candidate(&c2)?;
    }

    let candidates = b_agent.get_local_candidates().await?;
    for c in candidates {
        let c2: Arc<dyn Candidate + Send + Sync> =
            Arc::new(unmarshal_candidate(c.marshal().as_str())?);
        a_agent.add_remote_candidate(&c2)?;
    }

    Ok(())
}

// Assert that Agent on startup sends message, and doesn't wait for connectivityTicker to fire
#[test]
fn test_connectivity_on_startup() -> Result<()> {
    let keepalive_interval = Some(Duration::from_secs(3600)); //time.Hour
    let check_interval = Duration::from_secs(3600); //time.Hour
    let cfg0 = AgentConfig {
        keepalive_interval,
        check_interval,
        ..Default::default()
    };

    let mut a_agent = Agent::new(cfg0)?;

    let cfg1 = AgentConfig {
        keepalive_interval,
        check_interval,
        ..Default::default()
    };

    let mut b_agent = Agent::new(cfg1)?;

    // Manual signaling
    let (a_ufrag, a_pwd) = a_agent.get_local_user_credentials();
    let (b_ufrag, b_pwd) = b_agent.get_local_user_credentials();

    gather_and_exchange_candidates(&mut a_agent, &mut b_agent)?;

    a_agent.on_connection_state_change(Box::new(move |s: ConnectionState| {
        let accepted_tx_clone = Arc::clone(&accepting_tx);
        Box::pin(async move {
            if s == ConnectionState::Checking {
                let mut tx = accepted_tx_clone.lock();
                tx.take();
            }
        })
    }));

    tokio::spawn(async move {
        let result = a_agent.accept(a_cancel_rx, b_ufrag, b_pwd);
        assert!(result.is_ok(), "agent accept expected OK");
        drop(accepted_tx);
    });

    let _ = accepting_rx.recv();

    let _ = b_agent.dial(b_cancel_rx, a_ufrag, a_pwd)?;

    // Ensure accepted
    let _ = accepted_rx.recv();

    Ok(())
}


#[test]
fn test_connectivity_lite() -> Result<()> {
    let stun_server_url = Url {
        scheme: SchemeType::Stun,
        host: "1.2.3.4".to_owned(),
        port: 3478,
        proto: ProtoType::Udp,
        ..Default::default()
    };

    let nat_type = nat::NatType {
        mapping_behavior: nat::EndpointDependencyType::EndpointIndependent,
        filtering_behavior: nat::EndpointDependencyType::EndpointIndependent,
        ..Default::default()
    };

    let v = build_vnet(nat_type, nat_type)?;

    let (a_notifier, mut a_connected) = on_connected();
    let (b_notifier, mut b_connected) = on_connected();

    let cfg0 = AgentConfig {
        urls: vec![stun_server_url],
        network_types: supported_network_types(),
        net: Some(Arc::clone(&v.net0)),
        ..Default::default()
    };

    let a_agent = Arc::new(Agent::new(cfg0)?);
    a_agent.on_connection_state_change(a_notifier);

    let cfg1 = AgentConfig {
        urls: vec![],
        lite: true,
        candidate_types: vec![CandidateType::Host],
        network_types: supported_network_types(),
        net: Some(Arc::clone(&v.net1)),
        ..Default::default()
    };

    let b_agent = Arc::new(Agent::new(cfg1)?);
    b_agent.on_connection_state_change(b_notifier);

    let _ = connect_with_vnet(&a_agent, &b_agent)?;

    // Ensure pair selected
    // Note: this assumes ConnectionStateConnected is thrown after selecting the final pair
    let _ = a_connected.recv();
    let _ = b_connected.recv();

    v.close()?;

    Ok(())
}

struct MockPacketConn;

#[async_trait]
impl Conn for MockPacketConn {
    fn connect(&self, _addr: SocketAddr) -> std::result::Result<(), util::Error> {
        Ok(())
    }

    fn recv(&self, _buf: &mut [u8]) -> std::result::Result<usize, util::Error> {
        Ok(0)
    }

    fn recv_from(&self, _buf: &mut [u8]) -> std::result::Result<(usize, SocketAddr), util::Error> {
        Ok((0, SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0)))
    }

    fn send(&self, _buf: &[u8]) -> std::result::Result<usize, util::Error> {
        Ok(0)
    }

    fn send_to(&self, _buf: &[u8], _target: SocketAddr) -> std::result::Result<usize, util::Error> {
        Ok(0)
    }

    fn local_addr(&self) -> std::result::Result<SocketAddr, util::Error> {
        Ok(SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0))
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }

    fn close(&self) -> std::result::Result<(), util::Error> {
        Ok(())
    }
}

fn build_msg(c: MessageClass, username: String, key: String) -> Result<Message> {
    let mut msg = Message::new();
    msg.build(&[
        Box::new(MessageType::new(METHOD_BINDING, c)),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(MessageIntegrity::new_short_term_integrity(key)),
        Box::new(FINGERPRINT),
    ])?;
    Ok(msg)
}

#[test]
fn test_inbound_validity() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, LevelFilter::Trace)
    .init();*/

    let remote = SocketAddr::from_str("172.17.0.3:999")?;
    let local: Arc<dyn Candidate + Send + Sync> = Arc::new(
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "192.168.0.2".to_owned(),
                port: 777,
                component: 1,
                conn: Some(Arc::new(MockPacketConn {})),
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?,
    );

    //"Invalid Binding requests should be discarded"
    {
        let a = Agent::new(AgentConfig::default())?;

        {
            let local_pwd = {
                let ufrag_pwd = a.internal.ufrag_pwd.lock();
                ufrag_pwd.local_pwd.clone()
            };
            a.internal.handle_inbound(
                &mut build_msg(CLASS_REQUEST, "invalid".to_owned(), local_pwd)?,
                &local,
                remote,
            );
            {
                let remote_candidates = a.internal.remote_candidates.lock();
                assert_ne!(
                    remote_candidates.len(),
                    1,
                    "Binding with invalid Username was able to create prflx candidate"
                );
            }

            let username = {
                let ufrag_pwd = a.internal.ufrag_pwd.lock();
                format!("{}:{}", ufrag_pwd.local_ufrag, ufrag_pwd.remote_ufrag)
            };
            a.internal.handle_inbound(
                &mut build_msg(CLASS_REQUEST, username, "Invalid".to_owned())?,
                &local,
                remote,
            );
            {
                let remote_candidates = a.internal.remote_candidates.lock();
                assert_ne!(
                    remote_candidates.len(),
                    1,
                    "Binding with invalid MessageIntegrity was able to create prflx candidate"
                );
            }
        }

        a.close()?;
    }

    //"Invalid Binding success responses should be discarded"
    {
        let a = Agent::new(AgentConfig::default())?;

        {
            let username = {
                let ufrag_pwd = a.internal.ufrag_pwd.lock();
                format!("{}:{}", ufrag_pwd.local_ufrag, ufrag_pwd.remote_ufrag)
            };
            a.internal.handle_inbound(
                &mut build_msg(CLASS_SUCCESS_RESPONSE, username, "Invalid".to_owned())?,
                &local,
                remote,
            );
            {
                let remote_candidates = a.internal.remote_candidates.lock();
                assert_ne!(
                    remote_candidates.len(),
                    1,
                    "Binding with invalid Username was able to create prflx candidate"
                );
            }
        }

        a.close()?;
    }

    //"Discard non-binding messages"
    {
        let a = Agent::new(AgentConfig::default())?;

        {
            let username = {
                let ufrag_pwd = a.internal.ufrag_pwd.lock();
                format!("{}:{}", ufrag_pwd.local_ufrag, ufrag_pwd.remote_ufrag)
            };
            a.internal.handle_inbound(
                &mut build_msg(CLASS_ERROR_RESPONSE, username, "Invalid".to_owned())?,
                &local,
                remote,
            );
            let remote_candidates = a.internal.remote_candidates.lock();
            assert_ne!(
                remote_candidates.len(),
                1,
                "non-binding message was able to create prflxRemote"
            );
        }

        a.close()?;
    }

    //"Valid bind request"
    {
        let a = Agent::new(AgentConfig::default())?;

        {
            let (username, local_pwd) = {
                let ufrag_pwd = a.internal.ufrag_pwd.lock();
                (
                    format!("{}:{}", ufrag_pwd.local_ufrag, ufrag_pwd.remote_ufrag),
                    ufrag_pwd.local_pwd.clone(),
                )
            };
            a.internal.handle_inbound(
                &mut build_msg(CLASS_REQUEST, username, local_pwd)?,
                &local,
                remote,
            );
            let remote_candidates = a.internal.remote_candidates.lock();
            assert_eq!(
                remote_candidates.len(),
                1,
                "Binding with valid values was unable to create prflx candidate"
            );
        }

        a.close()?;
    }

    //"Valid bind without fingerprint"
    {
        let a = Agent::new(AgentConfig::default())?;

        {
            let (username, local_pwd) = {
                let ufrag_pwd = a.internal.ufrag_pwd.lock();
                (
                    format!("{}:{}", ufrag_pwd.local_ufrag, ufrag_pwd.remote_ufrag),
                    ufrag_pwd.local_pwd.clone(),
                )
            };

            let mut msg = Message::new();
            msg.build(&[
                Box::new(BINDING_REQUEST),
                Box::new(TransactionId::new()),
                Box::new(Username::new(ATTR_USERNAME, username)),
                Box::new(MessageIntegrity::new_short_term_integrity(local_pwd)),
            ])?;

            a.internal.handle_inbound(&mut msg, &local, remote);
            let remote_candidates = a.internal.remote_candidates.lock();
            assert_eq!(
                remote_candidates.len(),
                1,
                "Binding with valid values (but no fingerprint) was unable to create prflx candidate"
            );
        }

        a.close()?;
    }

    //"Success with invalid TransactionID"
    {
        let a = Agent::new(AgentConfig::default())?;

        {
            let remote = SocketAddr::from_str("172.17.0.3:999")?;

            let mut t_id = TransactionId::default();
            t_id.0[..3].copy_from_slice(b"ABC");

            let remote_pwd = {
                let ufrag_pwd = a.internal.ufrag_pwd.lock();
                ufrag_pwd.remote_pwd.clone()
            };

            let mut msg = Message::new();
            msg.build(&[
                Box::new(BINDING_SUCCESS),
                Box::new(t_id),
                Box::new(MessageIntegrity::new_short_term_integrity(remote_pwd)),
                Box::new(FINGERPRINT),
            ])?;

            a.internal.handle_inbound(&mut msg, &local, remote);

            {
                let remote_candidates = a.internal.remote_candidates.lock();
                assert_eq!(
                    remote_candidates.len(),
                    0,
                    "unknown remote was able to create a candidate"
                );
            }
        }

        a.close()?;
    }

    Ok(())
}

#[test]
fn test_invalid_agent_starts() -> Result<()> {
    let a = Agent::new(AgentConfig::default())?;

    let (_cancel_tx1, cancel_rx1) = mpsc::channel(1);
    let result = a.dial(cancel_rx1, "".to_owned(), "bar".to_owned());
    assert!(result.is_err());
    if let Err(err) = result {
        assert_eq!(Error::ErrRemoteUfragEmpty, err);
    }

    let (_cancel_tx2, cancel_rx2) = mpsc::channel(1);
    let result = a.dial(cancel_rx2, "foo".to_owned(), "".to_owned());
    assert!(result.is_err());
    if let Err(err) = result {
        assert_eq!(Error::ErrRemotePwdEmpty, err);
    }

    let (cancel_tx3, cancel_rx3) = mpsc::channel(1);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100));
        drop(cancel_tx3);
    });

    let result = a.dial(cancel_rx3, "foo".to_owned(), "bar".to_owned());
    assert!(result.is_err());
    if let Err(err) = result {
        assert_eq!(Error::ErrCanceledByCaller, err);
    }

    let (_cancel_tx4, cancel_rx4) = mpsc::channel(1);
    let result = a.dial(cancel_rx4, "foo".to_owned(), "bar".to_owned());
    assert!(result.is_err());
    if let Err(err) = result {
        assert_eq!(Error::ErrMultipleStart, err);
    }

    a.close()?;

    Ok(())
}

//use std::io::Write;

// Assert that Agent emits Connecting/Connected/Disconnected/Failed/Closed messages
#[test]
fn test_connection_state_callback() -> Result<()> {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, LevelFilter::Trace)
    .init();*/

    let disconnected_duration = Duration::from_secs(1);
    let failed_duration = Duration::from_secs(1);
    let keepalive_interval = Duration::from_secs(0);

    let cfg0 = AgentConfig {
        urls: vec![],
        network_types: supported_network_types(),
        disconnected_timeout: Some(disconnected_duration),
        failed_timeout: Some(failed_duration),
        keepalive_interval: Some(keepalive_interval),
        ..Default::default()
    };

    let cfg1 = AgentConfig {
        urls: vec![],
        network_types: supported_network_types(),
        disconnected_timeout: Some(disconnected_duration),
        failed_timeout: Some(failed_duration),
        keepalive_interval: Some(keepalive_interval),
        ..Default::default()
    };

    let a_agent = Arc::new(Agent::new(cfg0)?);
    let b_agent = Arc::new(Agent::new(cfg1)?);

    let (is_checking_tx, mut is_checking_rx) = mpsc::channel::<()>(1);
    let (is_connected_tx, mut is_connected_rx) = mpsc::channel::<()>(1);
    let (is_disconnected_tx, mut is_disconnected_rx) = mpsc::channel::<()>(1);
    let (is_failed_tx, mut is_failed_rx) = mpsc::channel::<()>(1);
    let (is_closed_tx, mut is_closed_rx) = mpsc::channel::<()>(1);

    let is_checking_tx = Arc::new(Mutex::new(Some(is_checking_tx)));
    let is_connected_tx = Arc::new(Mutex::new(Some(is_connected_tx)));
    let is_disconnected_tx = Arc::new(Mutex::new(Some(is_disconnected_tx)));
    let is_failed_tx = Arc::new(Mutex::new(Some(is_failed_tx)));
    let is_closed_tx = Arc::new(Mutex::new(Some(is_closed_tx)));

    a_agent.on_connection_state_change(Box::new(move |c: ConnectionState| {
        let is_checking_tx_clone = Arc::clone(&is_checking_tx);
        let is_connected_tx_clone = Arc::clone(&is_connected_tx);
        let is_disconnected_tx_clone = Arc::clone(&is_disconnected_tx);
        let is_failed_tx_clone = Arc::clone(&is_failed_tx);
        let is_closed_tx_clone = Arc::clone(&is_closed_tx);
        Box::pin(async move {
            match c {
                ConnectionState::Checking => {
                    debug!("drop is_checking_tx");
                    let mut tx = is_checking_tx_clone.lock();
                    tx.take();
                }
                ConnectionState::Connected => {
                    debug!("drop is_connected_tx");
                    let mut tx = is_connected_tx_clone.lock();
                    tx.take();
                }
                ConnectionState::Disconnected => {
                    debug!("drop is_disconnected_tx");
                    let mut tx = is_disconnected_tx_clone.lock();
                    tx.take();
                }
                ConnectionState::Failed => {
                    debug!("drop is_failed_tx");
                    let mut tx = is_failed_tx_clone.lock();
                    tx.take();
                }
                ConnectionState::Closed => {
                    debug!("drop is_closed_tx");
                    let mut tx = is_closed_tx_clone.lock();
                    tx.take();
                }
                _ => {}
            };
        })
    }));

    connect_with_vnet(&a_agent, &b_agent)?;

    debug!("wait is_checking_tx");
    let _ = is_checking_rx.recv();
    debug!("wait is_connected_rx");
    let _ = is_connected_rx.recv();
    debug!("wait is_disconnected_rx");
    let _ = is_disconnected_rx.recv();
    debug!("wait is_failed_rx");
    let _ = is_failed_rx.recv();

    a_agent.close()?;
    b_agent.close()?;

    debug!("wait is_closed_rx");
    let _ = is_closed_rx.recv();

    Ok(())
}

#[test]
fn test_invalid_gather() -> Result<()> {
    //"Gather with no OnCandidate should error"
    let a = Agent::new(AgentConfig::default())?;

    if let Err(err) = a.gather_candidates() {
        assert_eq!(
            Error::ErrNoOnCandidateHandler,
            err,
            "trickle GatherCandidates succeeded without OnCandidate"
        );
    }

    a.close()?;

    Ok(())
}

#[test]
fn test_candidate_pair_stats() -> Result<()> {
    let a = Agent::new(AgentConfig::default())?;

    let host_local: Arc<dyn Candidate + Send + Sync> = Arc::new(
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "192.168.1.1".to_owned(),
                port: 19216,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?,
    );

    let relay_remote: Arc<dyn Candidate + Send + Sync> = Arc::new(
        CandidateRelayConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "1.2.3.4".to_owned(),
                port: 2340,
                component: 1,
                ..Default::default()
            },
            rel_addr: "4.3.2.1".to_owned(),
            rel_port: 43210,
            ..Default::default()
        }
        .new_candidate_relay()?,
    );

    let srflx_remote: Arc<dyn Candidate + Send + Sync> = Arc::new(
        CandidateServerReflexiveConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "10.10.10.2".to_owned(),
                port: 19218,
                component: 1,
                ..Default::default()
            },
            rel_addr: "4.3.2.1".to_owned(),
            rel_port: 43212,
        }
        .new_candidate_server_reflexive()?,
    );

    let prflx_remote: Arc<dyn Candidate + Send + Sync> = Arc::new(
        CandidatePeerReflexiveConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "10.10.10.2".to_owned(),
                port: 19217,
                component: 1,
                ..Default::default()
            },
            rel_addr: "4.3.2.1".to_owned(),
            rel_port: 43211,
        }
        .new_candidate_peer_reflexive()?,
    );

    let host_remote: Arc<dyn Candidate + Send + Sync> = Arc::new(
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "1.2.3.5".to_owned(),
                port: 12350,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?,
    );

    for remote in &[
        Arc::clone(&relay_remote),
        Arc::clone(&srflx_remote),
        Arc::clone(&prflx_remote),
        Arc::clone(&host_remote),
    ] {
        let p = a.internal.find_pair(&host_local, remote);

        if p.is_none() {
            a.internal
                .add_pair(Arc::clone(&host_local), Arc::clone(remote));
        }
    }

    {
        if let Some(p) = a.internal.find_pair(&host_local, &prflx_remote) {
            p.state
                .store(CandidatePairState::Failed as u8, Ordering::SeqCst);
        }
    }

    let stats = a.get_candidate_pairs_stats();
    assert_eq!(stats.len(), 4, "expected 4 candidate pairs stats");

    let (mut relay_pair_stat, mut srflx_pair_stat, mut prflx_pair_stat, mut host_pair_stat) = (
        CandidatePairStats::default(),
        CandidatePairStats::default(),
        CandidatePairStats::default(),
        CandidatePairStats::default(),
    );

    for cps in stats {
        assert_eq!(
            cps.local_candidate_id,
            host_local.id(),
            "invalid local candidate id"
        );

        if cps.remote_candidate_id == relay_remote.id() {
            relay_pair_stat = cps;
        } else if cps.remote_candidate_id == srflx_remote.id() {
            srflx_pair_stat = cps;
        } else if cps.remote_candidate_id == prflx_remote.id() {
            prflx_pair_stat = cps;
        } else if cps.remote_candidate_id == host_remote.id() {
            host_pair_stat = cps;
        } else {
            panic!("invalid remote candidate ID");
        }
    }

    assert_eq!(
        relay_pair_stat.remote_candidate_id,
        relay_remote.id(),
        "missing host-relay pair stat"
    );
    assert_eq!(
        srflx_pair_stat.remote_candidate_id,
        srflx_remote.id(),
        "missing host-srflx pair stat"
    );
    assert_eq!(
        prflx_pair_stat.remote_candidate_id,
        prflx_remote.id(),
        "missing host-prflx pair stat"
    );
    assert_eq!(
        host_pair_stat.remote_candidate_id,
        host_remote.id(),
        "missing host-host pair stat"
    );
    assert_eq!(
        prflx_pair_stat.state,
        CandidatePairState::Failed,
        "expected host-prfflx pair to have state failed, it has state {} instead",
        prflx_pair_stat.state
    );

    a.close()?;

    Ok(())
}

#[test]
fn test_local_candidate_stats() -> Result<()> {
    let a = Agent::new(AgentConfig::default())?;

    let host_local: Arc<dyn Candidate + Send + Sync> = Arc::new(
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "192.168.1.1".to_owned(),
                port: 19216,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?,
    );

    let srflx_local: Arc<dyn Candidate + Send + Sync> = Arc::new(
        CandidateServerReflexiveConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "192.168.1.1".to_owned(),
                port: 19217,
                component: 1,
                ..Default::default()
            },
            rel_addr: "4.3.2.1".to_owned(),
            rel_port: 43212,
        }
        .new_candidate_server_reflexive()?,
    );

    {
        let mut local_candidates = a.internal.local_candidates.lock();
        local_candidates.insert(
            NetworkType::Udp4,
            vec![Arc::clone(&host_local), Arc::clone(&srflx_local)],
        );
    }

    let local_stats = a.get_local_candidates_stats();
    assert_eq!(
        local_stats.len(),
        2,
        "expected 2 local candidates stats, got {} instead",
        local_stats.len()
    );

    let (mut host_local_stat, mut srflx_local_stat) =
        (CandidateStats::default(), CandidateStats::default());
    for stats in local_stats {
        let candidate = if stats.id == host_local.id() {
            host_local_stat = stats.clone();
            Arc::clone(&host_local)
        } else if stats.id == srflx_local.id() {
            srflx_local_stat = stats.clone();
            Arc::clone(&srflx_local)
        } else {
            panic!("invalid local candidate ID");
        };

        assert_eq!(
            stats.candidate_type,
            candidate.candidate_type(),
            "invalid stats CandidateType"
        );
        assert_eq!(
            stats.priority,
            candidate.priority(),
            "invalid stats CandidateType"
        );
        assert_eq!(stats.ip, candidate.address(), "invalid stats IP");
    }

    assert_eq!(
        host_local_stat.id,
        host_local.id(),
        "missing host local stat"
    );
    assert_eq!(
        srflx_local_stat.id,
        srflx_local.id(),
        "missing srflx local stat"
    );

    a.close()?;

    Ok(())
}

#[test]
fn test_remote_candidate_stats() -> Result<()> {
    let a = Agent::new(AgentConfig::default())?;

    let relay_remote: Arc<dyn Candidate + Send + Sync> = Arc::new(
        CandidateRelayConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "1.2.3.4".to_owned(),
                port: 12340,
                component: 1,
                ..Default::default()
            },
            rel_addr: "4.3.2.1".to_owned(),
            rel_port: 43210,
            ..Default::default()
        }
        .new_candidate_relay()?,
    );

    let srflx_remote: Arc<dyn Candidate + Send + Sync> = Arc::new(
        CandidateServerReflexiveConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "10.10.10.2".to_owned(),
                port: 19218,
                component: 1,
                ..Default::default()
            },
            rel_addr: "4.3.2.1".to_owned(),
            rel_port: 43212,
        }
        .new_candidate_server_reflexive()?,
    );

    let prflx_remote: Arc<dyn Candidate + Send + Sync> = Arc::new(
        CandidatePeerReflexiveConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "10.10.10.2".to_owned(),
                port: 19217,
                component: 1,
                ..Default::default()
            },
            rel_addr: "4.3.2.1".to_owned(),
            rel_port: 43211,
        }
        .new_candidate_peer_reflexive()?,
    );

    let host_remote: Arc<dyn Candidate + Send + Sync> = Arc::new(
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "1.2.3.5".to_owned(),
                port: 12350,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?,
    );

    {
        let mut remote_candidates = a.internal.remote_candidates.lock();
        remote_candidates.insert(
            NetworkType::Udp4,
            vec![
                Arc::clone(&relay_remote),
                Arc::clone(&srflx_remote),
                Arc::clone(&prflx_remote),
                Arc::clone(&host_remote),
            ],
        );
    }

    let remote_stats = a.get_remote_candidates_stats();
    assert_eq!(
        remote_stats.len(),
        4,
        "expected 4 remote candidates stats, got {} instead",
        remote_stats.len()
    );

    let (mut relay_remote_stat, mut srflx_remote_stat, mut prflx_remote_stat, mut host_remote_stat) = (
        CandidateStats::default(),
        CandidateStats::default(),
        CandidateStats::default(),
        CandidateStats::default(),
    );
    for stats in remote_stats {
        let candidate = if stats.id == relay_remote.id() {
            relay_remote_stat = stats.clone();
            Arc::clone(&relay_remote)
        } else if stats.id == srflx_remote.id() {
            srflx_remote_stat = stats.clone();
            Arc::clone(&srflx_remote)
        } else if stats.id == prflx_remote.id() {
            prflx_remote_stat = stats.clone();
            Arc::clone(&prflx_remote)
        } else if stats.id == host_remote.id() {
            host_remote_stat = stats.clone();
            Arc::clone(&host_remote)
        } else {
            panic!("invalid remote candidate ID");
        };

        assert_eq!(
            stats.candidate_type,
            candidate.candidate_type(),
            "invalid stats CandidateType"
        );
        assert_eq!(
            stats.priority,
            candidate.priority(),
            "invalid stats CandidateType"
        );
        assert_eq!(stats.ip, candidate.address(), "invalid stats IP");
    }

    assert_eq!(
        relay_remote_stat.id,
        relay_remote.id(),
        "missing relay remote stat"
    );
    assert_eq!(
        srflx_remote_stat.id,
        srflx_remote.id(),
        "missing srflx remote stat"
    );
    assert_eq!(
        prflx_remote_stat.id,
        prflx_remote.id(),
        "missing prflx remote stat"
    );
    assert_eq!(
        host_remote_stat.id,
        host_remote.id(),
        "missing host remote stat"
    );

    a.close()?;

    Ok(())
}

#[test]
fn test_binding_request_timeout() -> Result<()> {
    const EXPECTED_REMOVAL_COUNT: usize = 2;

    let a = Agent::new(AgentConfig::default())?;

    let now = Instant::now();
    {
        {
            let mut pending_binding_requests = a.internal.pending_binding_requests.lock();
            pending_binding_requests.push(BindingRequest {
                timestamp: now, // valid
                ..Default::default()
            });
            pending_binding_requests.push(BindingRequest {
                timestamp: now.sub(Duration::from_millis(3900)), // valid
                ..Default::default()
            });
            pending_binding_requests.push(BindingRequest {
                timestamp: now.sub(Duration::from_millis(4100)), // invalid
                ..Default::default()
            });
            pending_binding_requests.push(BindingRequest {
                timestamp: now.sub(Duration::from_secs(75)), // invalid
                ..Default::default()
            });
        }

        a.internal.invalidate_pending_binding_requests(now);
        {
            let pending_binding_requests = a.internal.pending_binding_requests.lock();
            assert_eq!(pending_binding_requests.len(), EXPECTED_REMOVAL_COUNT, "Binding invalidation due to timeout did not remove the correct number of binding requests")
        }
    }

    a.close()?;

    Ok(())
}

// test_agent_credentials checks if local username fragments and passwords (if set) meet RFC standard
// and ensure it's backwards compatible with previous versions of the pion/ice
#[test]
fn test_agent_credentials() -> Result<()> {
    // Agent should not require any of the usernames and password to be set
    // If set, they should follow the default 16/128 bits random number generator strategy

    let a = Agent::new(AgentConfig::default())?;
    {
        let ufrag_pwd = a.internal.ufrag_pwd.lock();
        assert!(ufrag_pwd.local_ufrag.as_bytes().len() * 8 >= 24);
        assert!(ufrag_pwd.local_pwd.as_bytes().len() * 8 >= 128);
    }
    a.close()?;

    // Should honor RFC standards
    // Local values MUST be unguessable, with at least 128 bits of
    // random number generator output used to generate the password, and
    // at least 24 bits of output to generate the username fragment.

    if let Err(err) = Agent::new(AgentConfig {
        local_ufrag: "xx".to_owned(),
        ..Default::default()
    }) {
        assert_eq!(Error::ErrLocalUfragInsufficientBits, err);
    } else {
        panic!("expected error, but got ok");
    }

    if let Err(err) = Agent::new(AgentConfig {
        local_pwd: "xxxxxx".to_owned(),
        ..Default::default()
    }) {
        assert_eq!(Error::ErrLocalPwdInsufficientBits, err);
    } else {
        panic!("expected error, but got ok");
    }

    Ok(())
}

// Assert that Agent on Failure deletes all existing candidates
// User can then do an ICE Restart to bring agent back
#[test]
fn test_connection_state_failed_delete_all_candidates() -> Result<()> {
    let one_second = Duration::from_secs(1);
    let keepalive_interval = Duration::from_secs(0);

    let cfg0 = AgentConfig {
        network_types: supported_network_types(),
        disconnected_timeout: Some(one_second),
        failed_timeout: Some(one_second),
        keepalive_interval: Some(keepalive_interval),
        ..Default::default()
    };
    let cfg1 = AgentConfig {
        network_types: supported_network_types(),
        disconnected_timeout: Some(one_second),
        failed_timeout: Some(one_second),
        keepalive_interval: Some(keepalive_interval),
        ..Default::default()
    };

    let a_agent = Arc::new(Agent::new(cfg0)?);
    let b_agent = Arc::new(Agent::new(cfg1)?);

    let (is_failed_tx, mut is_failed_rx) = mpsc::channel::<()>(1);
    let is_failed_tx = Arc::new(Mutex::new(Some(is_failed_tx)));
    a_agent.on_connection_state_change(Box::new(move |c: ConnectionState| {
        let is_failed_tx_clone = Arc::clone(&is_failed_tx);
        Box::pin(async move {
            if c == ConnectionState::Failed {
                let mut tx = is_failed_tx_clone.lock();
                tx.take();
            }
        })
    }));

    connect_with_vnet(&a_agent, &b_agent)?;
    let _ = is_failed_rx.recv();

    {
        {
            let remote_candidates = a_agent.internal.remote_candidates.lock();
            assert_eq!(remote_candidates.len(), 0);
        }
        {
            let local_candidates = a_agent.internal.local_candidates.lock();
            assert_eq!(local_candidates.len(), 0);
        }
    }

    a_agent.close()?;
    b_agent.close()?;

    Ok(())
}

// Assert that the ICE Agent can go directly from Connecting -> Failed on both sides
#[test]
fn test_connection_state_connecting_to_failed() -> Result<()> {
    let one_second = Duration::from_secs(1);
    let keepalive_interval = Duration::from_secs(0);

    let cfg0 = AgentConfig {
        disconnected_timeout: Some(one_second),
        failed_timeout: Some(one_second),
        keepalive_interval: Some(keepalive_interval),
        ..Default::default()
    };
    let cfg1 = AgentConfig {
        disconnected_timeout: Some(one_second),
        failed_timeout: Some(one_second),
        keepalive_interval: Some(keepalive_interval),
        ..Default::default()
    };

    let a_agent = Arc::new(Agent::new(cfg0)?);
    let b_agent = Arc::new(Agent::new(cfg1)?);

    let is_failed = WaitGroup::new();
    let is_checking = WaitGroup::new();

    let connection_state_check = move |wf: Worker, wc: Worker| {
        let wf = Arc::new(Mutex::new(Some(wf)));
        let wc = Arc::new(Mutex::new(Some(wc)));
        let hdlr_fn: OnConnectionStateChangeHdlrFn = Box::new(move |c: ConnectionState| {
            let wf_clone = Arc::clone(&wf);
            let wc_clone = Arc::clone(&wc);
            Box::pin(async move {
                if c == ConnectionState::Failed {
                    let mut f = wf_clone.lock();
                    f.take();
                } else if c == ConnectionState::Checking {
                    let mut c = wc_clone.lock();
                    c.take();
                } else if c == ConnectionState::Connected || c == ConnectionState::Completed {
                    panic!("Unexpected ConnectionState: {c}");
                }
            })
        });
        hdlr_fn
    };

    let (wf1, wc1) = (is_failed.worker(), is_checking.worker());
    a_agent.on_connection_state_change(connection_state_check(wf1, wc1));

    let (wf2, wc2) = (is_failed.worker(), is_checking.worker());
    b_agent.on_connection_state_change(connection_state_check(wf2, wc2));

    let agent_a = Arc::clone(&a_agent);
    tokio::spawn(async move {
        let (_cancel_tx, cancel_rx) = mpsc::channel(1);
        let result = agent_a.accept(cancel_rx, "InvalidFrag".to_owned(), "InvalidPwd".to_owned());
        assert!(result.is_err());
    });

    let agent_b = Arc::clone(&b_agent);
    tokio::spawn(async move {
        let (_cancel_tx, cancel_rx) = mpsc::channel(1);
        let result = agent_b.dial(cancel_rx, "InvalidFrag".to_owned(), "InvalidPwd".to_owned());
        assert!(result.is_err());
    });

    is_checking.wait();
    is_failed.wait();

    a_agent.close()?;
    b_agent.close()?;

    Ok(())
}

#[test]
fn test_agent_restart_during_gather() -> Result<()> {
    //"Restart During Gather"

    let agent = Agent::new(AgentConfig::default())?;

    agent
        .gathering_state
        .store(GatheringState::Gathering as u8, Ordering::SeqCst);

    if let Err(err) = agent.restart("".to_owned(), "".to_owned()) {
        assert_eq!(Error::ErrRestartWhenGathering, err);
    } else {
        panic!("expected error, but got ok");
    }

    agent.close()?;

    Ok(())
}

#[test]
fn test_agent_restart_when_closed() -> Result<()> {
    //"Restart When Closed"

    let agent = Agent::new(AgentConfig::default())?;
    agent.close()?;

    if let Err(err) = agent.restart("".to_owned(), "".to_owned()) {
        assert_eq!(Error::ErrClosed, err);
    } else {
        panic!("expected error, but got ok");
    }

    Ok(())
}

#[test]
fn test_agent_restart_one_side() -> Result<()> {
    let one_second = Duration::from_secs(1);

    //"Restart One Side"
    let (_, _, agent_a, agent_b) = pipe(
        Some(AgentConfig {
            disconnected_timeout: Some(one_second),
            failed_timeout: Some(one_second),
            ..Default::default()
        }),
        Some(AgentConfig {
            disconnected_timeout: Some(one_second),
            failed_timeout: Some(one_second),
            ..Default::default()
        }),
    )?;

    let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);
    let cancel_tx = Arc::new(Mutex::new(Some(cancel_tx)));
    agent_b.on_connection_state_change(Box::new(move |c: ConnectionState| {
        let cancel_tx_clone = Arc::clone(&cancel_tx);
        Box::pin(async move {
            if c == ConnectionState::Failed || c == ConnectionState::Disconnected {
                let mut tx = cancel_tx_clone.lock();
                tx.take();
            }
        })
    }));

    agent_a.restart("".to_owned(), "".to_owned())?;

    let _ = cancel_rx.recv();

    agent_a.close()?;
    agent_b.close()?;

    Ok(())
}

#[test]
fn test_agent_restart_both_side() -> Result<()> {
    let one_second = Duration::from_secs(1);
    //"Restart Both Sides"

    // Get all addresses of candidates concatenated
    let generate_candidate_address_strings =
        |res: Result<Vec<Arc<dyn Candidate + Send + Sync>>>| -> String {
            assert!(res.is_ok());

            let mut out = String::new();
            if let Ok(candidates) = res {
                for c in candidates {
                    out += c.address().as_str();
                    out += ":";
                    out += c.port().to_string().as_str();
                }
            }
            out
        };

    // Store the original candidates, confirm that after we reconnect we have new pairs
    let (_, _, agent_a, agent_b) = pipe(
        Some(AgentConfig {
            disconnected_timeout: Some(one_second),
            failed_timeout: Some(one_second),
            ..Default::default()
        }),
        Some(AgentConfig {
            disconnected_timeout: Some(one_second),
            failed_timeout: Some(one_second),
            ..Default::default()
        }),
    )?;

    let conn_afirst_candidates = generate_candidate_address_strings(agent_a.get_local_candidates());
    let conn_bfirst_candidates = generate_candidate_address_strings(agent_b.get_local_candidates());

    let (a_notifier, mut a_connected) = on_connected();
    agent_a.on_connection_state_change(a_notifier);

    let (b_notifier, mut b_connected) = on_connected();
    agent_b.on_connection_state_change(b_notifier);

    // Restart and Re-Signal
    agent_a.restart("".to_owned(), "".to_owned())?;
    agent_b.restart("".to_owned(), "".to_owned())?;

    // Exchange Candidates and Credentials
    let (ufrag, pwd) = agent_b.get_local_user_credentials();
    agent_a.set_remote_credentials(ufrag, pwd)?;

    let (ufrag, pwd) = agent_a.get_local_user_credentials();
    agent_b.set_remote_credentials(ufrag, pwd)?;

    gather_and_exchange_candidates(&agent_a, &agent_b)?;

    // Wait until both have gone back to connected
    let _ = a_connected.recv();
    let _ = b_connected.recv();

    // Assert that we have new candiates each time
    assert_ne!(
        conn_afirst_candidates,
        generate_candidate_address_strings(agent_a.get_local_candidates())
    );
    assert_ne!(
        conn_bfirst_candidates,
        generate_candidate_address_strings(agent_b.get_local_candidates())
    );

    agent_a.close()?;
    agent_b.close()?;

    Ok(())
}

#[test]
fn test_get_remote_credentials() -> Result<()> {
    let a = Agent::new(AgentConfig::default())?;

    let (remote_ufrag, remote_pwd) = {
        let mut ufrag_pwd = a.internal.ufrag_pwd.lock();
        ufrag_pwd.remote_ufrag = "remoteUfrag".to_owned();
        ufrag_pwd.remote_pwd = "remotePwd".to_owned();
        (
            ufrag_pwd.remote_ufrag.to_owned(),
            ufrag_pwd.remote_pwd.to_owned(),
        )
    };

    let (actual_ufrag, actual_pwd) = a.get_remote_user_credentials();

    assert_eq!(actual_ufrag, remote_ufrag);
    assert_eq!(actual_pwd, remote_pwd);

    a.close()?;

    Ok(())
}

#[test]
fn test_close_in_connection_state_callback() -> Result<()> {
    let disconnected_duration = Duration::from_secs(1);
    let failed_duration = Duration::from_secs(1);
    let keepalive_interval = Duration::from_secs(0);

    let cfg0 = AgentConfig {
        urls: vec![],
        network_types: supported_network_types(),
        disconnected_timeout: Some(disconnected_duration),
        failed_timeout: Some(failed_duration),
        keepalive_interval: Some(keepalive_interval),
        check_interval: Duration::from_millis(500),
        ..Default::default()
    };

    let cfg1 = AgentConfig {
        urls: vec![],
        network_types: supported_network_types(),
        disconnected_timeout: Some(disconnected_duration),
        failed_timeout: Some(failed_duration),
        keepalive_interval: Some(keepalive_interval),
        check_interval: Duration::from_millis(500),
        ..Default::default()
    };

    let a_agent = Arc::new(Agent::new(cfg0)?);
    let b_agent = Arc::new(Agent::new(cfg1)?);

    let (is_closed_tx, mut is_closed_rx) = mpsc::channel::<()>(1);
    let (is_connected_tx, mut is_connected_rx) = mpsc::channel::<()>(1);
    let is_closed_tx = Arc::new(Mutex::new(Some(is_closed_tx)));
    let is_connected_tx = Arc::new(Mutex::new(Some(is_connected_tx)));
    a_agent.on_connection_state_change(Box::new(move |c: ConnectionState| {
        let is_closed_tx_clone = Arc::clone(&is_closed_tx);
        let is_connected_tx_clone = Arc::clone(&is_connected_tx);
        Box::pin(async move {
            if c == ConnectionState::Connected {
                let mut tx = is_connected_tx_clone.lock();
                tx.take();
            } else if c == ConnectionState::Closed {
                let mut tx = is_closed_tx_clone.lock();
                tx.take();
            }
        })
    }));

    connect_with_vnet(&a_agent, &b_agent)?;

    let _ = is_connected_rx.recv();
    a_agent.close()?;

    let _ = is_closed_rx.recv();
    b_agent.close()?;

    Ok(())
}

#[test]
fn test_run_task_in_connection_state_callback() -> Result<()> {
    let one_second = Duration::from_secs(1);
    let keepalive_interval = Duration::from_secs(0);

    let cfg0 = AgentConfig {
        urls: vec![],
        network_types: supported_network_types(),
        disconnected_timeout: Some(one_second),
        failed_timeout: Some(one_second),
        keepalive_interval: Some(keepalive_interval),
        check_interval: Duration::from_millis(50),
        ..Default::default()
    };

    let cfg1 = AgentConfig {
        urls: vec![],
        network_types: supported_network_types(),
        disconnected_timeout: Some(one_second),
        failed_timeout: Some(one_second),
        keepalive_interval: Some(keepalive_interval),
        check_interval: Duration::from_millis(50),
        ..Default::default()
    };

    let a_agent = Arc::new(Agent::new(cfg0)?);
    let b_agent = Arc::new(Agent::new(cfg1)?);

    let (is_complete_tx, mut is_complete_rx) = mpsc::channel::<()>(1);
    let is_complete_tx = Arc::new(Mutex::new(Some(is_complete_tx)));
    a_agent.on_connection_state_change(Box::new(move |c: ConnectionState| {
        let is_complete_tx_clone = Arc::clone(&is_complete_tx);
        Box::pin(async move {
            if c == ConnectionState::Connected {
                let mut tx = is_complete_tx_clone.lock();
                tx.take();
            }
        })
    }));

    connect_with_vnet(&a_agent, &b_agent)?;

    let _ = is_complete_rx.recv();
    let _ = a_agent.get_local_user_credentials();
    a_agent.restart("".to_owned(), "".to_owned())?;

    a_agent.close()?;
    b_agent.close()?;

    Ok(())
}

#[test]
fn test_run_task_in_selected_candidate_pair_change_callback() -> Result<()> {
    let one_second = Duration::from_secs(1);
    let keepalive_interval = Duration::from_secs(0);

    let cfg0 = AgentConfig {
        urls: vec![],
        network_types: supported_network_types(),
        disconnected_timeout: Some(one_second),
        failed_timeout: Some(one_second),
        keepalive_interval: Some(keepalive_interval),
        check_interval: Duration::from_millis(50),
        ..Default::default()
    };

    let cfg1 = AgentConfig {
        urls: vec![],
        network_types: supported_network_types(),
        disconnected_timeout: Some(one_second),
        failed_timeout: Some(one_second),
        keepalive_interval: Some(keepalive_interval),
        check_interval: Duration::from_millis(50),
        ..Default::default()
    };

    let a_agent = Arc::new(Agent::new(cfg0)?);
    let b_agent = Arc::new(Agent::new(cfg1)?);

    let (is_tested_tx, mut is_tested_rx) = mpsc::channel::<()>(1);
    let is_tested_tx = Arc::new(Mutex::new(Some(is_tested_tx)));
    a_agent.on_selected_candidate_pair_change(Box::new(
        move |_: &Arc<dyn Candidate + Send + Sync>, _: &Arc<dyn Candidate + Send + Sync>| {
            let is_tested_tx_clone = Arc::clone(&is_tested_tx);
            Box::pin(async move {
                let mut tx = is_tested_tx_clone.lock();
                tx.take();
            })
        },
    ));

    let (is_complete_tx, mut is_complete_rx) = mpsc::channel::<()>(1);
    let is_complete_tx = Arc::new(Mutex::new(Some(is_complete_tx)));
    a_agent.on_connection_state_change(Box::new(move |c: ConnectionState| {
        let is_complete_tx_clone = Arc::clone(&is_complete_tx);
        Box::pin(async move {
            if c == ConnectionState::Connected {
                let mut tx = is_complete_tx_clone.lock();
                tx.take();
            }
        })
    }));

    connect_with_vnet(&a_agent, &b_agent)?;

    let _ = is_complete_rx.recv();
    let _ = is_tested_rx.recv();

    let _ = a_agent.get_local_user_credentials();

    a_agent.close()?;
    b_agent.close()?;

    Ok(())
}

// Assert that a Lite agent goes to disconnected and failed
#[test]
fn test_lite_lifecycle() -> Result<()> {
    let (a_notifier, mut a_connected_rx) = on_connected();

    let a_agent = Arc::new(Agent::new(AgentConfig {
        network_types: supported_network_types(),
        ..Default::default()
    })?);

    a_agent.on_connection_state_change(a_notifier);

    let disconnected_duration = Duration::from_secs(1);
    let failed_duration = Duration::from_secs(1);
    let keepalive_interval = Duration::from_secs(0);

    let b_agent = Arc::new(Agent::new(AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        network_types: supported_network_types(),
        disconnected_timeout: Some(disconnected_duration),
        failed_timeout: Some(failed_duration),
        keepalive_interval: Some(keepalive_interval),
        check_interval: Duration::from_millis(500),
        ..Default::default()
    })?);

    let (b_connected_tx, mut b_connected_rx) = mpsc::channel::<()>(1);
    let (b_disconnected_tx, mut b_disconnected_rx) = mpsc::channel::<()>(1);
    let (b_failed_tx, mut b_failed_rx) = mpsc::channel::<()>(1);
    let b_connected_tx = Arc::new(Mutex::new(Some(b_connected_tx)));
    let b_disconnected_tx = Arc::new(Mutex::new(Some(b_disconnected_tx)));
    let b_failed_tx = Arc::new(Mutex::new(Some(b_failed_tx)));

    b_agent.on_connection_state_change(Box::new(move |c: ConnectionState| {
        let b_connected_tx_clone = Arc::clone(&b_connected_tx);
        let b_disconnected_tx_clone = Arc::clone(&b_disconnected_tx);
        let b_failed_tx_clone = Arc::clone(&b_failed_tx);

        Box::pin(async move {
            if c == ConnectionState::Connected {
                let mut tx = b_connected_tx_clone.lock();
                tx.take();
            } else if c == ConnectionState::Disconnected {
                let mut tx = b_disconnected_tx_clone.lock();
                tx.take();
            } else if c == ConnectionState::Failed {
                let mut tx = b_failed_tx_clone.lock();
                tx.take();
            }
        })
    }));

    connect_with_vnet(&b_agent, &a_agent)?;

    let _ = a_connected_rx.recv();
    let _ = b_connected_rx.recv();
    a_agent.close()?;

    let _ = b_disconnected_rx.recv();
    let _ = b_failed_rx.recv();

    b_agent.close()?;

    Ok(())
}
*/

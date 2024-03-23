use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use ice::agent::Agent;
use ice::url::Url;
use ice::Credentials;

use crate::api::setting_engine::SettingEngine;
use crate::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use crate::stats::stats_collector::StatsCollector;
use crate::stats::SourceStatsType::*;
use crate::stats::{ICECandidatePairStats, StatsReportType};
use crate::transports::ice_transport::ice_candidate::*;
use crate::transports::ice_transport::ice_gatherer_state::RTCIceGathererState;
use crate::transports::ice_transport::ice_parameters::RTCIceParameters;
use crate::transports::ice_transport::ice_server::RTCIceServer;
use shared::error::{Error, Result};

/// ICEGatherOptions provides options relating to the gathering of ICE candidates.
#[derive(Default, Debug, Clone)]
pub struct RTCIceGatherOptions {
    pub ice_servers: Vec<RTCIceServer>,
    pub ice_gather_policy: RTCIceTransportPolicy,
}

pub enum IceGathererEvent {
    OnLocalCandidate(RTCIceCandidate),
    OnICEGathererState(RTCIceGathererState),
    OnGatheringComplete,
}

/// ICEGatherer gathers local host, server reflexive and relay
/// candidates, as well as enabling the retrieval of local Interactive
/// Connectivity Establishment (ICE) parameters which can be
/// exchanged in signaling.
#[derive(Default)]
pub struct RTCIceGatherer {
    pub(crate) validated_servers: Vec<Url>,
    pub(crate) gather_policy: RTCIceTransportPolicy,
    pub(crate) setting_engine: Arc<SettingEngine>,

    pub(crate) state: RTCIceGathererState,
    pub(crate) events: VecDeque<IceGathererEvent>,

    pub(crate) agent: Option<Agent>,
}

impl RTCIceGatherer {
    pub(crate) fn new(
        validated_servers: Vec<Url>,
        gather_policy: RTCIceTransportPolicy,
        setting_engine: Arc<SettingEngine>,
    ) -> Self {
        RTCIceGatherer {
            gather_policy,
            validated_servers,
            setting_engine,

            state: RTCIceGathererState::New,
            events: VecDeque::new(),

            agent: None,
        }
    }

    pub(crate) fn create_agent(&mut self) -> Result<()> {
        if self.agent.is_some() || self.state() != RTCIceGathererState::New {
            return Ok(());
        }

        let mut candidate_types = vec![];
        if self.setting_engine.candidates.ice_lite {
            candidate_types.push(ice::candidate::CandidateType::Host);
        } else if self.gather_policy == RTCIceTransportPolicy::Relay {
            candidate_types.push(ice::candidate::CandidateType::Relay);
        }

        /*let nat_1to1_cand_type = match self.setting_engine.candidates.nat_1to1_ip_candidate_type {
            RTCIceCandidateType::Host => CandidateType::Host,
            RTCIceCandidateType::Srflx => CandidateType::ServerReflexive,
            _ => CandidateType::Unspecified,
        };*/

        //TOOD: let mdns_mode = self.setting_engine.candidates.multicast_dns_mode;

        let config = ice::agent::agent_config::AgentConfig {
            //TODO: udp_network: self.setting_engine.udp_network.clone(),
            lite: self.setting_engine.candidates.ice_lite,
            urls: self.validated_servers.clone(),
            disconnected_timeout: self.setting_engine.timeout.ice_disconnected_timeout,
            failed_timeout: self.setting_engine.timeout.ice_failed_timeout,
            keepalive_interval: self.setting_engine.timeout.ice_keepalive_interval,
            candidate_types,
            host_acceptance_min_wait: self.setting_engine.timeout.ice_host_acceptance_min_wait,
            srflx_acceptance_min_wait: self.setting_engine.timeout.ice_srflx_acceptance_min_wait,
            prflx_acceptance_min_wait: self.setting_engine.timeout.ice_prflx_acceptance_min_wait,
            relay_acceptance_min_wait: self.setting_engine.timeout.ice_relay_acceptance_min_wait,
            /*TODO: interface_filter: self.setting_engine.candidates.interface_filter.clone(),
            ip_filter: self.setting_engine.candidates.ip_filter.clone(),
            nat_1to1_ips: self.setting_engine.candidates.nat_1to1_ips.clone(),
            nat_1to1_ip_candidate_type: nat_1to1_cand_type,
            net: self.setting_engine.vnet.clone(),
            multicast_dns_mode: mdns_mode,
            multicast_dns_host_name: self
                .setting_engine
                .candidates
                .multicast_dns_host_name
                .clone(),*/
            local_ufrag: self.setting_engine.candidates.username_fragment.clone(),
            local_pwd: self.setting_engine.candidates.password.clone(),
            ..Default::default()
        };

        /*TODO: let requested_network_types = if self.setting_engine.candidates.ice_network_types.is_empty()
        {
            ice::network_type::supported_network_types()
        } else {
            self.setting_engine.candidates.ice_network_types.clone()
        };

        config.network_types.extend(requested_network_types);*/

        self.agent = Some(Agent::new(config)?);

        Ok(())
    }

    /*TODO:/// Gather ICE candidates.
    pub fn gather(&self) -> Result<()> {
        self.create_agent().await?;
        self.set_state(RTCIceGathererState::Gathering).await;

        if let Some(agent) = self.get_agent().await {
            let state = Arc::clone(&self.state);
            let on_local_candidate_handler = Arc::clone(&self.on_local_candidate_handler);
            let on_state_change_handler = Arc::clone(&self.on_state_change_handler);
            let on_gathering_complete_handler = Arc::clone(&self.on_gathering_complete_handler);

            agent.on_candidate(Box::new(
                move |candidate: Option<Arc<dyn Candidate + Send + Sync>>| {
                    let state_clone = Arc::clone(&state);
                    let on_local_candidate_handler_clone = Arc::clone(&on_local_candidate_handler);
                    let on_state_change_handler_clone = Arc::clone(&on_state_change_handler);
                    let on_gathering_complete_handler_clone =
                        Arc::clone(&on_gathering_complete_handler);

                    Box::pin(async move {
                        if let Some(cand) = candidate {
                            if let Some(handler) = &*on_local_candidate_handler_clone.load() {
                                let mut f = handler.lock().await;
                                f(Some(RTCIceCandidate::from(&cand))).await;
                            }
                        } else {
                            state_clone
                                .store(RTCIceGathererState::Complete as u8, Ordering::SeqCst);

                            if let Some(handler) = &*on_state_change_handler_clone.load() {
                                let mut f = handler.lock().await;
                                f(RTCIceGathererState::Complete).await;
                            }

                            if let Some(handler) = &*on_gathering_complete_handler_clone.load() {
                                let mut f = handler.lock().await;
                                f().await;
                            }

                            if let Some(handler) = &*on_local_candidate_handler_clone.load() {
                                let mut f = handler.lock().await;
                                f(None).await;
                            }
                        }
                    })
                },
            ));

            agent.gather_candidates()?;
        }
        Ok(())
    }*/

    /// Close prunes all local candidates, and closes the ports.
    pub fn close(&mut self) -> Result<()> {
        self.set_state(RTCIceGathererState::Closed);
        if let Some(mut agent) = self.agent.take() {
            agent.close()?;
        }
        Ok(())
    }

    /// get_local_parameters returns the ICE parameters of the ICEGatherer.
    pub fn get_local_parameters(&mut self) -> Result<RTCIceParameters> {
        self.create_agent()?;

        let Credentials { ufrag, pwd } = if let Some(agent) = self.get_agent() {
            agent.get_local_credentials()
        } else {
            return Err(Error::ErrICEAgentNotExist);
        };

        Ok(RTCIceParameters {
            username_fragment: ufrag.to_string(),
            password: pwd.to_string(),
            ice_lite: false,
        })
    }

    /// get_local_candidates returns the sequence of valid local candidates associated with the ICEGatherer.
    pub fn get_local_candidates(&mut self) -> Result<Vec<RTCIceCandidate>> {
        self.create_agent()?;

        let ice_candidates = if let Some(agent) = self.get_agent() {
            agent.get_local_candidates()
        } else {
            return Err(Error::ErrICEAgentNotExist);
        };

        Ok(rtc_ice_candidates_from_ice_candidates(ice_candidates))
    }

    /// State indicates the current state of the ICE gatherer.
    pub fn state(&self) -> RTCIceGathererState {
        self.state
    }

    pub fn set_state(&mut self, s: RTCIceGathererState) {
        self.state = s;
        self.events
            .push_back(IceGathererEvent::OnICEGathererState(s));
    }

    pub(crate) fn get_agent(&self) -> Option<&Agent> {
        self.agent.as_ref()
    }

    pub(crate) fn get_mut_agent(&mut self) -> Option<&mut Agent> {
        self.agent.as_mut()
    }

    pub(crate) fn collect_stats(&self, collector: &mut StatsCollector) {
        if let Some(agent) = self.get_agent() {
            let mut reports = HashMap::new();

            for stats in agent.get_candidate_pairs_stats() {
                let stats: ICECandidatePairStats = stats.into();
                reports.insert(stats.id.clone(), StatsReportType::CandidatePair(stats));
            }

            for stats in agent.get_local_candidates_stats() {
                reports.insert(
                    stats.id.clone(),
                    StatsReportType::from(LocalCandidate(stats)),
                );
            }

            for stats in agent.get_remote_candidates_stats() {
                reports.insert(
                    stats.id.clone(),
                    StatsReportType::from(RemoteCandidate(stats)),
                );
            }

            collector.merge(reports);
        }
    }
}

/*TODO: #[cfg(test)]
mod test {
    use tokio::sync::mpsc;

    use super::*;
    use crate::api::APIBuilder;
    use crate::transports::ice_transport::ice_gatherer::RTCIceGatherOptions;
    use crate::transports::ice_transport::ice_server::RTCIceServer;

    #[test]
    fn test_new_ice_gatherer_success() -> Result<()> {
        let opts = RTCIceGatherOptions {
            ice_servers: vec![RTCIceServer {
                urls: vec!["stun:stun.l.google.com:19302".to_owned()],
                ..Default::default()
            }],
            ..Default::default()
        };

        let gatherer = APIBuilder::new().build().new_ice_gatherer(opts)?;

        assert_eq!(
            gatherer.state(),
            RTCIceGathererState::New,
            "Expected gathering state new"
        );

        let (gather_finished_tx, mut gather_finished_rx) = mpsc::channel::<()>(1);
        let gather_finished_tx = Arc::new(Mutex::new(Some(gather_finished_tx)));
        gatherer.on_local_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
            let gather_finished_tx_clone = Arc::clone(&gather_finished_tx);
            Box::pin(async move {
                if c.is_none() {
                    let mut tx = gather_finished_tx_clone.lock().await;
                    tx.take();
                }
            })
        }));

        gatherer.gather().await?;

        let _ = gather_finished_rx.recv().await;

        let params = gatherer.get_local_parameters().await?;

        assert!(
            !params.username_fragment.is_empty() && !params.password.is_empty(),
            "Empty local username or password frag"
        );

        let candidates = gatherer.get_local_candidates().await?;

        assert!(!candidates.is_empty(), "No candidates gathered");

        gatherer.close().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_ice_gather_mdns_candidate_gathering() -> Result<()> {
        let mut s = SettingEngine::default();
        s.set_ice_multicast_dns_mode(ice::mdns::MulticastDnsMode::QueryAndGather);

        let gatherer = APIBuilder::new()
            .with_setting_engine(s)
            .build()
            .new_ice_gatherer(RTCIceGatherOptions::default())?;

        let (done_tx, mut done_rx) = mpsc::channel::<()>(1);
        let done_tx = Arc::new(Mutex::new(Some(done_tx)));
        gatherer.on_local_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
            let done_tx_clone = Arc::clone(&done_tx);
            Box::pin(async move {
                if let Some(c) = c {
                    if c.address.ends_with(".local") {
                        let mut tx = done_tx_clone.lock().await;
                        tx.take();
                    }
                }
            })
        }));

        gatherer.gather().await?;

        let _ = done_rx.recv().await;

        gatherer.close().await?;

        Ok(())
    }
}
*/

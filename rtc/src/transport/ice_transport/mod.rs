//use ice::candidate::Candidate;
//use ice::state::ConnectionState;
use ice::Credentials;
use ice_candidate::RTCIceCandidate;
use ice_candidate_pair::RTCIceCandidatePair;
use ice_gatherer::RTCIceGatherer;
use ice_role::RTCIceRole;
use std::collections::VecDeque;

//use crate::transports::ice_transport::ice_parameters::RTCIceParameters;
use crate::messages::RTCMessage;
use crate::stats::stats_collector::StatsCollector;
use crate::stats::ICETransportStats;
use crate::stats::StatsReportType::Transport;
use crate::transport::ice_transport::ice_transport_state::RTCIceTransportState;
use shared::error::Result;
use shared::Transmit;

/*TODO:#[cfg(test)]
mod ice_transport_test;
*/
pub mod ice_candidate;
pub mod ice_candidate_pair;
pub mod ice_candidate_type;
pub mod ice_connection_state;
pub mod ice_credential_type;
pub mod ice_gatherer;
pub mod ice_gatherer_state;
pub mod ice_gathering_state;
pub mod ice_parameters;
pub mod ice_protocol;
pub mod ice_role;
pub mod ice_server;
pub mod ice_transport_state;

#[derive(Debug)]
pub enum IceTransportEvent {
    OnConnectionStateChange(RTCIceTransportState),
    OnSelectedCandidatePairChange(Box<RTCIceCandidatePair>),
}

/// ICETransport allows an application access to information about the ICE
/// transport over which packets are sent and received.
pub struct RTCIceTransport {
    pub(crate) gatherer: RTCIceGatherer,
    state: RTCIceTransportState,
    role: RTCIceRole,

    pub(crate) transmits: VecDeque<Transmit<RTCMessage>>,
}

impl RTCIceTransport {
    /// creates a new new_ice_transport.
    pub(crate) fn new(gatherer: RTCIceGatherer) -> Self {
        RTCIceTransport {
            gatherer,
            state: RTCIceTransportState::New,
            role: Default::default(),
            transmits: Default::default(),
        }
    }

    /// get_selected_candidate_pair returns the selected candidate pair on which packets are sent
    /// if there is no selected pair nil is returned
    pub fn get_selected_candidate_pair(&self) -> Option<RTCIceCandidatePair> {
        if let Some((ice_pair_local, ice_pair_remote)) =
            self.gatherer.agent.get_selected_candidate_pair()
        {
            let local = RTCIceCandidate::from(&ice_pair_local);
            let remote = RTCIceCandidate::from(&ice_pair_remote);
            Some(RTCIceCandidatePair::new(local, remote))
        } else {
            None
        }
    }

    /*TODO: /// Start incoming connectivity checks based on its configured role.
       pub fn start(&mut self, params: &RTCIceParameters, role: Option<RTCIceRole>) -> Result<()> {
        if self.state() != RTCIceTransportState::New {
            return Err(Error::ErrICETransportNotInNew);
        }

        self.ensure_gatherer()?;

        if let Some(agent) = self.gatherer.get_agent().await {
            let state = Arc::clone(&self.state);

            let on_connection_state_change_handler =
                Arc::clone(&self.on_connection_state_change_handler);
            agent.on_connection_state_change(Box::new(move |ice_state: ConnectionState| {
                let s = RTCIceTransportState::from(ice_state);
                let on_connection_state_change_handler_clone =
                    Arc::clone(&on_connection_state_change_handler);
                state.store(s as u8, Ordering::SeqCst);
                Box::pin(async move {
                    if let Some(handler) = &*on_connection_state_change_handler_clone.load() {
                        let mut f = handler.lock().await;
                        f(s).await;
                    }
                })
            }));

            let on_selected_candidate_pair_change_handler =
                Arc::clone(&self.on_selected_candidate_pair_change_handler);
            agent.on_selected_candidate_pair_change(Box::new(
                move |local: &Arc<dyn Candidate + Send + Sync>,
                      remote: &Arc<dyn Candidate + Send + Sync>| {
                    let on_selected_candidate_pair_change_handler_clone =
                        Arc::clone(&on_selected_candidate_pair_change_handler);
                    let local = RTCIceCandidate::from(local);
                    let remote = RTCIceCandidate::from(remote);
                    Box::pin(async move {
                        if let Some(handler) =
                            &*on_selected_candidate_pair_change_handler_clone.load()
                        {
                            let mut f = handler.lock().await;
                            f(RTCIceCandidatePair::new(local, remote)).await;
                        }
                    })
                },
            ));

            let role = if let Some(role) = role {
                role
            } else {
                RTCIceRole::Controlled
            };

            let (cancel_tx, cancel_rx) = mpsc::channel(1);
            {
                let mut internal = self.internal.lock().await;
                internal.role = role;
                internal.cancel_tx = Some(cancel_tx);
            }

            let conn: Arc<dyn Conn + Send + Sync> = match role {
                RTCIceRole::Controlling => {
                    agent
                        .dial(
                            cancel_rx,
                            params.username_fragment.clone(),
                            params.password.clone(),
                        )
                        .await?
                }

                RTCIceRole::Controlled => {
                    agent
                        .accept(
                            cancel_rx,
                            params.username_fragment.clone(),
                            params.password.clone(),
                        )
                        .await?
                }

                _ => return Err(Error::ErrICERoleUnknown),
            };

            let config = Config {
                conn: Arc::clone(&conn),
                buffer_size: self.gatherer.setting_engine.get_receive_mtu(),
            };

            {
                let mut internal = self.internal.lock().await;
                internal.conn = Some(conn);
                internal.mux = Some(Mux::new(config));
            }

            Ok(())
        } else {
            Err(Error::ErrICEAgentNotExist)
        }
    }
    */

    /// restart is not exposed currently because ORTC has users create a whole new ICETransport
    /// so for now lets keep it private so we don't cause ORTC users to depend on non-standard APIs
    pub(crate) fn restart(&mut self) -> Result<()> {
        let (ufrag, pwd) = (
            self.gatherer
                .setting_engine
                .candidates
                .username_fragment
                .clone(),
            self.gatherer.setting_engine.candidates.password.clone(),
        );
        self.gatherer.agent.restart(ufrag, pwd, false)?;

        //TODO: self.gatherer.gather()
        Ok(())
    }

    /// Stop irreversibly stops the ICETransport.
    pub fn stop(&mut self) -> Result<()> {
        self.set_state(RTCIceTransportState::Closed);
        self.gatherer.close()
    }

    /// Role indicates the current role of the ICE transport.
    pub fn role(&self) -> RTCIceRole {
        self.role
    }

    /// add_local_candidates sets the sequence of candidates associated with the local ICETransport.
    pub fn add_local_candidates(&mut self, local_candidates: &[RTCIceCandidate]) -> Result<()> {
        for rc in local_candidates {
            self.gatherer.agent.add_local_candidate(rc.to_ice()?)?;
        }
        Ok(())
    }

    /// adds a candidate associated with the local ICETransport.
    pub fn add_local_candidate(&mut self, local_candidate: Option<RTCIceCandidate>) -> Result<()> {
        if let Some(r) = local_candidate {
            self.gatherer.agent.add_local_candidate(r.to_ice()?)?;
        }

        Ok(())
    }

    /// add_remote_candidates sets the sequence of candidates associated with the remote ICETransport.
    pub fn add_remote_candidates(&mut self, remote_candidates: &[RTCIceCandidate]) -> Result<()> {
        for rc in remote_candidates {
            self.gatherer.agent.add_remote_candidate(rc.to_ice()?)?;
        }
        Ok(())
    }

    /// adds a candidate associated with the remote ICETransport.
    pub fn add_remote_candidate(
        &mut self,
        remote_candidate: Option<RTCIceCandidate>,
    ) -> Result<()> {
        if let Some(r) = remote_candidate {
            self.gatherer.agent.add_remote_candidate(r.to_ice()?)?;
        }

        Ok(())
    }

    /// State returns the current ice transport state.
    pub fn state(&self) -> RTCIceTransportState {
        self.state
    }

    pub(crate) fn set_state(&mut self, s: RTCIceTransportState) {
        self.state = s;
    }

    pub(crate) fn collect_stats(&self, collector: &mut StatsCollector) {
        let stats = ICETransportStats::new("ice_transport".to_string(), &self.gatherer.agent);

        collector.insert("ice_transport".to_string(), Transport(stats));
    }

    pub(crate) fn have_remote_credentials_change(
        &mut self,
        new_ufrag: &str,
        new_pwd: &str,
    ) -> bool {
        if let Some(Credentials { ufrag, pwd }) = self.gatherer.agent.get_remote_credentials() {
            ufrag != new_ufrag || pwd != new_pwd
        } else {
            false
        }
    }

    pub(crate) fn set_remote_credentials(
        &mut self,
        new_ufrag: String,
        new_pwd: String,
    ) -> Result<()> {
        self.gatherer
            .agent
            .set_remote_credentials(new_ufrag, new_pwd)
    }
}

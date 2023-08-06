#[cfg(test)]
mod agent_test;
#[cfg(test)]
mod agent_transport_test;

pub mod agent_config;
pub(crate) mod agent_internal;
pub mod agent_selector;
pub mod agent_stats;
pub mod agent_transport;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::SystemTime;

use agent_config::*;
use agent_internal::*;
use agent_stats::*;
use std::time::{Duration, Instant};
use stun::attributes::*;
use stun::fingerprint::*;
use stun::integrity::*;
use stun::message::*;
use stun::xoraddr::*;

use crate::candidate::*;
use crate::network_type::*;
use crate::rand::*;
use crate::state::*;
use crate::tcp_type::TcpType;
use crate::url::*;
use shared::error::*;

#[derive(Debug, Clone)]
pub(crate) struct BindingRequest {
    pub(crate) timestamp: Instant,
    pub(crate) transaction_id: TransactionId,
    pub(crate) destination: SocketAddr,
    pub(crate) is_use_candidate: bool,
}

impl Default for BindingRequest {
    fn default() -> Self {
        Self {
            timestamp: Instant::now(),
            transaction_id: TransactionId::default(),
            destination: SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0),
            is_use_candidate: false,
        }
    }
}

/// Represents the ICE agent.
pub struct Agent {
    pub(crate) internal: AgentInternal,

    pub(crate) gathering_state: GatheringState,
    pub(crate) candidate_types: Vec<CandidateType>,
    pub(crate) urls: Vec<Url>,
    pub(crate) network_types: Vec<NetworkType>,
}

impl Agent {
    /// Creates a new Agent.
    pub fn new(config: AgentConfig) -> Result<Self> {
        let mut ai = AgentInternal::new(&config);

        config.init_with_defaults(&mut ai);

        let candidate_types = if config.candidate_types.is_empty() {
            default_candidate_types()
        } else {
            config.candidate_types.clone()
        };

        if ai.lite && (candidate_types.len() != 1 || candidate_types[0] != CandidateType::Host) {
            return Err(Error::ErrLiteUsingNonHostCandidates);
        }

        if !config.urls.is_empty()
            && !contains_candidate_type(CandidateType::ServerReflexive, &candidate_types)
            && !contains_candidate_type(CandidateType::Relay, &candidate_types)
        {
            return Err(Error::ErrUselessUrlsProvided);
        }

        let mut agent = Self {
            internal: ai,
            gathering_state: GatheringState::New,
            candidate_types,
            urls: config.urls.clone(),
            network_types: config.network_types.clone(),
        };

        /*agent.internal.start_on_connection_state_change_routine(
            chan_state_rx,
            chan_candidate_rx,
            chan_candidate_pair_rx,
        );*/

        // Restart is also used to initialize the agent for the first time
        if let Err(err) = agent.restart(config.local_ufrag, config.local_pwd) {
            let _ = agent.close();
            return Err(err);
        }

        Ok(agent)
    }

    pub fn get_bytes_received(&self) -> usize {
        self.internal.agent_conn.bytes_received()
    }

    pub fn get_bytes_sent(&self) -> usize {
        self.internal.agent_conn.bytes_sent()
    }

    /*
    /// Sets a handler that is fired when the connection state changes.
    pub fn on_connection_state_change(&self, f: OnConnectionStateChangeHdlrFn) {
        self.internal
            .on_connection_state_change_hdlr
            .store(Some(Arc::new(Mutex::new(f))))
    }

    /// Sets a handler that is fired when the final candidate pair is selected.
    pub fn on_selected_candidate_pair_change(&self, f: OnSelectedCandidatePairChangeHdlrFn) {
        self.internal
            .on_selected_candidate_pair_change_hdlr
            .store(Some(Arc::new(Mutex::new(f))))
    }

    /// Sets a handler that is fired when new candidates gathered. When the gathering process
    /// complete the last candidate is nil.
    pub fn on_candidate(&self, f: OnCandidateHdlrFn) {
        self.internal
            .on_candidate_hdlr
            .store(Some(Arc::new(Mutex::new(f))));
    }*/

    /// Adds a new remote candidate.
    pub fn add_remote_candidate(&self, c: &Rc<dyn Candidate>) -> Result<()> {
        // cannot check for network yet because it might not be applied
        // when mDNS hostame is used.
        if c.tcp_type() == TcpType::Active {
            // TCP Candidates with tcptype active will probe server passive ones, so
            // no need to do anything with them.
            log::info!("Ignoring remote candidate with tcpType active: {}", c);
            return Ok(());
        }

        // If we have a mDNS Candidate lets fully resolve it before adding it locally
        if c.candidate_type() == CandidateType::Host && c.address().ends_with(".local") {
            log::warn!(
                "remote mDNS candidate added, but mDNS is disabled: ({})",
                c.address()
            );
            return Err(Error::ErrMulticastDnsNotSupported);
        } else {
            /*TODO: let ai = Arc::clone(&self.internal);
            let candidate = Arc::clone(c);
            tokio::spawn(move {
                ai.add_remote_candidate(&candidate);
            });*/
        }

        Ok(())
    }

    /// Returns the local candidates.
    pub fn get_local_candidates(&self) -> Result<Vec<Rc<dyn Candidate>>> {
        let mut res = vec![];

        {
            let local_candidates = &self.internal.local_candidates;
            for candidates in local_candidates.values() {
                for candidate in candidates {
                    res.push(Rc::clone(candidate));
                }
            }
        }

        Ok(res)
    }

    /// Returns the local user credentials.
    pub fn get_local_user_credentials(&self) -> (String, String) {
        let ufrag_pwd = &self.internal.ufrag_pwd;
        (ufrag_pwd.local_ufrag.clone(), ufrag_pwd.local_pwd.clone())
    }

    /// Returns the remote user credentials.
    pub fn get_remote_user_credentials(&self) -> (String, String) {
        let ufrag_pwd = &self.internal.ufrag_pwd;
        (ufrag_pwd.remote_ufrag.clone(), ufrag_pwd.remote_pwd.clone())
    }

    /// Cleans up the Agent.
    pub fn close(&mut self) -> Result<()> {
        //FIXME: deadlock here
        self.internal.close()
    }

    /// Returns the selected pair or nil if there is none
    pub fn get_selected_candidate_pair(&self) -> Option<Rc<CandidatePair>> {
        self.internal.agent_conn.get_selected_pair()
    }

    /// Sets the credentials of the remote agent.
    pub fn set_remote_credentials(
        &mut self,
        remote_ufrag: String,
        remote_pwd: String,
    ) -> Result<()> {
        self.internal
            .set_remote_credentials(remote_ufrag, remote_pwd)
    }

    /// Restarts the ICE Agent with the provided ufrag/pwd
    /// If no ufrag/pwd is provided the Agent will generate one itself.
    ///
    /// Restart must only be called when `GatheringState` is `GatheringStateComplete`
    /// a user must then call `GatherCandidates` explicitly to start generating new ones.
    pub fn restart(&mut self, mut ufrag: String, mut pwd: String) -> Result<()> {
        if ufrag.is_empty() {
            ufrag = generate_ufrag();
        }
        if pwd.is_empty() {
            pwd = generate_pwd();
        }

        if ufrag.len() * 8 < 24 {
            return Err(Error::ErrLocalUfragInsufficientBits);
        }
        if pwd.len() * 8 < 128 {
            return Err(Error::ErrLocalPwdInsufficientBits);
        }

        if self.gathering_state == GatheringState::Gathering {
            return Err(Error::ErrRestartWhenGathering);
        }
        self.gathering_state = GatheringState::New;

        // Clear all agent needed to take back to fresh state
        {
            let mut ufrag_pwd = &mut self.internal.ufrag_pwd;
            ufrag_pwd.local_ufrag = ufrag;
            ufrag_pwd.local_pwd = pwd;
            ufrag_pwd.remote_ufrag = String::new();
            ufrag_pwd.remote_pwd = String::new();
        }

        self.internal.pending_binding_requests = vec![];

        self.internal.agent_conn.checklist = vec![];

        self.internal.set_selected_pair(None);
        self.internal.delete_all_candidates();
        self.internal.start();

        // Restart is used by NewAgent. Accept/Connect should be used to move to checking
        // for new Agents
        if self.internal.connection_state != ConnectionState::New {
            self.internal
                .update_connection_state(ConnectionState::Checking);
        }

        Ok(())
    }

    /// Initiates the trickle based gathering process.
    pub fn gather_candidates(&self) -> Result<()> {
        if self.gathering_state != GatheringState::New {
            return Err(Error::ErrMultipleGatherAttempted);
        }

        /*if self.internal.on_candidate_hdlr.load().is_none() {
            return Err(Error::ErrNoOnCandidateHandler);
        }


        let params = GatherCandidatesInternalParams {
            udp_network: self.udp_network.clone(),
            candidate_types: self.candidate_types.clone(),
            urls: self.urls.clone(),
            network_types: self.network_types.clone(),
            net: Arc::clone(&self.net),
            interface_filter: self.interface_filter.clone(),
            ip_filter: self.ip_filter.clone(),
            ext_ip_mapper: Arc::clone(&self.ext_ip_mapper),
            agent_internal: Arc::clone(&self.internal),
            gathering_state: Arc::clone(&self.gathering_state),
            chan_candidate_tx: Arc::clone(&self.internal.chan_candidate_tx),
        };
        tokio::spawn(move {
            Self::gather_candidates_internal(params);
        });*/

        Ok(())
    }

    /// Returns a list of candidate pair stats.
    pub fn get_candidate_pairs_stats(&self) -> Vec<CandidatePairStats> {
        self.internal.get_candidate_pairs_stats()
    }

    /// Returns a list of local candidates stats.
    pub fn get_local_candidates_stats(&self) -> Vec<CandidateStats> {
        self.internal.get_local_candidates_stats()
    }

    /// Returns a list of remote candidates stats.
    pub fn get_remote_candidates_stats(&self) -> Vec<CandidateStats> {
        self.internal.get_remote_candidates_stats()
    }
}

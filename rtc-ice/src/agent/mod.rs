#[cfg(test)]
mod agent_test;

pub mod agent_config;
mod agent_proto;
pub mod agent_selector;
pub mod agent_stats;

use agent_config::*;
use bytes::BytesMut;
use log::{debug, error, info, trace, warn};
use sansio::Protocol;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use stun::attributes::*;
use stun::fingerprint::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;
use stun::xoraddr::*;

use crate::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig;
use crate::candidate::{candidate_pair::*, *};
use crate::network_type::NetworkType;
use crate::rand::*;
use crate::state::*;
use crate::url::*;
use shared::error::*;
use shared::{TransportContext, TransportMessage, TransportProtocol};

const ZERO_DURATION: Duration = Duration::from_secs(0);

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

#[derive(Default, Clone)]
pub struct Credentials {
    pub ufrag: String,
    pub pwd: String,
}

#[derive(Default, Clone)]
pub(crate) struct UfragPwd {
    pub(crate) local_credentials: Credentials,
    pub(crate) remote_credentials: Option<Credentials>,
}

fn assert_inbound_username(m: &Message, expected_username: &str) -> Result<()> {
    let mut username = Username::new(ATTR_USERNAME, String::new());
    username.get_from(m)?;

    if username.to_string() != expected_username {
        return Err(Error::Other(format!(
            "{:?} expected({}) actual({})",
            Error::ErrMismatchUsername,
            expected_username,
            username,
        )));
    }

    Ok(())
}

fn assert_inbound_message_integrity(m: &mut Message, key: &[u8]) -> Result<()> {
    let message_integrity_attr = MessageIntegrity(key.to_vec());
    message_integrity_attr.check(m)
}

pub enum Event {
    ConnectionStateChange(ConnectionState),
    SelectedCandidatePairChange(Box<Candidate>, Box<Candidate>),
}

/// Represents the ICE agent.
pub struct Agent {
    pub(crate) tie_breaker: u64,
    pub(crate) is_controlling: bool,
    pub(crate) lite: bool,

    pub(crate) start_time: Instant,

    pub(crate) connection_state: ConnectionState,
    pub(crate) last_connection_state: ConnectionState,

    //pub(crate) started_ch_tx: Mutex<Option<broadcast::Sender<()>>>,
    pub(crate) ufrag_pwd: UfragPwd,

    pub(crate) local_candidates: Vec<Candidate>,
    pub(crate) remote_candidates: Vec<Candidate>,
    pub(crate) candidate_pairs: Vec<CandidatePair>,
    pub(crate) nominated_pair: Option<usize>,
    pub(crate) selected_pair: Option<usize>,

    // LRU of outbound Binding request Transaction IDs
    pub(crate) pending_binding_requests: Vec<BindingRequest>,

    // the following variables won't be changed after init_with_defaults()
    pub(crate) insecure_skip_verify: bool,
    pub(crate) max_binding_requests: u16,
    pub(crate) host_acceptance_min_wait: Duration,
    pub(crate) srflx_acceptance_min_wait: Duration,
    pub(crate) prflx_acceptance_min_wait: Duration,
    pub(crate) relay_acceptance_min_wait: Duration,
    // How long connectivity checks can fail before the ICE Agent
    // goes to disconnected
    pub(crate) disconnected_timeout: Duration,
    // How long connectivity checks can fail before the ICE Agent
    // goes to failed
    pub(crate) failed_timeout: Duration,
    // How often should we send keepalive packets?
    // 0 means never
    pub(crate) keepalive_interval: Duration,
    // How often should we run our internal taskLoop to check for state changes when connecting
    pub(crate) check_interval: Duration,
    pub(crate) checking_duration: Instant,
    pub(crate) last_checking_time: Instant,

    pub(crate) candidate_types: Vec<CandidateType>,
    pub(crate) urls: Vec<Url>,

    pub(crate) transmits: VecDeque<TransportMessage<BytesMut>>,
    pub(crate) events: VecDeque<Event>,
}

impl Default for Agent {
    fn default() -> Self {
        Self {
            tie_breaker: 0,
            is_controlling: false,
            lite: false,
            start_time: Instant::now(),
            connection_state: Default::default(),
            last_connection_state: Default::default(),
            ufrag_pwd: Default::default(),
            local_candidates: vec![],
            remote_candidates: vec![],
            candidate_pairs: vec![],
            nominated_pair: None,
            selected_pair: None,
            pending_binding_requests: vec![],
            insecure_skip_verify: false,
            max_binding_requests: 0,
            host_acceptance_min_wait: Default::default(),
            srflx_acceptance_min_wait: Default::default(),
            prflx_acceptance_min_wait: Default::default(),
            relay_acceptance_min_wait: Default::default(),
            disconnected_timeout: Default::default(),
            failed_timeout: Default::default(),
            keepalive_interval: Default::default(),
            check_interval: Default::default(),
            checking_duration: Instant::now(),
            last_checking_time: Instant::now(),
            candidate_types: vec![],
            urls: vec![],
            transmits: Default::default(),
            events: Default::default(),
        }
    }
}

impl Agent {
    /// Creates a new Agent.
    pub fn new(config: Arc<AgentConfig>) -> Result<Self> {
        let candidate_types = if config.candidate_types.is_empty() {
            default_candidate_types()
        } else {
            config.candidate_types.clone()
        };

        if config.lite && (candidate_types.len() != 1 || candidate_types[0] != CandidateType::Host)
        {
            return Err(Error::ErrLiteUsingNonHostCandidates);
        }

        if !config.urls.is_empty()
            && !contains_candidate_type(CandidateType::ServerReflexive, &candidate_types)
            && !contains_candidate_type(CandidateType::Relay, &candidate_types)
        {
            return Err(Error::ErrUselessUrlsProvided);
        }

        let mut agent = Self {
            tie_breaker: rand::random::<u64>(),
            is_controlling: config.is_controlling,
            lite: config.lite,

            start_time: Instant::now(),

            nominated_pair: None,
            selected_pair: None,
            candidate_pairs: vec![],

            connection_state: ConnectionState::New,

            insecure_skip_verify: config.insecure_skip_verify,

            //started_ch_tx: MuteSome(started_ch_tx)),

            //won't change after init_with_defaults()
            max_binding_requests: if let Some(max_binding_requests) = config.max_binding_requests {
                max_binding_requests
            } else {
                DEFAULT_MAX_BINDING_REQUESTS
            },
            host_acceptance_min_wait: if let Some(host_acceptance_min_wait) =
                config.host_acceptance_min_wait
            {
                host_acceptance_min_wait
            } else {
                DEFAULT_HOST_ACCEPTANCE_MIN_WAIT
            },
            srflx_acceptance_min_wait: if let Some(srflx_acceptance_min_wait) =
                config.srflx_acceptance_min_wait
            {
                srflx_acceptance_min_wait
            } else {
                DEFAULT_SRFLX_ACCEPTANCE_MIN_WAIT
            },
            prflx_acceptance_min_wait: if let Some(prflx_acceptance_min_wait) =
                config.prflx_acceptance_min_wait
            {
                prflx_acceptance_min_wait
            } else {
                DEFAULT_PRFLX_ACCEPTANCE_MIN_WAIT
            },
            relay_acceptance_min_wait: if let Some(relay_acceptance_min_wait) =
                config.relay_acceptance_min_wait
            {
                relay_acceptance_min_wait
            } else {
                DEFAULT_RELAY_ACCEPTANCE_MIN_WAIT
            },

            // How long connectivity checks can fail before the ICE Agent
            // goes to disconnected
            disconnected_timeout: if let Some(disconnected_timeout) = config.disconnected_timeout {
                disconnected_timeout
            } else {
                DEFAULT_DISCONNECTED_TIMEOUT
            },

            // How long connectivity checks can fail before the ICE Agent
            // goes to failed
            failed_timeout: if let Some(failed_timeout) = config.failed_timeout {
                failed_timeout
            } else {
                DEFAULT_FAILED_TIMEOUT
            },

            // How often should we send keepalive packets?
            // 0 means never
            keepalive_interval: if let Some(keepalive_interval) = config.keepalive_interval {
                keepalive_interval
            } else {
                DEFAULT_KEEPALIVE_INTERVAL
            },

            // How often should we run our internal taskLoop to check for state changes when connecting
            check_interval: if config.check_interval == Duration::from_secs(0) {
                DEFAULT_CHECK_INTERVAL
            } else {
                config.check_interval
            },
            checking_duration: Instant::now(),
            last_checking_time: Instant::now(),
            last_connection_state: ConnectionState::Unspecified,

            ufrag_pwd: UfragPwd::default(),

            local_candidates: vec![],
            remote_candidates: vec![],

            // LRU of outbound Binding request Transaction IDs
            pending_binding_requests: vec![],

            candidate_types,
            urls: config.urls.clone(),

            transmits: VecDeque::new(),
            events: VecDeque::new(),
        };

        // Restart is also used to initialize the agent for the first time
        if let Err(err) = agent.restart(config.local_ufrag.clone(), config.local_pwd.clone(), false)
        {
            let _ = agent.close();
            return Err(err);
        }

        Ok(agent)
    }

    /// Adds a new local candidate.
    pub fn add_local_candidate(&mut self, c: Candidate) -> Result<()> {
        for cand in &self.local_candidates {
            if cand.equal(&c) {
                return Ok(());
            }
        }

        self.local_candidates.push(c);

        for remote_index in 0..self.remote_candidates.len() {
            self.add_pair(self.local_candidates.len() - 1, remote_index);
        }

        self.request_connectivity_check();

        Ok(())
    }

    /// Adds a new remote candidate.
    pub fn add_remote_candidate(&mut self, c: Candidate) -> Result<()> {
        // If we have a mDNS Candidate lets fully resolve it before adding it locally
        if c.candidate_type() == CandidateType::Host && c.address().ends_with(".local") {
            warn!(
                "remote mDNS candidate added, but mDNS is disabled: ({})",
                c.address()
            );
            return Err(Error::ErrMulticastDnsNotSupported);
        }

        for cand in &self.remote_candidates {
            if cand.equal(&c) {
                return Ok(());
            }
        }

        self.remote_candidates.push(c);

        for local_index in 0..self.local_candidates.len() {
            self.add_pair(local_index, self.remote_candidates.len() - 1);
        }

        self.request_connectivity_check();

        Ok(())
    }

    /// Sets the credentials of the remote agent.
    pub fn set_remote_credentials(
        &mut self,
        remote_ufrag: String,
        remote_pwd: String,
    ) -> Result<()> {
        if remote_ufrag.is_empty() {
            return Err(Error::ErrRemoteUfragEmpty);
        } else if remote_pwd.is_empty() {
            return Err(Error::ErrRemotePwdEmpty);
        }

        self.ufrag_pwd.remote_credentials = Some(Credentials {
            ufrag: remote_ufrag,
            pwd: remote_pwd,
        });

        Ok(())
    }

    /// Returns the remote credentials.
    pub fn get_remote_credentials(&self) -> Option<&Credentials> {
        self.ufrag_pwd.remote_credentials.as_ref()
    }

    /// Returns the local credentials.
    pub fn get_local_credentials(&self) -> &Credentials {
        &self.ufrag_pwd.local_credentials
    }

    pub fn role(&self) -> bool {
        self.is_controlling
    }

    pub fn set_role(&mut self, is_controlling: bool) {
        self.is_controlling = is_controlling;
    }

    pub fn lite(&self) -> bool {
        self.lite
    }

    pub fn set_lite(&mut self, ice_lite: bool) {
        self.lite = ice_lite;
    }

    pub fn state(&self) -> ConnectionState {
        self.connection_state
    }

    pub fn read(&mut self, msg: TransportMessage<BytesMut>) -> Result<()> {
        if let Some(local_index) =
            self.find_local_candidate(msg.transport.local_addr, msg.transport.transport_protocol)
        {
            self.handle_inbound_candidate_msg(
                local_index,
                &msg.message,
                msg.transport.peer_addr,
                msg.transport.local_addr,
            )
        } else {
            warn!(
                "[{}]: Discarded message, not a valid local candidate from {:?}:{}",
                self.get_name(),
                msg.transport.transport_protocol,
                msg.transport.local_addr,
            );
            Err(Error::ErrUnhandledStunpacket)
        }
    }

    fn get_timeout_interval(&self) -> Duration {
        let (check_interval, keepalive_interval, disconnected_timeout, failed_timeout) = (
            self.check_interval,
            self.keepalive_interval,
            self.disconnected_timeout,
            self.failed_timeout,
        );
        let mut interval = DEFAULT_CHECK_INTERVAL;

        let mut update_interval = |x: Duration| {
            if x != ZERO_DURATION && (interval == ZERO_DURATION || interval > x) {
                interval = x;
            }
        };

        match self.last_connection_state {
            ConnectionState::New | ConnectionState::Checking => {
                // While connecting, check candidates more frequently
                update_interval(check_interval);
            }
            ConnectionState::Connected | ConnectionState::Disconnected => {
                update_interval(keepalive_interval);
            }
            _ => {}
        };
        // Ensure we run our task loop as quickly as the minimum of our various configured timeouts
        update_interval(disconnected_timeout);
        update_interval(failed_timeout);
        interval
    }

    /// Returns the selected pair (local_candidate, remote_candidate) or none
    pub fn get_selected_candidate_pair(&self) -> Option<(Candidate, Candidate)> {
        if let Some(pair_index) = self.get_selected_pair() {
            let candidate_pair = &self.candidate_pairs[pair_index];
            Some((
                self.local_candidates[candidate_pair.local_index].clone(),
                self.remote_candidates[candidate_pair.remote_index].clone(),
            ))
        } else {
            None
        }
    }

    /// start connectivity checks
    pub fn start_connectivity_checks(
        &mut self,
        is_controlling: bool,
        remote_ufrag: String,
        remote_pwd: String,
    ) -> Result<()> {
        debug!(
            "Started agent: isControlling? {}, remoteUfrag: {}, remotePwd: {}",
            is_controlling, remote_ufrag, remote_pwd
        );
        self.set_remote_credentials(remote_ufrag, remote_pwd)?;
        self.is_controlling = is_controlling;
        self.start();

        self.update_connection_state(ConnectionState::Checking);
        self.request_connectivity_check();

        Ok(())
    }

    /// Restarts the ICE Agent with the provided ufrag/pwd
    /// If no ufrag/pwd is provided the Agent will generate one itself.
    pub fn restart(
        &mut self,
        mut ufrag: String,
        mut pwd: String,
        keep_local_candidates: bool,
    ) -> Result<()> {
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

        // Clear all agent needed to take back to fresh state
        self.ufrag_pwd.local_credentials.ufrag = ufrag;
        self.ufrag_pwd.local_credentials.pwd = pwd;
        self.ufrag_pwd.remote_credentials = None;

        self.pending_binding_requests = vec![];

        self.candidate_pairs = vec![];

        self.set_selected_pair(None);
        self.delete_all_candidates(keep_local_candidates);
        self.start();

        // Restart is used by NewAgent. Accept/Connect should be used to move to checking
        // for new Agents
        if self.connection_state != ConnectionState::New {
            self.update_connection_state(ConnectionState::Checking);
        }

        Ok(())
    }

    /// Returns the local candidates.
    pub fn get_local_candidates(&self) -> &[Candidate] {
        &self.local_candidates
    }

    fn contact(&mut self, now: Instant) {
        if self.connection_state == ConnectionState::Failed {
            // The connection is currently failed so don't send any checks
            // In the future it may be restarted though
            self.last_connection_state = self.connection_state;
            return;
        }
        if self.connection_state == ConnectionState::Checking {
            // We have just entered checking for the first time so update our checking timer
            if self.last_connection_state != self.connection_state {
                self.checking_duration = now;
            }

            // We have been in checking longer then Disconnect+Failed timeout, set the connection to Failed
            if now
                .checked_duration_since(self.checking_duration)
                .unwrap_or_else(|| Duration::from_secs(0))
                > self.disconnected_timeout + self.failed_timeout
            {
                self.update_connection_state(ConnectionState::Failed);
                self.last_connection_state = self.connection_state;
                return;
            }
        }

        self.contact_candidates();

        self.last_connection_state = self.connection_state;
        self.last_checking_time = now;
    }

    pub(crate) fn update_connection_state(&mut self, new_state: ConnectionState) {
        if self.connection_state != new_state {
            // Connection has gone to failed, release all gathered candidates
            if new_state == ConnectionState::Failed {
                self.set_selected_pair(None);
                self.delete_all_candidates(false);
            }

            info!(
                "[{}]: Setting new connection state: {}",
                self.get_name(),
                new_state
            );
            self.connection_state = new_state;
            self.events
                .push_back(Event::ConnectionStateChange(new_state));
        }
    }

    pub(crate) fn set_selected_pair(&mut self, selected_pair: Option<usize>) {
        if let Some(pair_index) = selected_pair {
            trace!(
                "[{}]: Set selected candidate pair: {:?}",
                self.get_name(),
                self.candidate_pairs[pair_index]
            );

            self.candidate_pairs[pair_index].nominated = true;
            self.selected_pair = Some(pair_index);

            self.update_connection_state(ConnectionState::Connected);

            // Notify when the selected pair changes
            let candidate_pair = &self.candidate_pairs[pair_index];
            self.events.push_back(Event::SelectedCandidatePairChange(
                Box::new(self.local_candidates[candidate_pair.local_index].clone()),
                Box::new(self.remote_candidates[candidate_pair.remote_index].clone()),
            ));
        } else {
            self.selected_pair = None;
        }
    }

    pub(crate) fn ping_all_candidates(&mut self) {
        trace!("[{}]: pinging all candidates", self.get_name(),);

        let mut pairs: Vec<(usize, usize)> = vec![];

        {
            let name = self.get_name().to_string();
            if self.candidate_pairs.is_empty() {
                warn!(
                "[{}]: pingAllCandidates called with no candidate pairs. Connection is not possible yet.",
                name,
            );
            }
            for p in &mut self.candidate_pairs {
                if p.state == CandidatePairState::Waiting {
                    p.state = CandidatePairState::InProgress;
                } else if p.state != CandidatePairState::InProgress {
                    continue;
                }

                if p.binding_request_count > self.max_binding_requests {
                    trace!(
                        "[{}]: max requests reached for pair {}, marking it as failed",
                        name,
                        *p
                    );
                    p.state = CandidatePairState::Failed;
                } else {
                    p.binding_request_count += 1;
                    let local = p.local_index;
                    let remote = p.remote_index;
                    pairs.push((local, remote));
                }
            }
        }

        for (local, remote) in pairs {
            self.ping_candidate(local, remote);
        }
    }

    pub(crate) fn add_pair(&mut self, local_index: usize, remote_index: usize) {
        let p = CandidatePair::new(
            local_index,
            remote_index,
            self.local_candidates[local_index].priority(),
            self.remote_candidates[remote_index].priority(),
            self.is_controlling,
        );
        self.candidate_pairs.push(p);
    }

    pub(crate) fn find_pair(&self, local_index: usize, remote_index: usize) -> Option<usize> {
        for (index, p) in self.candidate_pairs.iter().enumerate() {
            if p.local_index == local_index && p.remote_index == remote_index {
                return Some(index);
            }
        }
        None
    }

    /// Checks if the selected pair is (still) valid.
    /// Note: the caller should hold the agent lock.
    pub(crate) fn validate_selected_pair(&mut self) -> bool {
        let (valid, disconnected_time) = {
            self.selected_pair.as_ref().map_or_else(
                || (false, Duration::from_secs(0)),
                |&pair_index| {
                    let remote_index = self.candidate_pairs[pair_index].remote_index;

                    let disconnected_time = Instant::now()
                        .duration_since(self.remote_candidates[remote_index].last_received());
                    (true, disconnected_time)
                },
            )
        };

        if valid {
            // Only allow transitions to fail if a.failedTimeout is non-zero
            let mut total_time_to_failure = self.failed_timeout;
            if total_time_to_failure != Duration::from_secs(0) {
                total_time_to_failure += self.disconnected_timeout;
            }

            if total_time_to_failure != Duration::from_secs(0)
                && disconnected_time > total_time_to_failure
            {
                self.update_connection_state(ConnectionState::Failed);
            } else if self.disconnected_timeout != Duration::from_secs(0)
                && disconnected_time > self.disconnected_timeout
            {
                self.update_connection_state(ConnectionState::Disconnected);
            } else {
                self.update_connection_state(ConnectionState::Connected);
            }
        }

        valid
    }

    /// Sends STUN Binding Indications to the selected pair.
    /// if no packet has been sent on that pair in the last keepaliveInterval.
    /// Note: the caller should hold the agent lock.
    pub(crate) fn check_keepalive(&mut self) {
        let (local_index, remote_index) = {
            self.selected_pair
                .as_ref()
                .map_or((None, None), |&pair_index| {
                    let p = &self.candidate_pairs[pair_index];
                    (Some(p.local_index), Some(p.remote_index))
                })
        };

        if let (Some(local_index), Some(remote_index)) = (local_index, remote_index) {
            let last_sent =
                Instant::now().duration_since(self.local_candidates[local_index].last_sent());

            let last_received =
                Instant::now().duration_since(self.remote_candidates[remote_index].last_received());

            if (self.keepalive_interval != Duration::from_secs(0))
                && ((last_sent > self.keepalive_interval)
                    || (last_received > self.keepalive_interval))
            {
                // we use binding request instead of indication to support refresh consent schemas
                // see https://tools.ietf.org/html/rfc7675
                self.ping_candidate(local_index, remote_index);
            }
        }
    }

    fn request_connectivity_check(&mut self) {
        if self.ufrag_pwd.remote_credentials.is_some() {
            self.contact(Instant::now());
        }
    }

    /// Remove all candidates.
    /// This closes any listening sockets and removes both the local and remote candidate lists.
    ///
    /// This is used for restarts, failures and on close.
    pub(crate) fn delete_all_candidates(&mut self, keep_local_candidates: bool) {
        if !keep_local_candidates {
            self.local_candidates.clear();
        }
        self.remote_candidates.clear();
    }

    pub(crate) fn find_remote_candidate(&self, addr: SocketAddr) -> Option<usize> {
        let (ip, port) = (addr.ip(), addr.port());
        for (index, c) in self.remote_candidates.iter().enumerate() {
            if c.address() == ip.to_string() && c.port() == port {
                return Some(index);
            }
        }
        None
    }

    pub(crate) fn find_local_candidate(
        &self,
        addr: SocketAddr,
        transport_protocol: TransportProtocol,
    ) -> Option<usize> {
        for (index, c) in self.local_candidates.iter().enumerate() {
            if c.addr() == addr && c.network_type().to_protocol() == transport_protocol {
                return Some(index);
            }
        }
        None
    }

    pub(crate) fn send_binding_request(
        &mut self,
        m: &Message,
        local_index: usize,
        remote_index: usize,
    ) {
        trace!(
            "[{}]: ping STUN from {} to {}",
            self.get_name(),
            self.local_candidates[local_index],
            self.remote_candidates[remote_index],
        );

        self.invalidate_pending_binding_requests(Instant::now());

        self.pending_binding_requests.push(BindingRequest {
            timestamp: Instant::now(),
            transaction_id: m.transaction_id,
            destination: self.remote_candidates[remote_index].addr(),
            is_use_candidate: m.contains(ATTR_USE_CANDIDATE),
        });

        self.send_stun(m, local_index, remote_index);
    }

    pub(crate) fn send_binding_success(
        &mut self,
        m: &Message,
        local_index: usize,
        remote_index: usize,
    ) {
        let addr = self.remote_candidates[remote_index].addr();
        let (ip, port) = (addr.ip(), addr.port());
        let local_pwd = self.ufrag_pwd.local_credentials.pwd.clone();

        let (out, result) = {
            let mut out = Message::new();
            let result = out.build(&[
                Box::new(m.clone()),
                Box::new(BINDING_SUCCESS),
                Box::new(XorMappedAddress { ip, port }),
                Box::new(MessageIntegrity::new_short_term_integrity(local_pwd)),
                Box::new(FINGERPRINT),
            ]);
            (out, result)
        };

        if let Err(err) = result {
            warn!(
                "[{}]: Failed to handle inbound ICE from: {} to: {} error: {}",
                self.get_name(),
                local_index,
                remote_index,
                err
            );
        } else {
            self.send_stun(&out, local_index, remote_index);
        }
    }

    /// Removes pending binding requests that are over `maxBindingRequestTimeout` old Let HTO be the
    /// transaction timeout, which SHOULD be 2*RTT if RTT is known or 500 ms otherwise.
    ///
    /// reference: (IETF ref-8445)[https://tools.ietf.org/html/rfc8445#appendix-B.1].
    pub(crate) fn invalidate_pending_binding_requests(&mut self, filter_time: Instant) {
        let pending_binding_requests = &mut self.pending_binding_requests;
        let initial_size = pending_binding_requests.len();

        let mut temp = vec![];
        for binding_request in pending_binding_requests.drain(..) {
            if filter_time
                .checked_duration_since(binding_request.timestamp)
                .map(|duration| duration < MAX_BINDING_REQUEST_TIMEOUT)
                .unwrap_or(true)
            {
                temp.push(binding_request);
            }
        }

        *pending_binding_requests = temp;
        let bind_requests_remaining = pending_binding_requests.len();
        let bind_requests_removed = initial_size - bind_requests_remaining;
        if bind_requests_removed > 0 {
            trace!(
                "[{}]: Discarded {} binding requests because they expired, still {} remaining",
                self.get_name(),
                bind_requests_removed,
                bind_requests_remaining,
            );
        }
    }

    /// Assert that the passed `TransactionID` is in our `pendingBindingRequests` and returns the
    /// destination, If the bindingRequest was valid remove it from our pending cache.
    pub(crate) fn handle_inbound_binding_success(
        &mut self,
        id: TransactionId,
    ) -> Option<BindingRequest> {
        self.invalidate_pending_binding_requests(Instant::now());

        let pending_binding_requests = &mut self.pending_binding_requests;
        for i in 0..pending_binding_requests.len() {
            if pending_binding_requests[i].transaction_id == id {
                let valid_binding_request = pending_binding_requests.remove(i);
                return Some(valid_binding_request);
            }
        }
        None
    }

    /// Processes STUN traffic from a remote candidate.
    pub(crate) fn handle_inbound(
        &mut self,
        m: &mut Message,
        local_index: usize,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        if m.typ.method != METHOD_BINDING
            || !(m.typ.class == CLASS_SUCCESS_RESPONSE
                || m.typ.class == CLASS_REQUEST
                || m.typ.class == CLASS_INDICATION)
        {
            trace!(
                "[{}]: unhandled STUN from {} to {} class({}) method({})",
                self.get_name(),
                remote_addr,
                local_index,
                m.typ.class,
                m.typ.method
            );
            return Err(Error::ErrUnhandledStunpacket);
        }

        if self.is_controlling {
            if m.contains(ATTR_ICE_CONTROLLING) {
                debug!(
                    "[{}]: inbound isControlling && a.isControlling == true",
                    self.get_name(),
                );
                return Err(Error::ErrUnexpectedStunrequestMessage);
            } else if m.contains(ATTR_USE_CANDIDATE) {
                debug!(
                    "[{}]: useCandidate && a.isControlling == true",
                    self.get_name(),
                );
                return Err(Error::ErrUnexpectedStunrequestMessage);
            }
        } else if m.contains(ATTR_ICE_CONTROLLED) {
            debug!(
                "[{}]: inbound isControlled && a.isControlling == false",
                self.get_name(),
            );
            return Err(Error::ErrUnexpectedStunrequestMessage);
        }

        let Some(remote_credentials) = &self.ufrag_pwd.remote_credentials else {
            debug!(
                "[{}]: ufrag_pwd.remote_credentials.is_none",
                self.get_name(),
            );
            return Err(Error::ErrPasswordEmpty);
        };

        let mut remote_candidate_index = self.find_remote_candidate(remote_addr);
        if m.typ.class == CLASS_SUCCESS_RESPONSE {
            if let Err(err) = assert_inbound_message_integrity(m, remote_credentials.pwd.as_bytes())
            {
                warn!(
                    "[{}]: discard message from ({}), {}",
                    self.get_name(),
                    remote_addr,
                    err
                );
                return Err(err);
            }

            if let Some(remote_index) = &remote_candidate_index {
                self.handle_success_response(m, local_index, *remote_index, remote_addr);
            } else {
                warn!(
                    "[{}]: discard success message from ({}), no such remote",
                    self.get_name(),
                    remote_addr
                );
                return Err(Error::ErrUnhandledStunpacket);
            }
        } else if m.typ.class == CLASS_REQUEST {
            {
                let username = self.ufrag_pwd.local_credentials.ufrag.clone()
                    + ":"
                    + remote_credentials.ufrag.as_str();
                if let Err(err) = assert_inbound_username(m, &username) {
                    warn!(
                        "[{}]: discard message from ({}), {}",
                        self.get_name(),
                        remote_addr,
                        err
                    );
                    return Err(err);
                } else if let Err(err) = assert_inbound_message_integrity(
                    m,
                    self.ufrag_pwd.local_credentials.pwd.as_bytes(),
                ) {
                    warn!(
                        "[{}]: discard message from ({}), {}",
                        self.get_name(),
                        remote_addr,
                        err
                    );
                    return Err(err);
                }
            }

            if remote_candidate_index.is_none() {
                let (ip, port, network_type) =
                    (remote_addr.ip(), remote_addr.port(), NetworkType::Udp4);

                let prflx_candidate_config = CandidatePeerReflexiveConfig {
                    base_config: CandidateConfig {
                        network: network_type.to_string(),
                        address: ip.to_string(),
                        port,
                        component: self.local_candidates[local_index].component(),
                        ..CandidateConfig::default()
                    },
                    rel_addr: "".to_owned(),
                    rel_port: 0,
                };

                match prflx_candidate_config.new_candidate_peer_reflexive() {
                    Ok(prflx_candidate) => {
                        let _ = self.add_remote_candidate(prflx_candidate);
                        remote_candidate_index = Some(self.remote_candidates.len() - 1);
                    }
                    Err(err) => {
                        error!(
                            "[{}]: Failed to create new remote prflx candidate ({})",
                            self.get_name(),
                            err
                        );
                        return Err(err);
                    }
                };

                debug!(
                    "[{}]: adding a new peer-reflexive candidate: {} ",
                    self.get_name(),
                    remote_addr
                );
            }

            trace!(
                "[{}]: inbound STUN (Request) from {} to {}",
                self.get_name(),
                remote_addr,
                local_index
            );

            if let Some(remote_index) = &remote_candidate_index {
                self.handle_binding_request(m, local_index, *remote_index);
            }
        }

        if let Some(remote_index) = remote_candidate_index {
            self.remote_candidates[remote_index].seen(false);
        }

        Ok(())
    }

    // Processes non STUN traffic from a remote candidate, and returns true if it is an actual
    // remote candidate.
    pub(crate) fn validate_non_stun_traffic(&mut self, remote_addr: SocketAddr) -> bool {
        self.find_remote_candidate(remote_addr)
            .is_some_and(|remote_index| {
                self.remote_candidates[remote_index].seen(false);
                true
            })
    }

    pub(crate) fn send_stun(&mut self, msg: &Message, local_index: usize, remote_index: usize) {
        let peer_addr = self.remote_candidates[remote_index].addr();
        let local_addr = self.local_candidates[local_index].addr();
        let transport_protocol = if self.local_candidates[local_index].network_type().is_tcp() {
            TransportProtocol::TCP
        } else {
            TransportProtocol::UDP
        };

        self.transmits.push_back(TransportMessage {
            now: Instant::now(),
            transport: TransportContext {
                local_addr,
                peer_addr,
                ecn: None,
                transport_protocol,
            },
            message: BytesMut::from(&msg.raw[..]),
        });

        self.local_candidates[local_index].seen(true);
    }

    fn handle_inbound_candidate_msg(
        &mut self,
        local_index: usize,
        buf: &[u8],
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Result<()> {
        if stun::message::is_message(buf) {
            let mut m = Message {
                raw: vec![],
                ..Message::default()
            };
            // Explicitly copy raw buffer so Message can own the memory.
            m.raw.extend_from_slice(buf);

            if let Err(err) = m.decode() {
                warn!(
                    "[{}]: Failed to handle decode ICE from {} to {}: {}",
                    self.get_name(),
                    local_addr,
                    remote_addr,
                    err
                );
                Err(err)
            } else {
                self.handle_inbound(&mut m, local_index, remote_addr)
            }
        } else {
            if !self.validate_non_stun_traffic(remote_addr) {
                warn!(
                    "[{}]: Discarded message, not a valid remote candidate from {}",
                    self.get_name(),
                    remote_addr,
                );
            } else {
                error!(
                    "[{}]: non-STUN traffic message from a valid remote candidate from {}",
                    self.get_name(),
                    remote_addr
                );
            }
            Err(Error::ErrNonStunmessage)
        }
    }

    pub(crate) fn get_name(&self) -> &str {
        if self.is_controlling {
            "controlling"
        } else {
            "controlled"
        }
    }

    pub(crate) fn get_selected_pair(&self) -> Option<usize> {
        self.selected_pair
    }

    pub(crate) fn get_best_available_candidate_pair(&self) -> Option<usize> {
        let mut best_pair_index: Option<usize> = None;

        for (index, p) in self.candidate_pairs.iter().enumerate() {
            if p.state == CandidatePairState::Failed {
                continue;
            }

            if let Some(pair_index) = &mut best_pair_index {
                let b = &self.candidate_pairs[*pair_index];
                if b.priority() < p.priority() {
                    *pair_index = index;
                }
            } else {
                best_pair_index = Some(index);
            }
        }

        best_pair_index
    }

    pub(crate) fn get_best_valid_candidate_pair(&self) -> Option<usize> {
        let mut best_pair_index: Option<usize> = None;

        for (index, p) in self.candidate_pairs.iter().enumerate() {
            if p.state != CandidatePairState::Succeeded {
                continue;
            }

            if let Some(pair_index) = &mut best_pair_index {
                let b = &self.candidate_pairs[*pair_index];
                if b.priority() < p.priority() {
                    *pair_index = index;
                }
            } else {
                best_pair_index = Some(index);
            }
        }

        best_pair_index
    }
}

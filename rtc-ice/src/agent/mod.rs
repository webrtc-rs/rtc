//TODO:#[cfg(test)]
//TODO:mod agent_test;

pub mod agent_config;
pub mod agent_selector;
pub mod agent_stats;

use agent_config::*;
use bytes::BytesMut;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use stun::attributes::*;
use stun::fingerprint::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;
use stun::xoraddr::*;

use crate::candidate::{candidate_pair::*, *};
use crate::rand::*;
use crate::state::*;
use crate::url::*;
use shared::error::*;
use shared::{Protocol, Transmit, TransportContext};

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

#[derive(Default)]
pub(crate) struct UfragPwd {
    pub(crate) local_ufrag: String,
    pub(crate) local_pwd: String,
    pub(crate) remote_ufrag: String,
    pub(crate) remote_pwd: String,
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

/// Represents the ICE agent.
pub struct Agent {
    pub(crate) tie_breaker: u64,
    pub(crate) is_controlling: bool,
    pub(crate) lite: bool,

    pub(crate) start_time: Instant,

    pub(crate) connection_state: ConnectionState,

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

    pub(crate) candidate_types: Vec<CandidateType>,
    pub(crate) urls: Vec<Url>,

    pub(crate) transmits: VecDeque<Transmit<BytesMut>>,
}

impl Agent {
    /// Creates a new Agent.
    pub fn new(config: AgentConfig) -> Result<Self> {
        let candidate_types = if config.candidate_types.is_empty() {
            default_candidate_types()
        } else {
            config.candidate_types.clone()
        };

        if config.lite && (candidate_types.len() != 1 || candidate_types[0] != CandidateType::Host)
        {
            return Err(Error::ErrLiteUsingNonHostCandidates);
        }
        if !config.lite {
            return Err(Error::ErrLiteSupportOnly);
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

            ufrag_pwd: UfragPwd::default(),

            local_candidates: vec![],
            remote_candidates: vec![],

            // LRU of outbound Binding request Transaction IDs
            pending_binding_requests: vec![],

            candidate_types,
            urls: config.urls.clone(),

            transmits: VecDeque::new(),
        };

        // Restart is also used to initialize the agent for the first time
        if let Err(err) = agent.restart(config.local_ufrag, config.local_pwd, false) {
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

        for remote_cand in 0..self.remote_candidates.len() {
            self.add_pair(self.local_candidates.len() - 1, remote_cand);
        }

        self.request_connectivity_check();

        Ok(())
    }

    /// Adds a new remote candidate.
    pub fn add_remote_candidate(&mut self, c: Candidate) -> Result<()> {
        // If we have a mDNS Candidate lets fully resolve it before adding it locally
        if c.candidate_type() == CandidateType::Host && c.address().ends_with(".local") {
            log::warn!(
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

        for local_cand in 0..self.local_candidates.len() {
            self.add_pair(local_cand, self.remote_candidates.len() - 1);
        }

        self.request_connectivity_check();

        Ok(())
    }

    /// Returns the local user credentials.
    pub fn get_local_user_credentials(&self) -> (String, String) {
        (
            self.ufrag_pwd.local_ufrag.clone(),
            self.ufrag_pwd.local_pwd.clone(),
        )
    }

    /// Returns the remote user credentials.
    pub fn get_remote_user_credentials(&self) -> (String, String) {
        (
            self.ufrag_pwd.remote_ufrag.clone(),
            self.ufrag_pwd.remote_pwd.clone(),
        )
    }

    pub fn poll_transmit(&mut self) -> Option<Transmit<BytesMut>> {
        self.transmits.pop_front()
    }

    /// Cleans up the Agent.
    pub fn close(&mut self) -> Result<()> {
        self.delete_all_candidates(false);
        self.update_connection_state(ConnectionState::Closed);

        Ok(())
    }

    /// Returns the selected pair or none if there is none
    pub fn get_selected_candidate_pair(&self) -> Option<usize> {
        //TODO:
        self.get_selected_pair()
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

        self.ufrag_pwd.remote_ufrag = remote_ufrag;
        self.ufrag_pwd.remote_pwd = remote_pwd;
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
        self.ufrag_pwd.local_ufrag = ufrag;
        self.ufrag_pwd.local_pwd = pwd;
        self.ufrag_pwd.remote_ufrag = String::new();
        self.ufrag_pwd.remote_pwd = String::new();

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

    // Returns the local candidates.
    pub(crate) fn get_local_candidates(&self) -> &[Candidate] {
        &self.local_candidates
    }

    pub(crate) fn start_connectivity_checks(
        &mut self,
        is_controlling: bool,
        remote_ufrag: String,
        remote_pwd: String,
    ) -> Result<()> {
        log::debug!(
            "Started agent: isControlling? {}, remoteUfrag: {}, remotePwd: {}",
            is_controlling,
            remote_ufrag,
            remote_pwd
        );
        self.set_remote_credentials(remote_ufrag, remote_pwd)?;
        self.is_controlling = is_controlling;
        self.start();

        self.update_connection_state(ConnectionState::Checking);
        self.request_connectivity_check();
        self.connectivity_checks();

        Ok(())
    }

    fn contact(
        &mut self,
        last_connection_state: &mut ConnectionState,
        checking_duration: &mut Instant,
    ) {
        if self.connection_state == ConnectionState::Failed {
            // The connection is currently failed so don't send any checks
            // In the future it may be restarted though
            *last_connection_state = self.connection_state;
            return;
        }
        if self.connection_state == ConnectionState::Checking {
            // We have just entered checking for the first time so update our checking timer
            if *last_connection_state != self.connection_state {
                *checking_duration = Instant::now();
            }

            // We have been in checking longer then Disconnect+Failed timeout, set the connection to Failed
            if Instant::now()
                .checked_duration_since(*checking_duration)
                .unwrap_or_else(|| Duration::from_secs(0))
                > self.disconnected_timeout + self.failed_timeout
            {
                self.update_connection_state(ConnectionState::Failed);
                *last_connection_state = self.connection_state;
                return;
            }
        }

        self.contact_candidates();

        *last_connection_state = self.connection_state;
    }

    fn connectivity_checks(&mut self) {
        const ZERO_DURATION: Duration = Duration::from_secs(0);
        /*TODO: let mut last_connection_state = ConnectionState::Unspecified;
        let mut checking_duration = Instant::now();
        let (check_interval, keepalive_interval, disconnected_timeout, failed_timeout) = (
            self.check_interval,
            self.keepalive_interval,
            self.disconnected_timeout,
            self.failed_timeout,
        );


        let done_and_force_candidate_contact_rx = {
            let mut done_and_force_candidate_contact_rx =
                self.done_and_force_candidate_contact_rx.lock().await;
            done_and_force_candidate_contact_rx.take()
        };*/

        /*TODO:
        if let Some((mut done_rx, mut force_candidate_contact_rx)) =
            done_and_force_candidate_contact_rx
        {
            let ai = Arc::clone(self);
            tokio::spawn(async move {
                loop {
                    let mut interval = DEFAULT_CHECK_INTERVAL;

                    let mut update_interval = |x: Duration| {
                        if x != ZERO_DURATION && (interval == ZERO_DURATION || interval > x) {
                            interval = x;
                        }
                    };

                    match last_connection_state {
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

                    let t = tokio::time::sleep(interval);
                    tokio::pin!(t);

                    tokio::select! {
                        _ = t.as_mut() => {
                            ai.contact(&mut last_connection_state, &mut checking_duration).await;
                        },
                        _ = force_candidate_contact_rx.recv() => {
                            ai.contact(&mut last_connection_state, &mut checking_duration).await;
                        },
                        _ = done_rx.recv() => {
                            return;
                        }
                    }
                }
            });
        }
         */
    }

    pub(crate) fn update_connection_state(&mut self, new_state: ConnectionState) {
        if self.connection_state != new_state {
            // Connection has gone to failed, release all gathered candidates
            if new_state == ConnectionState::Failed {
                self.delete_all_candidates(false);
            }

            log::info!(
                "[{}]: Setting new connection state: {}",
                self.get_name(),
                new_state
            );
            self.connection_state = new_state;

            // Call handler after finishing current task since we may be holding the agent lock
            // and the handler may also require it
            /*TODO:{
                let chan_state_tx = self.chan_state_tx.lock().await;
                if let Some(tx) = &*chan_state_tx {
                    let _ = tx.send(new_state).await;
                }
            }*/
        }
    }

    pub(crate) fn set_selected_pair(&mut self, selected_pair: Option<usize>) {
        if let Some(pair_index) = selected_pair {
            log::trace!(
                "[{}]: Set selected candidate pair: {:?}",
                self.get_name(),
                self.candidate_pairs[pair_index]
            );

            let p = &mut self.candidate_pairs[pair_index];
            p.nominated = true;
            self.selected_pair = Some(pair_index);

            self.update_connection_state(ConnectionState::Connected);

            // Notify when the selected pair changes
            /*TODO:{
                let chan_candidate_pair_tx = self.chan_candidate_pair_tx.lock().await;
                if let Some(tx) = &*chan_candidate_pair_tx {
                    let _ = tx.send(()).await;
                }
            }*/

            // Signal connected
            /*TODO:{
                let mut on_connected_tx = self.on_connected_tx.lock().await;
                on_connected_tx.take();
            }*/
        } else {
            self.selected_pair = None;
        }
    }

    pub(crate) fn ping_all_candidates(&mut self) {
        log::trace!("[{}]: pinging all candidates", self.get_name(),);

        let mut pairs: Vec<(usize, usize)> = vec![];

        {
            let name = self.get_name().to_string();
            if self.candidate_pairs.is_empty() {
                log::warn!(
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
                    log::trace!(
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
            // Only allow transitions to failed if a.failedTimeout is non-zero
            if self.failed_timeout != Duration::from_secs(0) {
                self.failed_timeout += self.disconnected_timeout;
            }

            if self.failed_timeout != Duration::from_secs(0)
                && disconnected_time > self.failed_timeout
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

    fn request_connectivity_check(&self) {
        //TODO: let _ = self.force_candidate_contact_tx.try_send(true);
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

    pub(crate) fn send_binding_request(
        &mut self,
        m: &Message,
        local_index: usize,
        remote_index: usize,
    ) {
        log::trace!(
            "[{}]: ping STUN from {} to {}",
            self.get_name(),
            local_index,
            remote_index
        );

        self.invalidate_pending_binding_requests(Instant::now());
        {
            self.pending_binding_requests.push(BindingRequest {
                timestamp: Instant::now(),
                transaction_id: m.transaction_id,
                destination: self.remote_candidates[remote_index].addr(),
                is_use_candidate: m.contains(ATTR_USE_CANDIDATE),
            });
        }

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
        let local_pwd = self.ufrag_pwd.local_pwd.clone();

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
            log::warn!(
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
        let bind_requests_removed = initial_size - pending_binding_requests.len();
        if bind_requests_removed > 0 {
            log::trace!(
                "[{}]: Discarded {} binding requests because they expired",
                self.get_name(),
                bind_requests_removed
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
    ) {
        if m.typ.method != METHOD_BINDING
            || !(m.typ.class == CLASS_SUCCESS_RESPONSE
                || m.typ.class == CLASS_REQUEST
                || m.typ.class == CLASS_INDICATION)
        {
            log::trace!(
                "[{}]: unhandled STUN from {} to {} class({}) method({})",
                self.get_name(),
                remote_addr,
                local_index,
                m.typ.class,
                m.typ.method
            );
            return;
        }

        if self.is_controlling {
            if m.contains(ATTR_ICE_CONTROLLING) {
                log::debug!(
                    "[{}]: inbound isControlling && a.isControlling == true",
                    self.get_name(),
                );
                return;
            } else if m.contains(ATTR_USE_CANDIDATE) {
                log::debug!(
                    "[{}]: useCandidate && a.isControlling == true",
                    self.get_name(),
                );
                return;
            }
        } else if m.contains(ATTR_ICE_CONTROLLED) {
            log::debug!(
                "[{}]: inbound isControlled && a.isControlling == false",
                self.get_name(),
            );
            return;
        }

        let remote_candidate_index = self.find_remote_candidate(remote_addr);
        if m.typ.class == CLASS_SUCCESS_RESPONSE {
            {
                let ufrag_pwd = &self.ufrag_pwd;
                if let Err(err) =
                    assert_inbound_message_integrity(m, ufrag_pwd.remote_pwd.as_bytes())
                {
                    log::warn!(
                        "[{}]: discard message from ({}), {}",
                        self.get_name(),
                        remote_addr,
                        err
                    );
                    return;
                }
            }

            if let Some(remote_index) = &remote_candidate_index {
                self.handle_success_response(m, local_index, *remote_index, remote_addr);
            } else {
                log::warn!(
                    "[{}]: discard success message from ({}), no such remote",
                    self.get_name(),
                    remote_addr
                );
                return;
            }
        } else if m.typ.class == CLASS_REQUEST {
            {
                let ufrag_pwd = &self.ufrag_pwd;
                let username =
                    ufrag_pwd.local_ufrag.clone() + ":" + ufrag_pwd.remote_ufrag.as_str();
                if let Err(err) = assert_inbound_username(m, &username) {
                    log::warn!(
                        "[{}]: discard message from ({}), {}",
                        self.get_name(),
                        remote_addr,
                        err
                    );
                    return;
                } else if let Err(err) =
                    assert_inbound_message_integrity(m, ufrag_pwd.local_pwd.as_bytes())
                {
                    log::warn!(
                        "[{}]: discard message from ({}), {}",
                        self.get_name(),
                        remote_addr,
                        err
                    );
                    return;
                }
            }

            /*TODO: FIXME
            if remote_candidate.is_none() {
                let (ip, port, network_type) = (remote.ip(), remote.port(), NetworkType::Udp4);

                let prflx_candidate_config = CandidatePeerReflexiveConfig {
                    base_config: CandidateBaseConfig {
                        network: network_type.to_string(),
                        address: ip.to_string(),
                        port,
                        component: local.component(),
                        ..CandidateBaseConfig::default()
                    },
                    rel_addr: "".to_owned(),
                    rel_port: 0,
                };

                match prflx_candidate_config.new_candidate_peer_reflexive() {
                    Ok(prflx_candidate) => remote_candidate = Some(Arc::new(prflx_candidate)),
                    Err(err) => {
                        log::error!(
                            "[{}]: Failed to create new remote prflx candidate ({})",
                            self.get_name(),
                            err
                        );
                        return;
                    }
                };

                log::debug!(
                    "[{}]: adding a new peer-reflexive candidate: {} ",
                    self.get_name(),
                    remote
                );
                if let Some(rc) = &remote_candidate {
                    self.add_remote_candidate_internal(rc).await;
                }
            }*/

            log::trace!(
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
    }

    // Processes non STUN traffic from a remote candidate, and returns true if it is an actual
    // remote candidate.
    pub(crate) fn validate_non_stun_traffic(&mut self, remote_addr: SocketAddr) -> bool {
        self.find_remote_candidate(remote_addr)
            .map_or(false, |remote_index| {
                self.remote_candidates[remote_index].seen(false);
                true
            })
    }

    pub(crate) fn send_stun(&mut self, msg: &Message, local_index: usize, remote_index: usize) {
        let peer_addr = self.remote_candidates[remote_index].addr();
        let local_addr = self.local_candidates[local_index].addr();
        let protocol = if self.local_candidates[local_index].network_type().is_tcp() {
            Protocol::TCP
        } else {
            Protocol::UDP
        };

        self.transmits.push_back(Transmit {
            now: Instant::now(),
            transport: TransportContext {
                local_addr,
                peer_addr,
                ecn: None,
                protocol,
            },
            message: BytesMut::from(&msg.raw[..]),
        });

        self.local_candidates[local_index].seen(true);
    }

    // Runs the candidate using the provided connection.
    /*fn start_candidate(
        &self,
        candidate: &Rc<dyn Candidate>,
        //TODO: _initialized_ch: Option<broadcast::Receiver<()>>,
    ) {
        TODO: let (closed_ch_tx, _closed_ch_rx) = broadcast::channel(1);
        {
            let closed_ch = candidate.get_closed_ch();
            let mut closed = closed_ch.lock().await;
            *closed = Some(closed_ch_tx);
        }

        let _cand = Rc::clone(candidate);
        TODO:if let Some(conn) = candidate.get_conn() {
            let conn = Arc::clone(conn);
            let addr = candidate.addr();
            let ai = Arc::clone(self);
            tokio::spawn(async move {
                let _ = ai
                    .recv_loop(cand, closed_ch_rx, initialized_ch, conn, addr)
                    .await;
            });
        } else
        {
            log::error!("[{}]: Can't start due to conn is_none", self.get_name(),);
        }
    }*/

    pub(super) fn start_on_connection_state_change_routine(
        &mut self,
        /*mut chan_state_rx: mpsc::Receiver<ConnectionState>,
        mut chan_candidate_rx: mpsc::Receiver<Option<Arc<dyn Candidate + Send + Sync>>>,
        mut chan_candidate_pair_rx: mpsc::Receiver<()>,*/
    ) {
        /*TODO:
        let ai = Arc::clone(self);
        tokio::spawn(async move {
            // CandidatePair and ConnectionState are usually changed at once.
            // Blocking one by the other one causes deadlock.
            while chan_candidate_pair_rx.recv().await.is_some() {
                if let (Some(cb), Some(p)) = (
                    &*ai.on_selected_candidate_pair_change_hdlr.load(),
                    &*ai.agent_conn.selected_pair.load(),
                ) {
                    let mut f = cb.lock().await;
                    f(&p.local, &p.remote).await;
                }
            }
        });

        let ai = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    opt_state = chan_state_rx.recv() => {
                        if let Some(s) = opt_state {
                            if let Some(handler) = &*ai.on_connection_state_change_hdlr.load() {
                                let mut f = handler.lock().await;
                                f(s).await;
                            }
                        } else {
                            while let Some(c) = chan_candidate_rx.recv().await {
                                if let Some(handler) = &*ai.on_candidate_hdlr.load() {
                                    let mut f = handler.lock().await;
                                    f(c).await;
                                }
                            }
                            break;
                        }
                    },
                    opt_cand = chan_candidate_rx.recv() => {
                        if let Some(c) = opt_cand {
                            if let Some(handler) = &*ai.on_candidate_hdlr.load() {
                                let mut f = handler.lock().await;
                                f(c).await;
                            }
                        } else {
                            while let Some(s) = chan_state_rx.recv().await {
                                if let Some(handler) = &*ai.on_connection_state_change_hdlr.load() {
                                    let mut f = handler.lock().await;
                                    f(s).await;
                                }
                            }
                            break;
                        }
                    }
                }
            }
        });

         */
    }

    /*TODO fn recv_loop(
        &self,
        _candidate: Rc<dyn Candidate>,
        //mut _closed_ch_rx: broadcast::Receiver<()>,
        //_initialized_ch: Option<broadcast::Receiver<()>>,
        //TODO:conn: Arc<dyn util::Conn + Send + Sync>,
        _addr: SocketAddr,
    ) -> Result<()> {
        if let Some(mut initialized_ch) = initialized_ch {
            tokio::select! {
                _ = initialized_ch.recv() => {}
                _ = closed_ch_rx.recv() => return Err(Error::ErrClosed),
            }
        }

        let mut buffer = vec![0_u8; RECEIVE_MTU];
        let mut n;
        let mut src_addr;
        loop {
            tokio::select! {
                result = conn.recv_from(&mut buffer) => {
                   match result {
                       Ok((num, src)) => {
                            n = num;
                            src_addr = src;
                       }
                       Err(err) => return Err(Error::Other(err.to_string())),
                   }
               },
                _  = closed_ch_rx.recv() => return Err(Error::ErrClosed),
            }

            self.handle_inbound_candidate_msg(&candidate, &buffer[..n], src_addr, addr)
                .await;
        }
        Ok(())
    }*/

    fn handle_inbound_candidate_msg(
        &mut self,
        local_index: usize,
        buf: &[u8],
        src_addr: SocketAddr,
        addr: SocketAddr,
    ) {
        if stun::message::is_message(buf) {
            let mut m = Message {
                raw: vec![],
                ..Message::default()
            };
            // Explicitly copy raw buffer so Message can own the memory.
            m.raw.extend_from_slice(buf);

            if let Err(err) = m.decode() {
                log::warn!(
                    "[{}]: Failed to handle decode ICE from {} to {}: {}",
                    self.get_name(),
                    addr,
                    src_addr,
                    err
                );
            } else {
                self.handle_inbound(&mut m, local_index, src_addr);
            }
        } else if !self.validate_non_stun_traffic(src_addr) {
            log::warn!(
                "[{}]: Discarded message, not a valid remote candidate",
                self.get_name(),
                //c.addr().await //from {}
            );
        } /*TODO: else if let Err(err) = self.buffer.write(buf).await {
              // NOTE This will return packetio.ErrFull if the buffer ever manages to fill up.
              log::warn!("[{}]: failed to write packet: {}", self.get_name(), err);
          }*/
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

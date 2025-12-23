use crate::agent::Agent;
use log::{debug, error, trace, warn};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use stun::attributes::*;
use stun::fingerprint::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;

use crate::attributes::{control::*, priority::*, use_candidate::*};
use crate::candidate::{candidate_pair::*, *};

trait ControllingSelector {
    fn start(&mut self);
    fn contact_candidates(&mut self);
    fn ping_candidate(&mut self, local_index: usize, remote_index: usize);
    fn handle_success_response(
        &mut self,
        m: &Message,
        local_index: usize,
        remote_index: usize,
        remote_addr: SocketAddr,
    );
    fn handle_binding_request(&mut self, m: &Message, local_index: usize, remote_index: usize);
}

trait ControlledSelector {
    fn start(&mut self);
    fn contact_candidates(&mut self);
    fn ping_candidate(&mut self, local_index: usize, remote_index: usize);
    fn handle_success_response(
        &mut self,
        m: &Message,
        local_index: usize,
        remote_index: usize,
        remote_addr: SocketAddr,
    );
    fn handle_binding_request(&mut self, m: &Message, local_index: usize, remote_index: usize);
}

impl Agent {
    fn is_nominatable(&self, index: usize, is_local: bool) -> bool {
        let start_time = self.start_time;
        let c = if is_local {
            &self.local_candidates[index]
        } else {
            &self.remote_candidates[index]
        };
        match c.candidate_type() {
            CandidateType::Host => {
                Instant::now()
                    .checked_duration_since(start_time)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    .as_nanos()
                    > self.host_acceptance_min_wait.as_nanos()
            }
            CandidateType::ServerReflexive => {
                Instant::now()
                    .checked_duration_since(start_time)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    .as_nanos()
                    > self.srflx_acceptance_min_wait.as_nanos()
            }
            CandidateType::PeerReflexive => {
                Instant::now()
                    .checked_duration_since(start_time)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    .as_nanos()
                    > self.prflx_acceptance_min_wait.as_nanos()
            }
            CandidateType::Relay => {
                Instant::now()
                    .checked_duration_since(start_time)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    .as_nanos()
                    > self.relay_acceptance_min_wait.as_nanos()
            }
            CandidateType::Unspecified => {
                error!(
                    "is_nominatable invalid candidate type {}",
                    c.candidate_type()
                );
                false
            }
        }
    }

    fn nominate_pair(&mut self) {
        let result = {
            let Some(remote_credentials) = &self.ufrag_pwd.remote_credentials else {
                error!("ufrag_pwd.remote_credentials is none");
                return;
            };
            if let Some(pair_index) = &self.nominated_pair {
                let pair = &self.candidate_pairs[*pair_index];
                // The controlling agent MUST include the USE-CANDIDATE attribute in
                // order to nominate a candidate pair (Section 8.1.1).  The controlled
                // agent MUST NOT include the USE-CANDIDATE attribute in a Binding
                // request.

                let (msg, result) = {
                    let username = remote_credentials.ufrag.clone()
                        + ":"
                        + self.ufrag_pwd.local_credentials.ufrag.as_str();
                    let mut msg = Message::new();
                    let result = msg.build(&[
                        Box::new(BINDING_REQUEST),
                        Box::new(TransactionId::new()),
                        Box::new(Username::new(ATTR_USERNAME, username)),
                        Box::<UseCandidateAttr>::default(),
                        Box::new(AttrControlling(self.tie_breaker)),
                        Box::new(PriorityAttr(pair.local_priority)),
                        Box::new(MessageIntegrity::new_short_term_integrity(
                            remote_credentials.pwd.clone(),
                        )),
                        Box::new(FINGERPRINT),
                    ]);
                    (msg, result)
                };

                if let Err(err) = result {
                    error!("{}", err);
                    None
                } else {
                    trace!(
                        "ping STUN (nominate candidate pair from {} to {}",
                        self.local_candidates[pair.local_index],
                        self.remote_candidates[pair.remote_index],
                    );
                    let local = pair.local_index;
                    let remote = pair.remote_index;
                    Some((msg, local, remote))
                }
            } else {
                None
            }
        };

        if let Some((msg, local, remote)) = result {
            self.send_binding_request(&msg, local, remote);
        }
    }

    pub(crate) fn start(&mut self) {
        if self.is_controlling {
            ControllingSelector::start(self);
        } else {
            ControlledSelector::start(self);
        }
    }

    pub(crate) fn contact_candidates(&mut self) {
        if self.is_controlling {
            ControllingSelector::contact_candidates(self);
        } else {
            ControlledSelector::contact_candidates(self);
        }
    }

    pub(crate) fn ping_candidate(&mut self, local_index: usize, remote_index: usize) {
        trace!("[{}]: ping_candidate", self.get_name());

        if self.is_controlling {
            ControllingSelector::ping_candidate(self, local_index, remote_index);
        } else {
            ControlledSelector::ping_candidate(self, local_index, remote_index);
        }
    }

    pub(crate) fn handle_success_response(
        &mut self,
        m: &Message,
        local_index: usize,
        remote_index: usize,
        remote_addr: SocketAddr,
    ) {
        if self.is_controlling {
            ControllingSelector::handle_success_response(
                self,
                m,
                local_index,
                remote_index,
                remote_addr,
            );
        } else {
            ControlledSelector::handle_success_response(
                self,
                m,
                local_index,
                remote_index,
                remote_addr,
            );
        }
    }

    pub(crate) fn handle_binding_request(
        &mut self,
        m: &Message,
        local_index: usize,
        remote_index: usize,
    ) {
        if self.is_controlling {
            ControllingSelector::handle_binding_request(self, m, local_index, remote_index);
        } else {
            ControlledSelector::handle_binding_request(self, m, local_index, remote_index);
        }
    }
}

impl ControllingSelector for Agent {
    fn start(&mut self) {
        self.nominated_pair = None;
        self.start_time = Instant::now();
    }

    fn contact_candidates(&mut self) {
        // A lite selector should not contact candidates
        if self.lite {
            // This only happens if both peers are lite. See RFC 8445 S6.1.1 and S6.2
            trace!("now falling back to full agent");
        }

        let nominated_pair_is_some = self.nominated_pair.is_some();

        if self.get_selected_pair().is_some() {
            if self.validate_selected_pair() {
                self.check_keepalive();
            }
        } else if nominated_pair_is_some {
            self.nominate_pair();
        } else {
            let has_nominated_pair = if let Some(pair_index) = self.get_best_valid_candidate_pair()
            {
                let p = self.candidate_pairs[pair_index];
                self.is_nominatable(p.local_index, true)
                    && self.is_nominatable(p.remote_index, false)
            } else {
                false
            };

            if has_nominated_pair {
                if let Some(pair_index) = self.get_best_valid_candidate_pair() {
                    let p = &mut self.candidate_pairs[pair_index];
                    trace!(
                        "Nominatable pair found, nominating ({}, {})",
                        self.local_candidates[p.local_index],
                        self.remote_candidates[p.remote_index],
                    );
                    p.nominated = true;
                    self.nominated_pair = Some(pair_index);
                }

                self.nominate_pair();
            } else {
                self.ping_all_candidates();
            }
        }
    }

    fn ping_candidate(&mut self, local_index: usize, remote_index: usize) {
        let (msg, result) = {
            let Some(remote_credentials) = &self.ufrag_pwd.remote_credentials else {
                error!("ufrag_pwd.remote_credentials is none");
                return;
            };

            let username = remote_credentials.ufrag.clone()
                + ":"
                + self.ufrag_pwd.local_credentials.ufrag.as_str();
            let mut msg = Message::new();
            let result = msg.build(&[
                Box::new(BINDING_REQUEST),
                Box::new(TransactionId::new()),
                Box::new(Username::new(ATTR_USERNAME, username)),
                Box::new(AttrControlling(self.tie_breaker)),
                Box::new(PriorityAttr(self.local_candidates[local_index].priority())),
                Box::new(MessageIntegrity::new_short_term_integrity(
                    remote_credentials.pwd.clone(),
                )),
                Box::new(FINGERPRINT),
            ]);
            (msg, result)
        };

        if let Err(err) = result {
            error!("{}", err);
        } else {
            self.send_binding_request(&msg, local_index, remote_index);
        }
    }

    fn handle_success_response(
        &mut self,
        m: &Message,
        local_index: usize,
        remote_index: usize,
        remote_addr: SocketAddr,
    ) {
        if let Some(pending_request) = self.handle_inbound_binding_success(m.transaction_id) {
            let transaction_addr = pending_request.destination;

            // Assert that NAT is not symmetric
            // https://tools.ietf.org/html/rfc8445#section-7.2.5.2.1
            if transaction_addr != remote_addr {
                debug!("discard message: transaction source and destination does not match expected({}), actual({})", transaction_addr, remote_index);
                return;
            }

            trace!(
                "inbound STUN (SuccessResponse) from {} to {}",
                remote_index,
                local_index
            );
            let selected_pair_is_none = self.get_selected_pair().is_none();

            if let Some(pair_index) = self.find_pair(local_index, remote_index) {
                let p = &mut self.candidate_pairs[pair_index];
                p.state = CandidatePairState::Succeeded;
                trace!(
                    "Found valid candidate pair: {}, p.state: {}, isUseCandidate: {}, {}",
                    *p,
                    p.state,
                    pending_request.is_use_candidate,
                    selected_pair_is_none
                );
                if pending_request.is_use_candidate && selected_pair_is_none {
                    self.set_selected_pair(Some(pair_index));
                }
            } else {
                // This shouldn't happen
                error!("Success response from invalid candidate pair");
            }
        } else {
            warn!(
                "discard message from ({}), unknown TransactionID 0x{:?}",
                remote_index, m.transaction_id
            );
        }
    }

    fn handle_binding_request(&mut self, m: &Message, local_index: usize, remote_index: usize) {
        self.send_binding_success(m, local_index, remote_index);
        trace!("controllingSelector: sendBindingSuccess");

        if let Some(pair_index) = self.find_pair(local_index, remote_index) {
            let p = &self.candidate_pairs[pair_index];
            let nominated_pair_is_none = self.nominated_pair.is_none();

            trace!(
                "controllingSelector: after findPair {}, p.state: {}, {}",
                p,
                p.state,
                nominated_pair_is_none,
                //self.get_selected_pair().await.is_none() //, {}
            );
            if p.state == CandidatePairState::Succeeded
                && nominated_pair_is_none
                && self.get_selected_pair().is_none()
            {
                if let Some(best_pair_index) = self.get_best_available_pair() {
                    trace!(
                        "controllingSelector: getBestAvailableCandidatePair {}",
                        best_pair_index
                    );
                    if best_pair_index == pair_index
                        && self.is_nominatable(p.local_index, true)
                        && self.is_nominatable(p.remote_index, false)
                    {
                        trace!("The candidate ({}, {}) is the best candidate available, marking it as nominated",
                            p.local_index, p.remote_index);
                        self.nominated_pair = Some(pair_index);
                        self.nominate_pair();
                    }
                } else {
                    trace!("No best pair available");
                }
            }
        } else {
            trace!("controllingSelector: addPair");
            self.add_pair(local_index, remote_index);
        }
    }
}

impl ControlledSelector for Agent {
    fn start(&mut self) {}

    fn contact_candidates(&mut self) {
        // A lite selector should not contact candidates
        if self.lite {
            self.validate_selected_pair();
        } else if self.get_selected_pair().is_some() {
            if self.validate_selected_pair() {
                self.check_keepalive();
            }
        } else {
            self.ping_all_candidates();
        }
    }

    fn ping_candidate(&mut self, local_index: usize, remote_index: usize) {
        let (msg, result) = {
            let Some(remote_credentials) = &self.ufrag_pwd.remote_credentials else {
                error!("ufrag_pwd.remote_credentials is none");
                return;
            };

            let username = remote_credentials.ufrag.clone()
                + ":"
                + self.ufrag_pwd.local_credentials.ufrag.as_str();
            let mut msg = Message::new();
            let result = msg.build(&[
                Box::new(BINDING_REQUEST),
                Box::new(TransactionId::new()),
                Box::new(Username::new(ATTR_USERNAME, username)),
                Box::new(AttrControlled(self.tie_breaker)),
                Box::new(PriorityAttr(self.local_candidates[local_index].priority())),
                Box::new(MessageIntegrity::new_short_term_integrity(
                    remote_credentials.pwd.clone(),
                )),
                Box::new(FINGERPRINT),
            ]);
            (msg, result)
        };

        if let Err(err) = result {
            error!("{}", err);
        } else {
            self.send_binding_request(&msg, local_index, remote_index);
        }
    }

    fn handle_success_response(
        &mut self,
        m: &Message,
        local_index: usize,
        remote_index: usize,
        remote_addr: SocketAddr,
    ) {
        // https://tools.ietf.org/html/rfc8445#section-7.3.1.5
        // If the controlled agent does not accept the request from the
        // controlling agent, the controlled agent MUST reject the nomination
        // request with an appropriate error code response (e.g., 400)
        // [RFC5389].

        if let Some(pending_request) = self.handle_inbound_binding_success(m.transaction_id) {
            let transaction_addr = pending_request.destination;

            // Assert that NAT is not symmetric
            // https://tools.ietf.org/html/rfc8445#section-7.2.5.2.1
            if transaction_addr != remote_addr {
                debug!("discard message: transaction source and destination does not match expected({}), actual({})", transaction_addr, remote_index);
                return;
            }

            trace!(
                "inbound STUN (SuccessResponse) from {} to {}",
                remote_index,
                local_index
            );

            if let Some(pair_index) = self.find_pair(local_index, remote_index) {
                let p = &mut self.candidate_pairs[pair_index];
                p.state = CandidatePairState::Succeeded;
                trace!("Found valid candidate pair: {}", *p);
            } else {
                // This shouldn't happen
                error!("Success response from invalid candidate pair");
            }
        } else {
            warn!(
                "discard message from ({}), unknown TransactionID 0x{:?}",
                remote_index, m.transaction_id
            );
        }
    }

    fn handle_binding_request(&mut self, m: &Message, local_index: usize, remote_index: usize) {
        if self.find_pair(local_index, remote_index).is_none() {
            self.add_pair(local_index, remote_index);
        }

        if let Some(pair_index) = self.find_pair(local_index, remote_index) {
            let p = &self.candidate_pairs[pair_index];
            let use_candidate = m.contains(ATTR_USE_CANDIDATE);
            if use_candidate {
                // https://tools.ietf.org/html/rfc8445#section-7.3.1.5

                if p.state == CandidatePairState::Succeeded {
                    // If the state of this pair is Succeeded, it means that the check
                    // previously sent by this pair produced a successful response and
                    // generated a valid pair (Section 7.2.5.3.2).  The agent sets the
                    // nominated flag value of the valid pair to true.
                    if self.get_selected_pair().is_none() {
                        self.set_selected_pair(Some(pair_index));
                    }
                    self.send_binding_success(m, local_index, remote_index);
                } else {
                    // If the received Binding request triggered a new check to be
                    // enqueued in the triggered-check queue (Section 7.3.1.4), once the
                    // check is sent and if it generates a successful response, and
                    // generates a valid pair, the agent sets the nominated flag of the
                    // pair to true.  If the request fails (Section 7.2.5.2), the agent
                    // MUST remove the candidate pair from the valid list, set the
                    // candidate pair state to Failed, and set the checklist state to
                    // Failed.
                    self.ping_candidate(local_index, remote_index);
                }
            } else {
                self.send_binding_success(m, local_index, remote_index);
                self.ping_candidate(local_index, remote_index);
            }
        }
    }
}

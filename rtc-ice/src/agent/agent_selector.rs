use crate::agent::Agent;
use crate::agent::agent_config::NominationValueGenerator;
use log::{debug, error, info, trace, warn};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use stun::attributes::*;
use stun::fingerprint::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;

use crate::attributes::{control::*, nomination::*, priority::*, use_candidate::*};
use crate::candidate::{candidate_pair::*, *};
use shared::error::{Error, Result};

trait ControllingSelector {
    fn start(&mut self, now: Instant);
    fn contact_candidates(&mut self, now: Instant);
    fn ping_candidate(&mut self, now: Instant, local_index: usize, remote_index: usize);
    fn handle_success_response(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_index: usize,
        remote_addr: SocketAddr,
    );
    fn handle_binding_request(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_index: usize,
    );
}

trait ControlledSelector {
    fn start(&mut self, now: Instant);
    fn contact_candidates(&mut self, now: Instant);
    fn ping_candidate(&mut self, now: Instant, local_index: usize, remote_index: usize);
    fn handle_success_response(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_index: usize,
        remote_addr: SocketAddr,
    );
    fn handle_binding_request(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_index: usize,
    );
}

impl Agent {
    /// Whether `index` has been waiting long enough to be nominated, as of `now`.
    ///
    /// `now` is supplied by the caller rather than sampled here so that one nomination decision
    /// makes one time observation: both halves of a pair are tested against the same instant.
    fn is_nominatable(&self, now: Instant, index: usize, is_local: bool) -> bool {
        let c = if is_local {
            &self.local_candidates[index]
        } else {
            &self.remote_candidates[index]
        };
        let min_wait = match c.candidate_type() {
            CandidateType::Host => self.host_acceptance_min_wait,
            CandidateType::ServerReflexive => self.srflx_acceptance_min_wait,
            CandidateType::PeerReflexive => self.prflx_acceptance_min_wait,
            CandidateType::Relay => self.relay_acceptance_min_wait,
            CandidateType::Unspecified => {
                error!(
                    "is_nominatable invalid candidate type {}",
                    c.candidate_type()
                );
                return false;
            }
        };
        now.saturating_duration_since(self.start_time) >= min_wait
    }

    pub(crate) fn nominate_pair(&mut self, now: Instant) {
        if let Some(pair_index) = self.nominated_pair {
            // The controlling agent MUST include the USE-CANDIDATE attribute in order to
            // nominate a candidate pair (Section 8.1.1). The controlled agent MUST NOT include
            // the USE-CANDIDATE attribute in a Binding request.
            let _ = self.send_nomination_request(now, pair_index, None);
        }
    }

    /// Sends a nomination (a Binding request with `USE-CANDIDATE`) on `pair_index`, carrying
    /// `nomination_value` when renomination is enabled and the value is non-zero.
    fn send_nomination_request(
        &mut self,
        now: Instant,
        pair_index: usize,
        nomination_value: Option<u32>,
    ) -> Result<()> {
        let pair = self.candidate_pairs[pair_index];
        let msg = {
            let Some(remote_credentials) = &self.ufrag_pwd.remote_credentials else {
                error!("ufrag_pwd.remote_credentials is none");
                return Err(Error::ErrPasswordEmpty);
            };

            let username = remote_credentials.ufrag.clone()
                + ":"
                + self.ufrag_pwd.local_credentials.ufrag.as_str();
            let mut setters: Vec<Box<dyn Setter>> = vec![
                Box::new(BINDING_REQUEST),
                Box::new(TransactionId::new()),
                Box::new(Username::new(ATTR_USERNAME, username)),
                Box::<UseCandidateAttr>::default(),
                Box::new(AttrControlling(self.tie_breaker)),
                Box::new(PriorityAttr(
                    self.local_candidates[pair.local_index].prflx_priority(),
                )),
            ];
            if let Some(value) = nomination_value
                && self.nomination_value_generator.is_some()
                && value > 0
            {
                setters.push(Box::new(NominationSetter {
                    value,
                    attr_type: self.nomination_attribute,
                }));
                trace!(
                    "sending renomination request from {} to {} with nomination value {}",
                    self.local_candidates[pair.local_index],
                    self.remote_candidates[pair.remote_index],
                    value
                );
            }
            setters.push(Box::new(
                MessageIntegrity::new_short_term_integrity_with_provider(
                    remote_credentials.pwd.clone(),
                    self.crypto_provider.crypto(),
                ),
            ));
            setters.push(Box::new(FINGERPRINT));

            let mut msg = Message::new();
            if let Err(err) = msg.build(&setters) {
                error!("failed to build the nomination request: {}", err);
                return Err(err);
            }
            msg
        };

        trace!(
            "ping STUN (nominate candidate pair from {} to {}",
            self.local_candidates[pair.local_index], self.remote_candidates[pair.remote_index],
        );
        self.send_binding_request(now, &msg, pair.local_index, pair.remote_index);
        Ok(())
    }

    /// Lets the application's [`BindingRequestHandler`], if any, take over selection for the pair
    /// a Binding request just came in on.
    fn handle_binding_request_with_custom_handler(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_index: usize,
        pair_index: usize,
    ) {
        let Some(handler) = &self.binding_request_handler else {
            return;
        };

        if handler.call(
            m,
            &self.local_candidates[local_index],
            &self.remote_candidates[remote_index],
            &self.candidate_pairs[pair_index],
        ) {
            if self.lite {
                // Lite agents send no checks, so a pair the handler approved has to be put in
                // the valid list directly.
                self.candidate_pairs[pair_index].state = CandidatePairState::Succeeded;
            }
            self.set_selected_pair(Some(now), Some(pair_index));
        }
    }

    /// Whether the priority rule applies when a nomination arrives for a pair other than the
    /// selected one: always for full agents, opt-in for lite ones.
    fn needs_to_check_priority_on_nominated(&self) -> bool {
        !self.lite || self.enable_use_candidate_check_priority
    }

    /// The next nomination value, or 0 without a generator.
    pub(crate) fn next_nomination_value(&self) -> u32 {
        self.nomination_value_generator
            .as_ref()
            .map_or(0, NominationValueGenerator::generate)
    }

    /// Lets the controlling agent nominate another pair while the connection is up
    /// (draft-thatcher-ice-renomination-01, pion's `RenominateCandidate`).
    ///
    /// The controlled agent switches when it sees the new nomination and answers it; the
    /// controlling agent switches when that answer arrives.
    pub fn renominate_candidate(
        &mut self,
        now: Instant,
        local: &Candidate,
        remote: &Candidate,
    ) -> Result<()> {
        if !self.is_controlling {
            return Err(Error::ErrOnlyControllingAgentCanRenominate);
        }
        if self.nomination_value_generator.is_none() {
            return Err(Error::ErrRenominationNotEnabled);
        }

        let local_index = self.local_candidates.iter().position(|c| c.equal(local));
        let remote_index = self.remote_candidates.iter().position(|c| c.equal(remote));
        let pair_index = match (local_index, remote_index) {
            (Some(local_index), Some(remote_index)) => self.find_pair(local_index, remote_index),
            _ => None,
        }
        .ok_or(Error::ErrCandidatePairNotFound)?;

        let value = self.next_nomination_value();
        self.send_nomination_request(now, pair_index, Some(value))
    }

    /// Pings every pair that has not failed, succeeded ones included, so their round-trip times
    /// stay fresh for automatic renomination. Unlike [`Agent::ping_all_candidates`] it ignores
    /// the binding-request limit: alternate paths are worth probing for as long as we run.
    pub(crate) fn keep_alive_candidates_for_renomination(&mut self, now: Instant) {
        trace!(
            "[{}]: keep alive candidates for renomination",
            self.get_name()
        );

        let mut pairs = vec![];
        for p in &mut self.candidate_pairs {
            match p.state {
                CandidatePairState::Failed => continue,
                CandidatePairState::Waiting => p.state = CandidatePairState::InProgress,
                _ => {}
            }
            pairs.push((p.local_index, p.remote_index));
        }

        for (local_index, remote_index) in pairs {
            self.ping_candidate(now, local_index, remote_index);
        }
    }

    /// A score for how good a succeeded pair is; higher is better. It weighs the candidate
    /// types (host > srflx > prflx > relay), the round-trip time, and whether the pair has
    /// answered recently. Zero for pairs that have not succeeded.
    pub(crate) fn evaluate_candidate_pair_quality(&self, now: Instant, pair_index: usize) -> f64 {
        let pair = &self.candidate_pairs[pair_index];
        if pair.state != CandidatePairState::Succeeded {
            return 0.0;
        }

        fn type_score(t: CandidateType) -> f64 {
            match t {
                CandidateType::Host => 100.0,
                CandidateType::ServerReflexive => 50.0,
                CandidateType::PeerReflexive => 30.0,
                CandidateType::Relay => 10.0,
                CandidateType::Unspecified => 0.0,
            }
        }

        let mut score = (type_score(self.local_candidates[pair.local_index].candidate_type())
            + type_score(self.remote_candidates[pair.remote_index].candidate_type()))
            / 2.0;

        if pair.current_round_trip_time.is_zero() {
            // No RTT yet: assume it is poor.
            score -= 30.0;
        } else {
            // Logarithmic, so very high RTTs do not dominate.
            let rtt_ms = (pair.current_round_trip_time.as_secs_f64() * 1000.0).max(1.0);
            score -= rtt_ms.log10() * 10.0;
        }

        // Stability bonus for a pair that answered in the last five seconds.
        if pair.responses_received > 0
            && let Some(last) = pair.last_response_received_at
            && now.saturating_duration_since(last) < Duration::from_secs(5)
        {
            score += 20.0;
        }

        score
    }

    /// Whether switching from `current` to `candidate` is worth it: a direct path replacing a
    /// relayed one, an RTT better by more than 10 ms, or a quality score better by 15 %.
    pub(crate) fn should_renominate(&self, now: Instant, current: usize, candidate: usize) -> bool {
        let (cur, cand) = (
            &self.candidate_pairs[current],
            &self.candidate_pairs[candidate],
        );
        if current == candidate || cand.state != CandidatePairState::Succeeded {
            return false;
        }

        let is_relay = |p: &CandidatePair| {
            self.local_candidates[p.local_index].candidate_type() == CandidateType::Relay
                || self.remote_candidates[p.remote_index].candidate_type() == CandidateType::Relay
        };
        let is_host_to_host = |p: &CandidatePair| {
            self.local_candidates[p.local_index].candidate_type() == CandidateType::Host
                && self.remote_candidates[p.remote_index].candidate_type() == CandidateType::Host
        };
        if is_relay(cur) && is_host_to_host(cand) {
            debug!("should renominate: relay -> direct connection available");
            return true;
        }

        // Only compare RTTs that were measured.
        if !cur.current_round_trip_time.is_zero()
            && !cand.current_round_trip_time.is_zero()
            && cur.current_round_trip_time > cand.current_round_trip_time
            && cur.current_round_trip_time - cand.current_round_trip_time
                > Duration::from_millis(10)
        {
            debug!("should renominate: RTT improvement");
            return true;
        }

        let current_score = self.evaluate_candidate_pair_quality(now, current);
        let candidate_score = self.evaluate_candidate_pair_quality(now, candidate);
        if candidate_score > current_score * 1.15 {
            debug!(
                "should renominate: quality score improved from {:.2} to {:.2}",
                current_score, candidate_score
            );
            return true;
        }

        false
    }

    /// The succeeded pair with the highest quality score.
    pub(crate) fn find_best_candidate_pair(&self, now: Instant) -> Option<usize> {
        let mut best: Option<(usize, f64)> = None;
        for (index, pair) in self.candidate_pairs.iter().enumerate() {
            if pair.state != CandidatePairState::Succeeded {
                continue;
            }
            let score = self.evaluate_candidate_pair_quality(now, index);
            if best.is_none_or(|(_, best_score)| score > best_score) {
                best = Some((index, score));
            }
        }
        best.map(|(index, _)| index)
    }

    /// Controlling side: renominates by itself when a clearly better pair has appeared, at
    /// most once per renomination interval.
    fn check_for_automatic_renomination(&mut self, now: Instant) {
        if !self.automatic_renomination || self.nomination_value_generator.is_none() {
            return;
        }

        if now.saturating_duration_since(self.start_time) < self.renomination_interval {
            return;
        }
        if let Some(last) = self.last_renomination_time
            && now.saturating_duration_since(last) < self.renomination_interval
        {
            return;
        }

        let Some(current) = self.get_selected_pair() else {
            return;
        };
        let Some(best) = self.find_best_candidate_pair(now) else {
            return;
        };

        if self.should_renominate(now, current, best) {
            info!(
                "[{}]: automatic renomination: switching from {} to {}",
                self.get_name(),
                self.candidate_pairs[current],
                self.candidate_pairs[best]
            );
            // Rate-limit even a failed attempt.
            self.last_renomination_time = Some(now);

            let value = self.next_nomination_value();
            if let Err(err) = self.send_nomination_request(now, best, Some(value)) {
                error!("failed to trigger automatic renomination: {}", err);
            }
        }
    }

    /// Controlled side: whether to honour this nomination. A nomination without a value is the
    /// ordinary RFC 8445 one; with a value, the highest value seen wins.
    pub(crate) fn should_accept_nomination(&mut self, nomination_value: Option<u32>) -> bool {
        let Some(value) = nomination_value else {
            return true;
        };

        if self.last_nomination.is_none_or(|last| value > last) {
            self.last_nomination = Some(value);
            trace!("accepting nomination with value {}", value);
            true
        } else {
            trace!(
                "rejecting nomination value {} (current is {:?})",
                value, self.last_nomination
            );
            false
        }
    }

    /// Controlled side: whether a nomination of `pair_index` should replace the selected pair.
    pub(crate) fn should_switch_selected_pair(
        &self,
        pair_index: usize,
        selected: Option<usize>,
        nomination_value: Option<u32>,
    ) -> bool {
        match selected {
            // No current selection: accept.
            None => true,
            // Same pair: nothing to do.
            Some(selected) if selected == pair_index => false,
            // A renomination value means the controlling side decides, not priority.
            Some(_) if nomination_value.is_some() => true,
            // Ordinary nomination: only a strictly better pair replaces the selected one
            // (lite agents accept any, unless configured to check).
            Some(selected) => {
                !self.needs_to_check_priority_on_nominated()
                    || self.candidate_pairs[selected].priority()
                        < self.candidate_pairs[pair_index].priority()
            }
        }
    }

    /// A lite agent never sends checks. Facing a full agent it only validates the pair the
    /// peer selects; facing another lite agent nobody sends anything, so it takes the best
    /// available pair itself.
    fn lite_contact_candidates(&mut self, now: Instant) {
        if !self.remote_lite {
            self.validate_selected_pair(now);
            return;
        }

        let mut selected = self.get_selected_pair();
        if selected.is_some() {
            self.validate_selected_pair(now);
            selected = self.get_selected_pair();
        }

        let Some(pair_index) = self.get_best_available_pair() else {
            return;
        };
        if selected == Some(pair_index) {
            return;
        }

        // The pair becomes valid without a connectivity check, so start its liveness window
        // now: a later candidate update must not fail a pair that was never seen.
        let remote_index = self.candidate_pairs[pair_index].remote_index;
        self.candidate_pairs[pair_index].state = CandidatePairState::Succeeded;
        self.remote_candidates[remote_index].seen(now, false);
        self.set_selected_pair(Some(now), Some(pair_index));
    }

    pub(crate) fn start(&mut self, now: Instant) {
        if self.is_controlling {
            ControllingSelector::start(self, now);
        } else {
            ControlledSelector::start(self, now);
        }
    }

    pub(crate) fn contact_candidates(&mut self, now: Instant) {
        if self.lite {
            self.lite_contact_candidates(now);
        } else if self.is_controlling {
            ControllingSelector::contact_candidates(self, now);
        } else {
            ControlledSelector::contact_candidates(self, now);
        }
    }

    pub(crate) fn ping_candidate(&mut self, now: Instant, local_index: usize, remote_index: usize) {
        trace!("[{}]: ping_candidate", self.get_name());

        // Lite agents answer checks; they never send any.
        if self.lite {
            return;
        }

        if self.is_controlling {
            ControllingSelector::ping_candidate(self, now, local_index, remote_index);
        } else {
            ControlledSelector::ping_candidate(self, now, local_index, remote_index);
        }
    }

    pub(crate) fn handle_success_response(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_index: usize,
        remote_addr: SocketAddr,
    ) {
        if self.lite {
            return;
        }

        if self.is_controlling {
            ControllingSelector::handle_success_response(
                self,
                now,
                m,
                local_index,
                remote_index,
                remote_addr,
            );
        } else {
            ControlledSelector::handle_success_response(
                self,
                now,
                m,
                local_index,
                remote_index,
                remote_addr,
            );
        }
    }

    pub(crate) fn handle_binding_request(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_index: usize,
    ) {
        if self.is_controlling {
            ControllingSelector::handle_binding_request(self, now, m, local_index, remote_index);
        } else {
            ControlledSelector::handle_binding_request(self, now, m, local_index, remote_index);
        }
    }
}

impl ControllingSelector for Agent {
    fn start(&mut self, now: Instant) {
        self.nominated_pair = None;
        self.start_time = now;
    }

    fn contact_candidates(&mut self, now: Instant) {
        let nominated_pair_is_some = self.nominated_pair.is_some();

        if self.get_selected_pair().is_some() {
            if self.validate_selected_pair(now) {
                self.check_keepalive(now);

                // With automatic renomination, keep every alternate path tested with fresh
                // RTTs so there is something to switch to.
                if self.automatic_renomination && self.nomination_value_generator.is_some() {
                    self.keep_alive_candidates_for_renomination(now);
                }

                self.check_for_automatic_renomination(now);
            }
        } else if nominated_pair_is_some {
            self.nominate_pair(now);
        } else {
            let has_nominated_pair = if let Some(pair_index) = self.get_best_valid_candidate_pair()
            {
                let p = self.candidate_pairs[pair_index];
                self.is_nominatable(now, p.local_index, true)
                    && self.is_nominatable(now, p.remote_index, false)
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

                self.nominate_pair(now);
            } else {
                self.ping_all_candidates(now);
            }
        }
    }

    fn ping_candidate(&mut self, now: Instant, local_index: usize, remote_index: usize) {
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
                Box::new(PriorityAttr(
                    self.local_candidates[local_index].prflx_priority(),
                )),
                Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                    remote_credentials.pwd.clone(),
                    self.crypto_provider.crypto(),
                )),
                Box::new(FINGERPRINT),
            ]);
            (msg, result)
        };

        if let Err(err) = result {
            error!("{}", err);
        } else {
            self.send_binding_request(now, &msg, local_index, remote_index);
        }
    }

    fn handle_success_response(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_index: usize,
        remote_addr: SocketAddr,
    ) {
        if let Some(pending_request) = self.handle_inbound_binding_success(now, m.transaction_id) {
            let transaction_addr = pending_request.destination;

            // Assert that NAT is not symmetric
            // https://tools.ietf.org/html/rfc8445#section-7.2.5.2.1
            if transaction_addr != remote_addr {
                debug!(
                    "discard message: transaction source and destination does not match expected({}), actual({})",
                    transaction_addr, remote_index
                );
                return;
            }

            trace!(
                "inbound STUN (SuccessResponse) from {} to {}",
                self.remote_candidates[remote_index], self.local_candidates[local_index]
            );
            let selected_pair_is_none = self.get_selected_pair().is_none();

            if let Some(pair_index) = self.find_pair(local_index, remote_index) {
                let p = &mut self.candidate_pairs[pair_index];
                p.state = CandidatePairState::Succeeded;

                // Calculate RTT and track response received
                let rtt = now.duration_since(pending_request.timestamp);
                p.on_response_received(rtt);
                p.last_response_received_at = Some(now);

                trace!(
                    "Found valid candidate pair: {} (local_addr {} <-> remote_addr {}), p.state: {}, isUseCandidate: {}, {}, rtt: {:.3}ms",
                    *p,
                    self.local_candidates[p.local_index].addr(),
                    self.remote_candidates[p.remote_index].addr(),
                    p.state,
                    pending_request.is_use_candidate,
                    selected_pair_is_none,
                    rtt.as_millis()
                );
                if pending_request.is_use_candidate {
                    if let Some(value) = pending_request.nomination_value {
                        // A renomination: the controlled side accepted it, so switch to the
                        // pair even though one is already selected.
                        info!(
                            "renomination success response received for pair {} (nomination value: {}), switching to this pair",
                            self.candidate_pairs[pair_index], value
                        );
                        self.set_selected_pair(Some(now), Some(pair_index));
                    } else if selected_pair_is_none {
                        self.set_selected_pair(Some(now), Some(pair_index));
                    }
                }
            } else {
                // This shouldn't happen
                error!("Success response from invalid candidate pair");
            }
        } else {
            warn!(
                "discard message from ({}), unknown TransactionID 0x{:?}",
                self.remote_candidates[remote_index], m.transaction_id
            );
        }
    }

    fn handle_binding_request(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_index: usize,
    ) {
        self.send_binding_success(now, m, local_index, remote_index);
        trace!("controllingSelector: sendBindingSuccess");

        if let Some(pair_index) = self.find_pair(local_index, remote_index) {
            // Track request received on the candidate pair
            self.candidate_pairs[pair_index].on_request_received();

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
                        && self.is_nominatable(now, p.local_index, true)
                        && self.is_nominatable(now, p.remote_index, false)
                    {
                        trace!(
                            "The candidate ({}, {}) is the best candidate available, marking it as nominated",
                            p.local_index, p.remote_index
                        );
                        self.nominated_pair = Some(pair_index);
                        self.nominate_pair(now);
                    }
                } else {
                    trace!("No best pair available");
                }
            }
            self.handle_binding_request_with_custom_handler(
                now,
                m,
                local_index,
                remote_index,
                pair_index,
            );
        } else {
            trace!("controllingSelector: addPair");
            self.add_pair(local_index, remote_index);
            // Track request received on newly created pair
            if let Some(pair_index) = self.find_pair(local_index, remote_index) {
                self.candidate_pairs[pair_index].on_request_received();
            }
        }
    }
}

impl ControlledSelector for Agent {
    fn start(&mut self, _now: Instant) {
        self.last_nomination = None;
    }

    fn contact_candidates(&mut self, now: Instant) {
        if self.get_selected_pair().is_some() {
            if self.validate_selected_pair(now) {
                self.check_keepalive(now);
            }
        } else {
            self.ping_all_candidates(now);
        }
    }

    fn ping_candidate(&mut self, now: Instant, local_index: usize, remote_index: usize) {
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
                Box::new(PriorityAttr(
                    self.local_candidates[local_index].prflx_priority(),
                )),
                Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                    remote_credentials.pwd.clone(),
                    self.crypto_provider.crypto(),
                )),
                Box::new(FINGERPRINT),
            ]);
            (msg, result)
        };

        if let Err(err) = result {
            error!("{}", err);
        } else {
            self.send_binding_request(now, &msg, local_index, remote_index);
        }
    }

    fn handle_success_response(
        &mut self,
        now: Instant,
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

        if let Some(pending_request) = self.handle_inbound_binding_success(now, m.transaction_id) {
            let transaction_addr = pending_request.destination;

            // Assert that NAT is not symmetric
            // https://tools.ietf.org/html/rfc8445#section-7.2.5.2.1
            if transaction_addr != remote_addr {
                debug!(
                    "discard message: transaction source and destination does not match expected({}), actual({})",
                    transaction_addr, remote_index
                );
                return;
            }

            trace!(
                "inbound STUN (SuccessResponse) from {} to {}",
                self.remote_candidates[remote_index], self.local_candidates[local_index]
            );

            if let Some(pair_index) = self.find_pair(local_index, remote_index) {
                let p = &mut self.candidate_pairs[pair_index];
                p.state = CandidatePairState::Succeeded;

                // Calculate RTT and track response received
                let rtt = now.duration_since(pending_request.timestamp);
                p.on_response_received(rtt);
                p.last_response_received_at = Some(now);

                trace!(
                    "Found valid candidate pair: {} (local_addr {} <-> remote_addr {}), rtt: {:.3}ms",
                    *p,
                    self.local_candidates[p.local_index].addr(),
                    self.remote_candidates[p.remote_index].addr(),
                    rtt.as_millis()
                );

                // The controlling side nominated this pair before our own check on it
                // succeeded; now that it has, select it.
                if self.candidate_pairs[pair_index].nominate_on_binding_success {
                    let selected = self.get_selected_pair();
                    let accept = match selected {
                        None => true,
                        Some(selected) => {
                            selected != pair_index
                                && (!self.needs_to_check_priority_on_nominated()
                                    || self.candidate_pairs[selected].priority()
                                        <= self.candidate_pairs[pair_index].priority())
                        }
                    };
                    if accept {
                        self.set_selected_pair(Some(now), Some(pair_index));
                    } else if selected != Some(pair_index) {
                        trace!("ignore nominate new pair, a pair is already nominated");
                    }
                }
            } else {
                // This shouldn't happen
                error!("Success response from invalid candidate pair");
            }
        } else {
            warn!(
                "discard message from ({}), unknown TransactionID 0x{:?}",
                self.remote_candidates[remote_index], m.transaction_id
            );
        }
    }

    fn handle_binding_request(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_index: usize,
    ) {
        let pair_index = match self.find_pair(local_index, remote_index) {
            Some(pair_index) => pair_index,
            None => {
                self.add_pair(local_index, remote_index);
                self.candidate_pairs.len() - 1
            }
        };
        self.candidate_pairs[pair_index].on_request_received();

        let has_use_candidate = m.contains(ATTR_USE_CANDIDATE);
        let mut nomination = NominationAttribute::default();
        let nomination_value = nomination
            .get_from_with_type(m, self.nomination_attribute)
            .ok()
            .map(|()| nomination.value);

        if has_use_candidate || nomination_value.is_some() {
            // https://tools.ietf.org/html/rfc8445#section-7.3.1.5

            // A renomination that is not newer than one already accepted is answered but
            // otherwise ignored.
            if !self.should_accept_nomination(nomination_value) {
                trace!("rejecting nomination request due to renomination rules");
                self.send_binding_success(now, m, local_index, remote_index);
                return;
            }

            if self.lite {
                // A lite agent never sends its own check, so an accepted nomination puts the
                // pair straight into the valid list (RFC 8445 §7.3.2).
                self.candidate_pairs[pair_index].state = CandidatePairState::Succeeded;
            }

            if self.candidate_pairs[pair_index].state == CandidatePairState::Succeeded {
                // The check previously sent on this pair produced a successful response and
                // a valid pair (Section 7.2.5.3.2), so the nomination takes effect.
                let selected = self.get_selected_pair();
                if self.should_switch_selected_pair(pair_index, selected, nomination_value) {
                    self.set_selected_pair(Some(now), Some(pair_index));
                } else {
                    trace!("ignore nominate new pair, a pair is already nominated");
                }
            } else {
                // If the received request triggered a new check (Section 7.3.1.4), the pair is
                // nominated once that check succeeds. If it fails (Section 7.2.5.2), the pair
                // is removed from the valid list.
                self.candidate_pairs[pair_index].nominate_on_binding_success = true;
            }
        }

        self.send_binding_success(now, m, local_index, remote_index);

        // Lite agents never send checks (RFC 8445 §7). For full agents a triggered check is
        // only useful while the pair is being established (§7.3.1.4); once it has succeeded
        // and a pair is selected, answering every request with a check makes the two sides
        // ping each other in a busy loop. Consent freshness is the keepalive timer's job.
        if !self.lite
            && (self.candidate_pairs[pair_index].state != CandidatePairState::Succeeded
                || self.get_selected_pair().is_none())
        {
            self.ping_candidate(now, local_index, remote_index);
        }

        self.handle_binding_request_with_custom_handler(
            now,
            m,
            local_index,
            remote_index,
            pair_index,
        );
    }
}

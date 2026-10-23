use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::*;
use crate::mdns::*;
use crate::network_type::NetworkType;
use crate::url::*;

/// The interval at which the agent performs candidate checks in the connecting phase.
pub(crate) const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_millis(200);

/// The interval used to keep candidates alive.
pub(crate) const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);

/// The default time till an Agent transitions disconnected.
pub(crate) const DEFAULT_DISCONNECTED_TIMEOUT: Duration = Duration::from_secs(5);

/// The default time till an Agent transitions to failed after disconnected.
pub(crate) const DEFAULT_FAILED_TIMEOUT: Duration = Duration::from_secs(25);

/// Wait time before nominating a host candidate.
pub(crate) const DEFAULT_HOST_ACCEPTANCE_MIN_WAIT: Duration = Duration::from_secs(0);

/// Wait time before nominating a srflx candidate.
pub(crate) const DEFAULT_SRFLX_ACCEPTANCE_MIN_WAIT: Duration = Duration::from_millis(500);

/// Wait time before nominating a prflx candidate.
pub(crate) const DEFAULT_PRFLX_ACCEPTANCE_MIN_WAIT: Duration = Duration::from_millis(1000);

/// Wait time before nominating a relay candidate.
pub(crate) const DEFAULT_RELAY_ACCEPTANCE_MIN_WAIT: Duration = Duration::from_millis(2000);

/// Max binding request before considering a pair failed.
pub(crate) const DEFAULT_MAX_BINDING_REQUESTS: u16 = 7;

/// The number of bytes that can be buffered before we start to error.
pub(crate) const MAX_BUFFER_SIZE: usize = 1000 * 1000; // 1MB

/// Wait time before binding requests can be deleted.
pub(crate) const MAX_BINDING_REQUEST_TIMEOUT: Duration = Duration::from_millis(4000);

/// How long to wait between automatic renomination evaluations unless configured otherwise
/// (pion's default, matching libwebrtc).
pub(crate) const DEFAULT_RENOMINATION_INTERVAL: Duration = Duration::from_secs(3);

/// Produces the values the controlling agent stamps on renomination requests.
///
/// Each call must return a larger value than the one before it: the controlled agent keeps only
/// the nomination with the highest value ("last nomination wins"). Zero means "no renomination
/// value" and is never sent, so generators should start at 1.
#[derive(Clone)]
pub struct NominationValueGenerator(Arc<dyn Fn() -> u32 + Send + Sync>);

impl NominationValueGenerator {
    /// A generator backed by `f`.
    pub fn new(f: impl Fn() -> u32 + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// A generator that starts at 1 and increments on every call (pion's
    /// `DefaultNominationValueGenerator`).
    pub fn incrementing() -> Self {
        let counter = AtomicU32::new(0);
        Self::new(move || counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1))
    }

    /// The next nomination value.
    pub fn generate(&self) -> u32 {
        (self.0)()
    }
}

impl std::fmt::Debug for NominationValueGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NominationValueGenerator")
    }
}

type BindingRequestFn =
    dyn Fn(&stun::message::Message, &Candidate, &Candidate, &CandidatePair) -> bool + Send + Sync;

/// A hook run for every Binding request an agent answers (pion's `BindingRequestHandler`): it
/// sees the request, the candidates it travelled between and the pair, and returns `true` to
/// make that pair the selected one.
///
/// This lets an application take over selection, for example to move to a pair its own
/// signaling or policy prefers. A lite agent has no checks of its own, so a pair the handler
/// approves is taken as valid straight away.
#[derive(Clone)]
pub struct BindingRequestHandler(Arc<BindingRequestFn>);

impl BindingRequestHandler {
    /// A handler backed by `f`.
    pub fn new(
        f: impl Fn(&stun::message::Message, &Candidate, &Candidate, &CandidatePair) -> bool
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self(Arc::new(f))
    }

    pub(crate) fn call(
        &self,
        request: &stun::message::Message,
        local: &Candidate,
        remote: &Candidate,
        pair: &CandidatePair,
    ) -> bool {
        (self.0)(request, local, remote, pair)
    }
}

impl std::fmt::Debug for BindingRequestHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BindingRequestHandler")
    }
}

pub(crate) fn default_candidate_types() -> Vec<CandidateType> {
    vec![
        CandidateType::Host,
        CandidateType::ServerReflexive,
        CandidateType::Relay,
    ]
}

/// Collects the arguments to `ice::Agent` construction into a single structure, for
/// future-proofness of the interface.
#[derive(Default)]
pub struct AgentConfig {
    /// The STUN and TURN servers to gather reflexive and relay candidates from.
    pub urls: Vec<Url>,

    /// It is used to perform connectivity checks. The values MUST be unguessable, with at least
    /// 128 bits of random number generator output used to generate the password, and at least 24
    /// bits of output to generate the username fragment.
    pub local_ufrag: String,
    /// It is used to perform connectivity checks. The values MUST be unguessable, with at least
    /// 128 bits of random number generator output used to generate the password, and at least 24
    /// bits of output to generate the username fragment.
    pub local_pwd: String,

    /// Controls mDNS query timeout
    /// If the duration is 0, we will never go to failed.
    pub multicast_dns_query_timeout: Option<Duration>,

    /// Controls mDNS behavior for the ICE agent.
    pub multicast_dns_mode: MulticastDnsMode,

    /// Controls the local name for this agent. If none is specified a random one will be generated.
    pub multicast_dns_local_name: String,

    /// Control mDNS local IP address
    pub multicast_dns_local_ip: Option<IpAddr>,

    /// Defaults to 5 seconds when this property is nil.
    /// If the duration is 0, the ICE Agent will never go to disconnected.
    pub disconnected_timeout: Option<Duration>,

    /// Defaults to 25 seconds when this property is nil.
    /// If the duration is 0, we will never go to failed.
    pub failed_timeout: Option<Duration>,

    /// Determines how often should we send ICE keepalives (should be less than connection timeout
    /// above) when this is nil, it defaults to 10 seconds.
    /// A keepalive interval of 0 means we never send keepalive packets
    pub keepalive_interval: Option<Duration>,

    /// An optional configuration for disabling or enabling support for specific candidate types.
    pub candidate_types: Vec<CandidateType>,

    /// An optional configuration for disabling or enabling support for specific network types.
    /// If empty, all network types are supported.
    pub network_types: Vec<NetworkType>,

    /// Controls how often our internal task loop runs when in the connecting state.
    /// Only useful for testing.
    pub check_interval: Duration,

    /// The max amount of binding requests the agent will send over a candidate pair for validation
    /// or nomination, if after max_binding_requests the candidate is yet to answer a binding
    /// request or a nomination we set the pair as failed.
    pub max_binding_requests: Option<u16>,

    /// Whether this agent takes the controlling role.
    pub is_controlling: bool,

    /// lite agents do not perform connectivity check and only provide host candidates.
    pub lite: bool,

    /// Specify a minimum wait time before selecting host candidates.
    pub host_acceptance_min_wait: Option<Duration>,
    /// Specify a minimum wait time before selecting srflx candidates.
    pub srflx_acceptance_min_wait: Option<Duration>,
    /// Specify a minimum wait time before selecting prflx candidates.
    pub prflx_acceptance_min_wait: Option<Duration>,
    /// Specify a minimum wait time before selecting relay candidates.
    pub relay_acceptance_min_wait: Option<Duration>,

    /// Controls if self-signed certificates are accepted when connecting to TURN servers via TLS or
    /// DTLS.
    pub insecure_skip_verify: bool,

    /// Enables ICE renomination (draft-thatcher-ice-renomination-01) with this value generator
    /// (pion's `WithRenomination`). Without it the agent nominates once, as RFC 8445 describes.
    pub renomination: Option<NominationValueGenerator>,

    /// The STUN attribute type that carries the nomination value; `0xC001` when `None`
    /// (pion's `WithNominationAttribute`). Zero is rejected.
    pub nomination_attribute: Option<u16>,

    /// Lets a controlling agent renominate by itself when a clearly better pair appears,
    /// checking at this interval (pion's `WithAutomaticRenomination`; zero means 3 seconds).
    /// Requires [`AgentConfig::renomination`].
    pub automatic_renomination: Option<Duration>,

    /// Makes a lite controlled agent also apply the priority rule when a nomination arrives
    /// for a pair other than the selected one (pion's `WithEnableUseCandidateCheckPriority`).
    /// Full agents always apply it.
    pub enable_use_candidate_check_priority: bool,

    /// Runs for every Binding request the agent answers and may select the pair it came in on
    /// (pion's `WithBindingRequestHandler`).
    pub binding_request_handler: Option<BindingRequestHandler>,

    /// Subtracted from the type preference of TCP candidates, so UDP is preferred over TCP;
    /// 27 when `None` (pion's `WithTCPPriorityOffset`).
    pub tcp_priority_offset: Option<u16>,
}

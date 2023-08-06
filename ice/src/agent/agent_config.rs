use std::time::Duration;

use super::*;
use crate::network_type::*;
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
    pub urls: Vec<Url>,

    /// It is used to perform connectivity checks. The values MUST be unguessable, with at least
    /// 128 bits of random number generator output used to generate the password, and at least 24
    /// bits of output to generate the username fragment.
    pub local_ufrag: String,
    /// It is used to perform connectivity checks. The values MUST be unguessable, with at least
    /// 128 bits of random number generator output used to generate the password, and at least 24
    /// bits of output to generate the username fragment.
    pub local_pwd: String,

    /// Defaults to 5 seconds when this property is nil.
    /// If the duration is 0, the ICE Agent will never go to disconnected.
    pub disconnected_timeout: Option<Duration>,

    /// Defaults to 25 seconds when this property is nil.
    /// If the duration is 0, we will never go to failed.
    pub failed_timeout: Option<Duration>,

    /// Determines how often should we send ICE keepalives (should be less then connectiontimeout
    /// above) when this is nil, it defaults to 10 seconds.
    /// A keepalive interval of 0 means we never send keepalive packets
    pub keepalive_interval: Option<Duration>,

    /// An optional configuration for disabling or enabling support for specific network types.
    pub network_types: Vec<NetworkType>,

    /// An optional configuration for disabling or enabling support for specific candidate types.
    pub candidate_types: Vec<CandidateType>,

    /// Controls how often our internal task loop runs when in the connecting state.
    /// Only useful for testing.
    pub check_interval: Duration,

    /// The max amount of binding requests the agent will send over a candidate pair for validation
    /// or nomination, if after max_binding_requests the candidate is yet to answer a binding
    /// request or a nomination we set the pair as failed.
    pub max_binding_requests: Option<u16>,

    pub is_controlling: bool,

    /// lite agents do not perform connectivity check and only provide host candidates.
    pub lite: bool,

    /// Specify a minimum wait time before selecting host candidates.
    pub host_acceptance_min_wait: Option<Duration>,

    /// Controls if self-signed certificates are accepted when connecting to TURN servers via TLS or
    /// DTLS.
    pub insecure_skip_verify: bool,
}

impl AgentConfig {
    /// Populates an agent and falls back to defaults if fields are unset.
    pub(crate) fn init_with_defaults(&self, a: &mut AgentInternal) {
        if let Some(max_binding_requests) = self.max_binding_requests {
            a.max_binding_requests = max_binding_requests;
        } else {
            a.max_binding_requests = DEFAULT_MAX_BINDING_REQUESTS;
        }

        if let Some(host_acceptance_min_wait) = self.host_acceptance_min_wait {
            a.host_acceptance_min_wait = host_acceptance_min_wait;
        } else {
            a.host_acceptance_min_wait = DEFAULT_HOST_ACCEPTANCE_MIN_WAIT;
        }

        if let Some(disconnected_timeout) = self.disconnected_timeout {
            a.disconnected_timeout = disconnected_timeout;
        } else {
            a.disconnected_timeout = DEFAULT_DISCONNECTED_TIMEOUT;
        }

        if let Some(failed_timeout) = self.failed_timeout {
            a.failed_timeout = failed_timeout;
        } else {
            a.failed_timeout = DEFAULT_FAILED_TIMEOUT;
        }

        if let Some(keepalive_interval) = self.keepalive_interval {
            a.keepalive_interval = keepalive_interval;
        } else {
            a.keepalive_interval = DEFAULT_KEEPALIVE_INTERVAL;
        }

        if self.check_interval == Duration::from_secs(0) {
            a.check_interval = DEFAULT_CHECK_INTERVAL;
        } else {
            a.check_interval = self.check_interval;
        }
    }
}

use serde::Serialize;
use std::fmt;

/// Represent the ICE candidate pair state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum CandidatePairState {
    #[serde(rename = "unspecified")]
    Unspecified = 0,

    /// Means a check has not been performed for this pair.
    #[serde(rename = "waiting")]
    Waiting = 1,

    /// Means a check has been sent for this pair, but the transaction is in progress.
    #[serde(rename = "in-progress")]
    InProgress = 2,

    /// Means a check for this pair was already done and failed, either never producing any response
    /// or producing an unrecoverable failure response.
    #[serde(rename = "failed")]
    Failed = 3,

    /// Means a check for this pair was already done and produced a successful result.
    #[serde(rename = "succeeded")]
    Succeeded = 4,
}

impl From<u8> for CandidatePairState {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Waiting,
            2 => Self::InProgress,
            3 => Self::Failed,
            4 => Self::Succeeded,
            _ => Self::Unspecified,
        }
    }
}

impl Default for CandidatePairState {
    fn default() -> Self {
        Self::Unspecified
    }
}

impl fmt::Display for CandidatePairState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            Self::Waiting => "waiting",
            Self::InProgress => "in-progress",
            Self::Failed => "failed",
            Self::Succeeded => "succeeded",
            Self::Unspecified => "unspecified",
        };

        write!(f, "{s}")
    }
}

/// Represents a combination of a local and remote candidate.
#[derive(Clone, Copy)]
pub struct CandidatePair {
    pub local_index: usize,
    pub remote_index: usize,
    pub local_priority: u32,
    pub remote_priority: u32,
    pub(crate) ice_role_controlling: bool,
    pub(crate) binding_request_count: u16,
    pub(crate) state: CandidatePairState,
    pub(crate) nominated: bool,
}

impl fmt::Debug for CandidatePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "prio {} (local, prio {}) {} <-> {} (remote, prio {})",
            self.priority(),
            self.local_priority,
            self.local_index,
            self.remote_index,
            self.remote_priority,
        )
    }
}

impl fmt::Display for CandidatePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "prio {} (local, prio {}) {} <-> {} (remote, prio {})",
            self.priority(),
            self.local_priority,
            self.local_index,
            self.remote_index,
            self.remote_priority,
        )
    }
}

impl PartialEq for CandidatePair {
    fn eq(&self, other: &Self) -> bool {
        self.local_index == other.local_index && self.remote_index == other.remote_index
    }
}

impl CandidatePair {
    #[must_use]
    pub fn new(
        local_index: usize,
        remote_index: usize,
        local_priority: u32,
        remote_priority: u32,
        ice_role_controlling: bool,
    ) -> Self {
        Self {
            local_index,
            remote_index,
            local_priority,
            remote_priority,
            ice_role_controlling,
            state: CandidatePairState::Waiting,
            binding_request_count: 0,
            nominated: false,
        }
    }

    /// RFC 5245 - 5.7.2.  Computing Pair Priority and Ordering Pairs
    /// Let G be the priority for the candidate provided by the controlling
    /// agent.  Let D be the priority for the candidate provided by the
    /// controlled agent.
    /// pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
    pub fn priority(&self) -> u64 {
        let (g, d) = if self.ice_role_controlling {
            (self.local_priority, self.remote_priority)
        } else {
            (self.remote_priority, self.local_priority)
        };

        // 1<<32 overflows uint32; and if both g && d are
        // maxUint32, this result would overflow uint64
        ((1 << 32_u64) - 1) * u64::from(std::cmp::min(g, d))
            + 2 * u64::from(std::cmp::max(g, d))
            + u64::from(g > d)
    }
}

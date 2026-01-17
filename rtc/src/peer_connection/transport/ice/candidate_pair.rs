use std::fmt;

use super::candidate::*;

/// ICECandidatePair represents an ICE Candidate pair
///
/// ## Specifications
///
/// * [MDN]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCIceCandidatePair
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct RTCIceCandidatePair {
    local: RTCIceCandidate,
    remote: RTCIceCandidate,
}

impl fmt::Display for RTCIceCandidatePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(local) {} <-> (remote) {}", self.local, self.remote)
    }
}

impl RTCIceCandidatePair {
    /// returns an initialized ICECandidatePair
    /// for the given pair of ICECandidate instances
    pub fn new(local: RTCIceCandidate, remote: RTCIceCandidate) -> Self {
        RTCIceCandidatePair { local, remote }
    }
}

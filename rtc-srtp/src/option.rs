use shared::replay_detector::*;

/// A factory for the [`ReplayDetector`] a context
/// should use.
///
/// A factory rather than a value because each SSRC in a session needs its own detector
/// state. Remote contexts default to a 64-packet sliding window; pass a different factory to
/// widen it or to disable replay protection.
pub type ContextOption = Box<dyn Fn() -> Box<dyn ReplayDetector> + Send + Sync>;

pub(crate) const MAX_SEQUENCE_NUMBER: u16 = 65535;
pub(crate) const MAX_SRTCP_INDEX: usize = 0x7FFFFFFF;

/// The highest SRTP packet index: `roc << 16 | seq` with both at their maxima.
const MAX_SRTP_INDEX: u64 = (u32::MAX as u64) << 16 | MAX_SEQUENCE_NUMBER as u64;

/// srtp_replay_protection sets SRTP replay protection window size.
///
/// As in pion, the window slides over the full 48-bit packet index `roc << 16 | seq`, not the
/// bare 16-bit sequence number: a window over `seq` alone cannot tell a replayed packet from two
/// rollovers ago apart from a fresh one, because both carry the same `seq`.
pub fn srtp_replay_protection(window_size: usize) -> ContextOption {
    Box::new(move || -> Box<dyn ReplayDetector> {
        Box::new(SlidingWindowDetector::new(window_size, MAX_SRTP_INDEX))
    })
}

/// Sets SRTCP replay protection window size.
///
/// The SRTCP index never wraps (the MSB of the word on the wire is the encryption flag), so the
/// detector is the plain sliding window over `0..=2^31-1`, as in pion: an index far behind the
/// window head is too old, not a wrap-around.
pub fn srtcp_replay_protection(window_size: usize) -> ContextOption {
    Box::new(move || -> Box<dyn ReplayDetector> {
        Box::new(SlidingWindowDetector::new(
            window_size,
            MAX_SRTCP_INDEX as u64,
        ))
    })
}

/// srtp_no_replay_protection disables SRTP replay protection.
pub fn srtp_no_replay_protection() -> ContextOption {
    Box::new(|| -> Box<dyn ReplayDetector> { Box::<NoOpReplayDetector>::default() })
}

/// srtcp_no_replay_protection disables SRTCP replay protection.
pub fn srtcp_no_replay_protection() -> ContextOption {
    Box::new(|| -> Box<dyn ReplayDetector> { Box::<NoOpReplayDetector>::default() })
}

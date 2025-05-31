use std::time::Duration;

// For backward compatibility, do not use
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub enum ReliabilityType {
    #[default]
    Reliable = 0,
    Rexmit,
    Timed,
}

#[derive(Debug, Default, Clone)]
pub struct Reliability {
    // It true, the channel does not enforce message ordering and out-of-order delivery is allowed
    pub unordered: bool,

    // If both max_packet_life_time or max_retransmits are unset, the channel is reliable.
    // If either max_packet_life_time or max_retransmits is set, the channel is unreliable.
    // (The settings are exclusive, so both maxPacketLifetime and max_retransmits must not be set.)

    // Time window during which transmissions and retransmissions may occur
    pub max_packet_life_time: Option<Duration>,

    // Maximum number of retransmissions that are attempted
    pub max_retransmits: Option<usize>,

    pub rexmit: usize, //TODO: or duration?
}

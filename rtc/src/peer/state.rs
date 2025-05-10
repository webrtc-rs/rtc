#[derive(Default, Debug, Copy, Clone)]
pub enum RTCSignalingState {
    Stable,
    HaveLocalOffer,
    HaveRemoteOffer,
    HaveLocalPranswer,
    HaveRemotePranswer,
    #[default]
    Closed,
}

#[derive(Default, Debug, Copy, Clone)]
pub enum RTCIceGatheringState {
    #[default]
    New,
    Gathering,
    Complete,
}

#[derive(Default, Debug, Copy, Clone)]
pub enum RTCPeerConnectionState {
    #[default]
    Closed,
    Failed,
    Disconnected,
    New,
    Connecting,
    Connected,
}

#[derive(Default, Debug, Copy, Clone)]
pub enum RTCIceConnectionState {
    #[default]
    Closed,
    Failed,
    Disconnected,
    New,
    Checking,
    Completed,
    Connected,
}

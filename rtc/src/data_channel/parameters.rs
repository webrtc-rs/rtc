use serde::{Deserialize, Serialize};

/// Internal parameters describing the configuration of a DataChannel.
///
/// This structure captures the essential parameters needed to establish and
/// configure a data channel, including reliability settings and negotiation details.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DataChannelParameters {
    /// The label that can be used to distinguish this DataChannel from others.
    pub(crate) label: String,

    /// The name of the sub-protocol in use.
    pub(crate) protocol: String,

    /// Whether the data channel guarantees in-order delivery of messages.
    pub(crate) ordered: bool,

    /// The maximum time in milliseconds during which transmissions and
    /// retransmissions may occur in unreliable mode.
    pub(crate) max_packet_life_time: Option<u16>,

    /// The maximum number of retransmission attempts in unreliable mode.
    pub(crate) max_retransmits: Option<u16>,

    /// The data channel ID if this channel was negotiated by the application.
    /// None if the channel was not pre-negotiated.
    pub(crate) negotiated: Option<u16>,
}

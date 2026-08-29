use sctp::StreamId;
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

    /// The SCTP stream identifier this channel was negotiated on out-of-band by the
    /// application. `None` if the channel was not pre-negotiated, in which case the stream id
    /// is assigned during the SCTP connected procedure once the DTLS role is known.
    pub(crate) negotiated: Option<StreamId>,
}

use crate::data_channel::parameters::DataChannelParameters;
use crate::data_channel::state::RTCDataChannelState;
use crate::data_channel::BinaryType;

#[derive(Default, Clone)]
pub(crate) struct RTCDataChannelInternal {
    pub(crate) label: String,
    pub(crate) ordered: bool,
    pub(crate) max_packet_lifetime: Option<u16>,
    pub(crate) max_retransmits: Option<u16>,
    pub(crate) protocol: String,
    pub(crate) negotiated: bool,
    pub(crate) ready_state: RTCDataChannelState,
    buffered_amount_low_threshold: usize,
    binary_type: BinaryType,
}

impl RTCDataChannelInternal {
    /// create the DataChannel object before the networking is set up.
    pub(crate) fn new(
        params: DataChannelParameters, /*TODO: setting_engine: Arc<SettingEngine>*/
    ) -> Self {
        Self {
            label: params.label,
            protocol: params.protocol,
            negotiated: params.negotiated.is_some(),
            ordered: params.ordered,
            max_packet_lifetime: params.max_packet_life_time,
            max_retransmits: params.max_retransmits,
            ready_state: RTCDataChannelState::Connecting,
            buffered_amount_low_threshold: 0,
            binary_type: BinaryType::default(),
        }
    }
}

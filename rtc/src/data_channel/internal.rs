use crate::data_channel::parameters::DataChannelParameters;
use crate::data_channel::state::RTCDataChannelState;
use crate::data_channel::{BinaryType, RTCDataChannelId};
use shared::error::Result;

#[derive(Default, Clone)]
pub(crate) struct RTCDataChannelInternal {
    pub(crate) id: RTCDataChannelId,
    pub(crate) label: String,
    pub(crate) ordered: bool,
    pub(crate) max_packet_life_time: Option<u16>,
    pub(crate) max_retransmits: Option<u16>,
    pub(crate) protocol: String,
    pub(crate) negotiated: bool,
    pub(crate) ready_state: RTCDataChannelState,
    pub(crate) buffered_amount_low_threshold: usize,
    pub(crate) binary_type: BinaryType,

    pub(crate) data_channel: Option<::datachannel::data_channel::DataChannel>,
}

impl RTCDataChannelInternal {
    /// create the DataChannel object before the networking is set up.
    pub(crate) fn new(id: RTCDataChannelId, params: DataChannelParameters) -> Self {
        Self {
            id,
            label: params.label,
            protocol: params.protocol,
            negotiated: params.negotiated.is_some(),
            ordered: params.ordered,
            max_packet_life_time: params.max_packet_life_time,
            max_retransmits: params.max_retransmits,
            ready_state: RTCDataChannelState::Connecting,
            buffered_amount_low_threshold: 0,
            binary_type: BinaryType::default(),
            data_channel: None,
        }
    }

    pub(crate) fn open(&mut self, association_handle: usize) -> Result<()> {
        let (channel_type, reliability_parameter) =
            ::datachannel::data_channel::DataChannel::get_channel_type_and_reliability_parameter(
                self.ordered,
                self.max_retransmits,
                self.max_packet_life_time,
            );

        let config = ::datachannel::data_channel::DataChannelConfig {
            channel_type,
            priority: ::datachannel::message::message_channel_open::CHANNEL_PRIORITY_NORMAL,
            reliability_parameter,
            label: self.label.clone(),
            protocol: self.protocol.clone(),
            negotiated: self.negotiated,
        };

        let data_channel =
            ::datachannel::data_channel::DataChannel::dial(config, association_handle, self.id)?;
        data_channel.set_buffered_amount_low_threshold(self.buffered_amount_low_threshold);

        self.data_channel = Some(data_channel);
        self.ready_state = RTCDataChannelState::Open;

        Ok(())
    }
}

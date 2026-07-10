use crate::data_channel::RTCDataChannelId;
use crate::data_channel::parameters::DataChannelParameters;
use crate::data_channel::state::RTCDataChannelState;
use datachannel::data_channel::DataChannelConfig;
use sansio::Protocol;
use sctp::{PayloadProtocolIdentifier, ReliabilityType};
use shared::error::Result;

#[derive(Clone)]
pub(crate) struct RTCDataChannelInternal {
    pub(crate) id: RTCDataChannelId,
    pub(crate) label: String,
    pub(crate) ordered: bool,
    pub(crate) max_packet_life_time: Option<u16>,
    pub(crate) max_retransmits: Option<u16>,
    pub(crate) protocol: String,
    pub(crate) negotiated: bool,
    pub(crate) ready_state: RTCDataChannelState,
    pub(crate) buffered_amount_high_threshold: u32,
    pub(crate) buffered_amount_low_threshold: u32,

    pub(crate) data_channel: Option<::datachannel::data_channel::DataChannel>,
}

impl Default for RTCDataChannelInternal {
    fn default() -> Self {
        Self {
            id: 0,
            label: "".to_string(),
            ordered: false,
            max_packet_life_time: None,
            max_retransmits: None,
            protocol: "".to_string(),
            negotiated: false,
            ready_state: RTCDataChannelState::default(),
            buffered_amount_high_threshold: u32::MAX,
            buffered_amount_low_threshold: 0,
            data_channel: None,
        }
    }
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
            buffered_amount_high_threshold: u32::MAX,
            buffered_amount_low_threshold: 0,
            data_channel: None,
        }
    }

    pub(crate) fn dial(&mut self, association_handle: usize) -> Result<()> {
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

        let mut data_channel =
            ::datachannel::data_channel::DataChannel::dial(config, association_handle, self.id)?;
        data_channel.set_buffered_amount_low_threshold(self.buffered_amount_low_threshold)?;
        data_channel.set_buffered_amount_high_threshold(self.buffered_amount_high_threshold)?;

        self.data_channel = Some(data_channel);
        self.ready_state = RTCDataChannelState::Open;

        Ok(())
    }

    pub(crate) fn accept(
        association_handle: usize,
        stream_id: u16,
        ppi: PayloadProtocolIdentifier,
        buf: &[u8],
    ) -> Result<Self> {
        let data_channel = ::datachannel::data_channel::DataChannel::accept(
            DataChannelConfig::default(),
            association_handle,
            stream_id,
            ppi,
            buf,
        )?;

        let data_channel_config = data_channel.config();

        let (unordered, reliability_type) =
            ::datachannel::data_channel::DataChannel::get_reliability_params(
                data_channel_config.channel_type,
            );

        let reliability_parameter = || {
            u16::try_from(data_channel_config.reliability_parameter).map_err(|_| {
                shared::error::Error::ErrDataChannelReliabilityParameterTooLarge(
                    data_channel_config.reliability_parameter,
                )
            })
        };
        let (max_packet_life_time, max_retransmits) = match reliability_type {
            ReliabilityType::Reliable => (None, None),
            ReliabilityType::Rexmit => (None, Some(reliability_parameter()?)),
            ReliabilityType::Timed => (Some(reliability_parameter()?), None),
        };

        let mut data_channel_internal = RTCDataChannelInternal::new(
            stream_id,
            DataChannelParameters {
                label: data_channel_config.label.clone(),
                protocol: data_channel_config.protocol.clone(),
                ordered: !unordered,
                max_packet_life_time,
                max_retransmits,
                negotiated: None,
            },
        );
        data_channel_internal.data_channel = Some(data_channel);
        data_channel_internal.ready_state = RTCDataChannelState::Open;

        Ok(data_channel_internal)
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        if let Some(data_channel) = self.data_channel.as_mut() {
            data_channel.close()?;
        }
        self.ready_state = RTCDataChannelState::Closed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_message(
        parameters: DataChannelParameters,
    ) -> Result<datachannel::data_channel::DataChannelMessage> {
        let mut channel = RTCDataChannelInternal::new(7, parameters);
        channel.dial(13)?;
        channel
            .data_channel
            .as_mut()
            .expect("dial must create the data channel")
            .poll_write()
            .ok_or(shared::error::Error::ErrDataChannelNotExisted)
    }

    #[test]
    fn accept_preserves_max_retransmits_and_ordering() -> Result<()> {
        let message = open_message(DataChannelParameters {
            label: "lossy".to_owned(),
            protocol: "test".to_owned(),
            ordered: false,
            max_retransmits: Some(0),
            ..Default::default()
        })?;

        let accepted = RTCDataChannelInternal::accept(
            message.association_handle,
            message.stream_id,
            message.ppi,
            &message.payload,
        )?;

        assert!(!accepted.ordered);
        assert_eq!(accepted.max_retransmits, Some(0));
        assert_eq!(accepted.max_packet_life_time, None);
        Ok(())
    }

    #[test]
    fn accept_preserves_max_packet_life_time() -> Result<()> {
        let message = open_message(DataChannelParameters {
            label: "timed".to_owned(),
            ordered: true,
            max_packet_life_time: Some(250),
            ..Default::default()
        })?;

        let accepted = RTCDataChannelInternal::accept(
            message.association_handle,
            message.stream_id,
            message.ppi,
            &message.payload,
        )?;

        assert!(accepted.ordered);
        assert_eq!(accepted.max_packet_life_time, Some(250));
        assert_eq!(accepted.max_retransmits, None);
        Ok(())
    }

    #[test]
    fn accept_rejects_unrepresentable_partial_reliability_parameter() -> Result<()> {
        let mut channel = datachannel::data_channel::DataChannel::dial(
            DataChannelConfig {
                channel_type:
                    datachannel::message::message_channel_open::ChannelType::PartialReliableRexmit,
                reliability_parameter: u16::MAX as u32 + 1,
                label: "too-large".to_owned(),
                ..Default::default()
            },
            13,
            7,
        )?;
        let message = channel
            .poll_write()
            .ok_or(shared::error::Error::ErrDataChannelNotExisted)?;

        let error = match RTCDataChannelInternal::accept(
            message.association_handle,
            message.stream_id,
            message.ppi,
            &message.payload,
        ) {
            Ok(_) => panic!("a 32-bit DCEP reliability parameter cannot fit the WebRTC API"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            shared::error::Error::ErrDataChannelReliabilityParameterTooLarge(65_536)
        );
        Ok(())
    }
}

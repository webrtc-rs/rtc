use crate::data_channel::RTCDataChannelHandle;
use crate::data_channel::RTCDataChannelId;
use crate::data_channel::parameters::DataChannelParameters;
use crate::data_channel::state::RTCDataChannelState;
use datachannel::data_channel::DataChannelConfig;
use sansio::Protocol;
use sctp::PayloadProtocolIdentifier;
use shared::error::{Error, Result};
use std::time::Instant;

#[derive(Clone)]
pub(crate) struct RTCDataChannelInternal {
    pub(crate) handle: RTCDataChannelHandle,
    /// The SCTP stream identifier for this channel.
    ///
    /// `None` until the DTLS role has been negotiated and the SCTP transport has connected
    /// (W3C section 6.1 step 18 / section 6.1.1.3). Negotiated channels with an explicit id and channels
    /// created after the transport is connected are assigned one immediately.
    pub(crate) stream_id: Option<RTCDataChannelId>,
    pub(crate) label: String,
    pub(crate) ordered: bool,
    pub(crate) max_packet_life_time: Option<u16>,
    pub(crate) max_retransmits: Option<u16>,
    pub(crate) protocol: String,
    pub(crate) negotiated: bool,
    pub(crate) ready_state: RTCDataChannelState,
    pub(crate) buffered_amount_high_threshold: u32,
    pub(crate) buffered_amount_low_threshold: u32,
    /// User payload bytes handed to `send()`/`send_text()` that SCTP has not yet
    /// released (acknowledged or abandoned). Incremented synchronously at the app
    /// send boundary and decremented on SCTP buffer-release events, so it accounts
    /// for bytes still in the app→core→SCTP send pipeline — not just the SCTP
    /// stream's own `buffered_amount`, which counts only post-packetization. Used
    /// for synchronous send back-pressure.
    pub(crate) outstanding_bytes: usize,

    /// Deadline by which an in-band channel's DCEP handshake must complete.
    /// Set when the channel is dialed; cleared on handshake completion or close.
    pub(crate) handshake_deadline: Option<Instant>,

    /// Set when the DCEP handshake times out and `OnClose` has already been
    /// emitted. Prevents `SCTPStreamClosed` from emitting/counting a second close.
    pub(crate) close_emitted: bool,

    pub(crate) data_channel: Option<::datachannel::data_channel::DataChannel>,
}

impl Default for RTCDataChannelInternal {
    fn default() -> Self {
        Self {
            handle: RTCDataChannelHandle::new(0),
            stream_id: None,
            label: "".to_string(),
            ordered: false,
            max_packet_life_time: None,
            max_retransmits: None,
            protocol: "".to_string(),
            negotiated: false,
            ready_state: RTCDataChannelState::default(),
            buffered_amount_high_threshold: u32::MAX,
            buffered_amount_low_threshold: 0,
            outstanding_bytes: 0,
            handshake_deadline: None,
            close_emitted: false,
            data_channel: None,
        }
    }
}

impl RTCDataChannelInternal {
    /// create the DataChannel object before the networking is set up.
    pub(crate) fn new(handle: RTCDataChannelHandle, params: DataChannelParameters) -> Self {
        let stream_id = params.negotiated;
        Self {
            handle,
            stream_id,
            label: params.label,
            protocol: params.protocol,
            negotiated: params.negotiated.is_some(),
            ordered: params.ordered,
            max_packet_life_time: params.max_packet_life_time,
            max_retransmits: params.max_retransmits,
            ready_state: RTCDataChannelState::Connecting,
            buffered_amount_high_threshold: u32::MAX,
            buffered_amount_low_threshold: 0,
            outstanding_bytes: 0,
            handshake_deadline: None,
            close_emitted: false,
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

        let stream_id = self.stream_id.ok_or(Error::ErrDataChannelNotOpen)?;
        let mut data_channel =
            ::datachannel::data_channel::DataChannel::dial(config, association_handle, stream_id)?;
        data_channel.set_buffered_amount_low_threshold(self.buffered_amount_low_threshold)?;
        data_channel.set_buffered_amount_high_threshold(self.buffered_amount_high_threshold)?;

        self.data_channel = Some(data_channel);

        // An in-band channel stays `Connecting` until the peer's `DATA_CHANNEL_ACK`
        // is processed in `DataChannelHandler::handle_read`. An out-of-band
        // `negotiated` channel has no DCEP handshake, so it is open immediately.
        self.ready_state = if self.negotiated {
            RTCDataChannelState::Open
        } else {
            RTCDataChannelState::Connecting
        };

        Ok(())
    }

    pub(crate) fn accept(
        handle: RTCDataChannelHandle,
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

        let (unordered, _reliability_type) =
            ::datachannel::data_channel::DataChannel::get_reliability_params(
                data_channel_config.channel_type,
            );

        let mut data_channel_internal = RTCDataChannelInternal::new(
            handle,
            DataChannelParameters {
                label: data_channel_config.label.clone(),
                protocol: data_channel_config.protocol.clone(),
                ordered: !unordered,
                max_packet_life_time: None,
                max_retransmits: None,
                negotiated: None,
            },
        );
        data_channel_internal.stream_id = Some(stream_id);
        data_channel_internal.data_channel = Some(data_channel);
        data_channel_internal.ready_state = RTCDataChannelState::Open;

        Ok(data_channel_internal)
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        if let Some(data_channel) = self.data_channel.as_mut() {
            data_channel.close()?;
        }
        self.handshake_deadline = None;
        self.ready_state = RTCDataChannelState::Closed;
        Ok(())
    }
}

use crate::data_channel::parameters::DataChannelParameters;
use crate::data_channel::state::RTCDataChannelState;
use datachannel::data_channel::DataChannelConfig;
use sansio::Protocol;
use sctp::PayloadProtocolIdentifier;
use shared::error::{Error, Result};

#[derive(Clone)]
pub(crate) struct RTCDataChannelInternal {
    /// The RFC 8832 §6 SCTP stream identifier.
    ///
    /// `None` until the SCTP connected procedure assigns it, which cannot happen before the
    /// DTLS role is resolved because the role decides the parity: even for the client, odd for
    /// the server. Out-of-band (`negotiated`) channels and channels accepted from the peer
    /// have it from birth, since their id is already fixed by the application or the wire.
    pub(crate) stream_id: Option<u16>,
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

    pub(crate) data_channel: Option<::datachannel::data_channel::DataChannel>,
}

impl Default for RTCDataChannelInternal {
    fn default() -> Self {
        Self {
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
            data_channel: None,
        }
    }
}

impl RTCDataChannelInternal {
    /// Creates the DataChannel object before the networking is set up.
    ///
    /// The handle is left at its placeholder; [`DataChannelRegistry::insert`] assigns the real
    /// one. The stream id comes from `params.negotiated` — `Some` for an out-of-band channel,
    /// whose id the application already fixed, and `None` for an in-band one, whose id has to
    /// wait for the DTLS role.
    ///
    /// [`DataChannelRegistry::insert`]: crate::data_channel::registry::DataChannelRegistry::insert
    pub(crate) fn new(params: DataChannelParameters) -> Self {
        Self {
            stream_id: params.negotiated,
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
            data_channel: None,
        }
    }

    pub(crate) fn dial(&mut self, association_handle: usize) -> Result<()> {
        // A channel cannot be dialed before its stream id exists, and the stream id cannot
        // exist before the DTLS role does. Making that an error rather than a fallback is the
        // whole point: guessing a parity here is what issue #199 was.
        let stream_id = self
            .stream_id
            .ok_or(Error::ErrDataChannelStreamIdNotAssigned)?;

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
            ::datachannel::data_channel::DataChannel::dial(config, association_handle, stream_id)?;
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

        let (unordered, _reliability_type) =
            ::datachannel::data_channel::DataChannel::get_reliability_params(
                data_channel_config.channel_type,
            );

        // `negotiated: None` — the peer opened this channel in-band over DCEP, so it is not an
        // out-of-band channel however well-known its stream id now is. The stream id is set
        // below instead of through `negotiated`, which would also flip the `negotiated` flag.
        let mut data_channel_internal = RTCDataChannelInternal::new(DataChannelParameters {
            label: data_channel_config.label.clone(),
            protocol: data_channel_config.protocol.clone(),
            ordered: !unordered,
            max_packet_life_time: None,
            max_retransmits: None,
            negotiated: None,
        });
        // Known from the wire: no deferral needed, and it must be registered so locally
        // generated ids cannot collide with it.
        data_channel_internal.stream_id = Some(stream_id);
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

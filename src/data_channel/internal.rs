use crate::data_channel::OutstandingBytes;
use crate::data_channel::RTCDataChannelId;
use crate::data_channel::parameters::DataChannelParameters;
use crate::data_channel::state::RTCDataChannelState;
use datachannel::data_channel::DataChannelConfig;
use sansio::Protocol;
use sctp::{PayloadProtocolIdentifier, ReliabilityType, StreamId};
use shared::error::{Error, Result};
use std::time::Instant;

#[derive(Clone)]
pub(crate) struct RTCDataChannelInternal {
    /// Connection-local handle. Assigned by `DataChannelRegistry::insert`, stable for the
    /// channel's lifetime, and the key this channel lives under. NOT the wire value — the
    /// differing widths (`usize` vs `StreamId`) are what stop the two being confused.
    ///
    /// Carried on the value as well as the key so the close and assignment paths can read it
    /// back without a reverse lookup.
    pub(crate) id: RTCDataChannelId,

    /// The RFC 8832 §6 SCTP stream identifier.
    ///
    /// `None` until the SCTP connected procedure assigns it, which cannot happen before the
    /// DTLS role is resolved because the role decides the parity: even for the client, odd for
    /// the server. Out-of-band (`negotiated`) channels and channels accepted from the peer
    /// have it from birth, since their id is already fixed by the application or the wire.
    pub(crate) stream_id: Option<StreamId>,
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
    pub(crate) outstanding_bytes: OutstandingBytes,

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
            id: 0,
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
            outstanding_bytes: OutstandingBytes::default(),
            handshake_deadline: None,
            close_emitted: false,
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
            id: 0,
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
            outstanding_bytes: OutstandingBytes::default(),
            handshake_deadline: None,
            close_emitted: false,
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
        association_handle: usize,
        stream_id: StreamId,
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

        // RFC 8832 §5.1: the Reliability Parameter is the retransmission limit of a
        // PartialReliableRexmit channel and the lifetime in milliseconds of a
        // PartialReliableTimed one, and carries nothing for the reliable types. Recording it
        // here is what lets `max_retransmits()` and `max_packet_life_time()` report the
        // channel the peer opened. The wire field is 32 bits but the W3C attributes are
        // `unsigned short`, so a larger value saturates; the SCTP stream itself is configured
        // with the full value.
        let reliability_parameter =
            u16::try_from(data_channel_config.reliability_parameter).unwrap_or(u16::MAX);
        let (max_retransmits, max_packet_life_time) = match reliability_type {
            ReliabilityType::Rexmit => (Some(reliability_parameter), None),
            ReliabilityType::Timed => (None, Some(reliability_parameter)),
            _ => (None, None),
        };

        // `negotiated: None` — the peer opened this channel in-band over DCEP, so it is not an
        // out-of-band channel however well-known its stream id now is. The stream id is set
        // below instead of through `negotiated`, which would also flip the `negotiated` flag.
        let mut data_channel_internal = RTCDataChannelInternal::new(DataChannelParameters {
            label: data_channel_config.label.clone(),
            protocol: data_channel_config.protocol.clone(),
            ordered: !unordered,
            max_packet_life_time,
            max_retransmits,
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
        self.handshake_deadline = None;
        self.ready_state = RTCDataChannelState::Closed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datachannel::message::Message;
    use datachannel::message::message_channel_open::{
        CHANNEL_PRIORITY_NORMAL, ChannelType, DataChannelOpen,
    };
    use shared::marshal::Marshal;

    const PEER_STREAM: StreamId = 3;

    fn accept_open(
        channel_type: ChannelType,
        reliability_parameter: u32,
    ) -> RTCDataChannelInternal {
        let open = Message::DataChannelOpen(DataChannelOpen {
            channel_type,
            priority: CHANNEL_PRIORITY_NORMAL,
            reliability_parameter,
            label: b"peer".to_vec(),
            protocol: b"proto".to_vec(),
        })
        .marshal()
        .expect("DCEP OPEN");
        RTCDataChannelInternal::accept(0, PEER_STREAM, PayloadProtocolIdentifier::Dcep, &open)
            .expect("accept the peer's OPEN")
    }

    /// `(ordered, max_retransmits, max_packet_life_time)` — what the W3C getters report.
    fn getters(dc: &RTCDataChannelInternal) -> (bool, Option<u16>, Option<u16>) {
        (dc.ordered, dc.max_retransmits, dc.max_packet_life_time)
    }

    /// RFC 8832 §5.1: the Reliability Parameter is the retransmission limit of a Rexmit channel
    /// and the lifetime in milliseconds of a Timed one.
    #[test]
    fn an_accepted_channel_reports_the_peers_channel_type_and_reliability() {
        let cases = [
            (ChannelType::Reliable, 0, (true, None, None)),
            (ChannelType::ReliableUnordered, 0, (false, None, None)),
            (ChannelType::PartialReliableRexmit, 3, (true, Some(3), None)),
            (
                ChannelType::PartialReliableRexmitUnordered,
                0,
                (false, Some(0), None),
            ),
            (
                ChannelType::PartialReliableTimed,
                1500,
                (true, None, Some(1500)),
            ),
            (
                ChannelType::PartialReliableTimedUnordered,
                250,
                (false, None, Some(250)),
            ),
        ];
        for (channel_type, reliability_parameter, expected) in cases {
            let dc = accept_open(channel_type, reliability_parameter);
            assert_eq!(
                getters(&dc),
                expected,
                "{channel_type:?} with reliability parameter {reliability_parameter}"
            );
            assert!(!dc.negotiated, "{channel_type:?}: opened in-band");
            assert_eq!(dc.stream_id, Some(PEER_STREAM));
            assert_eq!(dc.ready_state, RTCDataChannelState::Open);
            assert_eq!((dc.label.as_str(), dc.protocol.as_str()), ("peer", "proto"));
        }
    }

    /// The wire field is 32 bits and the W3C attributes are `unsigned short`: a larger value
    /// saturates rather than wrapping.
    #[test]
    fn a_reliability_parameter_beyond_u16_saturates() {
        for (reliability_parameter, reported) in [
            (u16::MAX as u32, u16::MAX),
            (u16::MAX as u32 + 1, u16::MAX),
            (70_000, u16::MAX),
            (u32::MAX, u16::MAX),
        ] {
            assert_eq!(
                getters(&accept_open(
                    ChannelType::PartialReliableRexmit,
                    reliability_parameter
                )),
                (true, Some(reported), None),
                "maxRetransmits from {reliability_parameter}"
            );
            assert_eq!(
                getters(&accept_open(
                    ChannelType::PartialReliableTimedUnordered,
                    reliability_parameter
                )),
                (false, None, Some(reported)),
                "maxPacketLifeTime from {reliability_parameter}"
            );
        }
    }

    /// The reliable types carry nothing in the Reliability Parameter, whatever the peer put
    /// there.
    #[test]
    fn a_reliable_channel_ignores_its_reliability_parameter() {
        for channel_type in [ChannelType::Reliable, ChannelType::ReliableUnordered] {
            for reliability_parameter in [5, 70_000] {
                let (_, max_retransmits, max_packet_life_time) =
                    getters(&accept_open(channel_type, reliability_parameter));
                assert_eq!(
                    (max_retransmits, max_packet_life_time),
                    (None, None),
                    "{channel_type:?} with reliability parameter {reliability_parameter}"
                );
            }
        }
    }
}

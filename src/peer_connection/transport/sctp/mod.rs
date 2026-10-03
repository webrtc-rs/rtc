use crate::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
use crate::peer_connection::transport::RTCTransportId;
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities;
use crate::peer_connection::transport::sctp::state::RTCSctpTransportState;
use sctp::{Association, AssociationHandle};
use shared::error::Result;
use shared::{TransportContext, TransportProtocol};
use std::collections::HashMap;

pub(crate) mod capabilities;
pub(crate) mod state;

/// The stream-count ceiling used when no negotiated value is available yet.
///
/// Not the spec's `maxChannels` — that is the negotiated minimum, reported by
/// [`SctpTransport::max_channels`]. This is only the "no constraint known" fallback.
pub(crate) const SCTP_MAX_CHANNELS: u16 = u16::MAX;

/// SCTPTransport provides details about the SCTP transport.
///
/// Not `Default`: `id` and `dtls_transport_id` identify *this* connection's transports, and a
/// default-constructed id would compare equal across connections — the one thing
/// [`RTCTransportId`] must never do. Nothing constructed one this way.
pub(crate) struct SctpTransport {
    pub(crate) id: RTCTransportId,
    pub(crate) dtls_transport_id: RTCTransportId,

    pub(crate) sctp_endpoint: Option<::sctp::Endpoint>,
    pub(crate) sctp_transport_config: Option<::sctp::TransportConfig>,
    pub(crate) sctp_associations: HashMap<AssociationHandle, Association>,

    // SCTPTransportState doesn't have an enum to distinguish between New/Connecting
    // so we need a dedicated field
    pub(crate) is_started: bool,

    // The *configured* ceiling from SettingEngine — an input to the negotiation below, not the
    // value W3C `maxMessageSize` reports. See `negotiated_max_message_size`.
    pub(crate) max_message_size: SctpMaxMessageSize,

    // The negotiated [[MaxMessageSize]] slot: the result of reconciling the configured ceiling
    // above with the peer's `max-message-size` SDP attribute, computed once in `start()`.
    // `None` before the association has been negotiated.
    pub(crate) negotiated_max_message_size: Option<u32>,

    // Optional override for the SCTP receive-buffer size (a_rwnd flow-control window),
    // in bytes. None uses the sctp crate default (INITIAL_RECV_BUF_SIZE, 1 MiB).
    pub(crate) max_receive_buffer_size: Option<u32>,

    // Optional override for the outbound SCTP DATA-packet budget, applied to the endpoint's
    // `EndpointConfig` in `start()`. None uses the sctp crate default (INITIAL_MTU, 1191).
    pub(crate) mtu: Option<u32>,
}

impl SctpTransport {
    pub(crate) fn new(
        max_message_size: SctpMaxMessageSize,
        max_receive_buffer_size: Option<u32>,
        mtu: Option<u32>,
        id: RTCTransportId,
        dtls_transport_id: RTCTransportId,
    ) -> Self {
        Self {
            id,
            dtls_transport_id,
            sctp_endpoint: None,
            sctp_transport_config: None,
            sctp_associations: HashMap::new(),

            is_started: false,
            max_message_size,
            negotiated_max_message_size: None,
            max_receive_buffer_size,
            mtu,
        }
    }

    pub(crate) fn calc_message_size(remote_max_message_size: u32, can_send_size: u32) -> u32 {
        if remote_max_message_size == 0 && can_send_size == 0 {
            u32::MAX
        } else if remote_max_message_size == 0 {
            can_send_size
        } else if can_send_size == 0 || can_send_size > remote_max_message_size {
            remote_max_message_size
        } else {
            can_send_size
        }
    }

    /// The single association this transport carries, if one has been created.
    ///
    /// `sctp_associations` is a map because the endpoint API is written for the general case, but
    /// a peer connection negotiates exactly one SCTP association.
    fn association(&self) -> Option<&Association> {
        self.sctp_associations.values().next()
    }

    /// W3C `SctpTransport.state`.
    ///
    /// Derived from the association rather than tracked separately: the previous `state` field was
    /// assigned once at construction and never updated or read, so any getter over it would have
    /// reported `Connecting` for the lifetime of the connection.
    pub(crate) fn state(&self) -> RTCSctpTransportState {
        match self.association() {
            None => RTCSctpTransportState::Connecting,
            Some(association) if association.is_closed() => RTCSctpTransportState::Closed,
            Some(association) if association.is_handshaking() => RTCSctpTransportState::Connecting,
            Some(_) => RTCSctpTransportState::Connected,
        }
    }

    /// W3C `SctpTransport.maxMessageSize`, in bytes.
    ///
    /// `None` until the association has been negotiated, at which point it is the reconciliation of
    /// this endpoint's configured ceiling with the peer's `max-message-size` SDP attribute
    /// ([RFC 8841 §6]).
    ///
    /// Always finite. The spec types the attribute `unrestricted double` so that an
    /// implementation with no limit can report positive infinity; this one always has a limit,
    /// because each message is held in memory whole — see [`Self::local_max_message_size`].
    ///
    /// [RFC 8841 §6]: https://datatracker.ietf.org/doc/html/rfc8841#section-6
    pub(crate) fn max_message_size(&self) -> Option<u32> {
        self.negotiated_max_message_size
    }

    /// This endpoint's own limit: its `canSendSize`, and the `max-message-size` it advertises and
    /// accepts.
    ///
    /// Inbound messages are bounded by this, not by [`Self::max_message_size`]: that is the
    /// peer's limit, and the peer may send anything up to the `max-message-size` advertised here.
    pub(crate) fn local_max_message_size(&self) -> u32 {
        // Capped at the SCTP receive buffer, which a message must fit in to be reassembled. W3C
        // §6.1.1.2 allows `canSendSize` to be 0 only when the implementation "can handle messages
        // of any size", so a configured 0 resolves to that cap rather than to "unlimited".
        let max_receive_buffer_size = self
            .max_receive_buffer_size
            .unwrap_or_else(|| ::sctp::TransportConfig::default().max_receive_buffer_size());
        match self.max_message_size {
            SctpMaxMessageSize::Bounded(0) | SctpMaxMessageSize::Unbounded => {
                max_receive_buffer_size
            }
            SctpMaxMessageSize::Bounded(size) => size.min(max_receive_buffer_size),
        }
    }

    /// W3C `SctpTransport.maxChannels`: the minimum of the negotiated inbound and outbound
    /// stream counts.
    ///
    /// `None` until the association reaches the connected state, matching the spec's "this
    /// attribute's value will be null until the SCTP transport goes into the `connected` state".
    pub(crate) fn max_channels(&self) -> Option<u16> {
        self.association()?.negotiated_max_streams()
    }

    /// Start the SCTPTransport. Since both local and remote parties must mutually
    /// create an SCTPTransport, SCTP SO (Simultaneous Open) is used to establish
    /// a connection over SCTP.
    pub(crate) fn start(
        &mut self,
        dtls_role: RTCDtlsRole,
        remote_caps: SCTPTransportCapabilities,
        local_port: u16,
        _remote_port: u16,
    ) -> Result<()> {
        if self.is_started {
            return Ok(());
        }
        self.is_started = true;

        let max_message_size = SctpTransport::calc_message_size(
            remote_caps.max_message_size,
            self.local_max_message_size(),
        );

        // This is the spec's [[MaxMessageSize]] slot.
        self.negotiated_max_message_size = Some(max_message_size);

        let mut sctp_endpoint_config = ::sctp::EndpointConfig::default();
        if let Some(mtu) = self.mtu {
            sctp_endpoint_config.max_payload_size(::sctp::max_payload_size_for_mtu(mtu));
        }
        let mut sctp_transport_config = ::sctp::TransportConfig::default()
            .with_max_message_size(max_message_size)
            .with_sctp_port(local_port);
        if let Some(recv_buf) = self.max_receive_buffer_size {
            sctp_transport_config = sctp_transport_config.with_max_receive_buffer_size(recv_buf);
        }
        //TODO: add remote_port support

        if dtls_role == RTCDtlsRole::Client {
            self.sctp_endpoint = Some(sctp::Endpoint::new(
                TransportContext::default().local_addr, // placeholder; rewritten per-transmit by the ICE handler
                TransportProtocol::UDP, // placeholder; rewritten per-transmit by the ICE handler
                sctp_endpoint_config.into(),
                None,
            ));
            self.sctp_transport_config = Some(sctp_transport_config);
        } else {
            self.sctp_endpoint = Some(::sctp::Endpoint::new(
                TransportContext::default().local_addr, // placeholder; rewritten per-transmit by the ICE handler
                TransportProtocol::UDP, // placeholder; rewritten per-transmit by the ICE handler
                sctp_endpoint_config.into(),
                Some(::sctp::ServerConfig::new(sctp_transport_config).into()),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::peer_connection::transport::{RTCTransportId, TransportKind};

    /// A fixed nonce keeps test ids deterministic while still distinguishing the kinds.
    fn test_transport_id(kind: TransportKind) -> RTCTransportId {
        RTCTransportId::new(0xabcd_ef01_2345_6789, kind)
    }
    use super::*;

    fn started_transport(
        configured: SctpMaxMessageSize,
        remote_max_message_size: u32,
    ) -> SctpTransport {
        let mut transport = SctpTransport::new(
            configured,
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .start(
                RTCDtlsRole::Client,
                SCTPTransportCapabilities {
                    max_message_size: remote_max_message_size,
                },
                5000,
                5000,
            )
            .expect("start");
        transport
    }

    // `maxMessageSize` is the *negotiated* value, not the configured ceiling. Configure 64 KiB
    // and have the peer advertise 16 KiB: reporting the configured value would answer 65536.
    #[test]
    fn max_message_size_reports_the_negotiated_value_not_the_configured_one() {
        let transport = started_transport(SctpMaxMessageSize::Bounded(65536), 16384);
        assert_eq!(Some(16384), transport.max_message_size());
    }

    // The reverse direction, so the test cannot pass by simply echoing the remote's number.
    #[test]
    fn max_message_size_takes_the_smaller_of_the_two_limits() {
        let transport = started_transport(SctpMaxMessageSize::Bounded(16384), 65536);
        assert_eq!(Some(16384), transport.max_message_size());
    }

    // The peer may send up to what this endpoint advertised, whatever its own limit.
    #[test]
    fn inbound_limit_is_the_local_one_not_the_negotiated_one() {
        let transport = started_transport(SctpMaxMessageSize::Bounded(65536), 16384);
        assert_eq!(Some(16384), transport.max_message_size());
        assert_eq!(65536, transport.local_max_message_size());
    }

    // Neither side names a limit. This implementation still has one, so `canSendSize` resolves to
    // the SCTP receive buffer size rather than to "unlimited" (W3C §6.1.1.2 allows 0 only for an
    // implementation that can handle any size).
    #[test]
    fn no_limit_on_either_side_resolves_to_the_implementation_ceiling() {
        let transport = started_transport(SctpMaxMessageSize::Bounded(0), 0);
        assert_eq!(
            Some(::sctp::TransportConfig::default().max_receive_buffer_size()),
            transport.max_message_size()
        );
    }

    #[test]
    fn local_limit_is_capped_at_the_receive_buffer() {
        let default_receive_buffer = ::sctp::TransportConfig::default().max_receive_buffer_size();
        for (configured, receive_buffer, expected) in [
            (SctpMaxMessageSize::Bounded(16384), Some(65536), 16384),
            (SctpMaxMessageSize::Bounded(65536), Some(16384), 16384),
            (SctpMaxMessageSize::Unbounded, Some(4 << 20), 4 << 20),
            (SctpMaxMessageSize::Unbounded, None, default_receive_buffer),
            (
                SctpMaxMessageSize::Bounded(u32::MAX),
                None,
                default_receive_buffer,
            ),
        ] {
            let transport = SctpTransport::new(
                configured,
                receive_buffer,
                None,
                test_transport_id(TransportKind::Sctp),
                test_transport_id(TransportKind::Dtls),
            );
            assert_eq!(expected, transport.local_max_message_size());
        }
    }

    #[test]
    fn max_message_size_is_none_before_start() {
        let transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        assert_eq!(None, transport.max_message_size());
    }

    // No association yet: the spec's initial state, and nothing to report for maxChannels.
    #[test]
    fn state_and_max_channels_before_any_association() {
        let transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        assert_eq!(RTCSctpTransportState::Connecting, transport.state());
        assert_eq!(None, transport.max_channels());
    }

    // A default `Association` is in `AssociationState::Closed`, so the transport must report
    // Closed rather than the Connecting it was constructed with. This is the case the old
    // never-updated `state` field got wrong.
    #[test]
    fn state_follows_a_closed_association() {
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .sctp_associations
            .insert(AssociationHandle(0), Association::default());
        assert_eq!(RTCSctpTransportState::Closed, transport.state());
        assert_eq!(
            None,
            transport.max_channels(),
            "a closed association negotiated nothing"
        );
    }

    // Starting a Client transport stores the built TransportConfig on the struct, so we
    // can assert the configured (or default) receive-buffer size flowed through `start()`.
    #[test]
    fn start_applies_configured_receive_buffer_size() {
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            Some(200_000),
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .start(
                RTCDtlsRole::Client,
                SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");
        assert_eq!(
            transport
                .sctp_transport_config
                .expect("client transport config")
                .max_receive_buffer_size(),
            200_000
        );
    }

    #[test]
    fn start_without_override_uses_default_receive_buffer_size() {
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .start(
                RTCDtlsRole::Client,
                SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");
        // `None` keeps the sctp crate default (INITIAL_RECV_BUF_SIZE = 1 MiB).
        assert_eq!(
            transport
                .sctp_transport_config
                .expect("client transport config")
                .max_receive_buffer_size(),
            1024 * 1024
        );
    }

    // Starting a Client transport builds the endpoint from an `EndpointConfig`, so we can
    // assert the configured MTU flowed through `start()` as the derived payload budget:
    // mtu minus the common and DATA chunk headers, rounded down to the 4-byte boundary.
    #[test]
    fn start_applies_configured_mtu() {
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            Some(1500),
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport
            .start(
                RTCDtlsRole::Client,
                SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");
        assert_eq!(
            transport
                .sctp_endpoint
                .expect("client endpoint")
                .endpoint_config()
                .get_max_payload_size(),
            (1500 - (12 + 16)) & !3
        );
    }
}

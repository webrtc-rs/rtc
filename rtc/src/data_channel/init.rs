/// Dictionary for configuring properties of an RTCDataChannel.
///
/// The `RTCDataChannelInit` dictionary is used to configure the properties of a data channel
/// when creating it via [`RTCPeerConnection::create_data_channel`].
///
/// ## Specifications
///
/// * [W3C RTCDataChannelInit Dictionary]
///
/// [W3C RTCDataChannelInit Dictionary]: https://www.w3.org/TR/webrtc/#dom-rtcdatachannelinit
/// [`RTCPeerConnection::create_data_channel`]: crate::peer_connection::RTCPeerConnection::create_data_channel
///
/// ## Examples
///
/// ```
/// use rtc::data_channel::RTCDataChannelInit;
///
/// let init = RTCDataChannelInit {
///     ordered: false,
///     max_retransmits: Some(3),
///     ..Default::default()
/// };
/// ```
#[derive(Default, Clone)]
pub struct RTCDataChannelInit {
    /// If set to `false`, data is allowed to be delivered out of order.
    ///
    /// The default value of `true` guarantees that data will be delivered in order.
    /// Setting this to `false` may improve latency at the cost of ordering guarantees.
    ///
    /// Corresponds to the `ordered` attribute in the [W3C specification].
    ///
    /// [W3C specification]: https://www.w3.org/TR/webrtc/#dom-rtcdatachannelinit-ordered
    pub ordered: bool,

    /// Limits the time (in milliseconds) during which the channel will transmit or retransmit
    /// data if not acknowledged.
    ///
    /// If set, this value may be clamped to the maximum value supported by the user agent.
    /// This option cannot be used together with `max_retransmits`.
    ///
    /// Corresponds to the `maxPacketLifeTime` attribute in the [W3C specification].
    ///
    /// [W3C specification]: https://www.w3.org/TR/webrtc/#dom-rtcdatachannelinit-maxpacketlifetime
    pub max_packet_life_time: Option<u16>,

    /// Limits the number of times the channel will retransmit data if not successfully delivered.
    ///
    /// If set, this value may be clamped to the maximum value supported by the user agent.
    /// This option cannot be used together with `max_packet_life_time`.
    ///
    /// Corresponds to the `maxRetransmits` attribute in the [W3C specification].
    ///
    /// [W3C specification]: https://www.w3.org/TR/webrtc/#dom-rtcdatachannelinit-maxretransmits
    pub max_retransmits: Option<u16>,

    /// The name of the subprotocol used for this channel.
    ///
    /// An empty string indicates no subprotocol is being used. The default is an empty string.
    ///
    /// Corresponds to the `protocol` attribute in the [W3C specification].
    ///
    /// [W3C specification]: https://www.w3.org/TR/webrtc/#dom-rtcdatachannelinit-protocol
    pub protocol: String,

    /// If `Some(id)`, the data channel is negotiated out-of-band with the given stream identifier.
    ///
    /// When set to `Some(id)`, the application is responsible for negotiating the channel and
    /// creating a matching data channel with the same `id` on the remote peer. The data channel
    /// will not be announced in-band.
    ///
    /// When set to `None` (the default), the user agent will announce the channel in-band and
    /// automatically create a corresponding data channel on the remote peer.
    ///
    /// Corresponds to the `negotiated` and `id` attributes in the [W3C specification].
    ///
    /// [W3C specification]: https://www.w3.org/TR/webrtc/#dom-rtcdatachannelinit-negotiated
    pub negotiated: Option<u16>,
}

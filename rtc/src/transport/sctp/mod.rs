use crate::configuration::setting_engine::SctpMaxMessageSize;
use crate::transport::sctp::state::RTCSctpTransportState;

pub mod state;

const SCTP_MAX_CHANNELS: u16 = u16::MAX;

/// SCTPTransport provides details about the SCTP transport.
#[derive(Default, Clone)]
pub struct RTCSctpTransport {
    //TODO: transport: RTCDtlsTransport,

    // State represents the current state of the SCTP transport.
    state: RTCSctpTransportState,

    // SCTPTransportState doesn't have an enum to distinguish between New/Connecting
    // so we need a dedicated field
    is_started: bool,

    // max_message_size represents the maximum size of data that can be passed to
    // RTCDataChannel's send() method. The attribute MUST, on getting,
    // return the value of the [[MaxMessageSize]] slot.
    max_message_size: SctpMaxMessageSize,

    // max_channels represents the maximum amount of DataChannel's that can
    // be used simultaneously.
    max_channels: u16,
}

impl RTCSctpTransport {
    pub(crate) fn new(max_message_size: SctpMaxMessageSize) -> Self {
        Self {
            state: RTCSctpTransportState::Connecting,
            is_started: false,
            max_message_size,
            max_channels: SCTP_MAX_CHANNELS,
            //sctp_association: Mutex::new(None),
            /*on_error_handler: Arc::new(ArcSwapOption::empty()),
            on_data_channel_handler: Arc::new(ArcSwapOption::empty()),
            on_data_channel_opened_handler: Arc::new(ArcSwapOption::empty()),

            data_channels: Arc::new(Mutex::new(vec![])),
            data_channels_opened: Arc::new(AtomicU32::new(0)),
            data_channels_requested: Arc::new(AtomicU32::new(0)),
            data_channels_accepted: Arc::new(AtomicU32::new(0)),

            notify_tx: Arc::new(Notify::new()),

            setting_engine,*/
        }
    }
}

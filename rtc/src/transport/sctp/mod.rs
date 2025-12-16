use crate::transport::sctp::state::RTCSctpTransportState;

pub mod state;

/// SCTPTransport provides details about the SCTP transport.
#[derive(Default)]
pub struct RTCSctpTransport {
    //TODO: transport: RTCDtlsTransport,

    // State represents the current state of the SCTP transport.
    state: RTCSctpTransportState,

    // max_message_size represents the maximum size of data that can be passed to
    // RTCDataChannel's send() method. The attribute MUST, on getting,
    // return the value of the [[MaxMessageSize]] slot.
    max_message_size: usize,

    // max_channels represents the maximum amount of DataChannel's that can
    // be used simultaneously.
    max_channels: u16,
}

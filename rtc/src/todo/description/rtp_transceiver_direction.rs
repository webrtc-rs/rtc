use crate::description::UNSPECIFIED_STR;
use std::fmt;

/// RTPTransceiverDirection indicates the direction of the RTPTransceiver.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum RTCRtpTransceiverDirection {
    #[default]
    Unspecified,

    /// Sendrecv indicates the RTPSender will offer
    /// to send RTP and RTPReceiver the will offer to receive RTP.
    Sendrecv,

    /// Sendonly indicates the RTPSender will offer to send RTP.
    Sendonly,

    /// Recvonly indicates the RTPReceiver the will offer to receive RTP.
    Recvonly,

    /// Inactive indicates the RTPSender won't offer
    /// to send RTP and RTPReceiver the won't offer to receive RTP.
    Inactive,
}

const RTP_TRANSCEIVER_DIRECTION_SENDRECV_STR: &str = "sendrecv";
const RTP_TRANSCEIVER_DIRECTION_SENDONLY_STR: &str = "sendonly";
const RTP_TRANSCEIVER_DIRECTION_RECVONLY_STR: &str = "recvonly";
const RTP_TRANSCEIVER_DIRECTION_INACTIVE_STR: &str = "inactive";

/// defines a procedure for creating a new
/// RTPTransceiverDirection from a raw string naming the transceiver direction.
impl From<&str> for RTCRtpTransceiverDirection {
    fn from(raw: &str) -> Self {
        match raw {
            RTP_TRANSCEIVER_DIRECTION_SENDRECV_STR => RTCRtpTransceiverDirection::Sendrecv,
            RTP_TRANSCEIVER_DIRECTION_SENDONLY_STR => RTCRtpTransceiverDirection::Sendonly,
            RTP_TRANSCEIVER_DIRECTION_RECVONLY_STR => RTCRtpTransceiverDirection::Recvonly,
            RTP_TRANSCEIVER_DIRECTION_INACTIVE_STR => RTCRtpTransceiverDirection::Inactive,
            _ => RTCRtpTransceiverDirection::Unspecified,
        }
    }
}

impl From<u8> for RTCRtpTransceiverDirection {
    fn from(v: u8) -> Self {
        match v {
            1 => RTCRtpTransceiverDirection::Sendrecv,
            2 => RTCRtpTransceiverDirection::Sendonly,
            3 => RTCRtpTransceiverDirection::Recvonly,
            4 => RTCRtpTransceiverDirection::Inactive,
            _ => RTCRtpTransceiverDirection::Unspecified,
        }
    }
}

impl fmt::Display for RTCRtpTransceiverDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RTCRtpTransceiverDirection::Sendrecv => {
                write!(f, "{RTP_TRANSCEIVER_DIRECTION_SENDRECV_STR}")
            }
            RTCRtpTransceiverDirection::Sendonly => {
                write!(f, "{RTP_TRANSCEIVER_DIRECTION_SENDONLY_STR}")
            }
            RTCRtpTransceiverDirection::Recvonly => {
                write!(f, "{RTP_TRANSCEIVER_DIRECTION_RECVONLY_STR}")
            }
            RTCRtpTransceiverDirection::Inactive => {
                write!(f, "{RTP_TRANSCEIVER_DIRECTION_INACTIVE_STR}")
            }
            _ => write!(f, "{}", UNSPECIFIED_STR),
        }
    }
}

impl RTCRtpTransceiverDirection {
    /// reverse indicate the opposite direction
    pub fn reverse(&self) -> RTCRtpTransceiverDirection {
        match *self {
            RTCRtpTransceiverDirection::Sendonly => RTCRtpTransceiverDirection::Recvonly,
            RTCRtpTransceiverDirection::Recvonly => RTCRtpTransceiverDirection::Sendonly,
            _ => *self,
        }
    }

    pub fn intersect(&self, other: RTCRtpTransceiverDirection) -> RTCRtpTransceiverDirection {
        Self::from_send_recv(
            self.has_send() && other.has_send(),
            self.has_recv() && other.has_recv(),
        )
    }

    pub fn from_send_recv(send: bool, recv: bool) -> RTCRtpTransceiverDirection {
        match (send, recv) {
            (true, true) => Self::Sendrecv,
            (true, false) => Self::Sendonly,
            (false, true) => Self::Recvonly,
            (false, false) => Self::Inactive,
        }
    }

    pub fn has_send(&self) -> bool {
        matches!(self, Self::Sendrecv | Self::Sendonly)
    }

    pub fn has_recv(&self) -> bool {
        matches!(self, Self::Sendrecv | Self::Recvonly)
    }
}

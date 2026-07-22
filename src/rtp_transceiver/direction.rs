use crate::peer_connection::configuration::UNSPECIFIED_STR;
use std::fmt;

/// Direction of media flow for an RTP transceiver.
///
/// Indicates whether the transceiver will send and/or receive RTP media.
///
/// # Specification
///
/// See [RTCRtpTransceiverDirection](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiverdirection)
/// in the W3C WebRTC specification.
///
/// # MDN
///
/// See [RTCRtpTransceiver.direction](https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpTransceiver/direction).
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum RTCRtpTransceiverDirection {
    /// Direction is not specified (internal use only).
    #[default]
    Unspecified,

    /// Transceiver will both send and receive RTP media.
    ///
    /// The RTP sender will offer to send RTP and the RTP receiver will offer to receive RTP.
    Sendrecv,

    /// Transceiver will only send RTP media.
    ///
    /// The RTP sender will offer to send RTP.
    Sendonly,

    /// Transceiver will only receive RTP media.
    ///
    /// The RTP receiver will offer to receive RTP.
    Recvonly,

    /// Transceiver will neither send nor receive RTP media.
    ///
    /// Neither the RTP sender nor receiver will be active.
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
    /// Returns the opposite direction.
    ///
    /// Swaps send-only with receive-only. Sendrecv and Inactive remain unchanged.
    pub fn reverse(&self) -> RTCRtpTransceiverDirection {
        match *self {
            RTCRtpTransceiverDirection::Sendonly => RTCRtpTransceiverDirection::Recvonly,
            RTCRtpTransceiverDirection::Recvonly => RTCRtpTransceiverDirection::Sendonly,
            _ => *self,
        }
    }

    /// Returns the intersection of two directions.
    ///
    /// The resulting direction will only send if both directions can send,
    /// and will only receive if both directions can receive.
    pub fn intersect(&self, other: RTCRtpTransceiverDirection) -> RTCRtpTransceiverDirection {
        Self::from_send_recv(
            self.has_send() && other.has_send(),
            self.has_recv() && other.has_recv(),
        )
    }

    /// Creates a direction from separate send and receive capabilities.
    pub fn from_send_recv(send: bool, recv: bool) -> RTCRtpTransceiverDirection {
        match (send, recv) {
            (true, true) => Self::Sendrecv,
            (true, false) => Self::Sendonly,
            (false, true) => Self::Recvonly,
            (false, false) => Self::Inactive,
        }
    }

    /// Returns true if this direction includes sending media.
    pub fn has_send(&self) -> bool {
        matches!(self, Self::Sendrecv | Self::Sendonly)
    }

    /// Returns true if this direction includes receiving media.
    pub fn has_recv(&self) -> bool {
        matches!(self, Self::Sendrecv | Self::Recvonly)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_rtp_transceiver_direction() {
        let tests = vec![
            ("Unspecified", RTCRtpTransceiverDirection::Unspecified),
            ("sendrecv", RTCRtpTransceiverDirection::Sendrecv),
            ("sendonly", RTCRtpTransceiverDirection::Sendonly),
            ("recvonly", RTCRtpTransceiverDirection::Recvonly),
            ("inactive", RTCRtpTransceiverDirection::Inactive),
        ];

        for (ct_str, expected_type) in tests {
            assert_eq!(RTCRtpTransceiverDirection::from(ct_str), expected_type);
        }
    }

    #[test]
    fn test_rtp_transceiver_direction_string() {
        let tests = vec![
            (RTCRtpTransceiverDirection::Unspecified, "Unspecified"),
            (RTCRtpTransceiverDirection::Sendrecv, "sendrecv"),
            (RTCRtpTransceiverDirection::Sendonly, "sendonly"),
            (RTCRtpTransceiverDirection::Recvonly, "recvonly"),
            (RTCRtpTransceiverDirection::Inactive, "inactive"),
        ];

        for (d, expected_string) in tests {
            assert_eq!(d.to_string(), expected_string);
        }
    }

    #[test]
    fn test_rtp_transceiver_has_send() {
        let tests = vec![
            (RTCRtpTransceiverDirection::Unspecified, false),
            (RTCRtpTransceiverDirection::Sendrecv, true),
            (RTCRtpTransceiverDirection::Sendonly, true),
            (RTCRtpTransceiverDirection::Recvonly, false),
            (RTCRtpTransceiverDirection::Inactive, false),
        ];

        for (d, expected_value) in tests {
            assert_eq!(d.has_send(), expected_value);
        }
    }

    #[test]
    fn test_rtp_transceiver_has_recv() {
        let tests = vec![
            (RTCRtpTransceiverDirection::Unspecified, false),
            (RTCRtpTransceiverDirection::Sendrecv, true),
            (RTCRtpTransceiverDirection::Sendonly, false),
            (RTCRtpTransceiverDirection::Recvonly, true),
            (RTCRtpTransceiverDirection::Inactive, false),
        ];

        for (d, expected_value) in tests {
            assert_eq!(d.has_recv(), expected_value);
        }
    }

    #[test]
    fn test_rtp_transceiver_from_send_recv() {
        let tests = vec![
            (RTCRtpTransceiverDirection::Sendrecv, (true, true)),
            (RTCRtpTransceiverDirection::Sendonly, (true, false)),
            (RTCRtpTransceiverDirection::Recvonly, (false, true)),
            (RTCRtpTransceiverDirection::Inactive, (false, false)),
        ];

        for (expected_value, (send, recv)) in tests {
            assert_eq!(
                RTCRtpTransceiverDirection::from_send_recv(send, recv),
                expected_value
            );
        }
    }

    #[test]
    fn test_rtp_transceiver_intersect() {
        use RTCRtpTransceiverDirection::*;

        let tests = vec![
            ((Sendrecv, Recvonly), Recvonly),
            ((Sendrecv, Sendonly), Sendonly),
            ((Sendrecv, Inactive), Inactive),
            ((Sendonly, Inactive), Inactive),
            ((Recvonly, Inactive), Inactive),
            ((Recvonly, Sendrecv), Recvonly),
            ((Sendonly, Sendrecv), Sendonly),
            ((Sendonly, Recvonly), Inactive),
            ((Recvonly, Recvonly), Recvonly),
        ];

        for ((a, b), expected_direction) in tests {
            assert_eq!(a.intersect(b), expected_direction);
        }
    }
}

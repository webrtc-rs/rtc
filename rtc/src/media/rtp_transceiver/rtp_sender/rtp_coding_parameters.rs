/// RTPCodingParameters provides information relating to both encoding and decoding.
/// This is a subset of the RFC since Pion WebRTC doesn't implement encoding/decoding itself
/// <http://draft.ortc.org/#dom-rtcrtpcodingparameters>
#[derive(Default, Debug, Clone)]
pub struct RTCRtpCodingParameters {
    pub rid: String,
    //pub ssrc: SSRC,
    //pub payload_type: PayloadType,
    //pub rtx: RTCRtpRtxParameters,
}

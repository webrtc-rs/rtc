//TODO: #[cfg(test)]
//mod track_local_static_test;

//pub mod track_local_static_rtp;
//pub mod track_local_static_sample;

use interceptor::Attributes;
use shared::marshal::Unmarshal;

use crate::media::rtp_transceiver::rtp_sender::rtp_codec::*;
use crate::media::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::media::rtp_transceiver::rtp_sender::rtp_header_extension_parameters::RTCRtpHeaderExtensionParameters;
use crate::media::rtp_transceiver::rtp_sender::rtp_parameters::RTCRtpParameters;
use crate::media::rtp_transceiver::*;
use shared::error::Result;

/// TrackLocal is an interface that controls how the user can send media
/// The user can provide their own TrackLocal implementations, or use
/// the implementations in pkg/media
#[derive(Default, Debug, Clone)]
pub struct TrackLocal {
    codec: RTCRtpCodec,
    rid: Option<String>,
    stream_id: String,

    pub(crate) id: String,
    pub(crate) params: RTCRtpParameters,
    pub(crate) ssrc: SSRC,
    pub(crate) paused: bool,
    pub(crate) mid: Option<String>,
}

impl TrackLocal {
    /// codec_parameters returns the negotiated RTPCodecParameters. These are the codecs supported by both
    /// PeerConnections and the SSRC/PayloadTypes
    pub fn codec_parameters(&self) -> &[RTCRtpCodecParameters] {
        &self.params.codecs
    }

    /// header_extensions returns the negotiated RTPHeaderExtensionParameters. These are the header extensions supported by
    /// both PeerConnections and the SSRC/PayloadTypes
    pub fn header_extensions(&self) -> &[RTCRtpHeaderExtensionParameters] {
        &self.params.header_extensions
    }

    /// ssrc requires the negotiated SSRC of this track
    /// This track may have multiple if RTX is enabled
    pub fn ssrc(&self) -> SSRC {
        self.ssrc
    }

    /// id is a unique identifier that is used for both bind/unbind
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    pub fn rid(&self) -> Option<&str> {
        self.rid.as_deref()
    }

    /// mid returns the id of media associated with the RTP stream
    pub fn mid(&self) -> &Option<String> {
        &self.mid
    }

    /// paused returns a boolean indicating whether the track is currently paused
    pub fn paused(&self) -> bool {
        self.paused
    }

    /// stream_id is the group this track belongs too. This must be unique
    pub fn stream_id(&self) -> &str {
        self.stream_id.as_str()
    }

    pub fn kind(&self) -> RTPCodecType {
        if self.codec.mime_type.starts_with("audio/") {
            RTPCodecType::Audio
        } else if self.codec.mime_type.starts_with("video/") {
            RTPCodecType::Video
        } else {
            RTPCodecType::Unspecified
        }
    }

    /// write_rtp_with_attributes encrypts a RTP packet and writes to the connection.
    /// attributes are delivered to the interceptor chain
    fn write_rtp_with_attributes(
        &self,
        _pkt: &rtp::packet::Packet,
        _attr: &Attributes,
    ) -> Result<usize> {
        Ok(0)
    }

    /// write_rtp encrypts a RTP packet and writes to the connection
    fn write_rtp(&self, pkt: &rtp::packet::Packet) -> Result<usize> {
        let attr = Attributes::new();
        self.write_rtp_with_attributes(pkt, &attr)
    }

    /// write encrypts and writes a full RTP packet
    fn write(&self, mut b: &[u8]) -> Result<usize> {
        let pkt = rtp::packet::Packet::unmarshal(&mut b)?;
        let attr = Attributes::new();
        self.write_rtp_with_attributes(&pkt, &attr)
    }
}

//! Inputs shared by the end-to-end benchmarks: certificates, codecs, and payloads.

use std::time::Duration;

use bytes::Bytes;
use rtc::crypto::{RTCCryptoProvider, SignatureScheme};
use rtc::peer_connection::certificate::{CertificateParams, RTCCertificate};
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_OPUS, MIME_TYPE_VP8};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};
use rtc::shared::error::{Error, Result};

/// A self-signed ECDSA P-256 certificate, the scheme browsers generate by default.
///
/// A peer connection built without a certificate generates one, and key generation then dominates
/// anything else construction does. Benchmarks that are not about key generation build their
/// certificates once, outside the timed region, and pass them in.
///
/// # Errors
///
/// If the provider cannot generate a P-256 key.
pub fn certificate(provider: &dyn RTCCryptoProvider) -> Result<RTCCertificate> {
    let params = CertificateParams::new(vec!["rtc-bench".to_owned()])
        .map_err(|err| Error::Other(err.to_string()))?;
    RTCCertificate::generate(provider.crypto(), SignatureScheme::EcdsaP256Sha256, params)
}

/// `len` bytes of a fixed, non-constant pattern.
///
/// Not all zeros, so nothing along the path can take a shortcut on trivial input.
pub fn payload(len: usize) -> Bytes {
    (0..len).map(|index| index as u8).collect::<Vec<_>>().into()
}

/// The kind of media a benchmark track carries, with the packet shape typical of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    /// Opus at 20 ms frames: small packets, 50 per second.
    Audio,
    /// VP8 at MTU-sized packets, 1000 per second (roughly 9.6 Mb/s).
    Video,
}

impl MediaKind {
    /// Label used in benchmark ids.
    pub fn label(self) -> &'static str {
        match self {
            MediaKind::Audio => "audio",
            MediaKind::Video => "video",
        }
    }

    /// The codec kind this media is negotiated under.
    pub fn codec_kind(self) -> RtpCodecKind {
        match self {
            MediaKind::Audio => RtpCodecKind::Audio,
            MediaKind::Video => RtpCodecKind::Video,
        }
    }

    /// The codec registered for this kind.
    ///
    /// The track's encoding copies these parameters exactly, so codec matching during negotiation
    /// cannot depend on how forgiving the fmtp comparison happens to be.
    pub fn codec(self) -> RTCRtpCodecParameters {
        match self {
            MediaKind::Audio => RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    clock_rate: 48_000,
                    channels: 2,
                    sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 111,
            },
            MediaKind::Video => RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90_000,
                    channels: 0,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                },
                payload_type: 96,
            },
        }
    }

    /// RTP payload bytes per packet: a 20 ms Opus frame at a typical voice bitrate, or a
    /// full-MTU video packet.
    pub fn payload_len(self) -> usize {
        match self {
            MediaKind::Audio => 160,
            MediaKind::Video => 1200,
        }
    }

    /// Spacing between packets. Virtual time advances by this much per packet, so periodic work —
    /// RTCP reports, TWCC feedback, ICE consent — is amortised over packets at a realistic rate.
    pub fn packet_interval(self) -> Duration {
        match self {
            MediaKind::Audio => Duration::from_millis(20),
            MediaKind::Video => Duration::from_millis(1),
        }
    }

    /// RTP timestamp increment per packet, in the codec's clock rate.
    pub fn timestamp_step(self) -> u32 {
        let interval = self.packet_interval().as_secs_f64();
        (interval * self.codec().rtp_codec.clock_rate as f64) as u32
    }
}

/// Which interceptor chain the peers are built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interceptors {
    /// No interceptors: the bare transport path, SRTP and demultiplexing only.
    None,
    /// `register_default_interceptors`: NACK, RTCP reports, TWCC and simulcast header extensions,
    /// which is what the examples and most applications use.
    Default,
}

impl Interceptors {
    /// Label used in benchmark ids.
    pub fn label(self) -> &'static str {
        match self {
            Interceptors::None => "no-interceptors",
            Interceptors::Default => "default-interceptors",
        }
    }
}

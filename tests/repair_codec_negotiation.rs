//! Repair codecs (RTX, FEC) must survive the codec narrowing that `add_track` performs.
//!
//! A track's encoding names one media codec, and `add_track` turns that into the transceiver's
//! codec preferences. Repair codecs are not alternatives to that choice — they accompany it — so
//! filtering them out yields an offer that names a repair SSRC in an `a=ssrc-group` while offering
//! no format to carry it, which no peer can act on.
//!
//! Registering the repair codec in the `MediaEngine` is what decides whether a repair flow exists
//! at all. Its SSRC then follows the same rule as the media SSRC: what the application named is
//! what gets used, and one is minted only when the track left it unset. Tests that do not name one
//! therefore read the SSRC back from the sender rather than asserting a constant.
//!
//! These assertions mirror pion's `TestConfigureFlexFEC03_FECParameters`.

use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_FLEX_FEC03, MIME_TYPE_RTX, MIME_TYPE_VP8, MIME_TYPE_VP9, MediaEngine,
};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RTCRtpFecParameters, RTCRtpRtxParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpSenderId, SSRC};
use std::time::Instant;

const MEDIA_SSRC: SSRC = 0x1111_1111;
const EXPLICIT_RTX_SSRC: SSRC = 0x2222_2222;
const EXPLICIT_FEC_SSRC: SSRC = 0x3333_3333;

const VP8_PT: u8 = 96;
const VP8_RTX_PT: u8 = 97;
const VP9_PT: u8 = 98;
const VP9_RTX_PT: u8 = 99;
const FLEX_FEC_PT: u8 = 49;

fn video_codec(mime_type: &str, payload_type: u8, sdp_fmtp_line: &str) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime_type.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: sdp_fmtp_line.to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type,
        ..Default::default()
    }
}

fn video_media_engine(codecs: &[RTCRtpCodecParameters]) -> MediaEngine {
    let mut media_engine = MediaEngine::default();
    for codec in codecs {
        media_engine
            .register_codec(codec.clone(), RtpCodecKind::Video)
            .expect("register codec");
    }
    media_engine
}

/// A single-encoding video track whose encoding names `codec` — which is what narrows the
/// transceiver's codec preferences to that one codec.
///
/// `rtx` and `fec` are left unset, so the peer connection mints those SSRCs. See
/// [`video_track_with_repair_ssrcs`] for the explicit case.
fn video_track(codec: &RTCRtpCodecParameters) -> MediaStreamTrack {
    MediaStreamTrack::new(
        "stream".to_string(),
        "video".to_string(),
        "video".to_string(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(MEDIA_SSRC),
                ..Default::default()
            },
            codec: codec.rtp_codec.clone(),
            ..Default::default()
        }],
    )
}

/// As [`video_track`], but naming every SSRC the track will use, repair flows included.
fn video_track_with_repair_ssrcs(
    codec: &RTCRtpCodecParameters,
    rtx_ssrc: Option<SSRC>,
    fec_ssrc: Option<SSRC>,
) -> MediaStreamTrack {
    MediaStreamTrack::new(
        "stream".to_string(),
        "video".to_string(),
        "video".to_string(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(MEDIA_SSRC),
                rtx: rtx_ssrc.map(|ssrc| RTCRtpRtxParameters { ssrc }),
                fec: fec_ssrc.map(|ssrc| RTCRtpFecParameters { ssrc }),
                ..Default::default()
            },
            codec: codec.rtp_codec.clone(),
            ..Default::default()
        }],
    )
}

/// The offer, plus the repair SSRCs the peer connection chose for the track's single encoding.
struct Offer {
    sdp: String,
    rtx_ssrc: Option<SSRC>,
    fec_ssrc: Option<SSRC>,
}

fn offer_for(media_engine: MediaEngine, codec: &RTCRtpCodecParameters) -> Offer {
    offer_for_track(media_engine, video_track(codec))
}

fn offer_for_track(media_engine: MediaEngine, track: MediaStreamTrack) -> Offer {
    let mut peer_connection = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(media_engine)
        .build(Instant::now())
        .expect("build peer connection");

    let sender_id = peer_connection.add_track(track).expect("add track");
    let sdp = peer_connection
        .create_offer(None)
        .expect("create offer")
        .sdp;

    let encodings = peer_connection
        .rtp_sender(sender_id)
        .expect("sender")
        .get_parameters()
        .encodings
        .clone();
    assert_eq!(encodings.len(), 1, "{sdp}");
    let coding = &encodings[0].rtp_coding_parameters;
    assert_eq!(coding.ssrc, Some(MEDIA_SSRC), "{sdp}");

    Offer {
        sdp,
        rtx_ssrc: coding.rtx.as_ref().map(|rtx| rtx.ssrc),
        fec_ssrc: coding.fec.as_ref().map(|fec| fec.ssrc),
    }
}

#[test]
fn flexfec_codec_is_offered_alongside_the_track_codec() {
    let vp8 = video_codec(MIME_TYPE_VP8, VP8_PT, "");
    let flexfec = video_codec(MIME_TYPE_FLEX_FEC03, FLEX_FEC_PT, "repair-window=10000000");

    let offer = offer_for(video_media_engine(&[vp8.clone(), flexfec]), &vp8);
    let sdp = &offer.sdp;

    // Without the repair-codec carve-out the encoding's VP8 narrows the offer to PT 96 alone, and
    // the FEC group points at a stream with no format to carry it.
    assert!(
        sdp.contains(&format!("a=rtpmap:{FLEX_FEC_PT} flexfec-03/90000")),
        "{sdp}"
    );
    assert!(
        sdp.contains(&format!("a=rtpmap:{VP8_PT} VP8/90000")),
        "{sdp}"
    );
}

#[test]
fn flexfec_repair_flow_is_grouped_with_fec_fr() {
    let vp8 = video_codec(MIME_TYPE_VP8, VP8_PT, "");
    let flexfec = video_codec(MIME_TYPE_FLEX_FEC03, FLEX_FEC_PT, "repair-window=10000000");

    let offer = offer_for(video_media_engine(&[vp8.clone(), flexfec]), &vp8);
    let sdp = &offer.sdp;

    // Registering the codec is enough — the FEC SSRC is minted for us, as it is in pion.
    let fec_ssrc = offer
        .fec_ssrc
        .unwrap_or_else(|| panic!("no FEC ssrc\n{sdp}"));
    assert_ne!(fec_ssrc, 0, "{sdp}");

    // `FEC-FR` (RFC 5956), not the RFC 4756 `FEC` semantic: this crate's own parser recognises
    // only `FEC-FR`, so the older token produced an offer it could not read back.
    assert!(
        sdp.contains(&format!("a=ssrc-group:FEC-FR {MEDIA_SSRC} {fec_ssrc}")),
        "{sdp}"
    );
    assert!(!sdp.contains("a=ssrc-group:FEC "), "{sdp}");
    assert!(sdp.contains(&format!("a=ssrc:{fec_ssrc} cname:")), "{sdp}");
}

#[test]
fn rtx_codec_is_offered_alongside_the_track_codec() {
    let vp8 = video_codec(MIME_TYPE_VP8, VP8_PT, "");
    let vp8_rtx = video_codec(MIME_TYPE_RTX, VP8_RTX_PT, "apt=96");

    let offer = offer_for(video_media_engine(&[vp8.clone(), vp8_rtx]), &vp8);
    let sdp = &offer.sdp;

    let rtx_ssrc = offer
        .rtx_ssrc
        .unwrap_or_else(|| panic!("no RTX ssrc\n{sdp}"));
    assert_ne!(rtx_ssrc, 0, "{sdp}");

    assert!(
        sdp.contains(&format!("a=rtpmap:{VP8_RTX_PT} rtx/90000")),
        "{sdp}"
    );
    assert!(
        sdp.contains(&format!("a=ssrc-group:FID {MEDIA_SSRC} {rtx_ssrc}")),
        "{sdp}"
    );
}

#[test]
fn rtx_codec_for_an_unoffered_primary_is_not_offered() {
    let vp8 = video_codec(MIME_TYPE_VP8, VP8_PT, "");
    let vp8_rtx = video_codec(MIME_TYPE_RTX, VP8_RTX_PT, "apt=96");
    let vp9 = video_codec(MIME_TYPE_VP9, VP9_PT, "");
    let vp9_rtx = video_codec(MIME_TYPE_RTX, VP9_RTX_PT, "apt=98");

    let offer = offer_for(
        video_media_engine(&[vp8.clone(), vp8_rtx, vp9, vp9_rtx]),
        &vp8,
    );
    let sdp = &offer.sdp;

    // RTX repairs one specific primary (RFC 4588 `apt`). VP9 was narrowed away by the track's
    // codec, so its RTX has nothing to repair and must not be offered — otherwise "keep repair
    // codecs" would degenerate into "keep every repair codec the media engine knows".
    assert!(
        sdp.contains(&format!("a=rtpmap:{VP8_RTX_PT} rtx/90000")),
        "{sdp}"
    );
    assert!(
        !sdp.contains(&format!("a=rtpmap:{VP9_RTX_PT} rtx/90000")),
        "{sdp}"
    );
    assert!(!sdp.contains("VP9/90000"), "{sdp}");
}

#[test]
fn no_repair_group_without_a_repair_codec() {
    // Falsifies the three tests above: they would all still pass if `a=ssrc-group` were emitted
    // unconditionally. Nothing repairs anything here, so neither group may appear.
    let vp8 = video_codec(MIME_TYPE_VP8, VP8_PT, "");

    let offer = offer_for(video_media_engine(&[vp8.clone()]), &vp8);
    let sdp = &offer.sdp;

    assert_eq!(offer.rtx_ssrc, None, "{sdp}");
    assert_eq!(offer.fec_ssrc, None, "{sdp}");
    assert!(!sdp.contains("a=ssrc-group:"), "{sdp}");
}

#[test]
fn explicit_repair_ssrcs_are_used_verbatim() {
    // rtc's contract is that an SSRC the application names is the one that goes on the wire —
    // media, RTX and FEC alike. `send_encodings_from_track` used to honour that for the media
    // SSRC while overwriting both repair SSRCs with fresh random values, so a track that named
    // them was silently ignored and the numbers in the offer matched nothing the caller held.
    let vp8 = video_codec(MIME_TYPE_VP8, VP8_PT, "");
    let vp8_rtx = video_codec(MIME_TYPE_RTX, VP8_RTX_PT, "apt=96");
    let flexfec = video_codec(MIME_TYPE_FLEX_FEC03, FLEX_FEC_PT, "repair-window=10000000");

    let offer = offer_for_track(
        video_media_engine(&[vp8.clone(), vp8_rtx, flexfec]),
        video_track_with_repair_ssrcs(&vp8, Some(EXPLICIT_RTX_SSRC), Some(EXPLICIT_FEC_SSRC)),
    );
    let sdp = &offer.sdp;

    assert_eq!(offer.rtx_ssrc, Some(EXPLICIT_RTX_SSRC), "{sdp}");
    assert_eq!(offer.fec_ssrc, Some(EXPLICIT_FEC_SSRC), "{sdp}");
    assert!(
        sdp.contains(&format!(
            "a=ssrc-group:FID {MEDIA_SSRC} {EXPLICIT_RTX_SSRC}"
        )),
        "{sdp}"
    );
    assert!(
        sdp.contains(&format!(
            "a=ssrc-group:FEC-FR {MEDIA_SSRC} {EXPLICIT_FEC_SSRC}"
        )),
        "{sdp}"
    );
}

#[test]
fn explicit_repair_ssrcs_are_dropped_without_a_repair_codec() {
    // Whether a repair flow exists at all is the media engine's call, and it is checked before the
    // application's SSRC is consulted. Honouring the SSRC here would put `a=ssrc-group:FEC-FR` in
    // the offer with no `a=rtpmap` to give the repair stream a format.
    let vp8 = video_codec(MIME_TYPE_VP8, VP8_PT, "");

    let offer = offer_for_track(
        video_media_engine(&[vp8.clone()]),
        video_track_with_repair_ssrcs(&vp8, Some(EXPLICIT_RTX_SSRC), Some(EXPLICIT_FEC_SSRC)),
    );
    let sdp = &offer.sdp;

    assert_eq!(offer.rtx_ssrc, None, "{sdp}");
    assert_eq!(offer.fec_ssrc, None, "{sdp}");
    assert!(!sdp.contains("a=ssrc-group:"), "{sdp}");
}

#[test]
fn explicit_repair_ssrcs_survive_add_transceiver_from_track() {
    // The same contract on the other entry point. This path already respected a caller-supplied
    // `send_encodings`, which is what made `add_track`'s behaviour an inconsistency rather than a
    // deliberate policy.
    let vp8 = video_codec(MIME_TYPE_VP8, VP8_PT, "");
    let flexfec = video_codec(MIME_TYPE_FLEX_FEC03, FLEX_FEC_PT, "repair-window=10000000");

    let mut peer_connection = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(video_media_engine(&[vp8.clone(), flexfec]))
        .build(Instant::now())
        .expect("build peer connection");

    let transceiver_id = peer_connection
        .add_transceiver_from_track(
            video_track_with_repair_ssrcs(&vp8, None, Some(EXPLICIT_FEC_SSRC)),
            None,
        )
        .expect("add transceiver from track");

    let sdp = peer_connection
        .create_offer(None)
        .expect("create offer")
        .sdp;
    assert!(
        sdp.contains(&format!(
            "a=ssrc-group:FEC-FR {MEDIA_SSRC} {EXPLICIT_FEC_SSRC}"
        )),
        "{sdp}"
    );

    let encodings = peer_connection
        .rtp_sender(RTCRtpSenderId::from(transceiver_id))
        .expect("sender")
        .get_parameters()
        .encodings
        .clone();
    assert_eq!(
        encodings[0]
            .rtp_coding_parameters
            .fec
            .as_ref()
            .map(|fec| fec.ssrc),
        Some(EXPLICIT_FEC_SSRC),
        "{sdp}"
    );
}

#[test]
fn sender_id_is_reachable_after_add_track() {
    // Guards the harness itself: `offer_for` reads the repair SSRCs back through `rtp_sender`,
    // and a `None` there would silently turn every assertion above into a no-op.
    let vp8 = video_codec(MIME_TYPE_VP8, VP8_PT, "");

    let mut peer_connection = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(video_media_engine(&[vp8.clone()]))
        .build(Instant::now())
        .expect("build peer connection");

    let sender_id: RTCRtpSenderId = peer_connection
        .add_track(video_track(&vp8))
        .expect("add track");
    assert!(peer_connection.rtp_sender(sender_id).is_some());
}

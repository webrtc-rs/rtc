/// Regression test for duplicate mid bug in generate_matched_sdp().
///
/// When create_offer() is called for a renegotiation (i.e. current_remote_description
/// exists), the function iterates remote media sections to build matched entries, then
/// iterates all local transceivers for unmatched ones. Without the fix, transceivers
/// already matched from the remote description would be added again, producing duplicate
/// m-sections with the same mid in the generated SDP.
use std::collections::HashSet;

use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_VP8};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use sansio::Protocol;

fn new_video_track(stream_id: &str, track_id: &str, ssrc: u32) -> MediaStreamTrack {
    MediaStreamTrack::new(
        stream_id.to_owned(),
        track_id.to_owned(),
        format!("track-{}", track_id),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }],
    )
}

/// Collect all mid values from a parsed SDP's media descriptions.
fn collect_mids(sdp: &RTCSessionDescription) -> Vec<String> {
    let parsed = sdp.unmarshal().expect("failed to parse SDP");
    parsed
        .media_descriptions
        .iter()
        .filter_map(|m| {
            m.attribute("mid")
                .and_then(|v| v.map(|s| s.to_owned()))
        })
        .collect()
}

/// After a full offer/answer exchange, a renegotiation offer must not contain
/// duplicate mids for transceivers that were already matched from the remote
/// description.
#[test]
fn test_renegotiation_no_duplicate_mids() -> Result<(), Box<dyn std::error::Error>> {
    let mut me = MediaEngine::default();
    me.register_default_codecs()?;
    let me2 = me.clone();

    // --- Offerer ---
    let mut offerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(me)
        .build()?;

    // Add an initial video track.
    let track1 = new_video_track("stream-1", "video-1", 11111);
    offerer.add_track(track1)?;

    // --- Answerer ---
    let mut answerer = RTCPeerConnectionBuilder::new()
        .with_media_engine(me2)
        .build()?;

    // ---- First offer/answer exchange ----
    let offer1 = offerer.create_offer(None)?;
    offerer.set_local_description(offer1.clone())?;

    answerer.set_remote_description(offer1)?;
    let answer1 = answerer.create_answer(None)?;
    answerer.set_local_description(answer1.clone())?;

    offerer.set_remote_description(answer1)?;

    // Sanity: first offer has unique mids.
    let offer1_for_check = offerer.create_offer(None)?;
    let mids = collect_mids(&offer1_for_check);
    let unique: HashSet<_> = mids.iter().collect();
    assert_eq!(
        mids.len(),
        unique.len(),
        "first renegotiation offer already has duplicate mids: {:?}",
        mids,
    );

    // ---- Add a second video track and renegotiate ----
    let track2 = new_video_track("stream-2", "video-2", 22222);
    offerer.add_track(track2)?;

    let offer2 = offerer.create_offer(None)?;
    let mids = collect_mids(&offer2);
    let unique: HashSet<_> = mids.iter().collect();
    assert_eq!(
        mids.len(),
        unique.len(),
        "renegotiation offer has duplicate mids: {:?}",
        mids,
    );

    // Verify we have the expected number of media sections (1 video + 1 new video = 2).
    assert_eq!(
        mids.len(),
        2,
        "expected 2 media sections, got {}: {:?}",
        mids.len(),
        mids,
    );

    offerer.close()?;
    answerer.close()?;
    Ok(())
}

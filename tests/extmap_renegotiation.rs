//! Extension ID reassignment after a bundled section is rejected must agree
//! across answers, RTP receiver parameters, and subsequent local offers.

use rtc::{
    peer_connection::{
        RTCPeerConnection, RTCPeerConnectionBuilder, configuration::media_engine::MediaEngine,
        sdp::RTCSessionDescription,
    },
    rtp_transceiver::rtp_sender::{RTCRtpHeaderExtensionCapability, RtpCodecKind},
};
use std::{collections::BTreeMap, time::Instant};

const MID: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
const TWCC: &str = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

fn peer() -> RTCPeerConnection {
    let mut media = MediaEngine::default();
    media.register_default_codecs().unwrap();
    for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
        for uri in [MID, TWCC] {
            media
                .register_header_extension(
                    RTCRtpHeaderExtensionCapability { uri: uri.into() },
                    kind,
                    None,
                )
                .unwrap();
        }
    }
    RTCPeerConnectionBuilder::new()
        .with_media_engine(media)
        .build(Instant::now())
        .unwrap()
}

// A previously negotiated video section is retired before a new audio
// section adopts the browser's new bundled extension mapping.
fn offer(sequence: u8) -> RTCSessionDescription {
    let mut lines = vec![
        "v=0".into(),
        format!("o=- 1 {sequence} IN IP4 127.0.0.1"),
        "s=-".into(),
        "t=0 0".into(),
        match sequence {
            1 => "a=group:BUNDLE 0",
            2 => "a=group:BUNDLE 1",
            _ => "a=group:BUNDLE 1 2",
        }
        .into(),
        "a=msid-semantic: WMS *".into(),
    ];
    let common = [
        "c=IN IP4 0.0.0.0",
        "a=rtcp-mux",
        "a=ice-ufrag:abcd",
        "a=ice-pwd:abcdefghijklmnopqrstuvwx",
        "a=setup:actpass",
        "a=fingerprint:sha-256 11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11",
    ];
    lines.push(format!(
        "m=video {} UDP/TLS/RTP/SAVPF 96",
        if sequence == 1 { 9 } else { 0 }
    ));
    lines.extend(common.iter().map(|line| line.to_string()));
    lines.extend([
        "a=mid:0".into(),
        "a=rtpmap:96 VP8/90000".into(),
        format!("a=extmap:4 {TWCC}"),
        format!("a=extmap:9 {MID}"),
        if sequence == 1 {
            "a=sendonly"
        } else {
            "a=inactive"
        }
        .into(),
    ]);
    if sequence != 1 {
        lines.push("m=audio 9 UDP/TLS/RTP/SAVPF 111".into());
        lines.extend(common.iter().map(|line| line.to_string()));
        lines.extend([
            "a=mid:1".into(),
            "a=rtpmap:111 opus/48000/2".into(),
            "a=sendonly".into(),
            format!("a=extmap:3 {TWCC}"),
            format!("a=extmap:4 {MID}"),
        ]);
    }
    if sequence >= 3 {
        lines.push("m=video 9 UDP/TLS/RTP/SAVPF 96".into());
        lines.extend(common.iter().map(|line| line.to_string()));
        lines.extend([
            "a=mid:2".into(),
            "a=rtpmap:96 VP8/90000".into(),
            "a=sendonly".into(),
            format!("a=extmap:3 {TWCC}"),
            format!("a=extmap:4 {MID}"),
        ]);
    }
    RTCSessionDescription::offer(lines.join("\r\n") + "\r\n").unwrap()
}

fn extensions(sdp: &str, mid: &str) -> BTreeMap<u16, String> {
    let section = sdp
        .split("\r\nm=")
        .skip(1)
        .find(|section| {
            section
                .lines()
                .any(|line| line.trim() == format!("a=mid:{mid}"))
        })
        .expect("MID is present");
    section
        .lines()
        .filter_map(|line| {
            let (id, uri) = line.trim().strip_prefix("a=extmap:")?.split_once(' ')?;
            Some((id.parse().unwrap(), uri.into()))
        })
        .collect()
}

fn receiver_extensions(pc: &mut RTCPeerConnection, mid: &str) -> BTreeMap<u16, String> {
    let transceivers: Vec<_> = pc.get_transceivers().collect();
    let receiver = transceivers
        .into_iter()
        .find_map(|id| {
            let transceiver = pc.rtp_transceiver(id).unwrap();
            (transceiver.mid().as_deref() == Some(mid)).then(|| transceiver.receiver().unwrap())
        })
        .unwrap();
    pc.rtp_receiver(receiver)
        .unwrap()
        .get_parameters()
        .rtp_parameters
        .header_extensions
        .iter()
        .map(|extension| (extension.id, extension.uri.clone()))
        .collect()
}

#[test]
fn retired_video_mapping_cannot_reassign_active_audio_extensions() {
    let mut pc = peer();
    for sequence in [1, 2] {
        pc.set_remote_description(Instant::now(), offer(sequence))
            .unwrap();
        let answer = pc.create_answer(None).unwrap();
        if sequence == 2 {
            assert_eq!(
                extensions(&answer.sdp, "1"),
                BTreeMap::from([(3, TWCC.into()), (4, MID.into())]),
                "answer must use the active section's negotiated extension IDs"
            );
        }
        pc.set_local_description(Instant::now(), answer).unwrap();
    }
    assert_eq!(
        receiver_extensions(&mut pc, "1"),
        BTreeMap::from([(3, TWCC.into()), (4, MID.into())]),
        "RTP processing must share the SDP's mapping"
    );
    let reoffer = pc.create_offer(None).unwrap();
    assert_eq!(
        extensions(&reoffer.sdp, "1"),
        BTreeMap::from([(3, TWCC.into()), (4, MID.into())]),
        "later local reoffer must retain the active mapping"
    );
}

#[test]
fn active_bundled_audio_and_new_video_keep_both_rtp_extension_maps() {
    let mut pc = peer();
    let expected = BTreeMap::from([(3, TWCC.into()), (4, MID.into())]);
    for sequence in [1, 2, 3] {
        pc.set_remote_description(Instant::now(), offer(sequence))
            .unwrap();
        let answer = pc.create_answer(None).unwrap();
        if sequence == 3 {
            for mid in ["1", "2"] {
                assert_eq!(
                    extensions(&answer.sdp, mid),
                    expected,
                    "both active sections must retain the offered bundled IDs"
                );
            }
        }
        pc.set_local_description(Instant::now(), answer).unwrap();
    }
    for mid in ["1", "2"] {
        assert_eq!(
            receiver_extensions(&mut pc, mid),
            expected,
            "adding video must preserve audio's RTP mapping and establish video's mapping"
        );
    }
    let reoffer = pc.create_offer(None).unwrap();
    for mid in ["1", "2"] {
        assert_eq!(
            extensions(&reoffer.sdp, mid),
            expected,
            "the local reoffer must preserve both active sections"
        );
    }
}

pub(crate) mod fmtp;
pub(crate) mod rtp_codec;
pub(crate) mod rtp_transceiver;
pub(crate) mod rtp_transceiver_direction;
pub(crate) mod sdp_type;

use crate::config::session_config::SessionConfig;
use crate::description::{
    rtp_codec::{RTCRtpCodecCapability, RTCRtpCodecParameters, RTCRtpHeaderExtensionParameters},
    rtp_transceiver::{
        MediaStreamId, PayloadType, RTCPFeedback, RTCRtpTransceiver, SsrcGroup, SSRC,
    },
    rtp_transceiver_direction::RTCRtpTransceiverDirection,
    sdp_type::RTCSdpType,
};
use crate::endpoint::candidate::RTCIceParameters;
use crate::server::certificate::RTCDtlsFingerprint;
use crate::types::Mid;
use sdp::description::common::{Address, ConnectionInformation};
use sdp::description::media::{MediaName, RangedPort};
use sdp::description::session::{
    Origin, ATTR_KEY_CONNECTION_SETUP, ATTR_KEY_EXT_MAP, ATTR_KEY_GROUP, ATTR_KEY_ICELITE,
    ATTR_KEY_MID, ATTR_KEY_RTCPMUX, ATTR_KEY_RTCPRSIZE,
};
use sdp::extmap::ExtMap;
use sdp::util::ConnectionRole;
use sdp::{MediaDescription, SessionDescription};
use serde::{Deserialize, Serialize};
use shared::error::{Error, Result};
use std::collections::HashMap;
use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use url::Url;

pub(crate) const UNSPECIFIED_STR: &str = "Unspecified";
pub(crate) const SDP_ATTRIBUTE_RID: &str = "rid";

/// RTCSessionDescription is used to expose local and remote session descriptions.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RTCSessionDescription {
    #[serde(rename = "type")]
    pub sdp_type: RTCSdpType,

    pub sdp: String,

    /// This will never be initialized by callers, internal use only
    #[serde(skip)]
    pub(crate) parsed: Option<SessionDescription>,
}

impl RTCSessionDescription {
    /// Given SDP representing an answer, wrap it in an RTCSessionDescription
    /// that can be given to an RTCPeerConnection.
    pub fn answer(sdp: String) -> Result<RTCSessionDescription> {
        let mut desc = RTCSessionDescription {
            sdp,
            sdp_type: RTCSdpType::Answer,
            parsed: None,
        };

        let parsed = desc.unmarshal()?;
        desc.parsed = Some(parsed);

        Ok(desc)
    }

    /// Given SDP representing an offer, wrap it in an RTCSessionDescription
    /// that can be given to an RTCPeerConnection.
    pub fn offer(sdp: String) -> Result<RTCSessionDescription> {
        let mut desc = RTCSessionDescription {
            sdp,
            sdp_type: RTCSdpType::Offer,
            parsed: None,
        };

        let parsed = desc.unmarshal()?;
        desc.parsed = Some(parsed);

        Ok(desc)
    }

    /// Given SDP representing an answer, wrap it in an RTCSessionDescription
    /// that can be given to an RTCPeerConnection. `pranswer` is used when the
    /// answer may not be final, or when updating a previously sent pranswer.
    pub fn pranswer(sdp: String) -> Result<RTCSessionDescription> {
        let mut desc = RTCSessionDescription {
            sdp,
            sdp_type: RTCSdpType::Pranswer,
            parsed: None,
        };

        let parsed = desc.unmarshal()?;
        desc.parsed = Some(parsed);

        Ok(desc)
    }

    /// Unmarshal is a helper to deserialize the sdp
    pub fn unmarshal(&self) -> Result<SessionDescription> {
        let mut reader = Cursor::new(self.sdp.as_bytes());
        let parsed = SessionDescription::unmarshal(&mut reader)
            .map_err(|err| Error::Other(err.to_string()))?;
        Ok(parsed)
    }
}

pub(crate) const MEDIA_SECTION_APPLICATION: &str = "application";

pub(crate) fn get_rids(media: &MediaDescription) -> HashMap<String, String> {
    let mut rids = HashMap::new();
    for attr in &media.attributes {
        if attr.key.as_str() == SDP_ATTRIBUTE_RID {
            if let Some(value) = &attr.value {
                let split: Vec<&str> = value.split(' ').collect();
                rids.insert(split[0].to_owned(), value.to_owned());
            }
        }
    }
    rids
}

/// ICEGatheringState describes the state of the candidate gathering process.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum RTCIceGatheringState {
    #[default]
    Unspecified,

    /// ICEGatheringStateNew indicates that any of the ICETransports are
    /// in the "new" gathering state and none of the transports are in the
    /// "gathering" state, or there are no transports.
    New,

    /// ICEGatheringStateGathering indicates that any of the ICETransports
    /// are in the "gathering" state.
    Gathering,

    /// ICEGatheringStateComplete indicates that at least one ICETransport
    /// exists, and all ICETransports are in the "completed" gathering state.
    Complete,
}

fn append_candidate_if_new(
    c: &SocketAddr,
    component: u16,
    m: MediaDescription,
) -> MediaDescription {
    let marshaled = format!("1 {} UDP 1 {} {} typ host", component, c.ip(), c.port());
    for a in &m.attributes {
        if let Some(value) = &a.value {
            if &marshaled == value {
                return m;
            }
        }
    }
    m.with_value_attribute("candidate".to_owned(), marshaled)
}

pub(crate) fn add_candidate_to_media_descriptions(
    candidate: &SocketAddr,
    mut m: MediaDescription,
    ice_gathering_state: RTCIceGatheringState,
) -> Result<MediaDescription> {
    m = append_candidate_if_new(candidate, 1, m); // 1: RTP

    //TODO: m = append_candidate_if_new(candidate, 2, m); // 2: RTCP

    if ice_gathering_state != RTCIceGatheringState::Complete {
        return Ok(m);
    }
    for a in &m.attributes {
        if &a.key == "end-of-candidates" {
            return Ok(m);
        }
    }

    Ok(m.with_property_attribute("end-of-candidates".to_owned()))
}

pub(crate) struct AddDataMediaSectionParams {
    should_add_candidates: bool,
    mid_value: String,
    ice_params: RTCIceParameters,
    dtls_role: ConnectionRole,
    ice_gathering_state: RTCIceGatheringState,
}

pub(crate) fn add_data_media_section(
    d: SessionDescription,
    dtls_fingerprints: &[RTCDtlsFingerprint],
    session_config: &SessionConfig,
    params: AddDataMediaSectionParams,
) -> Result<SessionDescription> {
    let mut media = MediaDescription {
        media_name: MediaName {
            media: MEDIA_SECTION_APPLICATION.to_owned(),
            port: RangedPort {
                value: 9,
                range: None,
            },
            protos: vec!["UDP".to_owned(), "DTLS".to_owned(), "SCTP".to_owned()],
            formats: vec!["webrtc-datachannel".to_owned()],
        },
        media_title: None,
        connection_information: Some(ConnectionInformation {
            network_type: "IN".to_owned(),
            address_type: "IP4".to_owned(),
            address: Some(Address {
                address: "0.0.0.0".to_owned(),
                ttl: None,
                range: None,
            }),
        }),
        bandwidth: vec![],
        encryption_key: None,
        attributes: vec![],
    }
    .with_value_attribute(
        ATTR_KEY_CONNECTION_SETUP.to_owned(),
        params.dtls_role.to_string(),
    )
    .with_value_attribute(ATTR_KEY_MID.to_owned(), params.mid_value)
    .with_property_attribute(RTCRtpTransceiverDirection::Sendrecv.to_string())
    .with_value_attribute(
        "sctp-port".to_owned(),
        session_config
            .server_config
            .sctp_server_config
            .transport
            .sctp_port()
            .to_string(),
    )
    .with_value_attribute(
        "max-message-size".to_owned(),
        session_config
            .server_config
            .sctp_server_config
            .transport
            .max_message_size()
            .to_string(),
    )
    .with_ice_credentials(
        params.ice_params.username_fragment,
        params.ice_params.password,
    );

    for f in dtls_fingerprints {
        media = media.with_fingerprint(f.algorithm.clone(), f.value.to_uppercase());
    }

    if params.should_add_candidates {
        media = add_candidate_to_media_descriptions(
            &session_config.local_addr,
            media,
            params.ice_gathering_state,
        )?;
    }

    Ok(d.with_media(media))
}

pub(crate) struct AddTransceiverSdpParams {
    should_add_candidates: bool,
    mid_value: String,
    dtls_role: ConnectionRole,
    ice_gathering_state: RTCIceGatheringState,
    offered_direction: Option<RTCRtpTransceiverDirection>,
}

pub(crate) fn add_transceiver_sdp(
    d: SessionDescription,
    dtls_fingerprints: &[RTCDtlsFingerprint],
    ice_params: &RTCIceParameters,
    session_config: &SessionConfig,
    media_section: &MediaSection,
    transceiver: &RTCRtpTransceiver,
    params: AddTransceiverSdpParams,
) -> Result<(SessionDescription, bool)> {
    let (should_add_candidates, mid_value, dtls_role, ice_gathering_state) = (
        params.should_add_candidates,
        params.mid_value,
        params.dtls_role,
        params.ice_gathering_state,
    );

    let mut media =
        MediaDescription::new_jsep_media_description(transceiver.kind.to_string(), vec![])
            .with_value_attribute(ATTR_KEY_CONNECTION_SETUP.to_owned(), dtls_role.to_string())
            .with_value_attribute(ATTR_KEY_MID.to_owned(), mid_value.clone())
            .with_ice_credentials(
                ice_params.username_fragment.clone(),
                ice_params.password.clone(),
            )
            .with_property_attribute(ATTR_KEY_RTCPMUX.to_owned())
            .with_property_attribute(ATTR_KEY_RTCPRSIZE.to_owned());

    for fingerprint in dtls_fingerprints {
        media = media.with_fingerprint(
            fingerprint.algorithm.to_owned(),
            fingerprint.value.to_uppercase(),
        );
    }

    if should_add_candidates {
        media = add_candidate_to_media_descriptions(
            &session_config.local_addr,
            media,
            ice_gathering_state,
        )?;
    }

    let codecs = session_config
        .server_config
        .media_config
        .get_codecs_by_kind(transceiver.kind);
    for codec in codecs {
        let name = codec
            .capability
            .mime_type
            .trim_start_matches("audio/")
            .trim_start_matches("video/")
            .to_owned();
        media = media.with_codec(
            codec.payload_type,
            name,
            codec.capability.clock_rate,
            codec.capability.channels,
            codec.capability.sdp_fmtp_line.clone(),
        );

        for feedback in &codec.capability.rtcp_feedbacks {
            media = media.with_value_attribute(
                "rtcp-fb".to_owned(),
                format!(
                    "{} {} {}",
                    codec.payload_type, feedback.typ, feedback.parameter
                ),
            );
        }
    }

    let parameters = session_config
        .server_config
        .media_config
        .get_rtp_parameters_by_kind(transceiver.kind, transceiver.direction);
    for rtp_extension in parameters.header_extensions {
        let ext_url = Url::parse(rtp_extension.uri.as_str())?;
        media = media.with_extmap(ExtMap {
            value: rtp_extension.id,
            uri: Some(ext_url),
            ..Default::default()
        });
    }

    if !media_section.rid_map.is_empty() {
        let mut recv_rids: Vec<String> = vec![];

        for rid in media_section.rid_map.keys() {
            media =
                media.with_value_attribute(SDP_ATTRIBUTE_RID.to_owned(), rid.to_owned() + " recv");
            recv_rids.push(rid.to_owned());
        }
        // Simulcast
        media = media.with_value_attribute(
            "simulcast".to_owned(),
            "recv ".to_owned() + recv_rids.join(";").as_str(),
        );
    }

    let direction = match params.offered_direction {
        Some(offered_direction) => {
            use RTCRtpTransceiverDirection::*;
            let transceiver_direction = transceiver.direction;

            match offered_direction {
                Sendonly | Recvonly => {
                    // If a stream is offered as sendonly, the corresponding stream MUST be
                    // marked as recvonly or inactive in the answer.

                    // If a media stream is
                    // listed as recvonly in the offer, the answer MUST be marked as
                    // sendonly or inactive in the answer.
                    offered_direction.reverse().intersect(transceiver_direction)
                }
                // If an offered media stream is
                // listed as sendrecv (or if there is no direction attribute at the
                // media or session level, in which case the stream is sendrecv by
                // default), the corresponding stream in the answer MAY be marked as
                // sendonly, recvonly, sendrecv, or inactive
                Sendrecv | Unspecified => transceiver_direction,
                // If an offered media
                // stream is listed as inactive, it MUST be marked as inactive in the
                // answer.
                Inactive => Inactive,
            }
        }
        None => {
            // If don't have an offered direction to intersect with just use the transceivers
            // current direction.
            //
            // https://datatracker.ietf.org/doc/html/rfc8829#section-4.2.3
            //
            //    When creating offers, the transceiver direction is directly reflected
            //    in the output, even for re-offers.
            transceiver.direction
        }
    };
    media = media.with_property_attribute(direction.to_string());

    if direction == RTCRtpTransceiverDirection::Sendonly {
        if let Some(sender) = transceiver.sender.as_ref() {
            media = media.with_property_attribute(format!(
                "msid:{} {}",
                sender.msid.stream_id, sender.msid.track_id
            ));

            for ssrc_group in &sender.ssrc_groups {
                media = media.with_property_attribute(format!(
                    "ssrc-group:{} {}",
                    ssrc_group.name,
                    ssrc_group
                        .ssrcs
                        .iter()
                        .map(|ssrc| ssrc.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                ));
            }

            for ssrc in &sender.ssrcs {
                media = media.with_media_source(
                    *ssrc,
                    sender.cname.clone(),
                    sender.msid.stream_id.clone(),
                    sender.msid.track_id.clone(),
                );
            }
        } else {
            return Err(Error::Other(
                "Sendonly transceiver doesn't have sender set".to_string(),
            ));
        }
    }

    Ok((d.with_media(media), true))
}

#[derive(Default)]
pub(crate) struct MediaSection {
    pub(crate) mid: Mid,
    pub(crate) data: bool,
    pub(crate) rid_map: HashMap<String, String>,
    pub(crate) offered_direction: Option<RTCRtpTransceiverDirection>,
}

/// populate_sdp serializes a PeerConnections state into an SDP
#[allow(clippy::too_many_arguments)]
pub(crate) fn populate_sdp(
    mut d: SessionDescription,
    dtls_fingerprints: &[RTCDtlsFingerprint],
    session_config: &SessionConfig,
    ice_params: &RTCIceParameters,
    connection_role: ConnectionRole,
    media_sections: &[MediaSection],
    transceivers: &HashMap<Mid, RTCRtpTransceiver>,
    media_description_fingerprint: bool,
) -> Result<SessionDescription> {
    let media_dtls_fingerprints = if media_description_fingerprint {
        dtls_fingerprints.to_vec()
    } else {
        vec![]
    };

    let mut bundle_value = "BUNDLE".to_owned();
    let mut bundle_count = 0;
    let append_bundle = |mid_value: &str, value: &mut String, count: &mut i32| {
        *value = value.clone() + " " + mid_value;
        *count += 1;
    };

    for (i, m) in media_sections.iter().enumerate() {
        if m.data && transceivers.get(&m.mid).is_some() {
            return Err(Error::Other(
                "ErrSDPMediaSectionMediaDataChanInvalid".to_string(),
            ));
        }

        let should_add_candidates = i == 0;

        let should_add_id = if m.data {
            let params = AddDataMediaSectionParams {
                should_add_candidates,
                mid_value: m.mid.clone(),
                ice_params: ice_params.clone(),
                dtls_role: connection_role,
                ice_gathering_state: RTCIceGatheringState::Complete,
            };
            d = add_data_media_section(d, &media_dtls_fingerprints, session_config, params)?;
            true
        } else {
            let params = AddTransceiverSdpParams {
                should_add_candidates,
                mid_value: m.mid.clone(),
                dtls_role: connection_role,
                ice_gathering_state: RTCIceGatheringState::Complete,
                offered_direction: m.offered_direction,
            };
            let (d1, should_add_id) = add_transceiver_sdp(
                d,
                &media_dtls_fingerprints,
                ice_params,
                session_config,
                m,
                transceivers
                    .get(&m.mid)
                    .ok_or(Error::Other("ErrSDPZeroTransceivers".to_string()))?,
                params,
            )?;
            d = d1;
            should_add_id
        };

        if should_add_id {
            append_bundle(&m.mid, &mut bundle_value, &mut bundle_count);
        }
    }

    if !media_description_fingerprint {
        for fingerprint in dtls_fingerprints {
            d = d.with_fingerprint(
                fingerprint.algorithm.clone(),
                fingerprint.value.to_uppercase(),
            );
        }
    }

    // is_ice_lite for SFU
    // RFC 5245 S15.3
    d = d.with_property_attribute(ATTR_KEY_ICELITE.to_owned());

    Ok(d.with_value_attribute(ATTR_KEY_GROUP.to_owned(), bundle_value))
}

pub(crate) fn get_mid_value(media: &MediaDescription) -> Option<&String> {
    for attr in &media.attributes {
        if attr.key == "mid" {
            return attr.value.as_ref();
        }
    }
    None
}

pub(crate) fn get_peer_direction(media: &MediaDescription) -> RTCRtpTransceiverDirection {
    for a in &media.attributes {
        let direction = RTCRtpTransceiverDirection::from(a.key.as_str());
        if direction != RTCRtpTransceiverDirection::Unspecified {
            return direction;
        }
    }
    RTCRtpTransceiverDirection::Unspecified
}

pub(crate) fn get_cname(media: &MediaDescription) -> Option<String> {
    for a in &media.attributes {
        if a.key == "ssrc" {
            if let Some(value) = a.value.as_ref() {
                if value.contains("cname") {
                    let fields: Vec<&str> = value.split(':').collect();
                    if let Some(cname) = fields.last() {
                        return Some(cname.to_string());
                    }
                }
            }
        }
    }
    None
}

pub(crate) fn get_msid(media: &MediaDescription) -> Option<MediaStreamId> {
    for a in &media.attributes {
        if a.key == "msid" {
            if let Some(value) = a.value.as_ref() {
                let fields: Vec<&str> = value.split_whitespace().collect();
                if fields.len() == 2 {
                    return Some(MediaStreamId {
                        stream_id: fields[0].to_string(),
                        track_id: fields[1].to_string(),
                    });
                }
            }
        } else if a.key == "ssrc" {
            if let Some(value) = a.value.as_ref() {
                if value.contains("msid") {
                    let fields_msid: Vec<&str> = value.split(':').collect();
                    if let Some(msid) = fields_msid.last() {
                        let fields: Vec<&str> = msid.split_whitespace().collect();
                        if fields.len() == 2 {
                            return Some(MediaStreamId {
                                stream_id: fields[0].to_string(),
                                track_id: fields[1].to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
    None
}

pub(crate) fn get_ssrc_groups(media: &MediaDescription) -> Result<Vec<SsrcGroup>> {
    let mut ssrc_groups = vec![];

    for a in &media.attributes {
        if a.key == "ssrc-group" {
            if let Some(value) = a.value.as_ref() {
                let fields: Vec<&str> = value.split_whitespace().collect();
                if fields.len() >= 3 {
                    let mut ssrcs = vec![];
                    for field in fields.iter().skip(1) {
                        let ssrc = field.parse::<u32>()?;
                        ssrcs.push(ssrc);
                    }
                    ssrc_groups.push(SsrcGroup {
                        name: fields[0].to_string(),
                        ssrcs,
                    });
                }
            }
        }
    }

    Ok(ssrc_groups)
}

pub(crate) fn get_ssrcs(media: &MediaDescription) -> Result<Vec<SSRC>> {
    let mut ssrcs = Vec::new();
    for a in &media.attributes {
        if a.key == "ssrc" {
            if let Some(value) = a.value.as_ref() {
                let fields: Vec<&str> = value.split_whitespace().collect();
                if !fields.is_empty() {
                    let ssrc = fields[0].parse::<u32>()?;
                    if ssrcs.contains(&ssrc) {
                        ssrcs.push(ssrc);
                    };
                }
            }
        }
    }
    Ok(ssrcs)
}

pub(crate) fn extract_fingerprint(desc: &SessionDescription) -> Result<(String, String)> {
    let mut fingerprints = vec![];

    if let Some(fingerprint) = desc.attribute("fingerprint") {
        fingerprints.push(fingerprint.to_string());
    }

    for m in &desc.media_descriptions {
        if let Some(fingerprint) = m.attribute("fingerprint").and_then(|o| o) {
            fingerprints.push(fingerprint.to_string());
        }
    }

    if fingerprints.is_empty() {
        return Err(Error::Other(
            "ErrSessionDescriptionNoFingerprint".to_string(),
        ));
    }

    for m in 1..fingerprints.len() {
        if fingerprints[m] != fingerprints[0] {
            return Err(Error::Other(
                "ErrSessionDescriptionConflictingFingerprints".to_string(),
            ));
        }
    }

    let parts: Vec<&str> = fingerprints[0].split(' ').collect();
    if parts.len() != 2 {
        return Err(Error::Other(
            "ErrSessionDescriptionInvalidFingerprint".to_string(),
        ));
    }

    Ok((parts[1].to_owned(), parts[0].to_owned()))
}

/*
pub(crate) fn extract_ice_details(
    desc: &SessionDescription,
) -> Result<(String, String, Vec<RTCIceCandidate>)> {
    let mut candidates = vec![];
    let mut remote_pwds = vec![];
    let mut remote_ufrags = vec![];

    if let Some(ufrag) = desc.attribute("ice-ufrag") {
        remote_ufrags.push(ufrag.clone());
    }
    if let Some(pwd) = desc.attribute("ice-pwd") {
        remote_pwds.push(pwd.clone());
    }

    for m in &desc.media_descriptions {
        if let Some(ufrag) = m.attribute("ice-ufrag").and_then(|o| o) {
            remote_ufrags.push(ufrag.to_owned());
        }
        if let Some(pwd) = m.attribute("ice-pwd").and_then(|o| o) {
            remote_pwds.push(pwd.to_owned());
        }

        for a in &m.attributes {
            if a.is_ice_candidate() {
                if let Some(value) = &a.value {
                    let c: Arc<dyn Candidate + Send + Sync> = Arc::new(unmarshal_candidate(value)?);
                    let candidate = RTCIceCandidate::from(&c);
                    candidates.push(candidate);
                }
            }
        }
    }

    if remote_ufrags.is_empty() {
        return Err(Error::ErrSessionDescriptionMissingIceUfrag);
    } else if remote_pwds.is_empty() {
        return Err(Error::ErrSessionDescriptionMissingIcePwd);
    }

    for m in 1..remote_ufrags.len() {
        if remote_ufrags[m] != remote_ufrags[0] {
            return Err(Error::ErrSessionDescriptionConflictingIceUfrag);
        }
    }

    for m in 1..remote_pwds.len() {
        if remote_pwds[m] != remote_pwds[0] {
            return Err(Error::ErrSessionDescriptionConflictingIcePwd);
        }
    }

    Ok((remote_ufrags[0].clone(), remote_pwds[0].clone(), candidates))
}
*/

pub(crate) fn have_application_media_section(desc: &SessionDescription) -> bool {
    for m in &desc.media_descriptions {
        if m.media_name.media == MEDIA_SECTION_APPLICATION {
            return true;
        }
    }

    false
}

pub(crate) fn get_by_mid<'a>(
    search_mid: &str,
    desc: &'a RTCSessionDescription,
) -> Option<&'a MediaDescription> {
    if let Some(parsed) = &desc.parsed {
        for m in &parsed.media_descriptions {
            if let Some(mid) = m.attribute(ATTR_KEY_MID).flatten() {
                if mid == search_mid {
                    return Some(m);
                }
            }
        }
    }
    None
}

/// have_data_channel return MediaDescription with MediaName equal application
pub(crate) fn have_data_channel(desc: &RTCSessionDescription) -> Option<&MediaDescription> {
    if let Some(parsed) = &desc.parsed {
        for d in &parsed.media_descriptions {
            if d.media_name.media == MEDIA_SECTION_APPLICATION {
                return Some(d);
            }
        }
    }
    None
}

pub(crate) fn codecs_from_media_description(
    m: &MediaDescription,
) -> Result<Vec<RTCRtpCodecParameters>> {
    let s = SessionDescription {
        media_descriptions: vec![m.clone()],
        ..Default::default()
    };

    let mut out = vec![];
    for payload_str in &m.media_name.formats {
        let payload_type: PayloadType = payload_str.parse::<u8>()?;
        let codec = match s.get_codec_for_payload_type(payload_type) {
            Ok(codec) => codec,
            Err(err) => {
                if payload_type == 0 {
                    continue;
                }
                return Err(Error::Other(format!("{}", err)));
            }
        };

        let channels = codec.encoding_parameters.parse::<u16>().unwrap_or(0);

        let mut feedback = vec![];
        for raw in &codec.rtcp_feedback {
            let split: Vec<&str> = raw.split(' ').collect();

            let entry = if split.len() == 2 {
                RTCPFeedback {
                    typ: split[0].to_string(),
                    parameter: split[1].to_string(),
                }
            } else {
                RTCPFeedback {
                    typ: split[0].to_string(),
                    parameter: String::new(),
                }
            };

            feedback.push(entry);
        }

        out.push(RTCRtpCodecParameters {
            capability: RTCRtpCodecCapability {
                mime_type: m.media_name.media.clone() + "/" + codec.name.as_str(),
                clock_rate: codec.clock_rate,
                channels,
                sdp_fmtp_line: codec.fmtp.clone(),
                rtcp_feedbacks: feedback,
            },
            payload_type,
            ..Default::default() //stats_id: String::new(),
        })
    }

    Ok(out)
}

pub(crate) fn rtp_extensions_from_media_description(
    m: &MediaDescription,
) -> Result<Vec<RTCRtpHeaderExtensionParameters>> {
    let mut out = vec![];

    for a in &m.attributes {
        if a.key == ATTR_KEY_EXT_MAP {
            let a_str = a.to_string();
            let mut reader = BufReader::new(a_str.as_bytes());
            let e =
                ExtMap::unmarshal(&mut reader).map_err(|err| Error::Other(format!("{}", err)))?;

            if let Some(uri) = e.uri {
                out.push(RTCRtpHeaderExtensionParameters {
                    uri: uri.to_string(),
                    id: e.value,
                });
            }
        }
    }

    Ok(out)
}

/// update_sdp_origin saves sdp.Origin in PeerConnection when creating 1st local SDP;
/// for subsequent calling, it updates Origin for SessionDescription from saved one
/// and increments session version by one.
/// <https://tools.ietf.org/html/draft-ietf-rtcweb-jsep-25#section-5.2.2>
pub(crate) fn update_sdp_origin(origin: &mut Origin, d: &mut SessionDescription) {
    //TODO: if atomic.CompareAndSwapUint64(&origin.SessionVersion, 0, d.Origin.SessionVersion)
    if origin.session_version == 0 {
        // store
        origin.session_version = d.origin.session_version;
        //atomic.StoreUint64(&origin.SessionID, d.Origin.SessionID)
        origin.session_id = d.origin.session_id;
    } else {
        // load
        /*for { // awaiting for saving session id
            d.Origin.SessionID = atomic.LoadUint64(&origin.SessionID)
            if d.Origin.SessionID != 0 {
                break
            }
        }*/
        d.origin.session_id = origin.session_id;

        //d.Origin.SessionVersion = atomic.AddUint64(&origin.SessionVersion, 1)
        origin.session_version += 1;
        d.origin.session_version += 1;
    }
}

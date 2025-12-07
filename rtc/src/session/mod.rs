use sdp::description::session::Origin;
use sdp::util::ConnectionRole;
use sdp::SessionDescription;
use shared::error::{Error, Result};
use shared::TransportContext;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::configs::session_config::SessionConfig;
use crate::description::{
    codecs_from_media_description, get_cname, get_mid_value, get_msid, get_peer_direction,
    get_rids, get_ssrc_groups, get_ssrcs, populate_sdp, rtp_extensions_from_media_description,
    update_sdp_origin, MediaSection, RTCSessionDescription, MEDIA_SECTION_APPLICATION,
};
use crate::description::{
    rtp_codec::{RTCRtpParameters, RTPCodecType},
    rtp_transceiver::{RTCRtpSender, RTCRtpTransceiver},
    rtp_transceiver_direction::RTCRtpTransceiverDirection,
    sdp_type::RTCSdpType,
};
use crate::endpoint::{
    candidate::{Candidate, DTLSRole, RTCIceParameters, DEFAULT_DTLS_ROLE_OFFER},
    transport::Transport,
    Endpoint,
};
use crate::types::{EndpointId, Mid, SessionId};

pub(crate) struct Session {
    session_config: SessionConfig,
    session_id: SessionId,
    endpoints: HashMap<EndpointId, Endpoint>,
}

impl Session {
    pub(crate) fn new(session_config: SessionConfig, session_id: SessionId) -> Self {
        Self {
            session_config,
            session_id,
            endpoints: HashMap::new(),
        }
    }

    pub(crate) fn session_id(&self) -> u64 {
        self.session_id
    }

    pub(crate) fn session_config(&self) -> &SessionConfig {
        &self.session_config
    }

    pub(crate) fn add_endpoint(
        &mut self,
        candidate: &Rc<Candidate>,
        transport_context: &TransportContext,
    ) -> Result<bool> {
        let dtls_handshake_config = self
            .session_config
            .server_config
            .dtls_handshake_config
            .clone();
        let sctp_endpoint_config = self
            .session_config
            .server_config
            .sctp_endpoint_config
            .clone();
        let sctp_server_config = self.session_config.server_config.sctp_server_config.clone();
        let endpoint_id = candidate.endpoint_id();
        let endpoint = self.get_mut_endpoint(&endpoint_id);
        let four_tuple = transport_context.into();
        if let Some(endpoint) = endpoint {
            if endpoint.has_transport(&four_tuple) {
                Ok(true)
            } else {
                let transport = Transport::new(
                    four_tuple,
                    Rc::clone(candidate),
                    dtls_handshake_config,
                    sctp_endpoint_config,
                    sctp_server_config,
                );
                endpoint.add_transport(transport);
                Ok(true)
            }
        } else {
            let registry = self.session_config.server_config.media_config.registry();
            let interceptor = registry.build(""); //TODO: use named registry id
            let mut endpoint = Endpoint::new(endpoint_id, interceptor);
            let transport = Transport::new(
                four_tuple,
                Rc::clone(candidate),
                dtls_handshake_config,
                sctp_endpoint_config,
                sctp_server_config,
            );
            endpoint.add_transport(transport);
            endpoint.set_local_description(candidate.local_description().clone());
            endpoint.set_remote_description(candidate.remote_description().clone());
            self.endpoints.insert(endpoint_id, endpoint);
            Ok(false)
        }
    }

    pub(crate) fn get_endpoint(&self, endpoint_id: &EndpointId) -> Option<&Endpoint> {
        self.endpoints.get(endpoint_id)
    }

    pub(crate) fn get_mut_endpoint(&mut self, endpoint_id: &EndpointId) -> Option<&mut Endpoint> {
        self.endpoints.get_mut(endpoint_id)
    }

    pub(crate) fn remove_endpoint(&mut self, endpoint_id: &EndpointId) -> Option<Endpoint> {
        self.endpoints.remove(endpoint_id)
    }

    pub(crate) fn has_endpoint(&self, endpoint_id: &EndpointId) -> bool {
        self.endpoints.contains_key(endpoint_id)
    }

    pub(crate) fn get_endpoints(&self) -> &HashMap<EndpointId, Endpoint> {
        &self.endpoints
    }

    pub(crate) fn get_mut_endpoints(&mut self) -> &mut HashMap<EndpointId, Endpoint> {
        &mut self.endpoints
    }

    pub(crate) fn set_remote_description(
        &mut self,
        endpoint_id: EndpointId,
        remote_description: &RTCSessionDescription,
    ) -> Result<()> {
        if !self.has_endpoint(&endpoint_id) {
            return Err(Error::Other(format!(
                "can't find endpoint id {}",
                endpoint_id
            )));
        }
        let parsed = remote_description
            .parsed
            .as_ref()
            .ok_or(Error::Other("Unparsed remote description".to_string()))?;

        let we_offer = remote_description.sdp_type == RTCSdpType::Answer;

        for media in &parsed.media_descriptions {
            if media.media_name.media == MEDIA_SECTION_APPLICATION {
                continue;
            }

            let kind = RTPCodecType::from(media.media_name.media.as_str());
            let direction = get_peer_direction(media);
            if kind == RTPCodecType::Unspecified
                || direction == RTCRtpTransceiverDirection::Unspecified
            {
                continue;
            }

            let mid_value = match get_mid_value(media) {
                Some(mid) => {
                    if mid.is_empty() {
                        return Err(Error::Other(
                            "ErrPeerConnRemoteDescriptionWithoutMidValue".to_string(),
                        ));
                    } else {
                        mid
                    }
                }
                None => continue,
            };

            if !we_offer {
                // This is an offer from the remote.
                let has_mid_value = self
                    .endpoints
                    .get(&endpoint_id)
                    .unwrap()
                    .get_transceivers()
                    .contains_key(mid_value);

                if !has_mid_value {
                    let cname = get_cname(media);
                    let msid = get_msid(media);
                    let ssrc_groups = get_ssrc_groups(media)?;
                    let ssrcs = get_ssrcs(media)?;
                    let codecs = codecs_from_media_description(media)?;
                    let header_extensions = rtp_extensions_from_media_description(media)?;
                    let rtp_params = RTCRtpParameters {
                        header_extensions,
                        codecs,
                    };

                    let local_direction = if direction == RTCRtpTransceiverDirection::Recvonly {
                        RTCRtpTransceiverDirection::Sendonly
                    } else {
                        RTCRtpTransceiverDirection::Recvonly
                    };

                    let sender = if let (Some(cname), Some(msid)) = (cname, msid) {
                        Some(RTCRtpSender {
                            cname,
                            msid,
                            ssrcs,
                            ssrc_groups,
                        })
                    } else {
                        None
                    };

                    let transceiver = RTCRtpTransceiver {
                        mid: mid_value.to_string(),
                        sender: sender.clone(),
                        direction: local_direction,
                        current_direction: RTCRtpTransceiverDirection::Unspecified,
                        rtp_params: rtp_params.clone(),
                        kind,
                    };

                    {
                        let endpoint = self.get_mut_endpoint(&endpoint_id).unwrap();
                        endpoint.get_mut_mids().push(mid_value.to_string());
                        endpoint
                            .get_mut_transceivers()
                            .insert(mid_value.to_string(), transceiver);
                    }

                    // add it to other endpoints' transceivers as send only

                    for (&other_endpoint_id, other_endpoint) in self.get_mut_endpoints().iter_mut()
                    {
                        if other_endpoint_id != endpoint_id {
                            let other_mid_value = format!("{}-{}", endpoint_id, mid_value);
                            let (other_mids, other_transceivers) =
                                other_endpoint.get_mut_mids_and_transceivers();
                            if let Some(other_transceiver) =
                                other_transceivers.get_mut(&other_mid_value)
                            {
                                if other_transceiver.direction != direction {
                                    other_transceiver.direction = direction;
                                    other_endpoint.set_renegotiation_needed(true);
                                }
                            } else if direction == RTCRtpTransceiverDirection::Sendonly {
                                let other_transceiver = RTCRtpTransceiver {
                                    mid: other_mid_value.clone(),
                                    sender: sender.clone(),
                                    direction,
                                    current_direction: RTCRtpTransceiverDirection::Unspecified,
                                    rtp_params: rtp_params.clone(),
                                    kind,
                                };

                                other_mids.push(other_mid_value.clone());
                                other_transceivers.insert(other_mid_value, other_transceiver);
                                other_endpoint.set_renegotiation_needed(true);
                            }
                        }
                    }
                }
            } else {
                // This is an answer from the remote.
                let endpoint = self.get_mut_endpoint(&endpoint_id).unwrap();
                if let Some(transceiver) = endpoint.get_mut_transceivers().get_mut(mid_value) {
                    //let previous_direction = transceiver.current_direction();

                    // 4.5.9.2.9
                    // Let direction be an RTCRtpTransceiverDirection value representing the direction
                    // from the media description, but with the send and receive directions reversed to
                    // represent this peer's point of view. If the media description is rejected,
                    // set direction to "inactive".
                    let reversed_direction = direction.reverse();

                    // 4.5.9.2.13.2
                    // Set transceiver.[[CurrentDirection]] and transceiver.[[Direction]]s to direction.
                    transceiver.set_current_direction(reversed_direction);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn set_local_description(
        &mut self,
        endpoint_id: EndpointId,
        local_description: &RTCSessionDescription,
    ) -> Result<()> {
        let parsed = local_description
            .parsed
            .as_ref()
            .ok_or(Error::Other("Unparsed local description".to_string()))?;
        let endpoint = self
            .get_mut_endpoint(&endpoint_id)
            .ok_or(Error::Other(format!(
                "can't find endpoint id {}",
                endpoint_id
            )))?;

        let transceivers = endpoint.get_mut_transceivers();
        let we_answer = local_description.sdp_type == RTCSdpType::Answer;
        if we_answer {
            for media in &parsed.media_descriptions {
                if media.media_name.media == MEDIA_SECTION_APPLICATION {
                    continue;
                }

                let kind = RTPCodecType::from(media.media_name.media.as_str());
                let direction = get_peer_direction(media);
                if kind == RTPCodecType::Unspecified
                    || direction == RTCRtpTransceiverDirection::Unspecified
                {
                    continue;
                }

                let mid_value = match get_mid_value(media) {
                    Some(mid) => {
                        if mid.is_empty() {
                            return Err(Error::Other(
                                "ErrPeerConnRemoteDescriptionWithoutMidValue".to_string(),
                            ));
                        } else {
                            mid
                        }
                    }
                    _ => continue,
                };

                if let Some(transceiver) = transceivers.get_mut(mid_value) {
                    //let previous_direction = transceiver.current_direction();
                    // 4.9.1.7.3 applying a local answer or pranswer
                    // Set transceiver.[[CurrentDirection]] and transceiver.[[FiredDirection]] to direction.
                    transceiver.set_current_direction(direction);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn create_offer(
        &self,
        endpoint_id: EndpointId,
        remote_description: &RTCSessionDescription,
        local_ice_params: &RTCIceParameters,
    ) -> Result<RTCSessionDescription> {
        let use_identity = false; //TODO: self.config.idp_login_url.is_some();

        let mut d = self.generate_matched_sdp(
            endpoint_id,
            remote_description,
            local_ice_params,
            use_identity,
            true, /*includeUnmatched */
            DEFAULT_DTLS_ROLE_OFFER.to_connection_role(),
        )?;

        let mut sdp_origin = Origin::default();
        update_sdp_origin(&mut sdp_origin, &mut d);

        let sdp = d.marshal();

        let offer = RTCSessionDescription {
            sdp_type: RTCSdpType::Offer,
            sdp,
            parsed: Some(d),
        };

        Ok(offer)
    }

    pub(crate) fn create_answer(
        &self,
        endpoint: EndpointId,
        remote_description: &RTCSessionDescription,
        local_ice_params: &RTCIceParameters,
    ) -> Result<RTCSessionDescription> {
        let use_identity = false; //TODO: self.config.idp_login_url.is_some();
        let mut d = self.generate_matched_sdp(
            endpoint,
            remote_description,
            local_ice_params,
            use_identity,
            false, /*includeUnmatched */
            DTLSRole::Server.to_connection_role(),
        )?;

        let mut sdp_origin = Origin::default();
        update_sdp_origin(&mut sdp_origin, &mut d);

        let sdp = d.marshal();

        let answer = RTCSessionDescription {
            sdp_type: RTCSdpType::Answer,
            sdp,
            parsed: Some(d),
        };

        Ok(answer)
    }

    /// generate_matched_sdp generates a SDP and takes the remote state into account
    /// this is used everytime we have a remote_description
    pub(crate) fn generate_matched_sdp(
        &self,
        endpoint_id: EndpointId,
        remote_description: &RTCSessionDescription,
        local_ice_params: &RTCIceParameters,
        use_identity: bool,
        include_unmatched: bool,
        connection_role: ConnectionRole,
    ) -> Result<SessionDescription> {
        let d = SessionDescription::new_jsep_session_description(use_identity);
        let (empty_mids, empty_transceivers) = (vec![], HashMap::new());

        let media_sections = {
            let (mids, transceivers) = if let Some(endpoint) = self.get_endpoint(&endpoint_id) {
                (endpoint.get_mids(), endpoint.get_transceivers())
            } else {
                (&empty_mids, &empty_transceivers)
            };

            let mut media_sections = vec![];
            let mut already_have_application_media_section = false;
            let mut matched: HashSet<Mid> = HashSet::new();
            if let Some(parsed) = remote_description.parsed.as_ref() {
                for media in &parsed.media_descriptions {
                    if let Some(mid_value) = get_mid_value(media) {
                        if mid_value.is_empty() {
                            return Err(Error::Other(
                                "ErrPeerConnRemoteDescriptionWithoutMidValue".to_string(),
                            ));
                        }

                        if media.media_name.media == MEDIA_SECTION_APPLICATION {
                            media_sections.push(MediaSection {
                                mid: mid_value.to_owned(),
                                data: true,
                                ..Default::default()
                            });
                            already_have_application_media_section = true;
                            continue;
                        }

                        let kind = RTPCodecType::from(media.media_name.media.as_str());
                        let direction = get_peer_direction(media);
                        if kind == RTPCodecType::Unspecified
                            || direction == RTCRtpTransceiverDirection::Unspecified
                        {
                            continue;
                        }

                        if transceivers.contains_key(mid_value) {
                            media_sections.push(MediaSection {
                                mid: mid_value.to_owned(),
                                rid_map: get_rids(media),
                                offered_direction: (!include_unmatched).then_some(direction),
                                ..Default::default()
                            });
                            matched.insert(mid_value.to_string());
                        } else {
                            return Err(Error::Other("ErrPeerConnTransceiverMidNil".to_string()));
                        }
                    }
                }
            }

            // If we are offering also include unmatched local transceivers
            if include_unmatched {
                for mid in mids.iter() {
                    if !matched.contains::<Mid>(mid) {
                        media_sections.push(MediaSection {
                            mid: mid.clone(),
                            ..Default::default()
                        });
                    }
                }

                if !already_have_application_media_section {
                    media_sections.push(MediaSection {
                        mid: format!("{}", media_sections.len()),
                        data: true,
                        ..Default::default()
                    });
                }
            }

            media_sections
        };

        let dtls_fingerprints =
            if let Some(cert) = self.session_config.server_config.certificates.first() {
                cert.get_fingerprints()
            } else {
                return Err(Error::Other("ErrNonCertificate".to_string()));
            };

        let transceivers = if let Some(endpoint) = self.get_endpoint(&endpoint_id) {
            endpoint.get_transceivers()
        } else {
            &empty_transceivers
        };

        populate_sdp(
            d,
            &dtls_fingerprints,
            &self.session_config,
            local_ice_params,
            connection_role,
            &media_sections,
            transceivers,
            true,
        )
    }
}

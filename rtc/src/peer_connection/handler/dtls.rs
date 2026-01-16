use crate::peer_connection::configuration::setting_engine::ReplayProtection;
use crate::peer_connection::event::RTCEventInternal;
use crate::peer_connection::handler::DEFAULT_TIMEOUT_DURATION;
use crate::peer_connection::message::internal::{
    DTLSMessage, RTCMessageInternal, TaggedRTCMessageInternal,
};
use crate::peer_connection::transport::dtls::RTCDtlsTransport;
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::statistics::accumulator::{CertificateStatsAccumulator, RTCStatsAccumulator};
use dtls::endpoint::EndpointEvent;
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use dtls::state::State;
use log::{debug, warn};
use sha2::{Digest, Sha256};
use shared::TransportContext;
use shared::error::{Error, Result};
use srtp::option::{srtcp_replay_protection, srtp_replay_protection};
use srtp::protection_profile::ProtectionProfile;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Default)]
pub(crate) struct DtlsHandlerContext {
    pub(crate) dtls_transport: RTCDtlsTransport,

    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<RTCEventInternal>,
}

impl DtlsHandlerContext {
    pub(crate) fn new(dtls_transport: RTCDtlsTransport) -> Self {
        Self {
            dtls_transport,
            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
        }
    }
}

/// DtlsHandler implements DTLS Protocol handling
pub(crate) struct DtlsHandler<'a> {
    ctx: &'a mut DtlsHandlerContext,
    stats: &'a mut RTCStatsAccumulator,
}

impl<'a> DtlsHandler<'a> {
    pub(crate) fn new(ctx: &'a mut DtlsHandlerContext, stats: &'a mut RTCStatsAccumulator) -> Self {
        DtlsHandler { ctx, stats }
    }

    pub(crate) fn name(&self) -> &'static str {
        "DtlsHandler"
    }

    /// Update stats when DTLS handshake completes
    fn update_dtls_stats_from_profile(
        &mut self,
        srtp_profile: SrtpProtectionProfile,
        peer_certificates: &[Vec<u8>],
        dtls_cipher: Option<String>,
    ) {
        // Update transport DTLS state
        self.stats
            .transport
            .on_dtls_state_changed(RTCDtlsTransportState::Connected);

        // Update DTLS role from transport
        self.stats.transport.dtls_role = self.ctx.dtls_transport.dtls_role;

        // Update SRTP cipher from DTLS negotiation
        let srtp_cipher = match srtp_profile {
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm => "SRTP_AEAD_AES_128_GCM",
            SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm => "SRTP_AEAD_AES_256_GCM",
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80 => "SRTP_AES128_CM_HMAC_SHA1_80",
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32 => "SRTP_AES128_CM_HMAC_SHA1_32",
            _ => "Unknown",
        };
        self.stats.transport.srtp_cipher = srtp_cipher.to_string();

        // Update TLS version
        self.stats.transport.tls_version = "DTLS 1.2".to_string();

        // Update DTLS cipher from the negotiated cipher suite
        if let Some(cipher) = dtls_cipher {
            self.stats.transport.dtls_cipher = cipher;
        }

        // Register local certificate and set local_certificate_id
        if let Some(local_cert) = self.ctx.dtls_transport.certificates.first() {
            let fingerprints = local_cert.get_fingerprints();
            if let Some(fp) = fingerprints.first() {
                let cert_id = local_cert.stats_id.clone();

                // Register certificate in accumulator
                // Use hex encoding for certificate (base64 would need additional dependency)
                if let Some(der) = local_cert.dtls_certificate.certificate.first() {
                    self.stats.register_certificate(
                        cert_id.clone(),
                        CertificateStatsAccumulator {
                            fingerprint: fp.value.clone(),
                            fingerprint_algorithm: fp.algorithm.clone(),
                            base64_certificate: hex::encode(der.as_ref()),
                            issuer_certificate_id: String::new(),
                        },
                    );
                }

                // Set local certificate ID in transport stats
                self.stats.transport.local_certificate_id = cert_id;
            }
        }

        // Register remote certificate and set remote_certificate_id
        if let Some(peer_cert_der) = peer_certificates.first() {
            // Compute fingerprint from peer certificate
            let mut hasher = Sha256::new();
            hasher.update(peer_cert_der);
            let hash = hasher.finalize();
            let fingerprint: String = hash
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":");

            let cert_id = format!("remote-certificate-{}", &fingerprint[..8]);

            // Register remote certificate in accumulator
            self.stats.register_certificate(
                cert_id.clone(),
                CertificateStatsAccumulator {
                    fingerprint,
                    fingerprint_algorithm: "sha-256".to_string(),
                    base64_certificate: hex::encode(peer_cert_der),
                    issuer_certificate_id: String::new(),
                },
            );

            // Set remote certificate ID in transport stats
            self.stats.transport.remote_certificate_id = cert_id;
        }
    }
}

impl<'a> sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, RTCEventInternal>
    for DtlsHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = RTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Dtls(DTLSMessage::Raw(dtls_message)) = msg.message {
            debug!("recv dtls RAW {:?}", msg.transport.peer_addr);

            let mut messages = vec![];
            let mut srtp_contexts = None;
            let mut srtp_profile_for_stats: Option<SrtpProtectionProfile> = None;
            let mut peer_certificates_for_stats: Vec<Vec<u8>> = vec![];
            let mut dtls_cipher_for_stats: Option<String> = None;

            let dtls_endpoint = self
                .ctx
                .dtls_transport
                .dtls_endpoint
                .as_mut()
                .ok_or(Error::ErrDtlsTransportNotStarted)?;

            for message in dtls_endpoint.read(
                msg.now,
                msg.transport.peer_addr,
                msg.transport.ecn,
                dtls_message,
            )? {
                match message {
                    EndpointEvent::HandshakeComplete => {
                        if let Some(state) =
                            dtls_endpoint.get_connection_state(msg.transport.peer_addr)
                        {
                            debug!("dtls handshake complete");

                            // Save profile for stats update after borrow ends
                            srtp_profile_for_stats = Some(state.srtp_protection_profile());

                            // Save peer certificates for stats
                            peer_certificates_for_stats = state.peer_certificates.clone();

                            // Save DTLS cipher suite for stats
                            dtls_cipher_for_stats = state.cipher_suite().map(|cs| cs.to_string());

                            let (local_srtp_context, remote_srtp_context) =
                                DtlsHandler::update_srtp_contexts(
                                    state,
                                    &self.ctx.dtls_transport.replay_protection,
                                )?;
                            srtp_contexts = Some((local_srtp_context, remote_srtp_context));
                        } else {
                            warn!(
                                "Unable to find connection state for {}",
                                msg.transport.peer_addr
                            );
                        }
                    }
                    EndpointEvent::ApplicationData(message) => {
                        debug!("recv dtls application RAW {:?}", msg.transport.peer_addr);
                        messages.push(message);
                    }
                }
            }

            while let Some(transmit) = dtls_endpoint.poll_transmit() {
                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now: transmit.now,
                    transport: transmit.transport,
                    message: RTCMessageInternal::Dtls(DTLSMessage::Raw(transmit.message)),
                });
            }

            if let Some((local_srtp_context, remote_srtp_context)) = srtp_contexts {
                self.ctx
                    .dtls_transport
                    .state_change(RTCDtlsTransportState::Connected);

                self.ctx
                    .event_outs
                    .push_back(RTCEventInternal::DTLSHandshakeComplete(
                        Some(local_srtp_context),
                        Some(remote_srtp_context),
                    ));
            }

            // Update stats after dtls_endpoint borrow ends
            if let Some(srtp_profile) = srtp_profile_for_stats {
                self.update_dtls_stats_from_profile(
                    srtp_profile,
                    &peer_certificates_for_stats,
                    dtls_cipher_for_stats,
                );
            }

            for message in messages {
                debug!("recv dtls application RAW {:?}", msg.transport.peer_addr);
                self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageInternal::Dtls(DTLSMessage::Raw(message)),
                });
            }
        } else {
            // Bypass
            debug!("bypass dtls read {:?}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Dtls(DTLSMessage::Raw(dtls_message)) = msg.message {
            debug!("send dtls RAW {:?}", msg.transport.peer_addr);

            let dtls_endpoint = self
                .ctx
                .dtls_transport
                .dtls_endpoint
                .as_mut()
                .ok_or(Error::ErrDtlsTransportNotStarted)?;

            dtls_endpoint.write(msg.transport.peer_addr, &dtls_message)?;
            while let Some(transmit) = dtls_endpoint.poll_transmit() {
                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now: transmit.now,
                    transport: transmit.transport,
                    message: RTCMessageInternal::Dtls(DTLSMessage::Raw(transmit.message)),
                });
            }
        } else {
            // Bypass
            debug!("Bypass dtls write {:?}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: RTCEventInternal) -> Result<()> {
        if let RTCEventInternal::ICESelectedCandidatePairChange = evt {
            if self.ctx.dtls_transport.dtls_role == RTCDtlsRole::Client {
                // dtls_endpoint only connect once when acts as DTLSRole::Client
                if let Some(dtls_handshake_config) =
                    self.ctx.dtls_transport.dtls_handshake_config.take()
                {
                    let dtls_endpoint = self
                        .ctx
                        .dtls_transport
                        .dtls_endpoint
                        .as_mut()
                        .ok_or(Error::ErrDtlsTransportNotStarted)?;
                    dtls_endpoint.connect(
                        TransportContext::default().peer_addr, // always use default for transport to make DTLS tunneled
                        dtls_handshake_config,
                        None,
                    )?;
                };
            }
        } else {
            self.ctx.event_outs.push_back(evt);
        }
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        let dtls_endpoint = self
            .ctx
            .dtls_transport
            .dtls_endpoint
            .as_mut()
            .ok_or(Error::ErrDtlsTransportNotStarted)?;

        let remotes: Vec<SocketAddr> = dtls_endpoint.get_connections_keys().copied().collect();
        for remote in remotes {
            let _ = dtls_endpoint.handle_timeout(remote, now);
        }
        while let Some(transmit) = dtls_endpoint.poll_transmit() {
            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                now: transmit.now,
                transport: transmit.transport,
                message: RTCMessageInternal::Dtls(DTLSMessage::Raw(transmit.message)),
            });
        }

        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        if let Some(dtls_endpoint) = self.ctx.dtls_transport.dtls_endpoint.as_ref() {
            let max_eto = Instant::now() + DEFAULT_TIMEOUT_DURATION;
            let mut eto = max_eto;

            let remotes = dtls_endpoint.get_connections_keys();
            for remote in remotes {
                let _ = dtls_endpoint.poll_timeout(*remote, &mut eto);
            }

            if eto != max_eto { Some(eto) } else { None }
        } else {
            None
        }
    }

    fn close(&mut self) -> Result<()> {
        self.ctx.dtls_transport.stop()
    }
}

impl<'a> DtlsHandler<'a> {
    const DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW: usize = 64;
    const DEFAULT_SESSION_SRTCP_REPLAY_PROTECTION_WINDOW: usize = 64;
    pub(crate) fn update_srtp_contexts(
        state: &State,
        replay_protection: &ReplayProtection,
    ) -> Result<(srtp::context::Context, srtp::context::Context)> {
        let profile = match state.srtp_protection_profile() {
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm => ProtectionProfile::AeadAes128Gcm,
            SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm => ProtectionProfile::AeadAes256Gcm,
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80 => {
                ProtectionProfile::Aes128CmHmacSha1_80
            }
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32 => {
                ProtectionProfile::Aes128CmHmacSha1_32
            }
            _ => return Err(Error::ErrNoSuchSrtpProfile),
        };

        let mut srtp_config = srtp::config::Config {
            profile,
            ..Default::default()
        };
        if replay_protection.srtp != 0 {
            srtp_config.remote_rtp_options =
                Some(srtp::option::srtp_replay_protection(replay_protection.srtp));
        }

        if replay_protection.srtcp != 0 {
            srtp_config.remote_rtcp_options = Some(srtp::option::srtcp_replay_protection(
                replay_protection.srtcp,
            ));
        }

        srtp_config.extract_session_keys_from_dtls(state, state.is_client())?;

        let local_context = srtp::context::Context::new(
            &srtp_config.keys.local_master_key,
            &srtp_config.keys.local_master_salt,
            srtp_config.profile,
            srtp_config.local_rtp_options,
            srtp_config.local_rtcp_options,
        )?;

        let remote_context = srtp::context::Context::new(
            &srtp_config.keys.remote_master_key,
            &srtp_config.keys.remote_master_salt,
            srtp_config.profile,
            if srtp_config.remote_rtp_options.is_none() {
                Some(srtp_replay_protection(
                    Self::DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW,
                ))
            } else {
                srtp_config.remote_rtp_options
            },
            if srtp_config.remote_rtcp_options.is_none() {
                Some(srtcp_replay_protection(
                    Self::DEFAULT_SESSION_SRTCP_REPLAY_PROTECTION_WINDOW,
                ))
            } else {
                srtp_config.remote_rtcp_options
            },
        )?;

        Ok((local_context, remote_context))
    }
}

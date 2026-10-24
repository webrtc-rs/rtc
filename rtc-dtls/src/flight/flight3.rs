use super::flight5::*;
use super::*;
use crate::config::*;
use crate::content::*;
use crate::extension::*;
use crate::extension::extension_use_srtp::SrtpProtectionProfile;
use crate::handshake::handshake_message_server_key_exchange::*;
use crate::handshake::*;
use crate::record_layer::record_layer_header::*;
use crate::record_layer::*;
use shared::error::Error;

use crate::cipher_suite::cipher_suite_for_id;
use crate::prf::{prf_pre_master_secret, prf_psk_pre_master_secret};
use crate::{find_matching_cipher_suite, find_matching_srtp_profile};


use log::*;
use std::fmt;

#[derive(Debug, PartialEq)]
pub(crate) struct Flight3;

impl fmt::Display for Flight3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flight 3")
    }
}

impl Flight for Flight3 {
    fn parse(
        &self,
        //_tx: &mut mpsc::Sender<mpsc::Sender<()>>,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Box<dyn Flight>, (Option<Alert>, Option<Error>)> {
        // Clients may receive multiple HelloVerifyRequest messages with different cookies.
        // Clients SHOULD handle this by sending a new ClientHello with a cookie in response
        // to the new HelloVerifyRequest. RFC 6347 Section 4.2.1
        if let Ok((seq, msgs)) = cache.full_pull_map(
            state.handshake_recv_sequence,
            &[HandshakeCachePullRule {
                typ: HandshakeType::HelloVerifyRequest,
                epoch: cfg.initial_epoch,
                is_client: false,
                optional: true,
            }],
        ) && let Some(message) = msgs.get(&HandshakeType::HelloVerifyRequest)
        {
            // DTLS 1.2 clients must not assume that the server will use the protocol version
            // specified in HelloVerifyRequest message. RFC 6347 Section 4.2.1
            let h = match message {
                HandshakeMessage::HelloVerifyRequest(h) => h,
                _ => {
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::InternalError,
                        }),
                        None,
                    ));
                }
            };

            // DTLS 1.2 clients must not assume that the server will use the protocol version
            // specified in HelloVerifyRequest message. RFC 6347 Section 4.2.1
            if h.version != PROTOCOL_VERSION1_0 && h.version != PROTOCOL_VERSION1_2 {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::ProtocolVersion,
                    }),
                    Some(Error::ErrUnsupportedProtocolVersion),
                ));
            }

            state.cookie.clone_from(&h.cookie);
            state.handshake_recv_sequence = seq;
            return Ok(Box::new(Flight3 {}) as Box<dyn Flight>);
        }

        // A ServerHello is judged as soon as it arrives, not when the rest of the flight has
        // (pion's flight 3 reads the hello alone).
        if let Ok((_, early)) = cache.full_pull_map(
            state.handshake_recv_sequence,
            &[HandshakeCachePullRule {
                typ: HandshakeType::ServerHello,
                epoch: cfg.initial_epoch,
                is_client: false,
                optional: false,
            }],
        ) && let Some(HandshakeMessage::ServerHello(h)) = early.get(&HandshakeType::ServerHello)
            && h.version != PROTOCOL_VERSION1_2
        {
            return Err((
                Some(Alert {
                    alert_level: AlertLevel::Fatal,
                    alert_description: AlertDescription::ProtocolVersion,
                }),
                Some(Error::ErrUnsupportedProtocolVersion),
            ));
        }

        let result = if cfg.local_psk_callback.is_some() {
            cache.full_pull_map(
                state.handshake_recv_sequence,
                &[
                    HandshakeCachePullRule {
                        typ: HandshakeType::ServerHello,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: false,
                    },
                    HandshakeCachePullRule {
                        typ: HandshakeType::ServerKeyExchange,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: true,
                    },
                    HandshakeCachePullRule {
                        typ: HandshakeType::ServerHelloDone,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: false,
                    },
                ],
            )
        } else {
            cache.full_pull_map(
                state.handshake_recv_sequence,
                &[
                    HandshakeCachePullRule {
                        typ: HandshakeType::ServerHello,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: false,
                    },
                    HandshakeCachePullRule {
                        typ: HandshakeType::Certificate,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: true,
                    },
                    HandshakeCachePullRule {
                        typ: HandshakeType::ServerKeyExchange,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: false,
                    },
                    HandshakeCachePullRule {
                        typ: HandshakeType::CertificateRequest,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: true,
                    },
                    HandshakeCachePullRule {
                        typ: HandshakeType::ServerHelloDone,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: false,
                    },
                ],
            )
        };

        let (seq, msgs) = match result {
            Ok((seq, msgs)) => (seq, msgs),
            Err(_) => return Err((None, None)),
        };

        state.handshake_recv_sequence = seq;

        if let Some(message) = msgs.get(&HandshakeType::ServerHello) {
            let h = match message {
                HandshakeMessage::ServerHello(h) => h,
                _ => {
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::InternalError,
                        }),
                        None,
                    ));
                }
            };

            if h.version != PROTOCOL_VERSION1_2 {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::ProtocolVersion,
                    }),
                    Some(Error::ErrUnsupportedProtocolVersion),
                ));
            }

            for extension in &h.extensions {
                match extension {
                    Extension::UseSrtp(e) => {
                        let profile = match find_matching_srtp_profile(
                            &e.protection_profiles,
                            &cfg.local_srtp_protection_profiles,
                        ) {
                            Ok(profile) => profile,
                            Err(_) => {
                                return Err((
                                    Some(Alert {
                                        alert_level: AlertLevel::Fatal,
                                        alert_description: AlertDescription::IllegalParameter,
                                    }),
                                    Some(Error::ErrClientNoMatchingSrtpProfile),
                                ));
                            }
                        };
                        state.srtp_protection_profile = profile;
                    }
                    Extension::Alpn(e) => {
                        // The server's answer names exactly one protocol, and it must be one
                        // this client offered (RFC 7301 §3.1).
                        let [selected] = &e.protocols[..] else {
                            return Err((
                                Some(Alert {
                                    alert_level: AlertLevel::Fatal,
                                    alert_description: AlertDescription::InternalError,
                                }),
                                Some(Error::ErrAlpnInvalidFormat),
                            ));
                        };
                        if !cfg.local_supported_protocols.contains(selected) {
                            return Err((
                                Some(Alert {
                                    alert_level: AlertLevel::Fatal,
                                    alert_description: AlertDescription::IllegalParameter,
                                }),
                                Some(Error::ErrAlpnInvalidFormat),
                            ));
                        }
                        state.negotiated_protocol.clone_from(selected);
                    }
                    Extension::UseExtendedMasterSecret(_)
                        if cfg.extended_master_secret != ExtendedMasterSecretType::Disable =>
                    {
                        state.extended_master_secret = true;
                    }
                    _ => {}
                };
            }

            if cfg.extended_master_secret == ExtendedMasterSecretType::Require
                && !state.extended_master_secret
            {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::InsufficientSecurity,
                    }),
                    Some(Error::ErrClientRequiredButNoServerEms),
                ));
            }
            if !cfg.local_srtp_protection_profiles.is_empty()
                && state.srtp_protection_profile == SrtpProtectionProfile::Unsupported
            {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::InsufficientSecurity,
                    }),
                    Some(Error::ErrRequestedButNoSrtpExtension),
                ));
            }
            if find_matching_cipher_suite(&[h.cipher_suite], &cfg.local_cipher_suites).is_err() {
                debug!(
                    "[handshake:{}] use cipher suite: {}",
                    srv_cli_str(state.is_client),
                    h.cipher_suite
                );

                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::InsufficientSecurity,
                    }),
                    Some(Error::ErrCipherSuiteNoIntersection),
                ));
            }

            let cipher_suite = match cipher_suite_for_id(h.cipher_suite) {
                Ok(cipher_suite) => cipher_suite,
                Err(_) => {
                    debug!(
                        "[handshake:{}] use cipher suite: {}",
                        srv_cli_str(state.is_client),
                        h.cipher_suite
                    );

                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::InsufficientSecurity,
                        }),
                        Some(Error::ErrInvalidCipherSuite),
                    ));
                }
            };

            debug!(
                "[handshake:{}] use cipher suite: {}",
                srv_cli_str(state.is_client),
                cipher_suite.to_string()
            );

            state.cipher_suite = Some(cipher_suite);
            state.remote_random = h.random.clone();
        }

        if let Some(message) = msgs.get(&HandshakeType::Certificate) {
            let h = match message {
                HandshakeMessage::Certificate(h) => h,
                _ => {
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::InternalError,
                        }),
                        None,
                    ));
                }
            };
            state.peer_certificates.clone_from(&h.certificate);
        }

        if let Some(message) = msgs.get(&HandshakeType::ServerKeyExchange) {
            let h = match message {
                HandshakeMessage::ServerKeyExchange(h) => h,
                _ => {
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::InternalError,
                        }),
                        None,
                    ));
                }
            };

            if let Err((alert, err)) = handle_server_key_exchange(state, cfg, h) {
                return Err((alert, err));
            }
        }

        if let Some(message) = msgs.get(&HandshakeType::CertificateRequest) {
            let request = match message {
                HandshakeMessage::CertificateRequest(request) => request,
                _ => {
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::InternalError,
                        }),
                        None,
                    ));
                }
            };
            state.remote_requested_certificate = true;
            // Retained for `get_client_certificate` and CertificateVerify scheme selection.
            state.remote_certificate_request = Some(crate::config::CertificateRequestInfo::new(
                request.certificate_types.clone(),
                request.signature_hash_algorithms.clone(),
                request.certificate_authorities_names.clone(),
            ));
        }

        Ok(Box::new(Flight5 {}) as Box<dyn Flight>)
    }

    fn generate(
        &self,
        state: &mut State,
        _cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Vec<Packet>, (Option<Alert>, Option<Error>)> {
        let message = super::build_client_hello_message(state, cfg)?;

        Ok(vec![Packet {
            record: RecordLayer::new(
                PROTOCOL_VERSION1_2,
                0,
                Content::Handshake(Handshake::new(message)),
            ),
            should_encrypt: false,
            reset_local_sequence_number: false,
        }])
    }
}

pub(crate) fn handle_server_key_exchange(
    state: &mut State,
    cfg: &HandshakeConfig,
    h: &HandshakeMessageServerKeyExchange,
) -> Result<(), (Option<Alert>, Option<Error>)> {
    if let Some(local_psk_callback) = &cfg.local_psk_callback {
        let psk = match local_psk_callback(&h.identity_hint) {
            Ok(psk) => psk,
            Err(err) => {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::InternalError,
                    }),
                    Some(err),
                ));
            }
        };

        state.identity_hint.clone_from(&h.identity_hint);
        state.pre_master_secret = prf_psk_pre_master_secret(&psk);
    } else {
        let mut local_keypair = match h
            .named_curve
            .generate_keypair_with_crypto(cfg.provider().crypto())
        {
            Ok(local_keypair) => local_keypair,
            Err(err) => {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::InternalError,
                    }),
                    Some(err),
                ));
            }
        };

        let curve = local_keypair.curve;
        state.pre_master_secret =
            match prf_pre_master_secret(&h.public_key, &mut local_keypair, curve) {
                Ok(pre_master_secret) => pre_master_secret,
                Err(err) => {
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::InternalError,
                        }),
                        Some(err),
                    ));
                }
            };

        state.local_keypair = Some(local_keypair);
    }

    Ok(())
}

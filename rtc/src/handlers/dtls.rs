use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::api::setting_engine::SettingEngine;
use crate::handlers::RTCHandler;
use crate::messages::{DTLSMessage, RTCEvent, RTCMessage};
use crate::transport::dtls_transport::RTCDtlsTransport;
use dtls::endpoint::EndpointEvent;
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use dtls::state::State;
use log::{debug, error, warn};
use shared::error::{Error, Result};
use shared::Transmit;
use srtp::option::{srtcp_replay_protection, srtp_no_replay_protection, srtp_replay_protection};
use srtp::protection_profile::ProtectionProfile;

impl RTCHandler for RTCDtlsTransport {
    fn handle_transmit(&mut self, msg: Transmit<RTCMessage>) -> Vec<Transmit<RTCMessage>> {
        if let RTCMessage::Dtls(DTLSMessage::Raw(dtls_message)) = msg.message {
            debug!("recv dtls RAW {:?}", msg.transport.peer_addr);

            let try_read = || -> Result<Vec<BytesMut>> {
                let dtls_endpoint = self
                    .dtls_endpoint
                    .as_mut()
                    .ok_or(Error::ErrInvalidDTLSStart)?;
                let mut messages = vec![];
                let mut contexts = vec![];

                {
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
                                    debug!("recv dtls handshake complete");
                                    let (local_context, remote_context) =
                                        update_srtp_contexts(state, &self.setting_engine)?;
                                    contexts.push((local_context, remote_context));
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
                        self.transmits.push_back(Transmit {
                            now: transmit.now,
                            transport: transmit.transport,
                            message: RTCMessage::Dtls(DTLSMessage::Raw(transmit.message)),
                        });
                    }
                }

                for (local_context, remote_context) in contexts {
                    self.set_local_srtp_context(local_context);
                    self.set_remote_srtp_context(remote_context);
                }

                Ok(messages)
            };

            let mut next_msgs = vec![];
            match try_read() {
                Ok(messages) => {
                    for message in messages {
                        debug!("recv dtls application RAW {:?}", msg.transport.peer_addr);
                        next_msgs.push(Transmit {
                            now: msg.now,
                            transport: msg.transport,
                            message: RTCMessage::Dtls(DTLSMessage::Raw(message)),
                        });
                    }
                }
                Err(err) => {
                    error!("try_read with error {}", err);
                    if err == Error::ErrAlertFatalOrClose {
                        if let Some(mut dtls_endpoint) = self.dtls_endpoint.take() {
                            let _ = dtls_endpoint.close();
                        }
                    } else {
                        self.handle_error(err);
                    }
                }
            };
            next_msgs
        } else {
            // Bypass
            debug!("bypass dtls read {:?}", msg.transport.peer_addr);
            vec![msg]
        }
    }

    fn poll_transmit(&mut self, msg: Option<Transmit<RTCMessage>>) -> Option<Transmit<RTCMessage>> {
        if let Some(msg) = msg {
            if let RTCMessage::Dtls(DTLSMessage::Raw(dtls_message)) = msg.message {
                debug!("send dtls RAW {:?}", msg.transport.peer_addr);
                let mut try_write = || -> Result<()> {
                    let dtls_endpoint = self
                        .dtls_endpoint
                        .as_mut()
                        .ok_or(Error::ErrInvalidDTLSStart)?;
                    dtls_endpoint.write(msg.transport.peer_addr, &dtls_message)?;
                    while let Some(transmit) = dtls_endpoint.poll_transmit() {
                        self.transmits.push_back(Transmit {
                            now: transmit.now,
                            transport: transmit.transport,
                            message: RTCMessage::Dtls(DTLSMessage::Raw(transmit.message)),
                        });
                    }

                    Ok(())
                };

                match try_write() {
                    Ok(_) => {}
                    Err(err) => {
                        error!("try_write with error {}", err);
                        self.handle_error(err);
                    }
                }
            } else {
                // Bypass
                debug!("Bypass dtls write {:?}", msg.transport.peer_addr);
                self.transmits.push_back(msg);
            }
        }

        self.transmits.pop_front()
    }

    fn poll_event(&mut self) -> Option<RTCEvent> {
        self.events.pop_front().map(RTCEvent::DtlsTransportEvent)
    }

    fn handle_timeout(&mut self, now: Instant) {
        let mut try_timeout = || -> Result<()> {
            let dtls_endpoint = self
                .dtls_endpoint
                .as_mut()
                .ok_or(Error::ErrInvalidDTLSStart)?;
            let remotes: Vec<SocketAddr> = dtls_endpoint.get_connections_keys().copied().collect();
            for remote in remotes {
                let _ = dtls_endpoint.handle_timeout(remote, now);
            }
            while let Some(transmit) = dtls_endpoint.poll_transmit() {
                self.transmits.push_back(Transmit {
                    now: transmit.now,
                    transport: transmit.transport,
                    message: RTCMessage::Dtls(DTLSMessage::Raw(transmit.message)),
                });
            }

            Ok(())
        };
        match try_timeout() {
            Ok(_) => {}
            Err(err) => {
                error!("try_timeout with error {}", err);
                self.handle_error(err);
            }
        }
    }

    fn poll_timeout(&mut self, eto: &mut Instant) {
        if let Some(dtls_endpoint) = self.dtls_endpoint.as_mut() {
            let remotes = dtls_endpoint.get_connections_keys();
            for remote in remotes {
                let _ = dtls_endpoint.poll_timeout(*remote, eto);
            }
        }
    }
}

pub(crate) fn update_srtp_contexts(
    state: &State,
    setting_engine: &Arc<SettingEngine>,
) -> Result<(srtp::context::Context, srtp::context::Context)> {
    let profile = match state.srtp_protection_profile() {
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80 => {
            ProtectionProfile::Aes128CmHmacSha1_80
        }
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm => ProtectionProfile::AeadAes128Gcm,
        _ => return Err(Error::ErrNoSuchSrtpProfile),
    };

    let mut srtp_config = srtp::config::Config {
        profile,
        ..Default::default()
    };
    if setting_engine.replay_protection.srtp != 0 {
        srtp_config.remote_rtp_options = Some(srtp_replay_protection(
            setting_engine.replay_protection.srtp,
        ));
    } else if setting_engine.disable_srtp_replay_protection {
        srtp_config.remote_rtp_options = Some(srtp_no_replay_protection());
    }

    srtp_config.extract_session_keys_from_dtls(state, false)?;

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
                crate::constants::DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW,
            ))
        } else {
            srtp_config.remote_rtp_options
        },
        if srtp_config.remote_rtcp_options.is_none() {
            Some(srtcp_replay_protection(
                crate::constants::DEFAULT_SESSION_SRTCP_REPLAY_PROTECTION_WINDOW,
            ))
        } else {
            srtp_config.remote_rtcp_options
        },
    )?;

    Ok((local_context, remote_context))
}

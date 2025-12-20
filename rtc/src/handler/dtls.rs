use std::collections::VecDeque;
use std::time::Instant;

use super::message::{DTLSMessage, RTCMessage, TaggedRTCMessage};
//TODO: use dtls::endpoint::EndpointEvent;
use crate::transport::dtls::RTCDtlsTransport;
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use dtls::state::State;
use log::debug;
use shared::error::{Error, Result};
use srtp::option::{srtcp_replay_protection, srtp_replay_protection};
use srtp::protection_profile::ProtectionProfile;

#[derive(Default)]
pub(crate) struct DtlsHandlerContext {
    pub(crate) dtls_transport: RTCDtlsTransport,

    //TODO: local_addr: SocketAddr,
    //todo:server_states: Rc<RefCell<ServerStates>>,
    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessage>,
}

impl DtlsHandlerContext {
    pub(crate) fn new(dtls_transport: RTCDtlsTransport) -> Self {
        Self {
            dtls_transport,
            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
        }
    }
}

/// DtlsHandler implements DTLS Protocol handling
pub(crate) struct DtlsHandler<'a> {
    ctx: &'a mut DtlsHandlerContext,
}

impl<'a> DtlsHandler<'a> {
    pub fn new(ctx: &'a mut DtlsHandlerContext) -> Self {
        DtlsHandler { ctx }
    }
}

impl<'a> sansio::Protocol<TaggedRTCMessage, TaggedRTCMessage, ()> for DtlsHandler<'a> {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedRTCMessage;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Dtls(DTLSMessage::Raw(_dtls_message)) = msg.message {
            debug!("recv dtls RAW {:?}", msg.transport.peer_addr);
            todo!()
            /*TODO:
            let four_tuple = (&msg.transport).into();

            let try_read = || -> Result<Vec<BytesMut>> {
                let mut server_states = self.server_states.borrow_mut();
                let transport = match server_states.get_mut_transport(&four_tuple) {
                    Ok(transport) => transport,
                    Err(err) => {
                        error!("get_mut_transport got error {}, it may be due to DTLS packet received earlier than STUN Binding Request", err);
                        return Err(err);
                    }
                };
                let mut messages = vec![];
                let mut contexts = vec![];

                {
                    let dtls_endpoint = transport.get_mut_dtls_endpoint();

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
                                        DtlsHandler::update_srtp_contexts(state)?;
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
                        self.ctx.write_outs.push_back(TaggedRTCMessage {
                            now: transmit.now,
                            transport: TransportContext {
                                local_addr: self.local_addr,
                                peer_addr: transmit.transport.peer_addr,
                                transport_protocol: TransportProtocol::UDP,
                                ecn: transmit.transport.ecn,
                            },
                            message: RTCMessage::Dtls(DTLSMessage::Raw(transmit.message)),
                        });
                    }
                }

                for (local_context, remote_context) in contexts {
                    transport.set_local_srtp_context(local_context);
                    transport.set_remote_srtp_context(remote_context);
                }

                Ok(messages)
            };

            match try_read() {
                Ok(messages) => {
                    for message in messages {
                        debug!("recv dtls application RAW {:?}", msg.transport.peer_addr);
                        self.ctx.read_outs.push_back(TaggedRTCMessage {
                            now: msg.now,
                            transport: msg.transport,
                            message: RTCMessage::Dtls(DTLSMessage::Raw(message)),
                        });
                    }
                }
                Err(err) => {
                    error!("try_read with error {}", err);
                    if err == Error::ErrAlertFatalOrClose {
                        let mut server_states = self.server_states.borrow_mut();
                        server_states.remove_transport(four_tuple);
                    }
                    return Err(err);
                }
            };*/
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

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<()> {
        if let RTCMessage::Dtls(DTLSMessage::Raw(_dtls_message)) = msg.message {
            debug!("send dtls RAW {:?}", msg.transport.peer_addr);
            todo!()
            /*
            let four_tuple = (&msg.transport).into();

            let mut try_write = || -> Result<()> {
                let mut server_states = self.server_states.borrow_mut();
                let transport = server_states.get_mut_transport(&four_tuple)?;
                let dtls_endpoint = transport.get_mut_dtls_endpoint();

                dtls_endpoint.write(msg.transport.peer_addr, &dtls_message)?;
                while let Some(transmit) = dtls_endpoint.poll_transmit() {
                    self.ctx.write_outs.push_back(TaggedRTCMessage {
                        now: transmit.now,
                        transport: TransportContext {
                            local_addr: self.local_addr,
                            peer_addr: transmit.transport.peer_addr,
                            transport_protocol: TransportProtocol::UDP,
                            ecn: transmit.transport.ecn,
                        },
                        message: RTCMessage::Dtls(DTLSMessage::Raw(transmit.message)),
                    });
                }

                Ok(())
            };

            match try_write() {
                Ok(_) => {}
                Err(err) => {
                    error!("try_write with error {}", err);
                    return Err(err);
                }
            }
             */
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

    fn handle_event(&mut self, _evt: ()) -> Result<()> {
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        None
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<()> {
        let /*mut*/ _try_timeout = || -> Result<()> {
            /*TODO:
            let mut server_states = self.server_states.borrow_mut();
            for session in server_states.get_mut_sessions().values_mut() {
                for endpoint in session.get_mut_endpoints().values_mut() {
                    for transport in endpoint.get_mut_transports().values_mut() {
                        let dtls_endpoint = transport.get_mut_dtls_endpoint();
                        let remotes: Vec<SocketAddr> =
                            dtls_endpoint.get_connections_keys().copied().collect();
                        for remote in remotes {
                            let _ = dtls_endpoint.handle_timeout(remote, now);
                        }
                        while let Some(transmit) = dtls_endpoint.poll_transmit() {
                            self.ctx.write_outs.push_back(TaggedRTCMessage {
                                now: transmit.now,
                                transport: TransportContext {
                                    local_addr: self.local_addr,
                                    peer_addr: transmit.transport.peer_addr,
                                    transport_protocol: TransportProtocol::UDP,
                                    ecn: transmit.transport.ecn,
                                },
                                message: RTCMessage::Dtls(DTLSMessage::Raw(transmit.message)),
                            });
                        }
                    }
                }
            }*/

            Ok(())
        };
        /*TODO:
        match try_timeout() {
            Ok(_) => {}
            Err(err) => {
                error!("try_timeout with error {}", err);
                return Err(err);
            }
        }*/

        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        /*TODO:
        {
            let server_states = self.server_states.borrow();
            for session in server_states.get_sessions().values() {
                for endpoint in session.get_endpoints().values() {
                    for transport in endpoint.get_transports().values() {
                        let dtls_endpoint = transport.get_dtls_endpoint();
                        let remotes = dtls_endpoint.get_connections_keys();
                        for remote in remotes {
                            let _ = dtls_endpoint.poll_timeout(*remote, eto);
                        }
                    }
                }
            }
        }*/
        None
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

impl<'a> DtlsHandler<'a> {
    const DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW: usize = 64;
    const DEFAULT_SESSION_SRTCP_REPLAY_PROTECTION_WINDOW: usize = 64;
    pub(crate) fn update_srtp_contexts(
        state: &State,
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
        /*if self.setting_engine.replay_protection.srtp != 0 {
            srtp_config.remote_rtp_options = Some(srtp::option::srtp_replay_protection(
                self.setting_engine.replay_protection.srtp,
            ));
        } else if self.setting_engine.disable_srtp_replay_protection {
            srtp_config.remote_rtp_options = Some(srtp::option::srtp_no_replay_protection());
        }*/

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

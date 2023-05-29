use crate::{config::*, context::*, option::*};
use shared::{error::Result, util::is_rtcp};

use retty::channel::{Handler, InboundContext, InboundHandler, OutboundContext, OutboundHandler};
use retty::transport::TaggedBytesMut;

const DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW: usize = 64;
const DEFAULT_SESSION_SRTCP_REPLAY_PROTECTION_WINDOW: usize = 64;

struct SrtpInboundHandler {
    remote_context: Context,
}
struct SrtpOutboundHandler {
    local_context: Context,
}
struct SrtpHandler {
    inbound: SrtpInboundHandler,
    outbound: SrtpOutboundHandler,
}

impl SrtpHandler {
    fn new(config: Config) -> Result<Self> {
        let local_context = Context::new(
            &config.keys.local_master_key,
            &config.keys.local_master_salt,
            config.profile,
            config.local_rtp_options,
            config.local_rtcp_options,
        )?;

        let remote_context = Context::new(
            &config.keys.remote_master_key,
            &config.keys.remote_master_salt,
            config.profile,
            if config.remote_rtp_options.is_none() {
                Some(srtp_replay_protection(
                    DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW,
                ))
            } else {
                config.remote_rtp_options
            },
            if config.remote_rtcp_options.is_none() {
                Some(srtcp_replay_protection(
                    DEFAULT_SESSION_SRTCP_REPLAY_PROTECTION_WINDOW,
                ))
            } else {
                config.remote_rtcp_options
            },
        )?;

        Ok(SrtpHandler {
            inbound: SrtpInboundHandler { remote_context },
            outbound: SrtpOutboundHandler { local_context },
        })
    }
}

impl InboundHandler for SrtpInboundHandler {
    type Rin = TaggedBytesMut;
    type Rout = Self::Rin;

    fn read(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>, mut msg: Self::Rin) {
        let result = if is_rtcp(&msg.message) {
            self.remote_context.decrypt_rtcp(&msg.message)
        } else {
            self.remote_context.decrypt_rtp(&msg.message)
        };

        match result {
            Ok(decrypted) => {
                msg.message = decrypted;
                ctx.fire_read(msg);
            }
            Err(err) => ctx.fire_read_exception(Box::new(err)),
        };
    }
}

impl OutboundHandler for SrtpOutboundHandler {
    type Win = TaggedBytesMut;
    type Wout = Self::Win;

    fn write(&mut self, ctx: &OutboundContext<Self::Win, Self::Wout>, mut msg: Self::Win) {
        let result = if is_rtcp(&msg.message) {
            self.local_context.encrypt_rtcp(&msg.message)
        } else {
            self.local_context.encrypt_rtp(&msg.message)
        };

        match result {
            Ok(encrypted) => {
                msg.message = encrypted;
                ctx.fire_write(msg);
            }
            Err(err) => ctx.fire_write_exception(Box::new(err)),
        };
    }
}

impl Handler for SrtpHandler {
    type Rin = TaggedBytesMut;
    type Rout = Self::Rin;
    type Win = TaggedBytesMut;
    type Wout = Self::Win;

    fn name(&self) -> &str {
        "SrtpHandler"
    }

    fn split(
        self,
    ) -> (
        Box<dyn InboundHandler<Rin = Self::Rin, Rout = Self::Rout>>,
        Box<dyn OutboundHandler<Win = Self::Win, Wout = Self::Wout>>,
    ) {
        (Box::new(self.inbound), Box::new(self.outbound))
    }
}

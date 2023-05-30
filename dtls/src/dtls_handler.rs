use retty::channel::{Handler, InboundContext, InboundHandler, OutboundContext, OutboundHandler};
use retty::transport::TaggedBytesMut;

struct DtlsInboundHandler {}
struct DtlsOutboundHandler {}
struct DtlsHandler {
    inbound: DtlsInboundHandler,
    outbound: DtlsOutboundHandler,
}

impl DtlsHandler {
    fn new() -> Self {
        DtlsHandler {
            inbound: DtlsInboundHandler {},
            outbound: DtlsOutboundHandler {},
        }
    }
}

impl InboundHandler for DtlsInboundHandler {
    type Rin = TaggedBytesMut;
    type Rout = Self::Rin;

    fn read(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>, msg: Self::Rin) {
        ctx.fire_read(msg);
    }
}

impl OutboundHandler for DtlsOutboundHandler {
    type Win = TaggedBytesMut;
    type Wout = Self::Win;

    fn write(&mut self, ctx: &OutboundContext<Self::Win, Self::Wout>, msg: Self::Win) {
        ctx.fire_write(msg);
    }
}

impl Handler for DtlsHandler {
    type Rin = TaggedBytesMut;
    type Rout = Self::Rin;
    type Win = TaggedBytesMut;
    type Wout = Self::Win;

    fn name(&self) -> &str {
        "DtlsHandler"
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

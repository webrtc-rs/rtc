use crate::config::ConfigBuilder;
use crate::crypto::*;
use crate::dtls_handlers::dtls_connection_handler::DtlsConnectionHandler;
use crate::extension::extension_use_srtp::SrtpProtectionProfile;

use bytes::BytesMut;
use core_affinity::CoreId;
use local_sync::mpsc::{
    unbounded::channel, unbounded::Rx as LocalReceiver, unbounded::Tx as LocalSender,
};
//use log::*;
use shared::error::Result;
use std::cell::RefCell;
//use std::io::Write;
use std::net::SocketAddr;
use std::rc::Rc;
use std::str::FromStr;
use std::time::Instant;

use retty::{
    bootstrap::{BootstrapUdpClient, BootstrapUdpServer},
    channel::{
        Handler, InboundContext, InboundHandler, OutboundContext, OutboundHandler, Pipeline,
    },
    executor::{spawn_local, yield_local, LocalExecutorBuilder},
    transport::{AsyncTransport, AsyncTransportWrite, TaggedBytesMut, TransportContext},
};

struct EchoDecoder {
    is_server: bool,
    tx: Rc<RefCell<Option<LocalSender<TaggedBytesMut>>>>,
}
struct EchoEncoder;
struct EchoHandler {
    decoder: EchoDecoder,
    encoder: EchoEncoder,
}

impl EchoHandler {
    fn new(is_server: bool, tx: Rc<RefCell<Option<LocalSender<TaggedBytesMut>>>>) -> Self {
        EchoHandler {
            decoder: EchoDecoder { is_server, tx },
            encoder: EchoEncoder,
        }
    }
}

impl InboundHandler for EchoDecoder {
    type Rin = TaggedBytesMut;
    type Rout = Self::Rin;

    fn read(&mut self, ctx: &InboundContext<Self::Rin, Self::Rout>, msg: Self::Rin) {
        if self.is_server {
            ctx.fire_write(msg);
        } else {
            let tx = self.tx.borrow_mut();
            if let Some(tx) = &*tx {
                let _ = tx.send(msg);
            }
        }
    }

    fn read_exception(
        &mut self,
        _ctx: &InboundContext<Self::Rin, Self::Rout>,
        _err: Box<dyn std::error::Error>,
    ) {
    }

    fn handle_timeout(&mut self, _ctx: &InboundContext<Self::Rin, Self::Rout>, _now: Instant) {}
}

impl OutboundHandler for EchoEncoder {
    type Win = TaggedBytesMut;
    type Wout = Self::Win;

    fn write(&mut self, ctx: &OutboundContext<Self::Win, Self::Wout>, msg: Self::Win) {
        ctx.fire_write(msg);
    }
}

impl Handler for EchoHandler {
    type Rin = TaggedBytesMut;
    type Rout = Self::Rin;
    type Win = TaggedBytesMut;
    type Wout = Self::Win;

    fn name(&self) -> &str {
        "EchoHandler"
    }

    fn split(
        self,
    ) -> (
        Box<dyn InboundHandler<Rin = Self::Rin, Rout = Self::Rout>>,
        Box<dyn OutboundHandler<Win = Self::Win, Wout = Self::Wout>>,
    ) {
        (Box::new(self.decoder), Box::new(self.encoder))
    }
}

fn create_test_client(
    mut builder: ConfigBuilder,
    generate_certificate: bool,
    client_transport: TransportContext,
) -> Result<(
    BootstrapUdpClient<TaggedBytesMut>,
    LocalReceiver<TaggedBytesMut>,
)> {
    if generate_certificate {
        let client_cert = Certificate::generate_self_signed(vec!["localhost".to_owned()])?;
        builder = builder.with_certificates(vec![client_cert]);
    }

    builder = builder.with_insecure_skip_verify(true);

    let handshake_config = builder.build(true, Some(client_transport.peer_addr))?;

    let (client_tx, client_rx) = channel();
    let client_tx = Rc::new(RefCell::new(Some(client_tx)));

    let mut client = BootstrapUdpClient::new();
    client.pipeline(Box::new(
        move |writer: AsyncTransportWrite<TaggedBytesMut>| {
            let pipeline: Pipeline<TaggedBytesMut, TaggedBytesMut> = Pipeline::new();

            let async_transport_handler = AsyncTransport::new(writer);
            let dtls_handler = DtlsConnectionHandler::new(
                handshake_config.clone(),
                true,
                Some(client_transport),
                None,
            );
            let echo_handler = EchoHandler::new(false, Rc::clone(&client_tx));
            pipeline.add_back(async_transport_handler);
            pipeline.add_back(dtls_handler);
            pipeline.add_back(echo_handler);
            pipeline.finalize()
        },
    ));

    Ok((client, client_rx))
}

fn create_test_server(
    mut builder: ConfigBuilder,
    generate_certificate: bool,
) -> Result<BootstrapUdpServer<TaggedBytesMut>> {
    if generate_certificate {
        let server_cert = Certificate::generate_self_signed(vec!["localhost".to_owned()])?;
        builder = builder.with_certificates(vec![server_cert]);
    }

    let handshake_config = builder.build(false, None)?;

    let server_tx = Rc::new(RefCell::new(None));

    let mut server = BootstrapUdpServer::new();
    server.pipeline(Box::new(
        move |writer: AsyncTransportWrite<TaggedBytesMut>| {
            let pipeline: Pipeline<TaggedBytesMut, TaggedBytesMut> = Pipeline::new();

            let async_transport_handler = AsyncTransport::new(writer);
            let dtls_handler =
                DtlsConnectionHandler::new(handshake_config.clone(), false, None, None);
            let echo_handler = EchoHandler::new(true, Rc::clone(&server_tx));

            pipeline.add_back(async_transport_handler);
            pipeline.add_back(dtls_handler);
            pipeline.add_back(echo_handler);
            pipeline.finalize()
        },
    ));

    Ok(server)
}

#[test]
fn test_dtls_handler() {
    /*env_logger::Builder::new()
    .format(|buf, record| {
        writeln!(
            buf,
            "{}:{} [{}] {} - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            record.level(),
            chrono::Local::now().format("%H:%M:%S.%6f"),
            record.args()
        )
    })
    .filter(None, LevelFilter::Debug)
    .try_init()
    .unwrap();*/

    let handler = LocalExecutorBuilder::new()
        .name("test_dtls_handler_thread")
        .core_id(CoreId { id: 0 })
        .spawn(|| async move {
            let (done_tx, mut done_rx) = channel();

            let mut server = create_test_server(
                ConfigBuilder::default().with_srtp_protection_profiles(vec![
                    SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
                ]),
                true,
            )
            .unwrap();

            let server_addr = server.bind("127.0.0.1:0").await.unwrap();

            let client_transport = TransportContext {
                local_addr: SocketAddr::from_str("0.0.0.0:0").unwrap(),
                peer_addr: server_addr,
                ecn: None,
            };

            spawn_local(async move {
                let (mut client, mut client_rx) = create_test_client(
                    ConfigBuilder::default().with_srtp_protection_profiles(vec![
                        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
                    ]),
                    true,
                    client_transport,
                )
                .unwrap();

                client.bind(client_transport.local_addr).await.unwrap();

                let client_pipeline = client.connect(server_addr).await.unwrap();
                yield_local();

                let buf = vec![0xFA; 100];

                client_pipeline.write(TaggedBytesMut {
                    now: Instant::now(),
                    transport: client_transport,
                    message: BytesMut::from(&buf[..]),
                });
                yield_local();

                if let Some(echo) = client_rx.recv().await {
                    assert_eq!(&buf, &echo.message);
                } else {
                    assert!(false);
                }

                client.graceful_stop().await;

                assert!(done_tx.send(()).is_ok());
            })
            .detach();

            assert!(done_rx.recv().await.is_some());

            server.graceful_stop().await;
        })
        .unwrap();

    handler.join().unwrap();
}

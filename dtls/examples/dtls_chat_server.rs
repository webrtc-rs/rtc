use bytes::BytesMut;
use clap::Parser;
use std::{
    cell::RefCell, collections::HashMap, io::Write, net::SocketAddr, rc::Rc, rc::Weak,
    str::FromStr, time::Instant,
};

use dtls::cipher_suite::CipherSuiteId;
use dtls::config::{ConfigBuilder, ExtendedMasterSecretType};
use dtls::dtls_handler::DtlsHandler;
use shared::error::*;

use retty::bootstrap::BootstrapUdpServer;
use retty::channel::{
    Handler, InboundContext, InboundHandler, OutboundContext, OutboundHandler, OutboundPipeline,
    Pipeline,
};
use retty::codec::string_codec::TaggedString;
use retty::executor::LocalExecutorBuilder;
use retty::transport::{AsyncTransport, AsyncTransportWrite, TaggedBytesMut, TransportContext};

////////////////////////////////////////////////////////////////////////////////////////////////////
struct Shared {
    peers: HashMap<SocketAddr, Weak<dyn OutboundPipeline<TaggedString>>>,
}

impl Shared {
    /// Create a new, empty, instance of `Shared`.
    fn new() -> Self {
        Shared {
            peers: HashMap::new(),
        }
    }

    fn contains(&self, peer: &SocketAddr) -> bool {
        self.peers.contains_key(peer)
    }

    fn join(&mut self, peer: SocketAddr, pipeline: Weak<dyn OutboundPipeline<TaggedString>>) {
        println!("{} joined", peer);
        self.peers.insert(peer, pipeline);
    }

    fn leave(&mut self, peer: &SocketAddr) {
        println!("{} left", peer);
        self.peers.remove(peer);
    }

    /// Send message to every peer, except for the sender.
    fn broadcast(&self, sender: SocketAddr, msg: TaggedString) {
        print!("broadcast message: {}", msg.message);
        for (peer, pipeline) in self.peers.iter() {
            if *peer != sender {
                let mut msg = msg.clone();
                msg.transport.peer_addr = *peer;
                if let Some(pipeline) = pipeline.upgrade() {
                    let _ = pipeline.write(msg);
                }
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
struct ChatDecoder {
    state: Rc<RefCell<Shared>>,
    pipeline: Weak<dyn OutboundPipeline<TaggedString>>,
}
struct ChatEncoder;
struct ChatHandler {
    decoder: ChatDecoder,
    encoder: ChatEncoder,
}

impl ChatHandler {
    fn new(state: Rc<RefCell<Shared>>, pipeline: Weak<dyn OutboundPipeline<TaggedString>>) -> Self {
        ChatHandler {
            decoder: ChatDecoder { state, pipeline },
            encoder: ChatEncoder,
        }
    }
}

impl InboundHandler for ChatDecoder {
    type Rin = TaggedBytesMut;
    type Rout = TaggedString;

    fn read(&mut self, _ctx: &InboundContext<Self::Rin, Self::Rout>, msg: Self::Rin) {
        let peer_addr = msg.transport.peer_addr;
        let message = String::from_utf8(msg.message.to_vec()).unwrap();
        println!(
            "received: {} from {:?} to {}",
            message, peer_addr, msg.transport.local_addr
        );

        let mut s = self.state.borrow_mut();
        if message == "bye" {
            s.leave(&peer_addr);
        } else {
            if !s.contains(&peer_addr) {
                s.join(peer_addr, self.pipeline.clone());
            }
            s.broadcast(
                peer_addr,
                TaggedString {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: msg.transport.local_addr,
                        ecn: msg.transport.ecn,
                        ..Default::default()
                    },
                    message,
                },
            );
        }
    }
    fn poll_timeout(&mut self, _ctx: &InboundContext<Self::Rin, Self::Rout>, _eto: &mut Instant) {
        //last handler, no need to fire_poll_timeout
    }
}

impl OutboundHandler for ChatEncoder {
    type Win = TaggedString;
    type Wout = TaggedBytesMut;

    fn write(&mut self, ctx: &OutboundContext<Self::Win, Self::Wout>, msg: Self::Win) {
        ctx.fire_write(TaggedBytesMut {
            now: msg.now,
            transport: msg.transport,
            message: BytesMut::from(msg.message.as_bytes()),
        });
    }
}

impl Handler for ChatHandler {
    type Rin = TaggedBytesMut;
    type Rout = TaggedString;
    type Win = TaggedString;
    type Wout = TaggedBytesMut;

    fn name(&self) -> &str {
        "ChatHandler"
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

#[derive(Parser)]
#[command(name = "DTLS Chat Server")]
#[command(author = "Rusty Rain <y@liu.mx>")]
#[command(version = "0.1.0")]
#[command(about = "An example of dtls chat server", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
    #[arg(long, default_value_t = format!("127.0.0.1"))]
    host: String,
    #[arg(long, default_value_t = 4444)]
    port: u16,
    #[arg(long, default_value_t = format!("INFO"))]
    log_level: String,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let host = cli.host;
    let port = cli.port;
    let log_level = log::LevelFilter::from_str(&cli.log_level)?;
    if cli.debug {
        env_logger::Builder::new()
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
            .filter(None, log_level)
            .init();
    }

    println!("listening {}:{}...", host, port);

    LocalExecutorBuilder::default().run(async move {
        // Create the shared state. This is how all the peers communicate.
        // The server task will hold a handle to this. For every new client, the
        // `state` handle is cloned and passed into the handler that processes the
        // client connection.
        let state = Rc::new(RefCell::new(Shared::new()));

        let handshake_config = ConfigBuilder::default()
            .with_psk(Some(Rc::new(|hint: &[u8]| -> Result<Vec<u8>> {
                println!("Client's hint: {}", String::from_utf8(hint.to_vec())?);
                Ok(vec![0xAB, 0xC1, 0x23])
            })))
            .with_psk_identity_hint(Some("webrtc-rs DTLS Client".as_bytes().to_vec()))
            .with_cipher_suites(vec![CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8])
            .with_extended_master_secret(ExtendedMasterSecretType::Require)
            .build(false, None)
            .unwrap();

        let mut bootstrap = BootstrapUdpServer::new();
        bootstrap.pipeline(Box::new(
            move |writer: AsyncTransportWrite<TaggedBytesMut>| {
                let pipeline: Rc<Pipeline<TaggedBytesMut, TaggedString>> = Rc::new(Pipeline::new());

                let local_addr = writer.get_local_addr();

                let async_transport_handler = AsyncTransport::new(writer);
                let dtls_handler =
                    DtlsHandler::new(local_addr, handshake_config.clone(), false, None, None);
                let pipeline_wr = Rc::downgrade(&pipeline);
                let chat_handler = ChatHandler::new(state.clone(), pipeline_wr);

                pipeline.add_back(async_transport_handler);
                pipeline.add_back(dtls_handler);
                pipeline.add_back(chat_handler);
                pipeline.update()
            },
        ));

        bootstrap.bind(format!("{}:{}", host, port)).await.unwrap();

        println!("Press ctrl-c to stop");
        let (tx, rx) = futures::channel::oneshot::channel();
        std::thread::spawn(move || {
            let mut tx = Some(tx);
            ctrlc::set_handler(move || {
                if let Some(tx) = tx.take() {
                    let _ = tx.send(());
                }
            })
            .expect("Error setting Ctrl-C handler");
        });
        let _ = rx.await;

        bootstrap.graceful_stop().await;
    });

    Ok(())
}

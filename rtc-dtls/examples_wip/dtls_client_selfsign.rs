use bytes::BytesMut;
use clap::Parser;
use futures::StreamExt;
use std::{io::Write, net::SocketAddr, str::FromStr, time::Instant};

use dtls::config::{ConfigBuilder, ExtendedMasterSecretType};
use dtls::crypto::Certificate;
use dtls::dtls_handlers::dtls_endpoint_handler::DtlsEndpointHandler;

use retty::bootstrap::BootstrapUdpClient;
use retty::channel::{
    Handler, InboundContext, InboundHandler, OutboundContext, OutboundHandler, Pipeline,
};
use retty::codec::string_codec::TaggedString;
use retty::executor::{yield_local, LocalExecutorBuilder};
use retty::transport::{AsyncTransport, AsyncTransportWrite, TaggedBytesMut, TransportContext};

////////////////////////////////////////////////////////////////////////////////////////////////////

struct EchoDecoder;
struct EchoEncoder;
struct EchoHandler {
    decoder: EchoDecoder,
    encoder: EchoEncoder,
}

impl EchoHandler {
    fn new() -> Self {
        EchoHandler {
            decoder: EchoDecoder,
            encoder: EchoEncoder,
        }
    }
}

impl InboundHandler for EchoDecoder {
    type Rin = TaggedBytesMut;
    type Rout = TaggedString;

    fn read(&mut self, _ctx: &InboundContext<Self::Rin, Self::Rout>, msg: Self::Rin) {
        let message = String::from_utf8(msg.message.to_vec()).unwrap();
        println!(
            "received back: {} from {:?}",
            message, msg.transport.peer_addr
        );
    }
    fn poll_timeout(&mut self, _ctx: &InboundContext<Self::Rin, Self::Rout>, _eto: &mut Instant) {
        //last handler, no need to fire_poll_timeout
    }
}

impl OutboundHandler for EchoEncoder {
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

impl Handler for EchoHandler {
    type Rin = TaggedBytesMut;
    type Rout = TaggedString;
    type Win = TaggedString;
    type Wout = TaggedBytesMut;

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

#[derive(Parser)]
#[command(name = "DTLS Echo Client")]
#[command(author = "Rusty Rain <y@liu.mx>")]
#[command(version = "0.1.0")]
#[command(about = "An example of dtls client", long_about = None)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
    #[arg(long, default_value_t = format!("127.0.0.1"))]
    host: String,
    #[arg(long, default_value_t = 3489)]
    port: u16,
    #[arg(long, default_value_t = format!("DEBUG"))]
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

    println!("Connecting {}:{}...", host, port);

    let transport = TransportContext {
        local_addr: SocketAddr::from_str("0.0.0.0:0")?,
        peer_addr: SocketAddr::from_str(&format!("{}:{}", host, port))?,
        ecn: None,
    };

    LocalExecutorBuilder::default().run(async move {
        let certificate = Certificate::generate_self_signed(vec!["localhost".to_owned()]).unwrap();

        let handshake_config = ConfigBuilder::default()
            .with_certificates(vec![certificate])
            .with_insecure_skip_verify(true)
            .with_extended_master_secret(ExtendedMasterSecretType::Require)
            .build(true, Some(transport.peer_addr))
            .unwrap();

        let mut bootstrap = BootstrapUdpClient::new();
        bootstrap.pipeline(Box::new(
            move |writer: AsyncTransportWrite<TaggedBytesMut>| {
                let pipeline: Pipeline<TaggedBytesMut, TaggedString> = Pipeline::new();

                let local_addr = writer.get_local_addr();
                let peer_addr = writer.get_peer_addr();

                let async_transport_handler = AsyncTransport::new(writer);
                let dtls_handler = DtlsEndpointHandler::new(
                    local_addr,
                    handshake_config.clone(),
                    true,
                    peer_addr,
                    None,
                );
                let echo_handler = EchoHandler::new();

                pipeline.add_back(async_transport_handler);
                pipeline.add_back(dtls_handler);
                pipeline.add_back(echo_handler);
                pipeline.finalize()
            },
        ));

        bootstrap.bind(transport.local_addr).await.unwrap();

        let pipeline = bootstrap.connect(transport.peer_addr).await.unwrap();
        yield_local();

        println!("Enter bye to stop");
        let (mut tx, mut rx) = futures::channel::mpsc::channel(8);
        std::thread::spawn(move || {
            let mut buffer = String::new();
            while std::io::stdin().read_line(&mut buffer).is_ok() {
                match buffer.trim_end() {
                    "" => break,
                    line => {
                        if tx.try_send(line.to_string()).is_err() {
                            break;
                        }
                        if line == "bye" {
                            break;
                        }
                    }
                };
                buffer.clear();
            }
        });
        while let Some(line) = rx.next().await {
            pipeline.write(TaggedString {
                now: Instant::now(),
                transport,
                message: format!("{}\r\n", line),
            });
            if line == "bye" {
                pipeline.close();
                break;
            }
        }

        bootstrap.graceful_stop().await;
    });

    Ok(())
}

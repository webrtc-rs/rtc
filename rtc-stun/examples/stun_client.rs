use rtc_stun::client::*;
use rtc_stun::message::*;
use rtc_stun::xoraddr::*;

use clap::Parser;
use shared::TransportProtocol;
use shared::error::Error;
use std::net::UdpSocket;

#[derive(Parser)]
#[command(name = "STUN Client")]
#[command(author = "Rusty Rain <y@ngr.tc>")]
#[command(version = "0.1.0")]
#[command(about = "An example of STUN Client", long_about = None)]
struct Cli {
    #[arg(long, default_value_t = format!("stun.l.google.com:19302"))]
    server: String,
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    let server = cli.server;

    let conn = UdpSocket::bind("0:0")?;
    println!("Local address: {}", conn.local_addr()?);

    println!("Connecting to: {server}");
    conn.connect(server)?;

    let mut client = ClientBuilder::new().build(
        conn.local_addr()?,
        conn.peer_addr()?,
        TransportProtocol::UDP,
    )?;

    let mut msg = Message::new();
    msg.build(&[Box::<TransactionId>::default(), Box::new(BINDING_REQUEST)])?;
    client.handle_write(msg)?;
    while let Some(transmit) = client.poll_transmit() {
        conn.send(&transmit.message)?;
    }

    let mut buf = vec![0u8; 1500];
    let n = conn.recv(&mut buf)?;
    client.handle_read(&buf[..n])?;

    if let Some(event) = client.poll_event() {
        let msg = event.result?;
        let mut xor_addr = XorMappedAddress::default();
        xor_addr.get_from(&msg)?;
        println!("Got response: {xor_addr}");
    }

    client.handle_close()?;

    Ok(())
}

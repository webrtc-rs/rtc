use stun::client::*;
use stun::message::*;
use stun::xoraddr::*;

use clap::{App, Arg};
use shared::error::Error;
use std::net::UdpSocket;

fn main() -> Result<(), Error> {
    let mut app = App::new("STUN Client")
        .version("0.1.0")
        .author("Rain Liu <yliu@webrtc.rs>")
        .about("An example of STUN Client")
        .arg(
            Arg::with_name("FULLHELP")
                .help("Prints more detailed help information")
                .long("fullhelp"),
        )
        .arg(
            Arg::with_name("server")
                .required_unless("FULLHELP")
                .takes_value(true)
                .default_value("stun.l.google.com:19302")
                .long("server")
                .help("STUN Server"),
        );

    let matches = app.clone().get_matches();

    if matches.is_present("FULLHELP") {
        app.print_long_help().unwrap();
        std::process::exit(0);
    }

    let server = matches.value_of("server").unwrap();

    let conn = UdpSocket::bind("0:0")?;
    println!("Local address: {}", conn.local_addr()?);

    println!("Connecting to: {server}");
    conn.connect(server)?;

    let mut client = ClientBuilder::new().build(conn.peer_addr()?)?;

    let mut msg = Message::new();
    msg.build(&[Box::<TransactionId>::default(), Box::new(BINDING_REQUEST)])?;
    client.handle_write(msg)?;
    while let Some(transmit) = client.poll_transmit() {
        conn.send(&transmit.payload)?;
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

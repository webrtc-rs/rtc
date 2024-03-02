use base64::prelude::*;
use clap::Parser;

use stun::message::Message;

#[derive(Parser)]
#[command(name = "STUN decode")]
#[command(author = "Rusty Rain <y@ngr.tc>")]
#[command(version = "0.1.0")]
#[command(about = "An example of STUN decode", long_about = None)]
struct Cli {
    /// base64 encoded message, e.g. 'AAEAHCESpEJML0JTQWsyVXkwcmGALwAWaHR0cDovL2xvY2FsaG9zdDozMDAwLwAA'"
    #[arg(long)]
    data: String,
}

fn main() {
    let cli = Cli::parse();

    let encoded_data = cli.data;
    let decoded_data = match BASE64_STANDARD.decode(encoded_data) {
        Ok(d) => d,
        Err(e) => panic!("Unable to decode base64 value: {e}"),
    };

    let mut message = Message::new();
    message.raw = decoded_data;

    match message.decode() {
        Ok(_) => println!("{message}"),
        Err(e) => panic!("Unable to decode message: {e}"),
    }
}

# rtcp-processing

rtcp-processing demonstrates the Public API for processing RTCP packets in sansio RTC.

## What is RTCP?

RTCP (RTP Control Protocol) is a companion protocol to RTP (Real-time Transport Protocol). While RTP carries the actual
media data, RTCP provides out-of-band statistics and control information for an RTP session:

- **Sender Reports (SR)**: Statistics from media senders (packets sent, bytes sent, timestamps)
- **Receiver Reports (RR)**: Reception quality feedback (packet loss, jitter, round-trip time)
- **Source Description (SDES)**: Identifies the source (CNAME, email, phone, etc.)
- **Goodbye (BYE)**: Indicates a source is leaving the session
- **Application-specific (APP)**: Custom application data
- **Feedback messages**: PLI, FIR, NACK, REMB, etc. for congestion control and quality

## How It Works

1. Paste a base64-encoded SDP offer from a browser
2. The example creates an answer and outputs it as base64
3. Paste the answer in the browser to establish the connection
4. As media flows, RTCP packets are received and printed in human-readable format

## Custom RTCP Forwarder Interceptor

**Important:** By default, RTCP packets are consumed by the interceptor chain (for generating statistics, NACK responses, congestion control, etc.) and are **not forwarded** to the application via `poll_read()`.

This example demonstrates how to create a custom `RtcpForwarderInterceptor` that captures RTCP packets and forwards them to the application:

```rust
pub struct RtcpForwarderInterceptor<P> {
    inner: P,
    read_queue: VecDeque<TaggedPacket>,
}

impl<P: Interceptor> Protocol<TaggedPacket, TaggedPacket, ()>
    for RtcpForwarderInterceptor<P>
{
    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // If this is an RTCP packet, queue a copy for the application
        if let Packet::Rtcp(rtcp_packets) = &msg.message {
            self.read_queue.push_back(TaggedPacket {
                now: msg.now,
                transport: msg.transport,
                message: Packet::Rtcp(rtcp_packets.clone()),
            });
        }
        // Always pass to inner interceptor for normal processing
        self.inner.handle_read(msg)
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        // First return any queued RTCP packets
        if let Some(pkt) = self.read_queue.pop_front() {
            return Some(pkt);
        }
        // Then check inner interceptor
        self.inner.poll_read()
    }
    // ... other Protocol methods delegate to inner
}
```

### Registering the Interceptor

The RTCP forwarder must be registered as the **outermost layer** in the interceptor chain to capture RTCP packets before they are consumed by other interceptors:

```rust
let registry = Registry::new();

// Register default interceptors (NACK, reports, TWCC, etc.)
let registry = register_default_interceptors(registry, &mut media_engine)?;

// Add RTCP forwarder as the outermost layer
let registry = registry.with(RtcpForwarderBuilder::new().build());

let config = RTCConfigurationBuilder::new()
    .with_interceptor_registry(registry)
    .build();
```

## Instructions

### Open rtcp-processing example page

[jsfiddle.net](https://jsfiddle.net/zurq6j7x/) you should see two text-areas, 'Start Session' button and 'Copy browser
SessionDescription to clipboard'

### Build

```bash
cargo build --example rtcp-processing
```

### Run

```bash
cargo run --example rtcp-processing
```

### With Debug Logging

```bash
cargo run --example rtcp-processing -- --debug
```

### Read SDP from File

```bash
cargo run --example rtcp-processing -- --input-sdp-file offer.txt
```

## Example Output

```
Paste your offer here:
<paste base64 encoded offer>

Offer received: ...
RTCP Processing listening on 127.0.0.1:54321...

Paste this answer in your browser:
eyJ0eXBlIjoiYW5zd2VyIiwic2RwIjoi...

Connection State has changed: checking
Connection State has changed: connected
Connection established\! Waiting for RTCP packets...

Track has started - track_id: video-track, receiver_id: 0
  Stream ID: my-stream, Track ID: video-track, Kind: video, Codec: video/VP8

=== RTCP Packet #1 (Track: video-track) ===
  [1] Type: SenderReport, Length: 12 words
      SenderReport from 1234567890
        NTPTime: 2024-01-15 10:30:45
        RTPTime: 987654321
        PacketCount: 1000
        OctetCount: 150000

=== RTCP Packet #2 (Track: audio-track) ===
  [1] Type: ReceiverReport, Length: 8 words
      ReceiverReport from 987654321
        SSRC: 1234567890
        FractionLost: 0
        TotalLost: 0
        LastSequence: 5000
        Jitter: 10
        LastSR: 12345
        Delay: 100

^C
Ctrl-C received, shutting down...
Total RTCP packets received: 42
Event loop exited
```

## RTCP Packet Types

| Type | Name                      | Description                  |
|------|---------------------------|------------------------------|
| 200  | Sender Report (SR)        | Statistics from media sender |
| 201  | Receiver Report (RR)      | Reception quality feedback   |
| 202  | Source Description (SDES) | Source identification        |
| 203  | Goodbye (BYE)             | Source leaving notification  |
| 204  | Application (APP)         | Custom application data      |
| 205  | Transport Feedback        | TWCC, NACK                   |
| 206  | Payload Feedback          | PLI, FIR, SLI, RPSI          |

## Using with Browser

1. Open a WebRTC demo page that can send video (e.g., the broadcast example's HTML page)
2. Run this example
3. Paste the offer from the browser
4. Paste the answer back into the browser
5. Watch RTCP packets being logged as media flows

## API Usage

With the `RtcpForwarderInterceptor` registered, RTCP packets become available via `poll_read()`:

```rust
while let Some(message) = peer_connection.poll_read() {
    match message {
        RTCMessage::RtcpPacket(track_id, rtcp_packets) => {
            for packet in rtcp_packets {
                // Get header info
                let header = packet.header();
                println!("Type: {:?}", header.packet_type);

                // Display full packet (implements Display trait)
                println!("{}", packet);
            }
        }
        _ => {}
    }
}
```

**Note:** Without the custom `RtcpForwarderInterceptor`, you will **not** receive `RTCMessage::RtcpPacket` messages since RTCP is consumed internally by the interceptor chain.

## Sending RTCP Packets

To send RTCP packets (e.g., PLI for keyframe requests):

```rust
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;

if let Some(mut receiver) = peer_connection.rtp_receiver(receiver_id) {
    receiver.write_rtcp(vec![Box::new(PictureLossIndication {
        sender_ssrc: 0,
        media_ssrc: track_ssrc,
    })])?;
}
```

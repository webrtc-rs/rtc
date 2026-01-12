# ice-tcp
ice-tcp demonstrates sansio RTC's ICE TCP abilities.

## About ICE TCP

ICE TCP is useful when UDP is blocked by firewalls. WebRTC normally uses UDP for media and data transport, but can fall back to TCP when necessary.

This example demonstrates:
- Using TCP-only network types (`Tcp4`, `Tcp6`)
- Creating TCP passive candidates
- TCP framing (RFC 4571) - 2-byte length prefix for each packet
- Managing TCP connections for ICE

## How It Works

1. The server listens for ICE TCP connections on port 8443
2. The server serves HTTP on port 8080
3. When a browser connects, it sends an SDP offer via HTTP POST
4. The server creates a peer connection with TCP-only candidates
5. ICE establishes connectivity over TCP instead of UDP
6. Data channel messages are exchanged over the TCP connection

## TCP Framing (RFC 4571)

Unlike UDP which is message-oriented, TCP is stream-oriented. ICE over TCP uses a 2-byte big-endian length prefix before each message:

```
+--------+--------+------------------------+
| Length (2 bytes) | Payload (n bytes)     |
+--------+--------+------------------------+
```

This example uses the `shared::tcp_framing` utilities:
- `frame_packet()` - adds the 2-byte header to outbound packets
- `TcpFrameDecoder` - stateful decoder that buffers incoming TCP data and extracts complete packets

## Instructions

### Run ice-tcp
From the `rtc` directory, execute:

```
cargo run --example ice-tcp
```

Or with debug logging:

```
cargo run --example ice-tcp -- --debug
```

### Open the Web UI
Open [http://localhost:8080](http://localhost:8080). This will automatically start a PeerConnection.

The page displays:
- ICE connection states
- Inbound DataChannel messages (server sends timestamps every 3 seconds)

## Note

Congrats, you have used sansio RTC with ICE TCP! Now start building something cool.

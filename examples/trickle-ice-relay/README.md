# trickle-ice-relay

trickle-ice-relay demonstrates the sansio RTC's Trickle ICE APIs with TURN relay candidates. ICE is the subsystem WebRTC uses to establish connectivity.

Trickle ICE is the process of sharing addresses as soon as they are gathered. This parallelizes establishing a connection with a remote peer and starting sessions with TURN servers. Using Trickle ICE can dramatically reduce the amount of time it takes to establish a WebRTC connection.

This example shows how to add Relay type local candidates using the sansio TURN client API.

## Prerequisites

You need a TURN server running. You can use either:

### Option 1: webrtc-rs/webrtc turn server

From the webrtc-rs/webrtc repository:

```bash
RUST_LOG=trace cargo run --color=always --package turn --example turn_server_udp -- --public-ip 127.0.0.1 --users user=pass
```

### Option 2: pion/turn server

From the pion/turn repository:

```bash
./simple -public-ip 127.0.0.1 -users user=pass
```

## Instructions

### Run trickle-ice-relay

From the `rtc` directory, execute:

```bash
cargo run --example trickle-ice-relay
```

Or with debug logging:

```bash
cargo run --example trickle-ice-relay -- --debug
```

With custom TURN server settings:

```bash
cargo run --example trickle-ice-relay -- --turn-host 127.0.0.1 --turn-port 3478 --turn-user user=pass --turn-realm webrtc.rs
```

### Open the Web UI

Open [http://localhost:8080](http://localhost:8080). Click the "Start" button to initiate a PeerConnection.

The WebSocket server runs on port 8081 and the HTTP server (for serving the HTML page) runs on port 8080.

## Note

Congrats, you have used sansio RTC with TURN relay candidates! Now start building something cool

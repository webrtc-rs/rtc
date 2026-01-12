# trickle-ice
trickle-ice demonstrates the sansio RTC's Trickle ICE APIs. ICE is the subsystem WebRTC uses to establish connectivity.

Trickle ICE is the process of sharing addresses as soon as they are gathered. This parallelizes
establishing a connection with a remote peer and starting sessions with TURN servers. Using Trickle ICE
can dramatically reduce the amount of time it takes to establish a WebRTC connection.

Trickle ICE isn't mandatory to use, but highly recommended.

## Instructions

### Run trickle-ice
From the `rtc` directory, execute:

```
cargo run --example trickle-ice
```

Or with debug logging:

```
cargo run --example trickle-ice -- --debug
```

### Open the Web UI
Open [http://localhost:8080](http://localhost:8080). Click the "Start" button to initiate a PeerConnection.

The WebSocket server runs on port 8081 and the HTTP server (for serving the HTML page) runs on port 8080.

## Note
Congrats, you have used sansio RTC! Now start building something cool

# ice-restart

ice-restart demonstrates WebRTC ICE restart functionality using the sansio API.

## Overview

This example shows how to handle ICE restart, which is useful when network conditions change and the existing ICE connection needs to be re-established. The Rust application acts as an answerer that communicates with a web browser.

## Architecture (Sansio API)

This example uses a **channel-based architecture** compatible with the sansio API:

- HTTP server runs in separate thread
- HTTP handlers send commands via `mpsc::channel` to the event loop
- Event loop runs in main thread with `RTCPeerConnection`
- All WebRTC operations happen in single-threaded event loop
- Peer connection is created on first signaling request
- Same peer connection is reused for ICE restart

## Instructions

Run the example:

```shell
cargo run --example ice-restart
```

or with debug logging:

```shell
cargo run --example ice-restart -- --debug
```

Then open your browser to:
```
http://localhost:8080
```

The web page will:
1. Automatically create a peer connection
2. Establish an ICE connection with the Rust peer
3. Display ICE connection states and selected candidate pairs
4. Show incoming data channel messages (timestamps sent every 3 seconds)

### Testing ICE Restart

Click the **"ICE Restart"** button on the web page to trigger an ICE restart. The connection will:
- Renegotiate ICE candidates
- Re-establish the connection
- Continue sending data channel messages

## How it works

1. **Browser** creates a WebRTC peer connection with a data channel
2. **Browser** generates an offer and sends it to `/doSignaling`
3. **Rust peer** receives the offer via HTTP
4. **Event loop** creates peer connection (first time) or reuses existing one (ICE restart)
5. **Rust peer** creates answer and sends it back
6. **ICE connection** established between browser and Rust peer
7. **Data channel** opens and Rust peer sends timestamps every 3 seconds
8. **ICE Restart** (when button clicked): Browser sends new offer with ICE restart flag
9. **Rust peer** processes restart and creates new answer
10. **Connection** re-established with new ICE candidates

## Key Features

- ✅ Browser-based WebRTC client (HTML + JavaScript)
- ✅ Rust sansio API peer (answerer)
- ✅ ICE restart handling
- ✅ Data channel messaging
- ✅ Real-time ICE state monitoring
- ✅ HTTP-based signaling
- ✅ Single peer connection reused for restart

## Implementation Notes

The sansio implementation:
- Creates `RTCPeerConnection` lazily on first signaling request
- Reuses the same peer connection for ICE restart
- Handles both initial connection and restart in the same code path
- Uses `mpsc::channel` to communicate between HTTP handlers and event loop
- Maintains single-threaded event loop with peer connection

This ensures the peer connection stays in one thread as required by sansio API design.

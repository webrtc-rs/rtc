# trickle-ice

trickle-ice demonstrates the comprehensive Trickle ICE APIs with all three types of ICE candidates.

ICE is the subsystem WebRTC uses to establish connectivity. Trickle ICE is the process of sharing addresses as soon as they are gathered. This parallelizes establishing a connection with a remote peer and starting sessions with STUN/TURN servers.

This example demonstrates gathering all three types of ICE candidates:
- **Host candidates** - Direct local network addresses
- **Server Reflexive (srflx) candidates** - Public addresses discovered via STUN servers
- **Relay candidates** - Relay addresses allocated via TURN servers

Using Trickle ICE can dramatically reduce the amount of time it takes to establish a WebRTC connection.

## Prerequisites

### For Host Candidates
No prerequisites - works out of the box.

### For Server Reflexive Candidates (STUN)
Uses Google's public STUN server by default (`stun.l.google.com:19302`).

### For Relay Candidates (TURN)
You need a TURN server running. The example defaults to `127.0.0.1:3478` with credentials `user=pass`.

#### Option 1: webrtc-rs/webrtc turn server

From the webrtc-rs/webrtc repository:

```bash
RUST_LOG=trace cargo run --color=always --package turn --example turn_server_udp -- --public-ip 127.0.0.1 --users user=pass
```

#### Option 2: pion/turn server

From the pion/turn repository:

```bash
./simple -public-ip 127.0.0.1 -users user=pass
```

## Instructions

### Run with default settings (Host)

From the `rtc` directory, execute:

```bash
cargo run --example trickle-ice
```

Or with debug logging:

```bash
cargo run --example trickle-ice -- --debug --log-level TRACE
```

### Customize candidate types

Enable only specific candidate types:

```bash
# Only host candidates
cargo run --example trickle-ice -- --enable-host

# Only STUN server reflexive candidates
cargo run --example trickle-ice -- --enable-srflx

# Only TURN relay candidates
# Requires a TURN server running at 127.0.0.1:3478 with credentials user=pass
cargo run --example trickle-ice -- --enable-relay

# Host + Relay (no STUN)
cargo run --example trickle-ice -- \
  --enable-host \
  --enable-relay
```

### Use custom STUN server

```bash
cargo run --example trickle-ice -- \
  --enable-srflx \
  --stun-server stun.example.com:3478
```

### Use custom TURN server

```bash
cargo run --example trickle-ice -- \
  --enable-relay \
  --turn-host turn.example.com \
  --turn-port 3478 \
  --turn-user myuser=mypass \
  --turn-realm myrealm.com
```

### Open the Web UI

Open [http://localhost:8080](http://localhost:8080). Click the "Start" button to initiate a PeerConnection.

The WebSocket server runs on port 8081 and the HTTP server (for serving the HTML page) runs on port 8080.

## Features

### Asynchronous Candidate Gathering
Candidates are added to the peer connection as soon as they become available, demonstrating true trickle ICE behavior.

### True Trickle ICE
Supports the case where STUN/TURN allocations complete after SDP exchange. When this happens:
- The answer is sent immediately without waiting for slow allocations
- Candidates are sent to the browser as they become available
- Connection establishment can proceed in parallel with candidate gathering

### Configurable Candidate Types
Enable/disable individual candidate types via CLI flags:
- `--enable-host` / `--no-enable-host`
- `--enable-srflx` / `--no-enable-srflx`
- `--enable-relay` / `--no-enable-relay`

### Event-Loop Based Architecture
Uses sansio APIs for:
- **RTC Peer Connection** - Main WebRTC state machine
- **STUN Client** - For gathering server reflexive candidates
- **TURN Client** - For allocating relay addresses and managing permissions

All three state machines run in a unified event loop with proper timeout coordination.

### Intelligent Packet Routing
- **STUN responses** → Routed to STUN client based on resolved server address
- **TURN responses** → Routed to TURN client based on resolved server address
- **WebRTC data** → Routed to peer connection
- **Outbound packets**:
  - Via TURN relay when relay mode is active and permission granted
  - Dropped when relay mode active but permission pending (avoids slow direct attempts)
  - Direct UDP when relay mode not active

### Multiple Remote Candidates
Automatically creates TURN permissions for all remote ICE candidates received from the browser.

### DNS Resolution
Both STUN and TURN server hostnames are resolved to IP addresses at startup for accurate packet routing.

## Implementation Details

### TURN Relay Mode Optimization
When running in relay-only mode or before TURN permissions are granted, the example **drops packets** instead of falling back to direct UDP. This is intentional:

- **Prevents wasted connectivity checks** - No point trying direct when only relay is available
- **Faster connection establishment** - Waits for TURN permissions instead of timing out on direct attempts
- **ICE retransmission handles it** - Dropped packets are retried once permissions are ready
- **Matches RFC behavior** - Relay candidates should only relay, not try direct

### Candidate Addition Timing
The example handles three timing scenarios correctly:

1. **Allocation before SDP** - Candidate added immediately during answer creation
2. **Allocation during SDP** - Candidate added and sent to browser right after answer
3. **Allocation after SDP** - Candidate trickled to browser when allocation completes

### Permission Management
TURN permissions are created dynamically:
- When remote ICE candidates arrive, extract peer addresses
- Create permission for each unique remote address
- Track pending and granted permissions
- Only send data through relay after permission is granted

## Troubleshooting

### Connection takes long time
- Check if TURN server is running and accessible
- Verify credentials are correct (`user=pass` by default)
- Enable debug logging: `--debug --log-level TRACE`
- Check for "TURN allocation successful" message

### STUN not working
- Verify DNS resolution: "Resolved STUN server ... to ..."
- Check firewall allows UDP to STUN server
- Try alternative STUN server: `--stun-server stun1.l.google.com:19302`

### TURN permissions failing
- Ensure remote peer's IP is reachable from TURN server
- Check TURN server logs for permission errors
- Verify network topology allows peer to reach TURN relay address

## Note

Congrats, you have used comprehensive sansio RTC with all ICE candidate types! Now start building something cool.

## See Also

- **trickle-ice-host** - Simple example with only host candidates
- **trickle-ice-srflx** - Example with STUN server reflexive candidates
- **trickle-ice-relay** - Example with TURN relay candidates

This comprehensive example combines all three into a single configurable implementation.

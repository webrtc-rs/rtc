# ice-tcp-active-passive

ice-tcp-active-passive demonstrates RTC's ICE TCP active mode abilities.

## About ICE TCP Types

ICE over TCP defines three connection types (RFC 6544):

- **Passive**: Listens for incoming TCP connections (like a server)
- **Active**: Initiates outgoing TCP connections (like a client)
- **Simultaneous-Open (S-O)**: Both sides attempt connections simultaneously

This example demonstrates **Active** mode on the offering side and **Passive** mode on the answering side.

## How It Works

1. **Answer side** (TCP passive):
    - Listens on a TCP port (default: 8443)
    - Creates a passive candidate that advertises this listening port
    - Waits for the offer side to connect

2. **Offer side** (TCP active):
    - Creates an active candidate (uses port 9 as a placeholder - active candidates don't listen)
    - When it receives the remote passive candidate, it initiates a TCP connection
    - Connects to the answer side's passive candidate port

3. **ICE connectivity**:
    - The active side connects to the passive side
    - TCP framing (RFC 4571) is used for all ICE messages
    - Once connected, data channel messages flow over the TCP connection

## TCP Candidate Pairing

In ICE, TCP candidates can only pair in specific ways:

| Local Type | Remote Type | Valid Pair? |
|------------|-------------|-------------|
| Active     | Passive     | Yes         |
| Passive    | Active      | Yes         |
| Active     | Active      | No          |
| Passive    | Passive     | No          |
| S-O        | S-O         | Yes         |

This example uses Active (offer) + Passive (answer) which is the most common pattern.

## RFC 6544: TCP Active Candidate Port Handling

### What Port Should Be Used for Active Candidates?

According to **RFC 6544 Section 3**:

> For active candidates, the port MUST be set to 9 (the discard port).

Port 9 is the "discard" service port (defined in RFC 863). It's used as a placeholder because:

1. A valid port number is required in the SDP candidate attribute syntax
2. Active TCP candidates don't listen on any port - they only initiate outgoing connections
3. Port 9 signals to the remote side that this is not a real listening port
4. The remote side should never attempt to connect to this port

### Signaling vs. Actual Connection

There's an important distinction between:

- **Signaled port (SDP)**: Port 9, as required by RFC 6544
- **Actual connection port**: The ephemeral port assigned by the OS when the TCP connection is established

When an active candidate initiates a TCP connection to a remote passive candidate, the OS assigns an ephemeral port (
e.g., 55764). This ephemeral port is used for the actual data transfer, not port 9.

### How sansio RTC Handles This

Since sansio RTC is I/O-free, the application manages TCP connections. This creates a challenge:

1. The application creates an active candidate with port 9 for signaling (before connecting)
2. When a remote passive candidate is discovered, the application initiates a TCP connection
3. The TCP connection uses an ephemeral port (e.g., 55764)
4. Incoming packets have `local_addr` with the ephemeral port, not port 9

To bridge this gap, sansio RTC's `find_local_candidate` function matches TCP active candidates by **IP address only** (
ignoring port). This allows the ICE agent to correctly associate incoming packets with the active candidate despite the
port mismatch.

### Remote Active Candidates Are Ignored

Remote TCP active candidates are ignored entirely. This is because:

- Active candidates don't have a listening port
- The remote active side will probe our passive candidates
- We don't need to (and can't) connect to a remote active candidate's port 9

## Instructions

### Run the answer side first (TCP passive)

```bash
cargo run --example ice-tcp-active-passive-answer
```

This will:

- Start a TCP listener on port 8443 (passive candidate)
- Start an HTTP server on port 60000 for signaling

### Run the offer side (TCP active)

```bash
cargo run --example ice-tcp-active-passive-offer
```

This will:

- Create a TCP active candidate
- Send an offer to the answer side
- When it receives the answer with a passive candidate, connect to it
- Exchange data channel messages

### Debug Mode

Add `--debug` flag for detailed logging:

```bash
cargo run --example ice-tcp-active-passive-answer -- --debug
cargo run --example ice-tcp-active-passive-offer -- --debug
```

### Custom Addresses

```bash
# Answer side
cargo run --example ice-tcp-active-passive-answer -- \
  --tcp-address 0.0.0.0:9443 \
  --http-address 0.0.0.0:60001 \
  --offer-address localhost:50001

# Offer side
cargo run --example ice-tcp-active-passive-offer -- \
  --http-address 0.0.0.0:50001 \
  --answer-address localhost:60001
```

## Key Differences from ice-tcp Example

| Aspect               | ice-tcp            | ice-tcp-active-passive |
|----------------------|--------------------|------------------------|
| Peers                | Browser + Rust     | Rust + Rust            |
| Offer side           | Browser (UDP)      | Rust (TCP active)      |
| Answer side          | Rust (TCP passive) | Rust (TCP passive)     |
| Connection initiator | Browser            | Rust offer side        |

## Note

This example demonstrates pure Rust-to-Rust ICE TCP connectivity without browser involvement, making it useful for
server-to-server WebRTC scenarios.

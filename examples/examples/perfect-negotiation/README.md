# perfect-negotiation

Demonstrates **Perfect Negotiation** pattern at the application level using webrtc-rs/rtc sans-I/O API.

## What is Perfect Negotiation?

Perfect Negotiation is a design pattern that allows both peers to use **identical connection setup code**, eliminating
the traditional offerer/answerer asymmetry. Key benefits:

- 🔄 **Bidirectional calling** - Either peer can initiate connection/renegotiation
- 🤝 **Symmetric code** - Same logic runs on both peers
- ⚡ **Collision handling** - Automatically resolves simultaneous offers
- 🎯 **Application-level** - Implemented using spec-compliant RTC primitives

## Architecture

This example demonstrates that Perfect Negotiation is an **application-level pattern**, not a library feature. It uses
only the spec-compliant primitives provided by webrtc-rs/rtc:

- `RTCSdpType::Rollback` - Recover from offer collisions
- `signaling_state()` - Detect collisions
- `OnNegotiationNeeded` - Handle renegotiation
- Standard offer/answer methods

### PerfectNegotiationHandler

The `PerfectNegotiationHandler` struct wraps `RTCPeerConnection` to implement collision detection and resolution:

```rust
struct PerfectNegotiationHandler {
    pc: RTCPeerConnection,
    polite: bool,                      // Role: yields on collision
    is_making_offer: bool,             // Track ongoing offer
    ignore_offer: bool,                // Collision resolution flag
    is_setting_remote_answer_pending: bool,
}
```

**Key methods:**

- `handle_negotiation_needed()` - Create and send offers
- `handle_remote_description()` - Collision detection and rollback
- `handle_remote_candidate()` - ICE candidate handling

### Collision Resolution

When both peers send offers simultaneously:

1. **Polite peer**: Rolls back local offer, accepts remote offer, sends answer
2. **Impolite peer**: Ignores remote offer, waits for remote peer to accept its offer

```rust
let offer_collision = description.sdp_type == RTCSdpType::Offer & &
( self .is_making_offer | | self .pc.signaling_state() != RTCSignalingState::Stable);

if self .polite & & offer_collision {
// Rollback using spec-compliant primitive
let rollback = RTCSessionDescription {
sdp_type: RTCSdpType::Rollback,
sdp: String::new(),
parsed: None,
};
self .pc.set_local_description(rollback) ?;
}
```

## How to Run

### 1. Start the Example

```bash
cargo run --example perfect-negotiation
```

Output:

```
Open http://localhost:8080/polite and http://localhost:8080/impolite in two browser tabs
Click 'Connect' in EITHER browser to start Perfect Negotiation
Press ctrl-c to stop
```

### 2. Open Two Browser Tabs

- **Tab 1**: http://localhost:8080/polite (Polite peer - yields on collision)
- **Tab 2**: http://localhost:8080/impolite (Impolite peer - stays on collision)

### 3. Test Perfect Negotiation

**Basic Connection:**

1. Click "Connect" in **either** tab (demonstrates bidirectionality)
2. Observe automatic negotiation in both tabs
3. Both peers establish connection using identical code

**Collision Testing:**

1. After connection, click "Renegotiate" in **both tabs simultaneously**
2. Observe collision detection messages
3. Polite peer automatically yields and accepts impolite peer's offer
4. Connection continues without interruption

**Data Channel:**

1. Once connected, type messages in either tab
2. Messages are exchanged bidirectionally
3. Both peers use the same data channel code

## Code Highlights

### Symmetric Peer Code

The `run_peer()` function demonstrates the key innovation - **identical code for both peers**:

```rust
async fn run_peer(polite: bool, ws: WebSocketStream<TcpStream>) -> Result<()> {
    let role = if polite { "POLITE" } else { "IMPOLITE" };

    // Create peer connection (same for both)
    let mut pc = RTCPeerConnection::new(config)?;

    // Wrap in Perfect Negotiation handler
    let mut negotiation = PerfectNegotiationHandler::new(pc, polite);

    // Event loop - IDENTICAL for both peers
    loop {
        tokio::select! {
            // Handle negotiation needed (same code)
            RTCPeerConnectionEvent::OnNegotiationNeeded => {
                negotiation.handle_negotiation_needed(|desc| {
                    ws.send(desc)
                }).await?;
            }
            
            // Handle remote description (same code)
            SignalingMessage::Description { description } => {
                negotiation.handle_remote_description(description, |desc| {
                    ws.send(desc)
                }).await?;
            }
            
            // ... rest of event loop
        }
    }
}
```

### Application-Level Implementation

This example proves that Perfect Negotiation **does not require library support**:

✅ **Uses only spec-compliant primitives:**

- No custom library APIs
- No convenience methods
- Just standard WebRTC operations

✅ **Flexible and customizable:**

- Applications control politeness assignment
- Can customize collision resolution
- Integrates with any signaling mechanism

✅ **Keeps library focused:**

- Library provides WebRTC spec compliance
- Applications implement design patterns
- Clear separation of concerns

## Comparison with Traditional Examples

| Aspect             | Traditional Approach             | Perfect Negotiation   |
|--------------------|----------------------------------|-----------------------|
| Code symmetry      | Asymmetric (offerer vs answerer) | Symmetric (identical) |
| Initiation         | Fixed roles                      | Either peer           |
| Renegotiation      | Often asymmetric                 | Fully bidirectional   |
| Collision handling | Manual or avoided                | Automatic             |
| Code reuse         | Separate paths                   | Single codebase       |

## Expected Output

### Polite Peer Log:

```
[POLITE] Starting peer
[POLITE] UDP socket bound to 0.0.0.0:54321
[POLITE] Created data channel 'data-polite'
[POLITE] Received 'connect' command - initiating negotiation
[POLITE] Negotiation needed
[POLITE] Sending Offer
[POLITE] Received remote Offer description
[POLITE] Collision detected, rolling back local offer
[POLITE] Creating answer
[POLITE] Sending Answer
[POLITE] ✓ Peer connection connected!
[POLITE] Data channel 'data-polite-0' opened
```

### Impolite Peer Log:

```
[IMPOLITE] Starting peer
[IMPOLITE] UDP socket bound to 0.0.0.0:54322
[IMPOLITE] Created data channel 'data-impolite'
[IMPOLITE] Received remote Offer description
[IMPOLITE] Ignoring remote offer due to collision (impolite)
[IMPOLITE] Received remote Answer description
[IMPOLITE] ✓ Peer connection connected!
[IMPOLITE] Data channel 'data-impolite-0' opened
```

## Key Takeaways

1. **Perfect Negotiation is an application pattern**, not a library feature
2. **webrtc-rs/rtc provides all necessary primitives** (rollback, state machine, events)
3. **Application-level implementation offers maximum flexibility**
4. **Symmetric code dramatically simplifies bidirectional applications**
5. **Collision handling is straightforward** with polite/impolite roles

## References

- [MDN: Perfect Negotiation](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Perfect_negotiation)
- [W3C WebRTC Spec: Perfect Negotiation Example](https://www.w3.org/TR/webrtc/#perfect-negotiation-example)
- [webrtc-rs/rtc Perfect Negotiation Analysis](https://webrtc.rs/blog/perfect-negotiation-analysis.html)

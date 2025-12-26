# RTC Integration Tests

## Overview

This directory contains integration tests for the `rtc` library, specifically testing interoperability with the `webrtc` library.

## Test 1: Data Channels Interop (Answer Mode)

**File:** `data_channels_interop.rs`

**Purpose:** Verifies that the `rtc` library (using the sansio/polling-based API) can successfully establish a peer connection and exchange data with the `webrtc` library (using the async API).

### Test Flow

1. **WebRTC Peer (Offerer)**:
   - Creates a WebRTC peer connection using the async API
   - Creates a data channel
   - Generates an offer with ICE candidates
   - Sets up message handlers to receive echoed messages

2. **RTC Peer (Answerer)**:
   - Creates an RTC peer connection using the sansio/polling API
   - Receives the offer from WebRTC peer
   - Binds a UDP socket and adds local ICE candidate
   - Generates an answer

3. **Connection Establishment**:
   - Both peers exchange SDP descriptions
   - The test runs both event loops in a single async context:
     - RTC peer uses polling-based API (`poll_write()`, `poll_event()`, `handle_read()`)
     - WebRTC peer uses async handlers

4. **Data Exchange**:
   - Once connected, WebRTC sends a message: "Hello from WebRTC!"
   - RTC peer receives the message and echoes it back
   - WebRTC peer receives the echo
   - Test succeeds if the echo is received within timeout

### Running the Test

```bash
RUST_LOG=info cargo test --test data_channels_interop -- --nocapture
```

### Key Features Tested

- ✅ SDP offer/answer exchange between rtc and webrtc (RTC as answerer)
- ✅ ICE candidate handling
- ✅ Data channel creation and opening
- ✅ Bidirectional message exchange
- ✅ Event-driven communication (rtc polling vs webrtc async)

---

## Test 2: Data Channels Create Interop (Offer Mode)

**File:** `data_channels_create_interop.rs`

**Purpose:** Verifies that the `rtc` library can create a data channel as the offerer, establish a connection with `webrtc` as the answerer, and send messages proactively.

### Test Flow

1. **RTC Peer (Offerer)**:
   - Creates an RTC peer connection using the sansio/polling API
   - **Creates a data channel** with label "test-channel"
   - Binds a UDP socket and adds local ICE candidate
   - Generates an offer

2. **WebRTC Peer (Answerer)**:
   - Creates a WebRTC peer connection using the async API
   - Sets up `on_data_channel` handler to receive the data channel
   - Receives the offer from RTC peer
   - Generates an answer with ICE candidates

3. **Connection Establishment**:
   - Both peers exchange SDP descriptions
   - The test runs both event loops in a single async context

4. **Data Exchange**:
   - Once connected and data channel is open, RTC sends: "Hello from RTC!"
   - WebRTC receives the message and echoes it back
   - RTC receives the echoed message
   - Test succeeds if both sides receive the correct messages within timeout

### Running the Test

```bash
RUST_LOG=info cargo test --test data_channels_create_interop -- --nocapture
```

### Key Features Tested

- ✅ SDP offer/answer exchange (RTC as offerer)
- ✅ Data channel creation from RTC side
- ✅ Data channel negotiation and opening
- ✅ Message sending from RTC to WebRTC
- ✅ Event-driven communication with RTC as initiator

### Difference from Test 1

| Aspect | Test 1 (data_channels_interop) | Test 2 (data_channels_create_interop) |
|--------|--------------------------------|---------------------------------------|
| **Offerer** | WebRTC | RTC |
| **Answerer** | RTC | WebRTC |
| **Data Channel Creator** | WebRTC | RTC |
| **Message Sender** | WebRTC → RTC → WebRTC (echo) | RTC → WebRTC → RTC (echo) |
| **Message Flow** | Bidirectional (with echo) | Bidirectional (with echo) |

---

## Test 3: Data Channels Close Interop

**File:** `data_channels_close_interop.rs`

**Purpose:** Verifies that data channels can be properly closed and that close events are detected correctly when RTC sends messages and closes.

### Test Flow

1. **RTC Peer (Offerer)**:
   - Creates an RTC peer connection using the sansio/polling API
   - **Creates a data channel**
   - Generates an offer
   - Sets up close event handler (OnClose event)

2. **WebRTC Peer (Answerer)**:
   - Creates a WebRTC peer connection using the async API
   - Sets up `on_data_channel` handler to receive the channel
   - Receives the offer from RTC peer
   - Generates an answer with ICE candidates
   - Sets up close event handler

3. **Connection Establishment**:
   - Both peers exchange SDP descriptions
   - The test runs both event loops in a single async context

4. **Data Exchange and Close**:
   - Once connected, **RTC sends 3 periodic messages** (every 500ms) to WebRTC
   - WebRTC receives the messages
   - After sending all messages, **RTC exits the event loop** (which closes the peer connection and data channel)
   - WebRTC detects the close event via `on_close` handler
   - Test succeeds when WebRTC detects the close

### Running the Test

```bash
RUST_LOG=info cargo test --test data_channels_close_interop -- --nocapture
```

### Key Features Tested

- ✅ Data channel creation by RTC (offerer)
- ✅ **Periodic message sending from RTC** (every 500ms)
- ✅ Message counting before close (sends exactly 3 messages)
- ✅ **Data channel close initiated by RTC** (via peer connection close)
- ✅ Close event detection on WebRTC side
- ✅ Proper cleanup on both sides

### Important Note: Sansio Close Behavior

The RTC sansio API doesn't expose an explicit `close()` method on `RTCDataChannel`. Instead:
- When RTC finishes sending messages, it **exits the event loop**
- This triggers `rtc_pc.close()` which closes the peer connection
- The data channel is implicitly closed as part of the peer connection closure
- WebRTC detects this via its `on_close` handler

### Difference from Other Tests

| Aspect | Test 1 | Test 2 | Test 3 (data_channels_close_interop) |
|--------|--------|--------|--------------------------------------|
| **Offerer** | WebRTC | RTC | **RTC** |
| **Focus** | Bidirectional echo | Bidirectional echo | **Close behavior** |
| **Message Pattern** | Single echo | Single echo | **3 periodic messages from RTC** |
| **Termination** | After echo received | After echo received | **After RTC closes (exit event loop)** |
| **Close Behavior** | N/A | N/A | **RTC exits → peer connection closes → data channel closes** |

---

## Dependencies

The tests require:
- `webrtc = "0.14.0"` - WebRTC async implementation
- `interceptor = "0.15.0"` - For webrtc interceptor registry
- `tokio` - Async runtime
- `anyhow` - Error handling

## Architecture

The integration tests demonstrate how to use both APIs together:

- **RTC API** (sansio): Poll-based, no async/await, uses `poll_write()`, `poll_event()`, and `handle_read()`
- **WebRTC API** (async): Fully async with tokio, uses `async/await` and event handlers

The tests successfully bridge these two different programming models in a single test function.

## Future Tests

Consider adding tests for:
- Multiple data channels
- RTP transceiver interop (audio/video)
- Reconnection scenarios
- Error handling and edge cases
- Different ICE transport policies
- DTLS role negotiation variations

# RTC Integration Tests

## Overview

This directory contains integration tests for the `rtc` library:
- **Interoperability tests** with the `webrtc` library (Tests 1-4)
- **Pure rtc-to-rtc tests** using only the sansio API (Test 5)

## Test Summary

| Test | File | Description |
|------|------|-------------|
| 1 | `data_channels_interop.rs` | rtc ↔ webrtc (webrtc offers) |
| 2 | `data_channels_create_interop.rs` | rtc ↔ webrtc (rtc offers) |
| 3 | `data_channels_close_by_rtc_interop.rs` | Close initiated by rtc |
| 4 | `data_channels_close_by_webrtc_interop.rs` | Close initiated by webrtc |
| 5 | `offer_answer_rtc2rtc.rs` | **Pure rtc ↔ rtc (no webrtc)** |

---

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

## Test 3: Data Channels Close by RTC

**File:** `data_channels_close_by_rtc_interop.rs`

**Purpose:** Verifies that data channels can be properly closed and that close events are detected correctly when RTC sends messages and closes the connection.

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
RUST_LOG=info cargo test --test data_channels_close_by_rtc_interop -- --nocapture
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

---

## Test 4: Data Channels Close by WebRTC

**File:** `data_channels_close_by_webrtc_interop.rs`

**Purpose:** Verifies that data channels can be properly closed and that close events are detected correctly when WebRTC initiates the close.

### Test Flow

1. **WebRTC Peer (Offerer)**:
   - Creates a WebRTC peer connection using the async API
   - Creates a data channel
   - Generates an offer with ICE candidates
   - Sets up message handlers

2. **RTC Peer (Answerer)**:
   - Creates an RTC peer connection using the sansio/polling API
   - Receives the offer from WebRTC peer
   - Generates an answer
   - Handles data channel events

3. **Connection Establishment**:
   - Both peers exchange SDP descriptions
   - The test runs both event loops in a single async context

4. **Data Exchange and Close**:
   - Once connected, messages are exchanged
   - **WebRTC initiates the close** of the data channel
   - RTC detects the close event via `OnClose` event
   - Test succeeds when RTC detects the close

### Running the Test

```bash
RUST_LOG=info cargo test --test data_channels_close_by_webrtc_interop -- --nocapture
```

### Key Features Tested

- ✅ Data channel creation by WebRTC (offerer)
- ✅ Message exchange
- ✅ **Data channel close initiated by WebRTC**
- ✅ Close event detection on RTC side
- ✅ Proper cleanup on both sides

### Difference from Other Tests

| Aspect | Test 1 | Test 2 | Test 3 (close_by_rtc) | Test 4 (close_by_webrtc) |
|--------|--------|--------|----------------------|--------------------------|
| **Offerer** | WebRTC | RTC | RTC | **WebRTC** |
| **Focus** | Bidirectional echo | Bidirectional echo | **Close by RTC** | **Close by WebRTC** |
| **Close Initiator** | N/A | N/A | **RTC** | **WebRTC** |
| **Close Detection** | N/A | N/A | **WebRTC detects** | **RTC detects** |

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

---

## Test 5: Offer-Answer RTC-to-RTC

**File:** `offer_answer_rtc2rtc.rs`

**Purpose:** Verifies that two `rtc` peers using the sansio API can establish a complete offer/answer connection and exchange data without requiring the `webrtc` library.

### Test Flow

1. **Offer Peer (RTC)**:
   - Creates an RTC peer connection using the sansio/polling API
   - Creates a data channel with label "test-channel"
   - Binds a UDP socket to 127.0.0.1 and adds local ICE candidate
   - Generates an offer
   - Sets local description
   - Sets DTLS role to Server

2. **Answer Peer (RTC)**:
   - Creates an RTC peer connection using the sansio/polling API
   - Binds a UDP socket to 127.0.0.1 and adds local ICE candidate
   - Receives the offer and sets it as remote description
   - Generates an answer
   - Sets local description
   - Sets DTLS role to Client

3. **ICE Candidate Exchange**:
   - Offer peer adds Answer peer's candidate
   - Answer peer adds Offer peer's candidate
   - Both peers know each other's socket addresses

4. **Connection Establishment**:
   - Both event loops run concurrently using `tokio::select!`
   - Polls write, events, and handles timeouts for both peers
   - Processes incoming UDP packets with `handle_read()`

5. **Data Exchange**:
   - Once connected, Offer sends: "Hello from offer!"
   - Answer receives the message and echoes: "Echo from answer!"
   - Offer receives the echo
   - Test succeeds when both messages are received

### Running the Test

```bash
cargo test --test offer_answer_rtc2rtc -- --nocapture
```

### Key Features Tested

- ✅ Pure RTC-to-RTC communication (no webrtc dependency)
- ✅ Complete offer/answer SDP exchange
- ✅ ICE candidate exchange
- ✅ DTLS role negotiation (Server/Client)
- ✅ Data channel creation and opening
- ✅ Bidirectional message exchange
- ✅ Event loop coordination for both peers
- ✅ Proper connection state transitions

### Architecture Highlights

This test demonstrates the pure sansio architecture:
- **Both peers use polling-based API**
- **Single test manages two event loops**
- **Manual timeout and I/O handling**
- **No async/await in peer connection code**
- **Direct UDP socket management**

### Comparison with Other Tests

| Aspect | Tests 1-4 | Test 5 (offer_answer_rtc2rtc) |
|--------|-----------|-------------------------------|
| **Peers** | rtc + webrtc | **rtc + rtc** |
| **Dependencies** | Requires webrtc crate | **Only rtc crate** |
| **Event Loops** | Mixed (polling + async) | **Pure polling for both** |
| **API Style** | Mixed sansio + async | **Pure sansio** |
| **Complexity** | Bridge two APIs | **Single consistent API** |

This test proves that the rtc sansio API is fully self-sufficient and can establish peer-to-peer connections without the webrtc library.


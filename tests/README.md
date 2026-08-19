# RTC Integration Tests

## Overview

This directory contains integration tests for the `rtc` library:

- **Interoperability tests** with the `webrtc` library (Tests 1-5)
- **Pure rtc-to-rtc tests** using only the sansio API (Test 6)
- **Interceptor integration tests** for RTCP report generation (Test 15)

---

## Dependencies

The tests require:

- `webrtc = "0.14.0"` - WebRTC async implementation
- `interceptor = "0.15.0"` - For webrtc interceptor registry
- `tokio` - Async runtime
- `anyhow` - Error handling

---

## Architecture

The integration tests demonstrate how to use both APIs together:

- **RTC API** (sansio): Poll-based, no async/await, uses `poll_write()`, `poll_event()`, and `handle_read()`
- **WebRTC API** (async): Fully async with tokio, uses `async/await` and event handlers

The tests successfully bridge these two different programming models in a single test function.

---

## Future Tests

Consider adding tests for:

- Multiple data channels
- RTP transceiver interop (audio/video)
- Reconnection scenarios
- Error handling and edge cases
- Different ICE transport policies
- DTLS role negotiation variations

---

## Test Summary

| Test | File                                                        | Description                             |
|------|-------------------------------------------------------------|-----------------------------------------|
| 1    | `data_channels_interop.rs`                                  | rtc ↔ webrtc (webrtc offers)            |
| 2    | `data_channels_create_interop.rs`                           | rtc ↔ webrtc (rtc offers)               |
| 3    | `data_channels_close_by_rtc_interop.rs`                     | Close initiated by rtc                  |
| 4    | `data_channels_close_by_webrtc_interop.rs`                  | Close initiated by webrtc               |
| 5    | `ice_restart_by_webrtc_interop.rs`                          | ICE restart initiated by webrtc         |
| 6    | `ice_restart_by_rtc_interop.rs`                             | ICE restart initiated by rtc            |
| 7    | `play_from_disk_vpx_interop.rs`                             | Media streaming: rtc→webrtc             |
| 8    | `play_from_disk_rtc_set_remote_before_add_track_interop.rs` | Media with track order variation        |
| 9    | `reflect_webrtc_to_rtc_interop.rs`                          | Media reflection: webrtc→rtc→webrtc     |
| 10   | `reflect_rtc_to_webrtc_interop.rs`                          | Media reflection: rtc→webrtc→rtc        |
| 11   | `save_to_disk_vpx_interop.rs`                               | Media capture: webrtc→rtc→disk          |
| 12   | `simulcast_webrtc_to_rtc_interop.rs`                        | simulcast: webrtc→rtc (IGNORED)         |
| 13   | `simulcast_rtc_to_webrtc_interop.rs`                        | Simulcast: rtc→webrtc (IGNORED)         |
| 14   | `offer_answer_rtc2rtc.rs`                                   | **Pure rtc ↔ rtc (no webrtc)**          |
| 15   | `interceptor_rtcp_reports_interop.rs`                       | **RTCP report interceptor integration** |

---

## Test 1: Data Channels Interop (Answer Mode)

**File:** `data_channels_interop.rs`

**Purpose:** Verifies that the `rtc` library (using the sansio/polling-based API) can successfully establish a peer
connection and exchange data with the `webrtc` library (using the async API).

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

**Purpose:** Verifies that the `rtc` library can create a data channel as the offerer, establish a connection with
`webrtc` as the answerer, and send messages proactively.

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

| Aspect                   | Test 1 (data_channels_interop) | Test 2 (data_channels_create_interop) |
|--------------------------|--------------------------------|---------------------------------------|
| **Offerer**              | WebRTC                         | RTC                                   |
| **Answerer**             | RTC                            | WebRTC                                |
| **Data Channel Creator** | WebRTC                         | RTC                                   |
| **Message Sender**       | WebRTC → RTC → WebRTC (echo)   | RTC → WebRTC → RTC (echo)             |
| **Message Flow**         | Bidirectional (with echo)      | Bidirectional (with echo)             |

---

## Test 3: Data Channels Close by RTC

**File:** `data_channels_close_by_rtc_interop.rs`

**Purpose:** Verifies that data channels can be properly closed and that close events are detected correctly when RTC
sends messages and closes the connection.

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

**Purpose:** Verifies that data channels can be properly closed and that close events are detected correctly when WebRTC
initiates the close.

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

| Aspect              | Test 1             | Test 2             | Test 3 (close_by_rtc) | Test 4 (close_by_webrtc) |
|---------------------|--------------------|--------------------|-----------------------|--------------------------|
| **Offerer**         | WebRTC             | RTC                | RTC                   | **WebRTC**               |
| **Focus**           | Bidirectional echo | Bidirectional echo | **Close by RTC**      | **Close by WebRTC**      |
| **Close Initiator** | N/A                | N/A                | **RTC**               | **WebRTC**               |
| **Close Detection** | N/A                | N/A                | **WebRTC detects**    | **RTC detects**          |

---

## Test 5: ICE Restart by WebRTC

**File:** `ice_restart_by_webrtc_interop.rs`

**Description:**
Tests ICE restart functionality when initiated by the WebRTC peer (offerer), with RTC as answerer using the sansio API.

### Test Flow

1. WebRTC peer creates offer and data channel
2. RTC peer receives offer and creates answer
3. Connection establishes and peers exchange messages before restart
4. WebRTC initiates ICE restart with new offer (ice_restart: true)
5. RTC processes restart offer and creates restart answer
6. Connection re-establishes
7. Peers can communicate again (RTC → WebRTC verified)

### Key Features Tested

- ✅ ICE restart initiated by WebRTC using `RTCOfferOptions { ice_restart: true }`
- ✅ RTC handles restart as answerer
- ✅ Connection successfully re-establishes
- ✅ Pre-restart bidirectional communication works
- ✅ RTC → WebRTC data channel works after restart
- ⚠️ WebRTC → RTC data channel after restart may have issues (known limitation)

### Running the Test

```bash
cargo test --test ice_restart_by_webrtc_interop -- --nocapture
```

---

## Test 6: ICE Restart by RTC

**File:** `ice_restart_by_rtc_interop.rs`

**Description:**
Tests ICE restart functionality when initiated by the RTC peer (offerer) using the sansio `restart_ice()` API, with
WebRTC as answerer.

### Test Flow

1. WebRTC peer creates offer and data channel
2. RTC peer receives offer and creates answer
3. Connection establishes and peers exchange messages before restart
4. RTC initiates ICE restart using `restart_ice()` method
5. RTC creates new offer with ICE restart
6. WebRTC processes restart offer and creates restart answer
7. RTC sets restart answer as remote description
8. Connection re-establishes via ICE
9. Data channel continues working after restart

### Key Features Tested

- ✅ ICE restart initiated by RTC using sansio `restart_ice()` API
- ✅ WebRTC handles restart as answerer
- ✅ Connection successfully re-establishes
- ✅ Pre-restart bidirectional communication works
- ✅ Data channel continues working after restart
- ✅ ICE connection state transitions properly (checking → connected/completed)

### Running the Test

```bash
cargo test --test ice_restart_by_rtc_interop -- --nocapture
```

---

## Test 7: Play from Disk VPX

**File:** `play_from_disk_vpx_interop.rs`

**Description:**
Tests media streaming from RTC to WebRTC by playing VP8/VP9 encoded video from disk.

### Key Features Tested

- ✅ RTC creates offer with video track
- ✅ WebRTC answers and receives video
- ✅ VP8/VP9 media streaming from rtc to webrtc

### Running the Test

```bash
cargo test --test play_from_disk_vpx_interop -- --nocapture
```

---

## Test 8: Play from Disk with Track Order Variation

**File:** `play_from_disk_rtc_set_remote_before_add_track_interop.rs`

**Description:**
Tests media streaming with a specific track order variation where RTC sets remote description before adding tracks.

### Key Features Tested

- ✅ Set remote description before add_track
- ✅ Track negotiation with non-standard order
- ✅ Media streaming works with alternate setup order

### Running the Test

```bash
cargo test --test play_from_disk_rtc_set_remote_before_add_track_interop -- --nocapture
```

---

## Test 9: Media Reflection (WebRTC to RTC)

**File:** `reflect_webrtc_to_rtc_interop.rs`

**Purpose:** Verifies that RTP packets can be sent from webrtc, received and reflected by rtc, and received back at
webrtc.

### Test Flow

1. **WebRTC Peer (Offerer)**:
    - Creates a video track using `TrackLocalStaticRTP`
    - Creates offer with video track
    - Sets up `on_track` handler to receive reflected packets

2. **RTC Peer (Answerer)**:
    - Receives offer from webrtc
    - Adds video track for reflecting packets
    - Creates answer

3. **Connection Establishment**:
    - Both peers exchange SDP and establish connection
    - Event loops run concurrently

4. **Packet Flow**:
    - WebRTC sends 10 RTP packets with VP8 codec
    - RTC receives packets via `poll_read()` → `RTCMessage::RtpPacket`
    - RTC reflects packets back via `write_rtp()`
    - WebRTC receives reflected packets
    - Test succeeds when ≥5 reflected packets received

### Running the Test

```bash
cargo test --test reflect_webrtc_to_rtc_interop -- --nocapture
```

### Key Features Tested

- ✅ WebRTC creates offer with video track
- ✅ RTC answers and adds video track
- ✅ RTP packet sending from webrtc
- ✅ RTP packet reception on rtc
- ✅ RTP packet reflection via `write_rtp()`
- ✅ Bidirectional media flow

---

## Test 10: Media Reflection (RTC to WebRTC)

**File:** `reflect_rtc_to_webrtc_interop.rs`

**Purpose:** Verifies that RTP packets can be sent from rtc, received and reflected by webrtc, and received back at rtc.

### Test Flow

1. **RTC Peer (Offerer)**:
    - Creates video track
    - Creates offer
    - Sends RTP packets to webrtc

2. **WebRTC Peer (Answerer)**:
    - Creates video track for reflecting
    - Receives offer and creates answer
    - Reflects packets back to rtc

3. **Expected Result**:
    - RTC sends → webrtc reflects → RTC receives

### Running the Test

```bash
cargo test --test reflect_rtc_to_webrtc_interop -- --nocapture
```

### Key Features Tested

- ✅ RTC creates offer with video track
- ✅ WebRTC answers and adds video track
- ✅ RTP packet sending from rtc
- ✅ RTP packet reflection by webrtc
- ✅ RTP packet reception on rtc

---

## Test 11: Save to Disk VPX

**File:** `save_to_disk_vpx_interop.rs`

**Description:**
Tests media capture from WebRTC to RTC, saving VP8/VP9 encoded video to disk.

### Key Features Tested

- ✅ WebRTC creates offer with video track
- ✅ RTC answers and receives video
- ✅ RTP packet capture from webrtc
- ✅ Media saving to disk

### Running the Test

```bash
cargo test --test save_to_disk_vpx_interop -- --nocapture
```

---

## Test 12: Simulcast (WebRTC to RTC)

**File:** `simulcast_webrtc_to_rtc_interop.rs`

**Status:** ⚠️ **IGNORED**

**Description:**
Tests simulcast functionality where WebRTC sends multiple quality layers to RTC.

### Running the Test

```bash
# Currently ignored, run with:
cargo test --test simulcast_webrtc_to_rtc_interop -- --ignored --nocapture
```

---

## Test 13: Simulcast (RTC to WebRTC)

**File:** `simulcast_rtc_to_webrtc_interop.rs`

**Status:** ⚠️ **IGNORED** - RID header extensions not implemented

**Description:**
Tests TRUE simulcast with RID (Restriction Identifier) support where rtc sends 3 layers and webrtc receives them.

### Current Issue

The RTC library does not automatically add RID (rtp-stream-id) header extensions to outgoing RTP packets. The
`write_rtp()` method has a TODO comment:

```rust
pub fn write_rtp(&mut self, mut packet: rtp::Packet) -> Result<()> {
    //TODO: handle rtp header extension, etc.
```

Without RID extensions in the RTP headers, webrtc cannot properly demultiplex the simulcast layers.

### Running the Test

```bash
# Currently ignored, run with:
cargo test --test simulcast_rtc_to_webrtc_interop -- --ignored --nocapture
```

---

## Test 14: Offer-Answer RTC-to-RTC

**File:** `offer_answer_rtc2rtc.rs`

**Purpose:** Verifies that two `rtc` peers using the sansio API can establish a complete offer/answer connection and
exchange data without requiring the `webrtc` library.

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

---

## Test 15: RTCP Report Interceptor Integration

**File:** `interceptor_rtcp_reports_interop.rs`

**Purpose:** Verifies that the `rtc-interceptor` crate's RTCP report interceptors work correctly when integrated at the
peer connection level with `Registry` and `RTCConfigurationBuilder.with_interceptor_registry()`.

### Overview

This test file contains 3 integration tests that verify:

1. Custom interceptor registry configuration with configurable report intervals
2. RTCP Sender Report generation when sending RTP packets
3. The `register_default_interceptors()` helper function

### Test 15a: Custom Interceptor Registry

**Function:** `test_custom_interceptor_registry_with_rtcp_reports`

Creates an rtc peer with a custom interceptor registry using `SenderReportBuilder` and `ReceiverReportBuilder` with
100ms intervals:

```rust
let registry = Registry::new()
.with(
ReceiverReportBuilder::new()
.with_interval(Duration::from_millis(100))
.build(),
)
.with(
SenderReportBuilder::new()
.with_interval(Duration::from_millis(100))
.build(),
);

let config = RTCConfigurationBuilder::new()
.with_interceptor_registry(registry)
.build();
```

**Test Flow:**

1. RTC peer creates offer with video track and custom interceptor registry
2. WebRTC peer creates answer with reflect track
3. Peers exchange SDP and establish connection
4. RTC sends RTP packets, webrtc reflects them back
5. Test verifies RTC receives reflected packets (proving interceptor chain works)

### Test 15b: Sender Report Generation

**Function:** `test_sender_report_generation_on_rtp_send`

Uses shorter report intervals (50ms) and monitors outgoing packets to detect RTCP Sender Report generation.

**Key Points:**

- Monitors `poll_write()` output for RTCP packets
- Detects Sender Reports by checking payload type (PT=200)
- Verifies that sending RTP triggers periodic Sender Report generation

### Test 15c: Default Interceptors Helper

**Function:** `test_register_default_interceptors_helper`

Tests the `register_default_interceptors()` helper function:

```rust
let registry = Registry::new();
let registry = rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors(
registry,
& mut media_engine,
) ?;
```

This verifies the convenience function correctly configures RTCP report interceptors.

### Running the Tests

```bash
cargo test --test interceptor_rtcp_reports_interop -- --nocapture
```

### Key Features Tested

- ✅ Custom interceptor registry with `Registry::new().with(...)`
- ✅ `SenderReportBuilder` with configurable intervals
- ✅ `ReceiverReportBuilder` with configurable intervals
- ✅ `RTCConfigurationBuilder.with_interceptor_registry()`
- ✅ `register_default_interceptors()` helper function
- ✅ RTCP Sender Report generation on RTP send
- ✅ Full peer connection with interceptor chain

### Related: rtc-interceptor Unit Tests

The `rtc-interceptor` crate also has its own integration tests at `rtc-interceptor/tests/rtcp_report_integration.rs`
which test the interceptor chain in isolation (without a full peer connection):

| Test                                                       | Description              |
|------------------------------------------------------------|--------------------------|
| `test_sender_report_interceptor_generates_sr_on_timeout`   | SR generation on timeout |
| `test_sender_report_tracks_packet_statistics`              | Packet/octet counting    |
| `test_sender_report_multiple_streams`                      | Multiple SSRCs           |
| `test_receiver_report_interceptor_generates_rr_on_timeout` | RR generation on timeout |
| `test_receiver_report_tracks_sequence_numbers`             | Sequence number tracking |
| `test_receiver_report_detects_packet_loss`                 | Loss detection           |
| `test_combined_sender_and_receiver_interceptors`           | Chained SR+RR            |
| `test_interceptor_chain_unbind_streams`                    | Stream unbinding         |
| `test_receiver_processes_sender_report`                    | SR→RR LSR/DLSR           |
| `test_report_interval_is_respected`                        | Interval timing          |
| `test_poll_timeout_returns_earliest`                       | Timeout scheduling       |

Run these with:

```bash
cargo test --package rtc-interceptor --test rtcp_report_integration
```

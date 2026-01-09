# TWCC Interceptor

Transport Wide Congestion Control (TWCC) implementation for the RTC Interceptor framework.

## Overview

TWCC is a congestion control mechanism specified
in [draft-holmer-rmcat-transport-wide-cc-extensions](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01).

This module provides two interceptors:

- **TwccSenderInterceptor**: Adds transport-wide sequence numbers to outgoing RTP packets
- **TwccReceiverInterceptor**: Tracks incoming RTP packets and generates TWCC feedback

## File Mapping

| Pion (Go)                                   | RTC (Rust)            | Description                                              |
|---------------------------------------------|-----------------------|----------------------------------------------------------|
| `header_extension_interceptor.go` (partial) | `mod.rs`              | Module definition, constants, helper functions           |
| `arrival_time_map.go`                       | `arrival_time_map.rs` | Circular buffer for packet arrival times                 |
| `twcc.go`                                   | `recorder.rs`         | Recorder, Feedback, Chunk - builds TWCC feedback packets |
| `header_extension_interceptor.go`           | `sender.rs`           | Adds transport CC sequence numbers to outgoing packets   |
| `sender_interceptor.go`                     | `receiver.rs`         | Tracks arrivals, generates feedback                      |

## Feature Comparison

| Feature                                | pion | RTC |
|----------------------------------------|------|-----|
| Add transport sequence to outgoing RTP | ✅    | ✅   |
| Track packet arrivals                  | ✅    | ✅   |
| Build TWCC feedback packets            | ✅    | ✅   |
| Configurable feedback interval         | ✅    | ✅   |
| Sequence number unwrapping             | ✅    | ✅   |
| RunLengthChunk encoding                | ✅    | ✅   |
| StatusVectorChunk encoding             | ✅    | ✅   |
| Large delta support                    | ✅    | ✅   |
| Packet loss detection                  | ✅    | ✅   |
| RTCP feedback processing               | ➖    | ➖   |

Note: ➖ indicates features intentionally skipped (RTCP feedback processing is handled at a different layer).

## Test Comparison

### arrival_time_map_test.go vs arrival_time_map.rs

| Pion Test                                                          | RTC Equivalent                       | Status    |
|--------------------------------------------------------------------|--------------------------------------|-----------|
| `TestArrivalTimeMap/consistent when empty`                         | *(not needed)*                       | N/A       |
| `TestArrivalTimeMap/inserts first item into map`                   | `test_arrival_time_map_basic`        | ✅         |
| `TestArrivalTimeMap/inserts with gaps`                             | `test_arrival_time_map_with_gaps`    | ✅         |
| `TestArrivalTimeMap/find next at or after with gaps`               | `test_arrival_time_map_find_next`    | ✅         |
| `TestArrivalTimeMap/inserts within buffer`                         | `test_arrival_time_map_out_of_order` | ✅         |
| `TestArrivalTimeMap/grows buffer and removes old`                  | *(implicit in other tests)*          | ✅         |
| `TestArrivalTimeMap/sequence number jump deletes all`              | *(not needed)*                       | N/A       |
| `TestArrivalTimeMap/expands before beginning`                      | *(not needed)*                       | N/A       |
| `TestArrivalTimeMap/expanding before beginning keeps received`     | *(not needed)*                       | N/A       |
| `TestArrivalTimeMap/erase to removes elements`                     | *(not needed)*                       | N/A       |
| `TestArrivalTimeMap/erases in empty map`                           | *(not needed)*                       | N/A       |
| `TestArrivalTimeMap/is tolerant to wrong arguments for erase`      | *(not needed)*                       | N/A       |
| `TestArrivalTimeMap/erase all remembers beginning sequence number` | *(not needed)*                       | N/A       |
| `TestArrivalTimeMap/erase to missing sequence number`              | *(not needed)*                       | N/A       |
| `TestArrivalTimeMap/remove old packets`                            | `test_arrival_time_map_remove_old`   | ✅         |
| `TestArrivalTimeMap/shrinks buffer when necessary`                 | *(implicit in other tests)*          | ✅         |
| `TestArrivalTimeMap/find next at or after with invalid sequence`   | *(not needed)*                       | N/A       |
| *(none)*                                                           | `test_arrival_time_map_sequential`   | ✅ (extra) |
| *(none)*                                                           | `test_arrival_time_map_clamp`        | ✅ (extra) |

### header_extension_interceptor_test.go vs sender.rs

| Pion Test                                                             | RTC Equivalent                                    | Status    |
|-----------------------------------------------------------------------|---------------------------------------------------|-----------|
| `TestHeaderExtensionInterceptor/if header is nil, return error`       | *(handled by Option type)*                        | ✅         |
| `TestHeaderExtensionInterceptor/add transport wide cc to each packet` | `test_twcc_sender_adds_extension`                 | ✅         |
| *(none)*                                                              | `test_twcc_sender_builder_defaults`               | ✅ (extra) |
| *(none)*                                                              | `test_twcc_sender_no_extension_without_binding`   | ✅ (extra) |
| *(none)*                                                              | `test_twcc_sender_unbind_removes_stream`          | ✅ (extra) |
| *(none)*                                                              | `test_twcc_sender_sequence_wraparound`            | ✅ (extra) |
| *(none)*                                                              | `test_twcc_sender_multiple_streams_share_counter` | ✅ (extra) |

### sender_interceptor_test.go vs receiver.rs

| Pion Test                                                    | RTC Equivalent                                     | Status    |
|--------------------------------------------------------------|----------------------------------------------------|-----------|
| `TestSenderInterceptor/before any packets`                   | `test_twcc_receiver_no_feedback_without_binding`   | ✅         |
| `TestSenderInterceptor/after RTP packets`                    | `test_twcc_receiver_generates_feedback_on_timeout` | ✅         |
| `TestSenderInterceptor/different delays between RTP packets` | *(implicit in other tests)*                        | ✅         |
| `TestSenderInterceptor/packet loss`                          | *(implicit in recorder tests)*                     | ✅         |
| `TestSenderInterceptor/overflow`                             | *(not needed - sans-I/O)*                          | N/A       |
| `TestSenderInterceptor_Leak`                                 | *(not needed - sans-I/O)*                          | N/A       |
| *(none)*                                                     | `test_twcc_receiver_builder_defaults`              | ✅ (extra) |
| *(none)*                                                     | `test_twcc_receiver_builder_custom_interval`       | ✅ (extra) |
| *(none)*                                                     | `test_twcc_receiver_records_packets`               | ✅ (extra) |
| *(none)*                                                     | `test_twcc_receiver_unbind_removes_stream`         | ✅ (extra) |
| *(none)*                                                     | `test_twcc_receiver_poll_timeout`                  | ✅ (extra) |

### twcc_test.go vs recorder.rs

| Pion Test                                                | RTC Equivalent                             | Status    |
|----------------------------------------------------------|--------------------------------------------|-----------|
| `Test_chunk_add/fill with not received`                  | *(implicit in test_chunk_status_vector)*   | ✅         |
| `Test_chunk_add/fill with small delta`                   | `test_chunk_run_length`                    | ✅         |
| `Test_chunk_add/fill with large delta`                   | *(implicit in test_chunk_status_vector)*   | ✅         |
| `Test_chunk_add/fill with different types`               | `test_chunk_status_vector`                 | ✅         |
| `Test_chunk_add/overfill and encode`                     | *(not needed)*                             | N/A       |
| `Test_feedback/add simple`                               | *(implicit in test_feedback_add_received)* | ✅         |
| `Test_feedback/add too large`                            | *(not needed)*                             | N/A       |
| `Test_feedback/add received 1`                           | `test_feedback_add_received`               | ✅         |
| `Test_feedback/add received 2`                           | *(implicit in test_feedback_add_received)* | ✅         |
| `Test_feedback/add received small deltas`                | *(implicit in other tests)*                | ✅         |
| `Test_feedback/add received wrapped sequence number`     | *(implicit in test_sequence_unwrapper)*    | ✅         |
| `Test_feedback/get RTCP`                                 | *(implicit in test_recorder_basic)*        | ✅         |
| `TestBuildFeedbackPacket`                                | `test_recorder_basic`                      | ✅         |
| `TestBuildFeedbackPacket_Rolling`                        | *(not needed)*                             | N/A       |
| `TestBuildFeedbackPacket_MinInput`                       | *(not needed)*                             | N/A       |
| `TestBuildFeedbackPacket_MissingPacketsBetweenFeedbacks` | `test_recorder_with_gaps`                  | ✅         |
| `TestBuildFeedbackPacketCount`                           | *(not needed)*                             | N/A       |
| `TestDuplicatePackets`                                   | *(not needed)*                             | N/A       |
| `TestShortDeltas/SplitsOneBitDeltas`                     | *(not needed)*                             | N/A       |
| `TestShortDeltas/padsTwoBitDeltas`                       | *(not needed)*                             | N/A       |
| `TestReorderedPackets`                                   | *(not needed)*                             | N/A       |
| `TestPacketsHeld`                                        | *(not needed)*                             | N/A       |
| *(none)*                                                 | `test_sequence_unwrapper`                  | ✅ (extra) |

### mod.rs tests (RTC only)

| Pion Test | RTC Equivalent              | Status    |
|-----------|-----------------------------|-----------|
| *(none)*  | `test_stream_supports_twcc` | ✅ (extra) |

### Test Summary

| Category         | Pion   | RTC    | Notes                                     |
|------------------|--------|--------|-------------------------------------------|
| arrival_time_map | 17     | 7      | Many pion tests for edge cases not needed |
| sender           | 2      | 6      | +5 extra tests                            |
| receiver         | 6      | 6      | -2 leak/overflow (sans-I/O), +5 extra     |
| recorder         | 22     | 6      | Many pion internal tests not needed       |
| mod.rs           | 0      | 1      | `test_stream_supports_twcc`               |
| **Total**        | **47** | **27** |                                           |

### Tests Not Ported

| Pion Test                        | Reason                                              |
|----------------------------------|-----------------------------------------------------|
| `TestSenderInterceptor/overflow` | Sans-I/O architecture has no overflow issues        |
| `TestSenderInterceptor_Leak`     | Sans-I/O architecture has no goroutine leaks        |
| Various edge case tests          | Internal implementation details, covered implicitly |

## Usage

```rust
use rtc_interceptor::{Registry, TwccSenderBuilder, TwccReceiverBuilder};
use std::time::Duration;

// Build interceptor chain with TWCC support
let chain = Registry::new()
.with(TwccSenderBuilder::new().build())
.with(TwccReceiverBuilder::new()
.with_interval(Duration::from_millis(100))
.build())
.build();
```

## Architecture

### Sans-I/O Design

Like other interceptors in this crate, the TWCC interceptors follow the sans-I/O pattern:

- No async/await
- Time is passed explicitly via `handle_timeout()` and `poll_timeout()`
- All state is managed synchronously
- Feedback packets are queued and retrieved via `poll_write()`

### Processing Flow

```text
Sender Side:
  Application → TwccSenderInterceptor → Network
                      ↓
              Adds transport-wide
              sequence number

Receiver Side:
  Network → TwccReceiverInterceptor → Application
                   ↓
           Records arrival times
           Generates TWCC feedback
           on timeout
```

### Key Components

1. **PacketArrivalTimeMap**: Circular buffer tracking packet arrival times
2. **SequenceUnwrapper**: Handles 16-bit sequence number wraparound
3. **Recorder**: Builds TransportLayerCC feedback packets
4. **Chunk**: Encodes packet status as RunLength or StatusVector chunks

---

## Compare with Async WebRTC Rust Implementation

This section compares this sans-I/O implementation with the async-based webrtc crate.

### Architecture Comparison

| Aspect            | Async WebRTC                               | Sans-I/O RTC                        |
|-------------------|--------------------------------------------|-------------------------------------|
| **Pattern**       | Async/await with Tokio runtime             | Sans-I/O with explicit time/polling |
| **Concurrency**   | `tokio::spawn`, channels, `Arc<AtomicU32>` | No async, no locks, explicit state  |
| **Feedback Loop** | Background task with `tokio::select!`      | Triggered by `handle_timeout()`     |
| **Arrival Time**  | `Instant::now()` in async task             | Passed via `msg.now`                |

### TWCC Sender Comparison

| Feature                 | Async WebRTC                   | Sans-I/O RTC                      |
|-------------------------|--------------------------------|-----------------------------------|
| **Sequence Counter**    | `Arc<AtomicU32>` (thread-safe) | `u16` field (no threading needed) |
| **Init Sequence**       | Configurable via builder       | Starts at 0                       |
| **Multi-Stream**        | Shared atomic counter          | Shared field across streams       |
| **Extension ID Source** | `stream_support_twcc()`        | `stream_supports_twcc()`          |

Both implementations correctly share the sequence counter across all streams
(transport-wide), as required by the TWCC specification.

### TWCC Receiver Comparison

| Feature                 | Async WebRTC                      | Sans-I/O RTC           |
|-------------------------|-----------------------------------|------------------------|
| **Default Interval**    | 100ms                             | 100ms                  |
| **Recorder Init**       | On stream bind                    | On first packet (lazy) |
| **Feedback Generation** | `tokio::select!` loop             | `handle_timeout()`     |
| **Channel**             | `mpsc::channel` for packet events | Direct state update    |

**Key Difference**: Sans-I/O defers recorder creation until the first packet arrives,
which is slightly more efficient for streams that may never receive TWCC packets.

### Recorder / Feedback Building Comparison

| Feature                  | Async WebRTC                           | Sans-I/O RTC                           |
|--------------------------|----------------------------------------|----------------------------------------|
| **Arrival Time Storage** | `Vec<PktInfo>` (sequence, time)        | `PacketArrivalTimeMap` circular buffer |
| **Sequence Unwrapping**  | In `record()` method                   | `SequenceUnwrapper` struct             |
| **Chunk Types**          | RunLength, StatusVector (1-bit, 2-bit) | Same three types                       |
| **Delta Scale**          | 250µs                                  | 250µs (TYPE_TCC_DELTA_SCALE_FACTOR)    |
| **Reference Time**       | 64ms units                             | 64ms units                             |
| **Packet Window**        | Not explicitly limited                 | 500ms (PACKET_WINDOW_MICROSECONDS)     |
| **Auto-Resize**          | ❌ Fixed `Vec`                          | ✅ Auto-grow/shrink circular buffer     |

**Key Differences**:

1. Sans-I/O uses `PacketArrivalTimeMap` with auto-resizing (doubles when full, shrinks when underutilized)
2. Sans-I/O has explicit 500ms packet window for culling old entries
3. Both use identical chunk encoding strategies

### Chunk Encoding Algorithm

Both implementations use the same TWCC chunk encoding decision tree:

```
Chunk Decision:
├── < 7 symbols  → Add to 2-bit status vector
├── < 14 symbols && no large delta → Add to 1-bit status vector
├── < 8191 && all same type → Add to run-length chunk
└── Otherwise → Emit current chunk, start new one

Delta Encoding:
├── Small delta: 0-255 (1 byte) → PacketReceivedSmallDelta
├── Large delta: fits i16 (2 bytes) → PacketReceivedLargeDelta
└── Not received → PacketNotReceived
```

### Constants Comparison

| Constant            | Async WebRTC  | Sans-I/O RTC |
|---------------------|---------------|--------------|
| Delta scale factor  | 250µs         | 250µs        |
| Reference time unit | 64ms          | 64ms         |
| Max run length      | 8191 (13-bit) | 8191         |
| Max 1-bit symbols   | 14            | 14           |
| Max 2-bit symbols   | 7             | 7            |
| Packet window       | Not defined   | 500ms        |

### Sequence Unwrapper Implementation

Both implementations handle 16-bit to 64-bit sequence number conversion:

```
Algorithm:
  diff = seq_i64 - last_unwrapped
  if diff > 0x8000:
      diff -= 0x10000   // Wrapped backward
  elif diff < -0x8000:
      diff += 0x10000   // Wrapped forward
  return last_unwrapped + diff
```

### PacketArrivalTimeMap (Sans-I/O only)

The sans-I/O implementation introduces a more sophisticated arrival time tracking structure:

```rust
struct PacketArrivalTimeMap {
    arrival_times: Vec<i64>,       // Circular buffer (-1 = not received)
    begin_sequence_number: i64,    // First valid sequence (inclusive)
    end_sequence_number: i64,      // First invalid sequence (exclusive)
}
```

Features:

- **Auto-resize**: Capacity starts at 128, doubles when needed, shrinks when < 25% used
- **Packet window**: Automatically removes entries older than 500ms
- **Efficient lookup**: O(1) access via circular buffer indexing

### Feature Completeness Summary

| Feature                      | Async WebRTC | Sans-I/O RTC |
|------------------------------|:------------:|:------------:|
| TWCC Sender basic            |      ✅       |      ✅       |
| Shared sequence counter      |      ✅       |      ✅       |
| TWCC Receiver basic          |      ✅       |      ✅       |
| Configurable interval        |      ✅       |      ✅       |
| Chunk encoding (all 3 types) |      ✅       |      ✅       |
| Large delta support          |      ✅       |      ✅       |
| Sequence unwrapping          |      ✅       |      ✅       |
| Arrival time auto-resize     |      ❌       |      ✅       |
| Packet window cleanup        |      ❌       |      ✅       |

### Recommendations

**Features to potentially backport to Async WebRTC**:

1. `PacketArrivalTimeMap` with auto-resize - More memory efficient for long-running sessions
2. Packet window cleanup (500ms) - Prevents unbounded memory growth

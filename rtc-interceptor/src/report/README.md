# RTCP Report Interceptors

This module provides RTCP report interceptors ported
from [pion/interceptor](https://github.com/pion/interceptor/tree/master/pkg/report).

## Overview

- **SenderReportInterceptor**: Generates RTCP Sender Reports (SR) for outgoing RTP streams with packet/octet counts and
  NTP timestamps.
- **ReceiverReportInterceptor**: Generates RTCP Receiver Reports (RR) for incoming RTP streams with loss statistics,
  jitter, and delay measurements.

## Usage

```rust
use rtc_interceptor::{Registry, SenderReportBuilder, ReceiverReportBuilder};
use std::time::Duration;

let chain = Registry::new()
.with(SenderReportBuilder::new()
.with_interval(Duration::from_secs(1))
.with_use_latest_packet(true)
.build())
.with(ReceiverReportBuilder::new()
.with_interval(Duration::from_secs(1))
.build())
.build();
```

## File Mapping (Pion to RTC)

| Pion (Go)                 | RTC (Rust)           | Description                                                |
|---------------------------|----------------------|------------------------------------------------------------|
| `report.go`               | `mod.rs`             | Module definition                                          |
| `sender_interceptor.go`   | `sender_report.rs`   | Sender Report interceptor                                  |
| `sender_option.go`        | `sender_report.rs`   | Builder options (merged into same file)                    |
| `sender_stream.go`        | `sender_stream.rs`   | Per-stream state for SR generation                         |
| `receiver_interceptor.go` | `receiver_report.rs` | Receiver Report interceptor                                |
| `receiver_option.go`      | `receiver_report.rs` | Builder options (merged into same file)                    |
| `receiver_stream.go`      | `receiver_stream.rs` | Per-stream state for RR generation                         |
| `ticker.go`               | *(not needed)*       | Custom ticker interface (sans-I/O uses `handle_timeout()`) |

## Feature Comparison

| Feature                | Pion | RTC | Notes                                  |
|------------------------|------|-----|----------------------------------------|
| **Sender Report**      |      |     |                                        |
| Configurable interval  | ✅    | ✅   | Duration between SR generation         |
| Custom logger          | ✅    | ➖   | Skipped                                |
| Custom ticker          | ✅    | ➖   | Sans-I/O uses `handle_timeout()`       |
| Custom now function    | ✅    | ➖   | Sans-I/O passes time explicitly        |
| useLatestPacket option | ✅    | ✅   | Use latest packet even if out-of-order |
| NTP timestamp          | ✅    | ✅   | Converts `Instant` to NTP format       |
| RTP timestamp          | ✅    | ✅   | From latest packet                     |
| Packet count           | ✅    | ✅   | Total packets sent                     |
| Octet count            | ✅    | ✅   | Total bytes sent                       |
| **Receiver Report**    |      |     |                                        |
| Configurable interval  | ✅    | ✅   | Duration between RR generation         |
| Custom logger          | ✅    | ➖   | Skipped                                |
| Custom now function    | ✅    | ➖   | Sans-I/O passes time explicitly        |
| Fraction lost          | ✅    | ✅   | Loss in last interval (8-bit)          |
| Cumulative lost        | ✅    | ✅   | Total packets lost (24-bit signed)     |
| Extended highest seq   | ✅    | ✅   | Cycles + highest seq number            |
| Jitter                 | ✅    | ✅   | Interarrival jitter estimate           |
| LSR (Last SR)          | ✅    | ✅   | Middle 32 bits of NTP timestamp        |
| DLSR (Delay since LSR) | ✅    | ✅   | Delay in 1/65536 seconds               |
| Sequence wrap handling | ✅    | ✅   | Tracks 16-bit cycle count              |

## Architecture Differences

| Aspect          | Pion                                 | RTC                                 |
|-----------------|--------------------------------------|-------------------------------------|
| Options pattern | Functional options in separate files | Builder pattern in same file        |
| Logging         | `logging.LeveledLogger`              | Not implemented                     |
| Concurrency     | `sync.Mutex`, goroutines             | Sans-I/O (no locks needed)          |
| Timer/Ticker    | `time.Ticker` in goroutine           | `handle_timeout()`/`poll_timeout()` |
| Time source     | `time.Now()` or injected function    | Time passed via `TaggedPacket.now`  |
| NTP conversion  | `toNtpTime()` helper                 | `instant_to_ntp()` helper           |
| History bitmap  | `[]uint64` with manual bit ops       | `Vec<u64>` with manual bit ops      |

## Test Comparison

### sender_interceptor_test.go vs sender_report.rs + sender_stream.rs

| Pion Test                                                       | RTC Equivalent                                           | Status    |
|-----------------------------------------------------------------|----------------------------------------------------------|-----------|
| `TestSenderInterceptor/before any packet`                       | `test_sender_stream_before_any_packet`                   | ✅         |
| `TestSenderInterceptor/after RTP packets`                       | `test_sender_stream_after_rtp_packets`                   | ✅         |
| `TestSenderInterceptor/out of order RTP packets`                | `test_sender_stream_out_of_order_packets`                | ✅         |
| `TestSenderInterceptor/out of order with SenderUseLatestPacket` | `test_sender_stream_out_of_order_with_use_latest_packet` | ✅         |
| `TestSenderInterceptor/inject ticker`                           | *(not needed - sans-I/O)*                                | ➖         |
| *(none)*                                                        | `test_sender_report_builder_default`                     | ✅ (extra) |
| *(none)*                                                        | `test_sender_report_builder_with_custom_interval`        | ✅ (extra) |
| *(none)*                                                        | `test_sender_report_chain_handle_read_write`             | ✅ (extra) |
| *(none)*                                                        | `test_should_filter`                                     | ✅ (extra) |
| *(none)*                                                        | `test_inner_access`                                      | ✅ (extra) |
| *(none)*                                                        | `test_use_latest_packet_option`                          | ✅ (extra) |
| *(none)*                                                        | `test_use_latest_packet_combined_options`                | ✅ (extra) |
| *(none)*                                                        | `test_sender_report_generation_on_timeout`               | ✅ (extra) |
| *(none)*                                                        | `test_sender_report_multiple_streams`                    | ✅ (extra) |
| *(none)*                                                        | `test_sender_report_unbind_stream`                       | ✅ (extra) |
| *(none)*                                                        | `test_poll_timeout_returns_earliest`                     | ✅ (extra) |
| *(none)*                                                        | `test_sender_stream_frame_first_packet_optimization`     | ✅ (extra) |
| *(none)*                                                        | `test_sender_stream_sequence_wrap`                       | ✅ (extra) |
| *(none)*                                                        | `test_counters_wrapping`                                 | ✅ (extra) |

### receiver_interceptor_test.go vs receiver_report.rs + receiver_stream.rs

| Pion Test                                            | RTC Equivalent                                      | Status    |
|------------------------------------------------------|-----------------------------------------------------|-----------|
| `TestReceiverInterceptor/before any packet`          | `test_receiver_stream_before_any_packet`            | ✅         |
| `TestReceiverInterceptor/after RTP packets`          | `test_receiver_stream_after_rtp_packets`            | ✅         |
| `TestReceiverInterceptor/after RTP and RTCP packets` | `test_receiver_report_with_sender_report`           | ✅         |
| `TestReceiverInterceptor/overflow`                   | `test_receiver_stream_overflow`                     | ✅         |
| `TestReceiverInterceptor/packet loss`                | `test_receiver_stream_packet_loss`                  | ✅         |
| `TestReceiverInterceptor/overflow and packet loss`   | `test_receiver_stream_overflow_and_packet_loss`     | ✅         |
| `TestReceiverInterceptor/reordered packets`          | `test_receiver_stream_reordered_packets`            | ✅         |
| `TestReceiverInterceptor/jitter`                     | `test_receiver_stream_jitter`                       | ✅         |
| `TestReceiverInterceptor/delay`                      | `test_receiver_stream_delay`                        | ✅         |
| *(none)*                                             | `test_receiver_report_builder_default`              | ✅ (extra) |
| *(none)*                                             | `test_receiver_report_builder_with_custom_interval` | ✅ (extra) |
| *(none)*                                             | `test_receiver_report_chain_handle_read_write`      | ✅ (extra) |
| *(none)*                                             | `test_register_stream`                              | ✅ (extra) |
| *(none)*                                             | `test_process_rtp`                                  | ✅ (extra) |
| *(none)*                                             | `test_generate_reports`                             | ✅ (extra) |
| *(none)*                                             | `test_chained_interceptors`                         | ✅ (extra) |
| *(none)*                                             | `test_receiver_report_generation_on_timeout`        | ✅ (extra) |
| *(none)*                                             | `test_receiver_report_with_packet_loss`             | ✅ (extra) |
| *(none)*                                             | `test_receiver_report_multiple_streams`             | ✅ (extra) |
| *(none)*                                             | `test_receiver_report_unbind_stream`                | ✅ (extra) |
| *(none)*                                             | `test_receiver_report_sequence_wrap`                | ✅ (extra) |
| *(none)*                                             | `test_receiver_stream_delay_before_sender_report`   | ✅ (extra) |
| *(none)*                                             | `test_receiver_stream_cumulative_loss`              | ✅ (extra) |
| *(none)*                                             | `test_receiver_stream_24bit_loss_clamping`          | ✅ (extra) |

### receiver_stream_test.go vs receiver_stream.rs

| Pion Test                                        | RTC Equivalent                     | Status |
|--------------------------------------------------|------------------------------------|--------|
| `TestReceiverStream/can use entire history size` | `test_can_use_entire_history_size` | ✅      |

### Integration Tests (tests/rtcp_report_integration.rs)

| Test                                                       | Description              |
|------------------------------------------------------------|--------------------------|
| `test_sender_report_interceptor_generates_sr_on_timeout`   | SR generation on timeout |
| `test_sender_report_tracks_packet_statistics`              | Packet/octet counting    |
| `test_sender_report_multiple_streams`                      | Multiple SSRC handling   |
| `test_receiver_report_interceptor_generates_rr_on_timeout` | RR generation on timeout |
| `test_receiver_report_tracks_sequence_numbers`             | Sequence tracking        |
| `test_receiver_report_detects_packet_loss`                 | Loss detection           |
| `test_combined_sender_and_receiver_interceptors`           | SR + RR chain            |
| `test_interceptor_chain_unbind_streams`                    | Stream cleanup           |
| `test_receiver_processes_sender_report`                    | LSR/DLSR calculation     |
| `test_report_interval_is_respected`                        | Interval timing          |
| `test_poll_timeout_returns_earliest`                       | Timeout ordering         |

### Test Summary

| Category           | Pion   | RTC    | Notes                                                      |
|--------------------|--------|--------|------------------------------------------------------------|
| sender_report.rs   | -      | 11     | Builder, chain, timeout, filtering tests                   |
| sender_stream.rs   | 4      | 7      | +3 extra (sequence wrap, counter wrap, frame optimization) |
| receiver_report.rs | -      | 13     | Builder, chain, timeout, loss, SR processing tests         |
| receiver_stream.rs | 10     | 12     | +2 extra (delay before SR, 24-bit clamping)                |
| integration        | 0      | 11     | All extra                                                  |
| **Total**          | **14** | **54** |                                                            |

### Tests Not Ported

| Pion Test            | Reason                                    |
|----------------------|-------------------------------------------|
| `inject ticker` test | Sans-I/O architecture doesn't use tickers |

---

## Compare with Async WebRTC Rust Implementation

This section compares this sans-I/O implementation with the async-based webrtc crate.

### Architecture Comparison

| Aspect          | Async WebRTC                                      | Sans-I/O RTC                            |
|-----------------|---------------------------------------------------|-----------------------------------------|
| **Pattern**     | Async/await with Tokio runtime                    | Sans-I/O with explicit time/polling     |
| **Concurrency** | `Arc<Mutex<>>`, `tokio::spawn`, WaitGroup         | No async, no locks, explicit state      |
| **Timer**       | `tokio::time::interval()` with MissedTickBehavior | `handle_timeout()` / `poll_timeout()`   |
| **Time Source** | `SystemTime::now()` or injected function          | `Instant` passed via `TaggedPacket.now` |
| **Lifecycle**   | WaitGroup for graceful shutdown                   | No background tasks to manage           |

### Sender Report Comparison

| Feature                | Async WebRTC                         | Sans-I/O RTC                     |
|------------------------|--------------------------------------|----------------------------------|
| **Default Interval**   | 1 second                             | 1 second                         |
| **Custom Interval**    | ✅ `with_interval()`                  | ✅ `with_interval()`              |
| **Custom Time Source** | ✅ `with_now_fn()`                    | ➖ Time passed explicitly         |
| **use_latest_packet**  | ❌ Not implemented                    | ✅ `with_use_latest_packet()`     |
| **NTP Timestamp**      | `unix2ntp()` from SystemTime         | `instant_to_ntp()` from Instant  |
| **RTP Timestamp**      | `last_rtp + elapsed * clock_rate`    | Same algorithm                   |
| **Packet Count**       | Wrapping u32                         | Wrapping u32                     |
| **Octet Count**        | Wrapping u32 (saturates on overflow) | Wrapping u32 (warns on overflow) |
| **Report Generation**  | Background tokio task                | `handle_timeout()` triggers      |

**Key Difference**: Sans-I/O adds `use_latest_packet` option that controls whether out-of-order
packets update the RTP↔NTP timestamp mapping. This prevents timestamp corruption when packets
arrive reordered.

### Sender Stream State Comparison

| Field                | Async WebRTC   | Sans-I/O RTC                   |
|----------------------|----------------|--------------------------------|
| `ssrc`               | ✅              | ✅                              |
| `clock_rate`         | ✅ f64          | ✅ f64                          |
| `last_rtp_time_rtp`  | ✅ u32          | ✅ u32                          |
| `last_rtp_time_time` | ✅ SystemTime   | ✅ Instant                      |
| `counters.packets`   | ✅ u32 wrapping | ✅ u32 wrapping                 |
| `counters.octets`    | ✅ u32 wrapping | ✅ u32 wrapping                 |
| `use_latest_packet`  | ❌              | ✅ bool                         |
| `last_rtp_sn`        | ❌              | ✅ u16 (for order detection)    |
| `time_baseline`      | ❌              | ✅ SystemInstant (for NTP calc) |

### Receiver Report Comparison

| Feature                  | Async WebRTC             | Sans-I/O RTC                |
|--------------------------|--------------------------|-----------------------------|
| **Default Interval**     | 1 second                 | 1 second                    |
| **Custom Interval**      | ✅ `with_interval()`      | ✅ `with_interval()`         |
| **Custom Time Source**   | ✅ `with_now_fn()`        | ➖ Time passed explicitly    |
| **Fraction Lost**        | ✅ 8-bit (0-255)          | ✅ 8-bit (0-255)             |
| **Total Lost**           | ✅ 24-bit clamped         | ✅ 24-bit clamped            |
| **Extended Highest Seq** | ✅ cycles << 16           | seq                         | ✅ Same algorithm |
| **Jitter**               | ✅ RFC 3550 (1/16 weight) | ✅ RFC 3550 (1/16 weight)    |
| **LSR**                  | ✅ Middle 32 bits of NTP  | ✅ Middle 32 bits of NTP     |
| **DLSR**                 | ✅ 1/65536 second units   | ✅ 1/65536 second units      |
| **Report Generation**    | Background tokio task    | `handle_timeout()` triggers |

Both implementations are **RFC 3550 compliant** for all receiver report fields.

### Receiver Stream State Comparison

| Field                     | Async WebRTC                   | Sans-I/O RTC                   |
|---------------------------|--------------------------------|--------------------------------|
| `ssrc`                    | ✅                              | ✅                              |
| `receiver_ssrc`           | ✅ random                       | ✅ random                       |
| `clock_rate`              | ✅ f64                          | ✅ f64                          |
| `packets` (bitmap)        | ✅ `Vec<u64>` (128 × 64 = 8192) | ✅ `Vec<u64>` (128 × 64 = 8192) |
| `seq_num_cycles`          | ✅ u16                          | ✅ u16                          |
| `last_seq_num`            | ✅ i32                          | ✅ u16                          |
| `last_report_seq_num`     | ✅ i32                          | ✅ u16                          |
| `last_rtp_time_rtp`       | ✅ u32                          | ✅ u32                          |
| `last_rtp_time_time`      | ✅ SystemTime                   | ✅ Instant                      |
| `jitter`                  | ✅ f64                          | ✅ f64                          |
| `last_sender_report`      | ✅ u32                          | ✅ u32                          |
| `last_sender_report_time` | ✅ SystemTime                   | ✅ Option<Instant>              |
| `total_lost`              | ✅ u32                          | ✅ u32                          |

### Packet Loss Tracking Algorithm

Both implementations use identical bitmap-based packet tracking:

```
Bitmap Structure:
  - 128 u64 entries = 8192 packet capacity
  - Each bit represents one sequence number
  - Index: (seq % 8192) / 64
  - Bit:   (seq % 8192) % 64

Loss Detection:
  - On each in-order packet: gaps marked as lost
  - Wraparound: seq < last_seq increments cycle counter
  - Out-of-order: still tracked in bitmap
```

### Jitter Calculation (RFC 3550)

Both implementations use identical jitter calculation:

```
D = |arrival_delta × clock_rate - timestamp_delta|
jitter = jitter + (|D| - jitter) / 16.0
```

The 1/16 weighting factor provides exponential smoothing as specified in RFC 3550 Section 6.4.4.

### DLSR Calculation

Both implementations calculate DLSR identically:

```
DLSR = (now - last_sr_receive_time) × 65536
```

Returns 0 if no Sender Report has been received yet.

### Filtering Behavior

| Packet Type               | Async WebRTC     | Sans-I/O RTC            |
|---------------------------|------------------|-------------------------|
| ReceiverReport (RR)       | ❌ Not filtered   | ✅ Filtered (hop-by-hop) |
| TransportSpecificFeedback | ❌ Not filtered   | ✅ Filtered (hop-by-hop) |
| SenderReport (SR)         | ✅ Passed through | ✅ Passed through        |
| Goodbye (BYE)             | ✅ Passed through | ✅ Passed through        |
| SourceDescription (SDES)  | ✅ Passed through | ✅ Passed through        |

**Key Difference**: Sans-I/O implementation filters hop-by-hop RTCP reports (RR and
TransportSpecificFeedback) that shouldn't be forwarded end-to-end.

### Frame-First Packet Optimization

| Feature                 | Async WebRTC              | Sans-I/O RTC               |
|-------------------------|---------------------------|----------------------------|
| Frame detection         | ❌ Updates on every packet | ✅ Only on timestamp change |
| Processing delay impact | May affect SR timestamps  | Minimized                  |

**Sans-I/O Optimization**: Only the first packet of each video frame (detected by RTP timestamp
change) updates the RTP↔NTP mapping. This prevents processing delays from affecting SR accuracy.

### Feature Completeness Summary

| Feature                     | Async WebRTC |   Sans-I/O RTC    |
|-----------------------------|:------------:|:-----------------:|
| Sender Report basic         |      ✅       |         ✅         |
| SR custom interval          |      ✅       |         ✅         |
| SR use_latest_packet        |      ❌       |         ✅         |
| SR frame-first optimization |      ❌       |         ✅         |
| Receiver Report basic       |      ✅       |         ✅         |
| RR custom interval          |      ✅       |         ✅         |
| RR fraction lost            |      ✅       |         ✅         |
| RR total lost (24-bit)      |      ✅       |         ✅         |
| RR jitter (RFC 3550)        |      ✅       |         ✅         |
| RR LSR/DLSR                 |      ✅       |         ✅         |
| Sequence wraparound         |      ✅       |         ✅         |
| Hop-by-hop filtering        |      ❌       |         ✅         |
| Custom time source          |      ✅       | ➖ (explicit time) |

### Recommendations

**Features to potentially backport to Async WebRTC**:

1. `use_latest_packet` option - Prevents timestamp corruption from reordered packets
2. Frame-first packet optimization - More accurate SR timestamps
3. Hop-by-hop RTCP filtering - Proper end-to-end forwarding behavior

**Features unique to Async WebRTC**:

1. Custom time source injection (`with_now_fn()`) - Useful for testing without sans-I/O pattern

# RTCP Report Interceptors

This module provides RTCP report interceptors ported from [pion/interceptor](https://github.com/pion/interceptor/tree/master/pkg/report).

## Overview

- **SenderReportInterceptor**: Generates RTCP Sender Reports (SR) for outgoing RTP streams with packet/octet counts and NTP timestamps.
- **ReceiverReportInterceptor**: Generates RTCP Receiver Reports (RR) for incoming RTP streams with loss statistics, jitter, and delay measurements.

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

## File Mapping (Pion to webrtc-rs)

| Pion (Go) | webrtc-rs (Rust) | Description |
|-----------|------------------|-------------|
| `report.go` | `mod.rs` | Module definition |
| `sender_interceptor.go` | `sender_report.rs` | Sender Report interceptor |
| `sender_option.go` | `sender_report.rs` | Builder options (merged into same file) |
| `sender_stream.go` | `sender_stream.rs` | Per-stream state for SR generation |
| `receiver_interceptor.go` | `receiver_report.rs` | Receiver Report interceptor |
| `receiver_option.go` | `receiver_report.rs` | Builder options (merged into same file) |
| `receiver_stream.go` | `receiver_stream.rs` | Per-stream state for RR generation |
| `ticker.go` | *(not needed)* | Custom ticker interface (sans-I/O uses `handle_timeout()`) |

## Feature Comparison

| Feature | Pion | webrtc-rs | Notes |
|---------|------|-----------|-------|
| **Sender Report** | | | |
| Configurable interval | ✅ | ✅ | Duration between SR generation |
| Custom logger | ✅ | ➖ | Skipped |
| Custom ticker | ✅ | ➖ | Sans-I/O uses `handle_timeout()` |
| Custom now function | ✅ | ➖ | Sans-I/O passes time explicitly |
| useLatestPacket option | ✅ | ✅ | Use latest packet even if out-of-order |
| NTP timestamp | ✅ | ✅ | Converts `Instant` to NTP format |
| RTP timestamp | ✅ | ✅ | From latest packet |
| Packet count | ✅ | ✅ | Total packets sent |
| Octet count | ✅ | ✅ | Total bytes sent |
| **Receiver Report** | | | |
| Configurable interval | ✅ | ✅ | Duration between RR generation |
| Custom logger | ✅ | ➖ | Skipped |
| Custom now function | ✅ | ➖ | Sans-I/O passes time explicitly |
| Fraction lost | ✅ | ✅ | Loss in last interval (8-bit) |
| Cumulative lost | ✅ | ✅ | Total packets lost (24-bit signed) |
| Extended highest seq | ✅ | ✅ | Cycles + highest seq number |
| Jitter | ✅ | ✅ | Interarrival jitter estimate |
| LSR (Last SR) | ✅ | ✅ | Middle 32 bits of NTP timestamp |
| DLSR (Delay since LSR) | ✅ | ✅ | Delay in 1/65536 seconds |
| Sequence wrap handling | ✅ | ✅ | Tracks 16-bit cycle count |

## Architecture Differences

| Aspect | Pion | webrtc-rs |
|--------|------|-----------|
| Options pattern | Functional options in separate files | Builder pattern in same file |
| Logging | `logging.LeveledLogger` | Not implemented |
| Concurrency | `sync.Mutex`, goroutines | Sans-I/O (no locks needed) |
| Timer/Ticker | `time.Ticker` in goroutine | `handle_timeout()`/`poll_timeout()` |
| Time source | `time.Now()` or injected function | Time passed via `TaggedPacket.now` |
| NTP conversion | `toNtpTime()` helper | `instant_to_ntp()` helper |
| History bitmap | `[]uint64` with manual bit ops | `Vec<u64>` with manual bit ops |

## Test Comparison

### sender_interceptor_test.go vs sender_report.rs + sender_stream.rs

| Pion Test | webrtc-rs Equivalent | Status |
|-----------|---------------------|--------|
| `TestSenderInterceptor/before any packet` | `test_sender_stream_before_any_packet` | ✅ |
| `TestSenderInterceptor/after RTP packets` | `test_sender_stream_after_rtp_packets` | ✅ |
| `TestSenderInterceptor/out of order RTP packets` | `test_sender_stream_out_of_order_packets` | ✅ |
| `TestSenderInterceptor/out of order with SenderUseLatestPacket` | `test_sender_stream_out_of_order_with_use_latest_packet` | ✅ |
| `TestSenderInterceptor/inject ticker` | *(not needed - sans-I/O)* | ➖ |
| *(none)* | `test_sender_report_builder_default` | ✅ (extra) |
| *(none)* | `test_sender_report_builder_with_custom_interval` | ✅ (extra) |
| *(none)* | `test_sender_report_chain_handle_read_write` | ✅ (extra) |
| *(none)* | `test_should_filter` | ✅ (extra) |
| *(none)* | `test_inner_access` | ✅ (extra) |
| *(none)* | `test_use_latest_packet_option` | ✅ (extra) |
| *(none)* | `test_use_latest_packet_combined_options` | ✅ (extra) |
| *(none)* | `test_sender_report_generation_on_timeout` | ✅ (extra) |
| *(none)* | `test_sender_report_multiple_streams` | ✅ (extra) |
| *(none)* | `test_sender_report_unbind_stream` | ✅ (extra) |
| *(none)* | `test_poll_timeout_returns_earliest` | ✅ (extra) |
| *(none)* | `test_sender_stream_frame_first_packet_optimization` | ✅ (extra) |
| *(none)* | `test_sender_stream_sequence_wrap` | ✅ (extra) |
| *(none)* | `test_counters_wrapping` | ✅ (extra) |

### receiver_interceptor_test.go vs receiver_report.rs + receiver_stream.rs

| Pion Test | webrtc-rs Equivalent | Status |
|-----------|---------------------|--------|
| `TestReceiverInterceptor/before any packet` | `test_receiver_stream_before_any_packet` | ✅ |
| `TestReceiverInterceptor/after RTP packets` | `test_receiver_stream_after_rtp_packets` | ✅ |
| `TestReceiverInterceptor/after RTP and RTCP packets` | `test_receiver_report_with_sender_report` | ✅ |
| `TestReceiverInterceptor/overflow` | `test_receiver_stream_overflow` | ✅ |
| `TestReceiverInterceptor/packet loss` | `test_receiver_stream_packet_loss` | ✅ |
| `TestReceiverInterceptor/overflow and packet loss` | `test_receiver_stream_overflow_and_packet_loss` | ✅ |
| `TestReceiverInterceptor/reordered packets` | `test_receiver_stream_reordered_packets` | ✅ |
| `TestReceiverInterceptor/jitter` | `test_receiver_stream_jitter` | ✅ |
| `TestReceiverInterceptor/delay` | `test_receiver_stream_delay` | ✅ |
| *(none)* | `test_receiver_report_builder_default` | ✅ (extra) |
| *(none)* | `test_receiver_report_builder_with_custom_interval` | ✅ (extra) |
| *(none)* | `test_receiver_report_chain_handle_read_write` | ✅ (extra) |
| *(none)* | `test_register_stream` | ✅ (extra) |
| *(none)* | `test_process_rtp` | ✅ (extra) |
| *(none)* | `test_generate_reports` | ✅ (extra) |
| *(none)* | `test_chained_interceptors` | ✅ (extra) |
| *(none)* | `test_receiver_report_generation_on_timeout` | ✅ (extra) |
| *(none)* | `test_receiver_report_with_packet_loss` | ✅ (extra) |
| *(none)* | `test_receiver_report_multiple_streams` | ✅ (extra) |
| *(none)* | `test_receiver_report_unbind_stream` | ✅ (extra) |
| *(none)* | `test_receiver_report_sequence_wrap` | ✅ (extra) |
| *(none)* | `test_receiver_stream_delay_before_sender_report` | ✅ (extra) |
| *(none)* | `test_receiver_stream_cumulative_loss` | ✅ (extra) |
| *(none)* | `test_receiver_stream_24bit_loss_clamping` | ✅ (extra) |

### receiver_stream_test.go vs receiver_stream.rs

| Pion Test | webrtc-rs Equivalent | Status |
|-----------|---------------------|--------|
| `TestReceiverStream/can use entire history size` | `test_can_use_entire_history_size` | ✅ |

### Integration Tests (tests/rtcp_report_integration.rs)

| Test | Description |
|------|-------------|
| `test_sender_report_interceptor_generates_sr_on_timeout` | SR generation on timeout |
| `test_sender_report_tracks_packet_statistics` | Packet/octet counting |
| `test_sender_report_multiple_streams` | Multiple SSRC handling |
| `test_receiver_report_interceptor_generates_rr_on_timeout` | RR generation on timeout |
| `test_receiver_report_tracks_sequence_numbers` | Sequence tracking |
| `test_receiver_report_detects_packet_loss` | Loss detection |
| `test_combined_sender_and_receiver_interceptors` | SR + RR chain |
| `test_interceptor_chain_unbind_streams` | Stream cleanup |
| `test_receiver_processes_sender_report` | LSR/DLSR calculation |
| `test_report_interval_is_respected` | Interval timing |
| `test_poll_timeout_returns_earliest` | Timeout ordering |

### Test Summary

| Category | Pion | webrtc-rs | Notes |
|----------|------|-----------|-------|
| sender_report.rs | - | 11 | Builder, chain, timeout, filtering tests |
| sender_stream.rs | 4 | 7 | +3 extra (sequence wrap, counter wrap, frame optimization) |
| receiver_report.rs | - | 13 | Builder, chain, timeout, loss, SR processing tests |
| receiver_stream.rs | 10 | 12 | +2 extra (delay before SR, 24-bit clamping) |
| integration | 0 | 11 | All extra |
| **Total** | **14** | **54** | |

### Tests Not Ported

| Pion Test | Reason |
|-----------|--------|
| `inject ticker` test | Sans-I/O architecture doesn't use tickers |

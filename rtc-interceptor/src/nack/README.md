# NACK Interceptor

This module provides NACK (Negative Acknowledgement) interceptors ported
from [pion/interceptor](https://github.com/pion/interceptor/tree/master/pkg/nack).

## Overview

- **NackGeneratorInterceptor**: Monitors incoming RTP packets and generates NACK requests for missing packets.
- **NackResponderInterceptor**: Buffers outgoing RTP packets and retransmits them when NACK requests are received.

## Usage

```rust
use rtc_interceptor::{Registry, NackGeneratorBuilder, NackResponderBuilder};
use std::time::Duration;

let chain = Registry::new()
.with(NackGeneratorBuilder::new()
.with_size(512)
.with_interval(Duration::from_millis(100))
.with_skip_last_n(2)
.build())
.with(NackResponderBuilder::new()
.with_size(1024)
.build())
.build();
```

## File Mapping (Pion to webrtc-rs)

| Pion (Go)                         | webrtc-rs (Rust) | Description                                        |
|-----------------------------------|------------------|----------------------------------------------------|
| `nack.go`                         | `mod.rs`         | Module definition, `stream_supports_nack()` helper |
| `receive_log.go`                  | `receive_log.rs` | Bitmap for tracking received packets               |
| `internal/rtpbuffer/rtpbuffer.go` | `send_buffer.rs` | Buffer for storing sent RTP packets                |
| `generator_interceptor.go`        | `generator.rs`   | NACK generator interceptor                         |
| `generator_option.go`             | `generator.rs`   | Builder options (merged into same file)            |
| `responder_interceptor.go`        | `responder.rs`   | NACK responder interceptor                         |
| `responder_option.go`             | `responder.rs`   | Builder options (merged into same file)            |
| `errors.go`                       | *(not needed)*   | Error types (using `Option` instead)               |

## Feature Comparison

| Feature                       | Pion | webrtc-rs | Notes                                             |
|-------------------------------|------|-----------|---------------------------------------------------|
| **Generator**                 |      |           |                                                   |
| Configurable size             | ✅    | ✅         | 64-32768, power of 2                              |
| Configurable interval         | ✅    | ✅         | Duration between NACK cycles                      |
| skip_last_n                   | ✅    | ✅         | Skip recent packets                               |
| max_nacks_per_packet          | ✅    | ✅         | Limit retransmission requests                     |
| Stream filter                 | ✅    | ✅         | Via `stream_supports_nack()`                      |
| Custom logger                 | ✅    | ➖         | Skipped                                           |
| Custom ticker                 | ✅    | ➖         | Sans-I/O uses `handle_timeout()`                  |
| **Responder**                 |      |           |                                                   |
| Configurable size             | ✅    | ✅         | 1-32768, power of 2                               |
| Stream filter                 | ✅    | ✅         | Via `stream_supports_nack()`                      |
| Packet factory (copy/no-copy) | ✅    | ➖         | Always clone packets                              |
| RFC4588 RTX support           | ✅    | ✅         | Retransmit on separate SSRC with modified payload |
| Custom logger                 | ✅    | ➖         | Skipped                                           |

## Architecture Differences

| Aspect          | Pion                                         | webrtc-rs                           |
|-----------------|----------------------------------------------|-------------------------------------|
| Options pattern | Functional options in separate files         | Builder pattern in same file        |
| Error handling  | `ErrInvalidSize` error                       | `Option<T>` return type             |
| Logging         | `logging.LeveledLogger`                      | Not implemented                     |
| Concurrency     | `sync.Mutex`, goroutines                     | Sans-I/O (no locks needed)          |
| Timer/Ticker    | `time.Ticker` in goroutine                   | `handle_timeout()`/`poll_timeout()` |
| RTP buffer      | `internal/rtpbuffer` with `RetainablePacket` | Simple `Vec<Option<rtp::Packet>>`   |
| Packet factory  | `PacketFactory` interface                    | Always clone                        |

## Test Comparison

### receive_log_test.go vs receive_log.rs

| Pion Test                                    | webrtc-rs Equivalent            | Status    |
|----------------------------------------------|---------------------------------|-----------|
| `TestReceivedBuffer` (multiple start points) | `test_receive_log_pion_compat`  | ✅         |
| *(implicit)*                                 | `test_receive_log_basic`        | ✅ (extra) |
| *(implicit)*                                 | `test_receive_log_invalid_size` | ✅ (extra) |
| *(implicit)*                                 | `test_receive_log_valid_sizes`  | ✅ (extra) |
| *(implicit)*                                 | `test_receive_log_with_gap`     | ✅ (extra) |
| *(implicit)*                                 | `test_receive_log_skip_last_n`  | ✅ (extra) |
| *(implicit)*                                 | `test_receive_log_out_of_order` | ✅ (extra) |
| *(implicit)*                                 | `test_receive_log_wraparound`   | ✅ (extra) |

### generator_interceptor_test.go vs generator.rs

| Pion Test                                                    | webrtc-rs Equivalent                          | Status    |
|--------------------------------------------------------------|-----------------------------------------------|-----------|
| `TestGeneratorInterceptor`                                   | `test_nack_generator_generates_nack`          | ✅         |
| `TestGeneratorInterceptor_InvalidSize`                       | *(handled by Option return)*                  | ✅         |
| `TestGeneratorInterceptor_StreamFilter`                      | `test_nack_generator_no_nack_support`         | ✅         |
| `TestGeneratorInterceptor_UnbindRemovesCorrespondingSSRC`    | `test_nack_generator_unbind_removes_stream`   | ✅         |
| `TestGeneratorInterceptor_NoDeadlockWithReentrantRTCPWriter` | *(not needed - sans-I/O)*                     | N/A       |
| *(none)*                                                     | `test_nack_generator_builder_defaults`        | ✅ (extra) |
| *(none)*                                                     | `test_nack_generator_builder_custom`          | ✅ (extra) |
| *(none)*                                                     | `test_nack_generator_no_nack_without_binding` | ✅ (extra) |
| *(none)*                                                     | `test_nack_generator_skip_last_n`             | ✅ (extra) |

### responder_interceptor_test.go vs responder.rs

| Pion Test                                                   | webrtc-rs Equivalent                                | Status    |
|-------------------------------------------------------------|-----------------------------------------------------|-----------|
| `TestResponderInterceptor` (with copy)                      | `test_nack_responder_retransmits_packet`            | ✅         |
| `TestResponderInterceptor` (without copy)                   | *(not needed - always clone)*                       | N/A       |
| `TestResponderInterceptor_InvalidSize`                      | *(handled by Option return)*                        | ✅         |
| `TestResponderInterceptor_DisableCopy`                      | *(not needed)*                                      | N/A       |
| `TestResponderInterceptor_Race`                             | *(not needed - sans-I/O)*                           | N/A       |
| `TestResponderInterceptor_RaceConcurrentStreams`            | *(not needed - sans-I/O)*                           | N/A       |
| `TestResponderInterceptor_StreamFilter`                     | `test_nack_responder_no_nack_support`               | ✅         |
| `TestResponderInterceptor_RFC4588`                          | `test_nack_responder_rfc4588_rtx`                   | ✅         |
| `TestResponderInterceptor_BypassUnknownSSRCs`               | *(implicit in other tests)*                         | ✅         |
| `TestResponderInterceptor_NoDeadlockWithReentrantRTPWriter` | *(not needed - sans-I/O)*                           | N/A       |
| *(none)*                                                    | `test_nack_responder_builder_defaults`              | ✅ (extra) |
| *(none)*                                                    | `test_nack_responder_builder_custom`                | ✅ (extra) |
| *(none)*                                                    | `test_nack_responder_no_retransmit_without_binding` | ✅ (extra) |
| *(none)*                                                    | `test_nack_responder_no_retransmit_expired_packet`  | ✅ (extra) |
| *(none)*                                                    | `test_nack_responder_unbind_removes_stream`         | ✅ (extra) |
| *(none)*                                                    | `test_nack_responder_passthrough`                   | ✅ (extra) |

### send_buffer.rs (no pion equivalent tests)

| Pion Test | webrtc-rs Equivalent                  | Status    |
|-----------|---------------------------------------|-----------|
| *(none)*  | `test_send_buffer_basic`              | ✅ (extra) |
| *(none)*  | `test_send_buffer_invalid_size`       | ✅ (extra) |
| *(none)*  | `test_send_buffer_valid_sizes`        | ✅ (extra) |
| *(none)*  | `test_send_buffer_overwrite`          | ✅ (extra) |
| *(none)*  | `test_send_buffer_gap_clears_packets` | ✅ (extra) |
| *(none)*  | `test_send_buffer_out_of_range`       | ✅ (extra) |
| *(none)*  | `test_send_buffer_wraparound`         | ✅ (extra) |
| *(none)*  | `test_send_buffer_out_of_order`       | ✅ (extra) |

### Test Summary

| Category    | Pion   | webrtc-rs | Notes                                                          |
|-------------|--------|-----------|----------------------------------------------------------------|
| receive_log | 1      | 8         | Pion's single test covers many cases; split into focused tests |
| generator   | 4      | 7         | +3 extra, -1 deadlock test (not needed in sans-I/O)            |
| responder   | 8      | 9         | -3 race/deadlock, +4 extra, +1 RFC4588                         |
| send_buffer | 0      | 8         | All extra (pion tests rtpbuffer indirectly)                    |
| mod.rs      | 0      | 1         | `test_stream_supports_nack`                                    |
| **Total**   | **13** | **33**    |                                                                |

### Tests Not Ported

| Pion Test           | Reason                                          |
|---------------------|-------------------------------------------------|
| Race/deadlock tests | Sans-I/O architecture has no concurrency issues |
| `DisableCopy` test  | No packet factory - always clone                |

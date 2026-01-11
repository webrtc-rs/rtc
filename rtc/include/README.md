# RTC C/C++ Header

This directory contains the C/C++ API header for the RTC WebRTC library.

## Files

- **`rtc.h`** - Complete C API header (685 lines, 37 functions)

## Quick Start

### 1. Include the header

```c
#include <rtc.h>
```

### 2. Link the library

**Static linking:**
```bash
gcc -o app main.c -I./rtc/include -L./target/release -lrtc -lpthread -ldl -lm
```

**Dynamic linking:**
```bash
gcc -o app main.c -I./rtc/include -L./target/release -lrtc
export LD_LIBRARY_PATH=./target/release:$LD_LIBRARY_PATH
./app
```

### 3. Example code

```c
#include <rtc.h>
#include <stdio.h>

int main() {
    // Create configuration
    rtc_configuration *config = rtc_configuration_new();
    rtc_configuration_add_ice_server(config, 
        "stun:stun.l.google.com:19302", NULL, NULL);
    
    // Create peer connection
    rtc_peer_connection *pc = rtc_peer_connection_new(config);
    if (!pc) {
        fprintf(stderr, "Failed to create peer connection\n");
        return 1;
    }
    
    // Create offer
    char offer[4096];
    size_t offer_len = sizeof(offer);
    int result = rtc_peer_connection_create_offer(pc, 
        (uint8_t*)offer, &offer_len);
    
    if (result == 0) {
        printf("SDP Offer:\n%.*s\n", (int)offer_len, offer);
    }
    
    // Cleanup
    rtc_peer_connection_free(pc);
    rtc_configuration_free(config);
    
    return 0;
}
```

## API Categories

### Configuration (4 functions)
- `rtc_configuration_new()` / `rtc_configuration_free()`
- `rtc_configuration_add_ice_server()`
- `rtc_configuration_set_interceptor_registry()`

### Interceptor Registry (6 functions)
- `rtc_interceptor_registry_new()` / `rtc_interceptor_registry_free()`
- `rtc_interceptor_registry_add_nack()`
- `rtc_interceptor_registry_add_rtcp_reports()`
- `rtc_interceptor_registry_add_twcc()`
- `rtc_interceptor_registry_add_defaults()`

### Peer Connection (12 functions)
- `rtc_peer_connection_new()` / `rtc_peer_connection_free()` / `rtc_peer_connection_close()`
- `rtc_peer_connection_create_offer()` / `rtc_peer_connection_create_answer()`
- `rtc_peer_connection_set_local_description()` / `rtc_peer_connection_set_remote_description()`
- `rtc_peer_connection_add_local_candidate()` / `rtc_peer_connection_add_remote_candidate()`

### Sans-I/O Event Loop (6 functions)
- `rtc_peer_connection_poll_write()` - Get outgoing packets
- `rtc_peer_connection_poll_event()` - Get connection events
- `rtc_peer_connection_poll_read()` - Get application messages
- `rtc_peer_connection_poll_timeout()` - Get timer deadline
- `rtc_peer_connection_handle_read()` - Feed incoming packets
- `rtc_peer_connection_handle_timeout()` - Handle timer expiration

### Data Channels (3 functions)
- `rtc_peer_connection_create_data_channel()`
- `rtc_data_channel_send()`
- `rtc_data_channel_label()`

### Media (3 functions)
- `rtc_peer_connection_add_track()`
- `rtc_rtp_sender_write_rtp()`
- `rtc_rtp_receiver_write_rtcp()`

### Utilities (2 functions)
- `rtc_version()`
- `rtc_enable_debug_logging()`

## Design Philosophy

This API follows the **Sans-I/O** pattern, where you control all I/O:

1. **You handle networking** - `poll_write()` gives you packets to send
2. **You handle timing** - `poll_timeout()` tells you when to wake up
3. **You handle events** - `poll_event()` gives you state changes
4. **You feed packets** - `handle_read()` processes incoming data

This gives you complete control over:
- Threading model (sync, async, multi-threaded)
- I/O framework (epoll, kqueue, IOCP, tokio, etc.)
- Event loop integration
- Resource scheduling

## Platform Support

- ✅ Linux (x86_64, aarch64)
- ✅ macOS (x86_64, aarch64/M1)
- ✅ Windows (x86_64)
- ✅ BSD systems
- ⚠️ iOS/Android (untested but should work)

## Thread Safety

**Not thread-safe by default.** Each `rtc_peer_connection` is single-threaded:

- ✅ Safe: Multiple connections in different threads
- ❌ Unsafe: Same connection accessed from multiple threads
- ⚠️ Consider: External synchronization if needed

## Documentation

See `../C_API_DESIGN.md` for detailed design documentation.
See `../FFI_IMPLEMENTATION_SUMMARY.md` for implementation details.

## Building

The library is built with cargo:

```bash
# Development build
cargo build --features ffi

# Release build (optimized)
cargo build --release --features ffi
```

Outputs:
- `../target/release/librtc.a` - Static library
- `../target/release/librtc.so` - Dynamic library (Linux)
- `../target/release/librtc.dylib` - Dynamic library (macOS)
- `../target/release/rtc.dll` - Dynamic library (Windows)

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.

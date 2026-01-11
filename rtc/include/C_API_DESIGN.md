# RTC C/C++ API Design

This document describes the C/C++ FFI (Foreign Function Interface) for the RTC library, following the methodology used by Cloudflare's quiche library.

## Overview

The RTC C API provides a complete Sans-I/O WebRTC implementation accessible from C and C++ applications. It exposes the full functionality of the Rust implementation while maintaining memory safety and proper resource management.

## Key Design Principles

### 1. **Opaque Pointers**

All Rust types are exposed as opaque pointers in C, preventing direct access to internal structure:

```c
typedef struct rtc_peer_connection rtc_peer_connection;
typedef struct rtc_configuration rtc_configuration;
typedef struct rtc_interceptor_registry rtc_interceptor_registry;
```

This provides:
- **Type safety**: Prevents misuse of internal structures
- **ABI stability**: Internal changes don't break C code
- **Memory safety**: Enforces proper ownership through creation/destruction functions

### 2. **Type-Erased Interceptor Registry**

The interceptor registry handles the generic parameter `Registry<P>` through type erasure:

```rust
pub struct InterceptorRegistryBox {
    inner: InterceptorChain,
}

enum InterceptorChain {
    Empty(Registry<NoopInterceptor>),
    Configured(Box<dyn Any + Send>),
}
```

**Why this approach?**
- Interceptors use Rust generics: `Registry<P> where P: Interceptor`
- C cannot represent generic types
- Type erasure hides the concrete interceptor chain type
- Registry is built incrementally by wrapping interceptors

**C API:**
```c
// Create empty registry
rtc_interceptor_registry *registry = rtc_interceptor_registry_new();

// Add interceptors one by one
rtc_interceptor_registry_add_nack(registry);
rtc_interceptor_registry_add_rtcp_reports(registry);
rtc_interceptor_registry_add_twcc(registry);

// Or use defaults
rtc_interceptor_registry_add_defaults(registry);

// Transfer ownership to configuration
rtc_configuration_set_interceptor_registry(config, registry);
```

**How it works:**
1. Start with `Registry<NoopInterceptor>` (empty chain)
2. Each add function wraps the current chain: `Registry<P> -> Registry<NewInterceptor<P>>`
3. Type is erased into `Box<dyn Any + Send>`
4. Configuration accepts the type-erased registry

### 3. **Sans-I/O Event Loop**

The C API follows the same Sans-I/O pattern as the Rust API:

```c
rtc_peer_connection *pc = rtc_peer_connection_new(config);

// Main event loop
while (running) {
    // 1. Poll for outgoing packets
    rtc_network_message msg;
    while (rtc_peer_connection_poll_write(pc, &msg) > 0) {
        sendto(sock, msg.data, msg.len, ...);
    }
    
    // 2. Poll for events
    rtc_event event;
    while (rtc_peer_connection_poll_event(pc, &event) > 0) {
        // Handle connection state changes
    }
    
    // 3. Poll for application messages
    rtc_message app_msg;
    while (rtc_peer_connection_poll_read(pc, &app_msg) > 0) {
        // Handle RTP/RTCP/data channel messages
    }
    
    // 4. Get timeout
    uint64_t timeout_us;
    if (rtc_peer_connection_poll_timeout(pc, &timeout_us) > 0) {
        // Wait for timeout or incoming packet
    }
    
    // 5. Handle incoming packets
    recvfrom(sock, buffer, ...);
    rtc_network_message incoming = {...};
    rtc_peer_connection_handle_read(pc, &incoming);
    
    // 6. Handle timeout expiration
    rtc_peer_connection_handle_timeout(pc, current_time_us);
}
```

### 4. **Error Handling**

Functions return integer error codes (0 for success, negative for errors):

```c
enum rtc_error {
    RTC_ERR_DONE = -1,
    RTC_ERR_BUFFER_TOO_SHORT = -2,
    RTC_ERR_INVALID_STATE = -3,
    // ... more error codes
};

int result = rtc_peer_connection_create_offer(pc, buffer, &buffer_len);
if (result == RTC_ERR_BUFFER_TOO_SHORT) {
    // buffer_len now contains required size
    buffer = realloc(buffer, buffer_len);
    result = rtc_peer_connection_create_offer(pc, buffer, &buffer_len);
}
```

### 5. **Resource Management**

Clear ownership semantics with create/free pairs:

```c
// Allocated on heap - caller owns
rtc_configuration *config = rtc_configuration_new();

// Use configuration
rtc_configuration_add_ice_server(config, "stun:...", NULL, NULL);

// Ownership transferred to peer connection
rtc_peer_connection *pc = rtc_peer_connection_new(config);

// Configuration is borrowed, still owned by caller
rtc_configuration_free(config);

// Free peer connection
rtc_peer_connection_free(pc);
```

**Ownership rules:**
- `_new()` functions return owned pointers - caller must call `_free()`
- `_set_*()` functions typically transfer ownership (documented)
- `const` pointers indicate borrowing (no ownership transfer)

### 6. **Platform Compatibility**

Platform-specific handling for socket addresses and types:

```c
#if defined(WIN32) || defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#endif

#ifdef _MSC_VER
#define ssize_t SSIZE_T
#endif
```

Rust implementation handles platform differences:

```rust
#[cfg(not(windows))]
use libc::{AF_INET, AF_INET6, sockaddr_in, sockaddr_in6};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, ...};
```

## File Structure

Following quiche's methodology:

```
rtc/
├── include/
│   └── rtc.h              # Public C API header
├── src/
│   ├── lib.rs             # Rust library entry (adds #[cfg(feature = "ffi")] mod ffi;)
│   └── ffi.rs             # FFI implementation
├── build.rs               # Build script
└── Cargo.toml             # Build configuration
```

### Cargo.toml Configuration

```toml
[lib]
crate-type = ["lib", "staticlib", "cdylib"]

[features]
ffi = ["dep:cdylib-link-lines", "dep:libc", "dep:windows-sys"]

[build-dependencies]
cdylib-link-lines = { version = "0.1", optional = true }

[dependencies]
libc = { version = "0.2", optional = true }

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.59", features = ["Win32_Networking_WinSock"], optional = true }
```

### build.rs

```rust
fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    
    // MacOS: Allow cdylib to link with undefined symbols
    if target_os == "macos" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }

    #[cfg(feature = "ffi")]
    if target_os != "windows" {
        cdylib_link_lines::metabuild();
    }
}
```

## API Categories

### 1. Configuration API

Create and configure peer connections:

```c
rtc_configuration *config = rtc_configuration_new();
rtc_configuration_add_ice_server(config, "stun:stun.l.google.com:19302", NULL, NULL);
```

### 2. Interceptor Registry API

Configure RTP/RTCP interceptors:

```c
rtc_interceptor_registry *registry = rtc_interceptor_registry_new();
rtc_interceptor_registry_add_defaults(registry);  // NACK + RTCP Reports + TWCC
rtc_configuration_set_interceptor_registry(config, registry);
```

### 3. Peer Connection API

Core WebRTC functionality:

```c
rtc_peer_connection *pc = rtc_peer_connection_new(config);
rtc_peer_connection_create_offer(pc, buffer, &len);
rtc_peer_connection_set_local_description(pc, "offer", sdp);
```

### 4. Data Channel API

Bidirectional data transfer:

```c
rtc_data_channel_init init = { .ordered = true, .max_retransmits = -1 };
uint16_t channel_id;
rtc_peer_connection_create_data_channel(pc, "my-channel", &init, &channel_id);
rtc_data_channel_send(pc, channel_id, data, len, true);
```

### 5. Media API

RTP sender/receiver:

```c
rtc_media_stream_track *track = create_video_track();
uint64_t sender_id;
rtc_peer_connection_add_track(pc, track, &sender_id);
rtc_rtp_sender_write_rtp(pc, sender_id, rtp_packet, packet_len);
```

## Comparison with Quiche

| Aspect | Quiche | RTC |
|--------|--------|-----|
| **Protocol** | QUIC/HTTP3 | WebRTC |
| **Opaque types** | `quiche_conn`, `quiche_config` | `rtc_peer_connection`, `rtc_configuration` |
| **Error handling** | Negative int codes | Negative int codes |
| **Resource mgmt** | `_new()` / `_free()` pairs | `_new()` / `_free()` pairs |
| **Build system** | cmake (BoringSSL) + build.rs | build.rs only |
| **Generic handling** | N/A (no generics in API) | Type-erased interceptor registry |
| **I/O model** | Sans-I/O | Sans-I/O |

## Interceptor Design Deep Dive

### The Generic Challenge

Rust interceptors are generic:

```rust
pub trait Interceptor: Protocol<...> { }

pub struct Registry<P: Interceptor> {
    inner: P,
}

impl<P: Interceptor> Registry<P> {
    pub fn with<O, F>(self, f: F) -> Registry<O>
    where F: FnOnce(P) -> O, O: Interceptor { ... }
}
```

Each `.with()` call creates a new type:
- `Registry<NoopInterceptor>`
- `Registry<NackGenerator<NoopInterceptor>>`
- `Registry<SenderReport<NackGenerator<NoopInterceptor>>>`

### Type Erasure Solution

**Step 1:** Define type-erased container

```rust
enum InterceptorChain {
    Empty(Registry<NoopInterceptor>),
    Configured(Box<dyn Any + Send>),
}
```

**Step 2:** Store in opaque box

```rust
pub struct InterceptorRegistryBox {
    inner: InterceptorChain,
}
```

**Step 3:** Provide mutation methods

```rust
impl InterceptorRegistryBox {
    fn add_nack(&mut self, media_engine: &mut MediaEngine) -> Result<()> {
        self.inner = match std::mem::replace(&mut self.inner, InterceptorChain::Empty(...)) {
            InterceptorChain::Empty(registry) => {
                let registry = configure_nack(registry, media_engine);
                InterceptorChain::Configured(Box::new(registry))
            }
            InterceptorChain::Configured(_) => {
                return Err(Error::Other("Cannot modify configured registry".into()));
            }
        };
        Ok(())
    }
}
```

**Step 4:** Extract for use

```rust
impl ConfigurationBox {
    fn build(self, registry_opt: Option<InterceptorRegistryBox>) -> RTCConfiguration {
        if let Some(registry_box) = registry_opt {
            match registry_box.inner {
                InterceptorChain::Empty(registry) => {
                    self.builder.with_interceptor_registry(registry)
                }
                InterceptorChain::Configured(any) => {
                    // Downcast to concrete type if needed
                    // Or use trait objects
                }
            }
        }
        // ...
    }
}
```

### Alternative Approaches Considered

1. **Trait Objects**: `Box<dyn Interceptor>`
   - ❌ Interceptor trait has associated types, not object-safe
   
2. **Enum Dispatch**: List all interceptor combinations
   - ❌ Combinatorial explosion (2^N for N interceptor types)
   
3. **Runtime String Config**: Parse configuration strings
   - ❌ Loses type safety, adds runtime overhead

4. **Fixed Concrete Type**: Use one specific interceptor chain
   - ✅ Simple but ❌ inflexible

5. **Type Erasure** (chosen)
   - ✅ Flexible, safe, ergonomic C API
   - ⚠️ Slightly more complex implementation

## Building and Usage

### Build the Library

```bash
# Build as static library
cargo build --release --features ffi

# Build as dynamic library (cdylib)
cargo build --release --features ffi --crate-type=cdylib

# Outputs:
# - librtc.a (static)
# - librtc.so / librtc.dylib / rtc.dll (dynamic)
```

### Link from C/C++

```bash
# Compile C application
gcc -o app main.c -I./rtc/include -L./target/release -lrtc -lpthread -ldl -lm

# Or with CMake
# target_link_libraries(myapp rtc pthread dl m)
```

### Example C Program

```c
#include <rtc.h>
#include <stdio.h>

int main() {
    // Create configuration
    rtc_configuration *config = rtc_configuration_new();
    rtc_configuration_add_ice_server(config, "stun:stun.l.google.com:19302", NULL, NULL);
    
    // Create interceptor registry
    rtc_interceptor_registry *registry = rtc_interceptor_registry_new();
    rtc_interceptor_registry_add_defaults(registry);
    rtc_configuration_set_interceptor_registry(config, registry);
    
    // Create peer connection
    rtc_peer_connection *pc = rtc_peer_connection_new(config);
    if (!pc) {
        fprintf(stderr, "Failed to create peer connection\n");
        return 1;
    }
    
    // Create offer
    char offer_buffer[4096];
    size_t offer_len = sizeof(offer_buffer);
    if (rtc_peer_connection_create_offer(pc, (uint8_t*)offer_buffer, &offer_len) != 0) {
        fprintf(stderr, "Failed to create offer\n");
        return 1;
    }
    
    printf("SDP Offer:\n%.*s\n", (int)offer_len, offer_buffer);
    
    // Cleanup
    rtc_peer_connection_free(pc);
    rtc_configuration_free(config);
    
    return 0;
}
```

## Future Enhancements

1. **Callback-based events**: Alternative to polling
2. **Thread-safe operations**: Concurrent access support
3. **Statistics API**: Detailed WebRTC metrics
4. **Language bindings**: Python, Go, Node.js via FFI
5. **Complete interceptor API**: Full customization from C

## References

- [Quiche FFI Implementation](https://github.com/cloudflare/quiche/tree/master/quiche/include)
- [Sans-I/O Protocol Design](https://sans-io.readthedocs.io/)
- [Rust FFI Guide](https://doc.rust-lang.org/nomicon/ffi.html)
- [WebRTC Specification](https://w3c.github.io/webrtc-pc/)

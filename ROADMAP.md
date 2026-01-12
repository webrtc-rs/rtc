# RTC Project Roadmap

**Architecture:** Sans-I/O WebRTC Implementation in Rust  
**Last Updated:** January 2026

---

## Project Vision

Build a production-ready, runtime-independent WebRTC stack in pure Rust using the sans-I/O architecture pattern,
providing developers with complete control over networking, threading, and async runtime integration while maintaining
full WebRTC specification compliance.

---

## Current Status

### ✅ Completed Features

**Core Protocol Stack**

- ✅ ICE (Interactive Connectivity Establishment) with STUN/TURN support
- ✅ ICE Restart support
- ✅ DTLS (Datagram Transport Layer Security) v1.2
- ✅ SCTP (Stream Control Transmission Protocol)
- ✅ RTP/RTCP (Real-time Transport Protocol)
- ✅ SRTP with AEAD AES-GCM support (RFC 7714)
- ✅ SDP (Session Description Protocol) with offer/answer
- ✅ Unified Plan SDP (modern API)
- ✅ BUNDLE support
- ✅ mDNS (Multicast DNS) for local network discovery

**WebRTC Features**

- ✅ Data Channels (reliable & unreliable, configurable)
- ✅ Media Tracks (audio/video)
- ✅ Simulcast (send & receive)
- ✅ SVC (Scalable Video Coding)
- ✅ Add/Remove tracks at runtime
- ✅ Insertable Streams

**Interceptors & Media Processing**

- ✅ Interceptor framework for RTP/RTCP manipulation
- ✅ NACK (Negative Acknowledgment) interceptor
- ✅ TWCC (Transport Wide Congestion Control) interceptor
- ✅ Sender/Receiver Report interceptors

**Codec Support**

- ✅ VP8/VP9 packetizers and depacketizers
- ✅ H.264/H.265 packetizers and depacketizers
- ✅ AV1 support
- ✅ Opus audio
- ✅ PCM audio
- ✅ IVF reader/writer for disk I/O

**Architecture**

- ✅ Sans-I/O design with `poll_*` and `handle_*` APIs
- ✅ Runtime-independent (works with tokio, async-std, smol, blocking I/O)
- ✅ Modular crate structure (15 composable crates)
- ✅ Zero-copy packet processing where possible

**Development & Quality**

- ✅ 30+ comprehensive examples (data channels, media streaming, simulcast, broadcast, etc.)
- ✅ Integration tests with WebRTC (browser) interoperability
- ✅ API documentation on docs.rs
- ✅ CI/CD pipeline with automated testing

### 🚧 In Progress / Partially Complete

- 🚧 Trickle ICE
- 🚧 ICE TCP candidates (passive/active)
- 🚧 Statistics API

### 🔴 Missing Features (Compared to Pion)

- ❌ Jitter Buffer interceptor
- ❌ FEC (Forward Error Correction) interceptor
- ❌ Full Congestion Control (Google Congestion Control / BBR)
- ❌ Active ICE TCP candidates
- ❌ Complete DTLS Restart support
- ❌ PeerConnection serialization/deserialization
- ❌ Automated performance/allocation testing in CI
- ❌ Automated fuzzing (oss-fuzz integration)
- ❌ Auto changelog generation
- ❌ Embedded/IoT support
- ❌ FFI C API (work in progress on `ffi` branch)
- ❌ TCP TURN support

---

## Roadmap

### Phase 1: Stability & Polish (Q1 2026)

**Goal:** Make production-ready with excellent developer experience

#### 1.1 Bug Fixes & Stability

- [ ] Address all critical TODOs and FIXMEs in codebase
- [ ] Resolve flaky integration tests
- [ ] Improve error handling and error messages
- [ ] Add more validation for invalid inputs

#### 1.2 Documentation & Examples

- [ ] Complete API documentation coverage (aim for 100%)
- [ ] Add "Getting Started" guide for common use cases
- [ ] Create migration guide from traditional WebRTC libraries
- [ ] Add troubleshooting guide
- [ ] Document performance tuning best practices
- [ ] Add more real-world examples:
    - [ ] Video conferencing server
    - [ ] Screen sharing
    - [ ] File transfer over data channels
    - [ ] Selective forwarding unit (SFU) implementation
    - [ ] Recording server (save multiple streams to disk)

#### 1.3 Testing & Quality

- [ ] Increase unit test coverage to >80%
- [ ] Add more WebRTC interoperability tests (Chrome, Firefox, Safari)
- [ ] Automated fuzz testing in CI
- [ ] Create test suite for NAT traversal scenarios
- [ ] Add stress tests for concurrent connections
- [ ] Automated performance/allocation testing in CI

---

### Phase 2: Performance & Optimization (Q2 2026)

**Goal:** Optimize for production workloads and high-performance scenarios

#### 2.1 Performance Optimization

- [ ] Profile hot paths and optimize critical sections
- [ ] Reduce allocations in packet processing paths
- [ ] Optimize DTLS handshake performance
- [ ] Improve ICE candidate gathering speed
- [ ] Optimize SRTP encryption/decryption (leverage hardware acceleration where possible)
- [ ] Add SIMD optimizations where applicable
- [ ] SCTP performance improvements

#### 2.2 Benchmarking & Testing

- [ ] Create comprehensive benchmark suite
- [ ] Benchmark against other WebRTC implementations
- [ ] Add CI performance regression testing
- [ ] Document performance characteristics
- [ ] Publish performance comparison results

#### 2.3 Memory Efficiency

- [ ] Audit memory usage patterns
- [ ] Reduce memory footprint per connection
- [ ] Implement better buffer pooling
- [ ] Add memory usage documentation
- [ ] Memory profiling tools integration

---

### Phase 3: Advanced Features (Q3 2026)

**Goal:** Add advanced WebRTC features and expand ecosystem

#### 3.1 Media Quality & Resilience

- [ ] **Jitter Buffer improvements** (if not in Phase 1)
    - Adaptive strategies based on network conditions
    - Low-latency vs quality tradeoffs
- [ ] **Full Congestion Control** 🔴 Critical for production
    - Google Congestion Control (GCC) implementation
    - BBR congestion control
    - Integration with TWCC feedback
    - Bandwidth probing and estimation
- [ ] **FEC (Forward Error Correction) Interceptor**
    - FlexFEC support
    - RED (Redundant Encoding) support
    - Configurable FEC strategies
- [ ] **H.264 Interceptor** 🟠 High Priority
    - Analyze and fix common issues (missing SPS/PPS with IDR frames)
    - Automatic bitstream repair
    - Parameter set injection

#### 3.2 Protocol Extensions

- [ ] Perfect Negotiation pattern support
- [ ] WebRTC Stats improvements (align with latest W3C spec)
- [ ] ICE consent freshness (RFC 7675)
- [ ] BUNDLE policy improvements
- [ ] RTX (Retransmission) support improvements

#### 3.3 Codec Support

- [ ] Expand audio codec support (Opus optimizations, additional codecs)
- [ ] Improve H.264/H.265 handling and negotiation
- [ ] Add AV1 support improvements (packetization edge cases)
- [ ] Codec negotiation enhancements
- [ ] Better handling of codec parameters and profiles

---

### Phase 4: Language Bindings & Ecosystem (Q4 2026)

**Goal:** Make RTC accessible from other languages and build ecosystem

#### 4.1 FFI & Language Bindings

- [ ] Complete C API (merge `ffi` branch)
- [ ] Create C header files and documentation
- [ ] Python bindings (PyO3)
- [ ] Node.js bindings (napi-rs)
- [ ] Go bindings (via CGO)
- [ ] WASM bindings for browser
- [ ] Cross-language example applications

#### 4.2 Integration Libraries

- [ ] Integration with popular async runtimes
    - [ ] Tokio adapter with best practices
    - [ ] async-std adapter
    - [ ] smol adapter
- [ ] WebSocket signaling library
- [ ] HTTP/REST signaling library
- [ ] Redis-based signaling for distributed systems

#### 4.3 Higher-Level APIs

- [ ] "Batteries included" wrapper for common use cases
- [ ] Simplified API for beginners
- [ ] Opinionated defaults for quick prototyping
- [ ] Framework integrations (e.g., Actix, Axum)

---

### Phase 5: Production Features (2027+)

**Goal:** Enterprise-ready features for production deployments

#### 5.1 Scalability & Infrastructure

- [ ] Connection pooling strategies
- [ ] Distributed ICE coordination
- [ ] Horizontal scaling patterns
- [ ] Load balancing support
- [ ] Multi-threaded optimizations
- [ ] Better SettingEngine for SFU use cases

#### 5.2 Observability & Monitoring

- [ ] Structured logging with tracing
- [ ] Metrics export (Prometheus format)
- [ ] OpenTelemetry integration
- [ ] Connection quality metrics
- [ ] Diagnostic tools and utilities
- [ ] Real-time debugging tools

#### 5.3 Security & Hardening

- [ ] **Security audit by external firm** 🔴 Critical before 1.0
- [ ] **Automated fuzzing in production** (continuous oss-fuzz)
- [ ] DTLS 1.3 support
- [ ] Enhanced certificate validation
- [ ] Rate limiting and DoS protection
- [ ] Security best practices guide
- [ ] CVE response process

#### 5.4 Compliance & Standards

- [ ] Full W3C WebRTC 1.0 compliance
- [ ] RFC compliance verification
- [ ] Standards-based testing suite
- [ ] Regular spec update tracking

#### 5.5 Developer Experience

- [ ] Auto changelog generation
- [ ] Automated release process
- [ ] Better error messages and diagnostics
- [ ] Migration guides between versions

---

## Future Exploration (Beyond 2027)

### Emerging Technologies

- [ ] QUIC transport integration
    - WebRTC over QUIC
    - Performance comparisons with UDP
- [ ] WebTransport support
- [ ] WebCodecs integration
- [ ] WebNN (Neural Networks) integration for ML features
- [ ] Post-quantum cryptography exploration

### Embedded & IoT

- [ ] Embedded/IoT platform support
    - no_std compatibility where possible
    - Reduced memory footprint variants
    - Embedded-friendly examples
    - ARM/RISC-V optimizations

### Ecosystem Growth

- [ ] SFU (Selective Forwarding Unit) reference implementation
- [ ] MCU (Multipoint Control Unit) reference implementation
- [ ] TURN server implementation (pure Rust)
- [ ] STUN server implementation
- [ ] Signaling server reference implementations
- [ ] Media server framework

### Developer Experience

- [ ] Interactive tutorial website
- [ ] Video course/tutorials
- [ ] Conference talks and presentations
- [ ] Regular blog posts on WebRTC topics
- [ ] Community forum/discussions

---

## Contributing to the Roadmap

This roadmap is a living document and we welcome community input:

1. **Feature Requests**: Open an issue with the `enhancement` label
2. **Prioritization**: Join discussions on Discord or GitHub
3. **Implementation**: Check items you're interested in implementing
4. **Sponsorship**: Priority can be influenced by sponsors' needs

### Priority Levels

- 🔴 **Critical**: Blocks production use or causes data loss
- 🟠 **High**: Important for production deployments
- 🟡 **Medium**: Nice to have, improves user experience
- 🟢 **Low**: Future enhancements, non-urgent

---

## Release Strategy

### Versioning (SemVer)

- **0.7.x**: Current series - stability and polish
- **0.8.0**: Performance optimizations + advanced features
- **0.9.0**: FFI + language bindings
- **1.0.0**: Production-ready milestone (all critical features complete)

### Release Cadence

- **Patch releases** (0.7.x): As needed for bug fixes
- **Minor releases** (0.x.0): Every 2-3 months
- **Major release** (1.0.0): When production-ready criteria met

### Production-Ready Criteria for 1.0

- [ ] Complete WebRTC 1.0 spec compliance
- [ ] External security audit passed
- [ ] Automated fuzzing infrastructure
- [ ] Above 80% test coverage
- [ ] Comprehensive documentation
- [ ] Performance benchmarks published
- [ ] Multiple production deployments
- [ ] Stable API (no breaking changes planned)
- [ ] Active community and maintenance commitment

---

## Comparison with Pion WebRTC

This roadmap incorporates learnings from [Pion WebRTC's roadmap](https://github.com/pion/webrtc/issues/9). Here's how we
compare:

## Feature Comparison of Pion vs RTC

| Feature                        | Pion Version | RTC Status       | Priority    |
|--------------------------------|--------------|------------------|-------------|
| **Core Protocol Stack**        |
| ICE (Full)                     | 1.1.0        | ✅ Complete       | -           |
| DTLS (Native)                  | 1.2.0        | ✅ Pure Rust      | -           |
| STUN                           | 1.1.0        | ✅ Complete       | -           |
| TURN                           | 2.1.0        | ✅ Complete       | -           |
| TCP TURN                       | 2.2.0        | ✅ Complete       | -           |
| mDNS Candidates                | 2.1.0        | ✅ Complete       | -           |
| SCTP                           | 1.0.0        | ✅ Complete       | -           |
| **WebRTC Features**            |
| Data Channels                  | 1.1.0        | ✅ Complete       | -           |
| Configurable Reliability       | 2.0.0        | ✅ Complete       | -           |
| Trickle ICE                    | 2.1.0        | ✅ Complete       | -           |
| Add/Remove Tracks              | 2.2.0        | ✅ Complete       | -           |
| Unified Plan                   | 2.0.0        | ✅ Complete       | -           |
| Bundling                       | 1.1.0        | ✅ Complete       | -           |
| ICE Restart                    | 3.0.0        | ✅ Complete       | -           |
| ICE TCP (Passive)              | 3.0.0        | ❌ Missing        | 🟠 High     |
| ICE TCP (Active)               | 4.0.0        | ❌ Missing        | 🟠 High     |
| ICE Regular Nomination         | 2.0.0        | ✅ Complete       | -           |
| **Media & Codecs**             |
| VP8/VP9                        | 1.0.0        | ✅ Complete       | -           |
| H.264/H.265                    | Various      | ✅ Packetizers    | -           |
| AV1                            | 3.2.0        | ✅ Complete       | -           |
| Opus                           | Various      | ✅ Complete       | -           |
| PCM                            | 2.2.0        | ✅ Complete       | -           |
| **Advanced Features**          |
| Simulcast                      | 3.0.0        | ✅ Send & Receive | -           |
| Sender/Receiver Reports        | 3.1.0        | ✅ Complete       | -           |
| TWCC                           | 3.1.0        | ✅ Complete       | -           |
| Congestion Control             | 3.2.0        | 🚧 TWCC only     | 🔴 Critical |
| Jitter Buffer                  | 4.0.0        | ❌ Missing        | 🔴 Critical |
| SRTP AEAD-GCM                  | 3.0.0        | ✅ Complete       | -           |
| UDPMux (Single Port)           | 3.1.0        | ✅ Via Setting    | -           |
| Interceptor API                | 3.0.0        | ✅ Complete       | -           |
| NACK Interceptor               | 3.0.0        | ✅ Complete       | -           |
| Stats Interceptor              | 3.2.0        | ✅ Complete       | -           |
| H.264 Interceptor              | Roadmap      | ❌ Missing        | 🟢 Low      |
| FEC Interceptor                | Planned      | ❌ Missing        | 🟡 Medium   |
| DTLS Restart                   | Planned      | 🚧 Partial       | 🟡 Medium   |
| **Development Infrastructure** |
| Automated Fuzzing              | Production   | ❌ Missing        | 🔴 Critical |
| Performance CI                 | Production   | ❌ Missing        | 🔴 High     |
| Allocation Tracking            | Production   | ❌ Missing        | 🟠 High     |
| Auto Changelog                 | Production   | ❌ Missing        | 🟡 Medium   |
| **API Features**               |
| PeerConnection Serialize       | Roadmap      | ❌ Missing        | 🟠 Medium   |
| WASM Support                   | 2.0.0        | 🚧 Partial       | 🟡 Medium   |
| Mobile Support                 | 1.2.0        | ✅ Rust works     | -           |
| Embedded/IoT (TinyGo)          | Roadmap      | ❌ no_std         | 🟡 Future   |

### ✅ Features We Have (Pion Parity)

- ✅ Complete protocol stack (ICE, DTLS, SCTP, RTP/RTCP, SRTP, SDP)
- ✅ STUN and TURN support (including TCP TURN)
- ✅ Trickle ICE and mDNS
- ✅ Data Channels with configurable reliability
- ✅ Simulcast (send & receive)
- ✅ Interceptor API (NACK, TWCC, Sender/Receiver Reports, Stats)
- ✅ Unified Plan SDP
- ✅ BUNDLE support
- ✅ Add/Remove tracks at runtime
- ✅ ICE Restart
- ✅ AV1, H.264, H.265, VP8, VP9 support
- ✅ UDPMux capability (single port for multiple connections)
- ✅ SRTP AEAD AES-GCM
- ✅ ICE TCP (passive candidates)
- ✅ Insertable Streams API

### 🚧 Features We're Missing (Need Implementation)

- 🔴 **Jitter Buffer** - Critical for smooth media playback (Pion 4.0.0)
- 🔴 **Full Congestion Control** - GCC/BBR implementation (Pion 3.2.0)
- 🔴 **Automated Fuzzing** - oss-fuzz integration (Pion has this)
- 🟠 **H.264 Interceptor** - Bitstream fixing for common issues (Pion roadmap)
- 🟠 **Active ICE TCP** - Active TCP candidates (Pion 4.0.0)
- 🟠 **DTLS Restart** - Complete implementation (Pion roadmap)
- 🟠 **PeerConnection Serialization** - Save/restore connection state (Pion roadmap)
- 🟡 **FEC Interceptor** - Forward Error Correction (planned)
- 🟡 **Embedded/IoT Support** - Equivalent to TinyGo support (future exploration)

### 🎯 Our Unique Advantages

- **Sans-I/O Architecture** - Complete control over I/O, threading, and runtime
- **Pure Rust** - Memory safety, no CGO overhead, no OpenSSL dependency
- **Runtime Independence** - Works with any async runtime or blocking I/O
- **Modular Design** - 15 independent crates for flexible composition
- **Zero-Copy Design** - Efficient packet processing where possible

### 📊 Development Infrastructure Comparison

| Feature                        | Pion | RTC     | Priority    |
|--------------------------------|------|---------|-------------|
| Automated fuzzing (oss-fuzz)   | ✅    | ❌       | 🔴 Critical |
| Performance regression testing | ✅    | ❌       | 🔴 High     |
| Allocation tracking in CI      | ✅    | ❌       | 🟠 High     |
| Auto changelog generation      | ✅    | ❌       | 🟡 Medium   |
| Comprehensive examples         | ✅    | ✅ (30+) | ✅ Done      |
| Browser interop tests          | ✅    | ✅       | ✅ Done      |

---

## Communication

- **GitHub Issues**: Bug reports and feature requests
- **Discord**: Real-time discussions and support
- **GitHub Discussions**: Long-form technical discussions
- **Blog**: Major announcements and technical deep-dives
- **Roadmap Updates**: Quarterly reviews and adjustments

---

**Questions or suggestions?** Open an issue or join us on [Discord](https://discord.gg/4Ju8UHdXMs)!

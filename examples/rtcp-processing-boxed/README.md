# rtcp-processing-boxed

The type-erased counterpart of the [`rtcp-processing`](../rtcp-processing) example.

It does exactly the same thing — installs a custom `RtcpForwarderInterceptor` so RTCP packets surface through
`poll_read()`, then prints them — but it stores the peer connection as `RTCPeerConnection<BoxedInterceptor>` instead of
letting the interceptor chain's type leak into the application. Read `rtcp-processing` first for the RTCP concepts and
the forwarder interceptor itself; this README only covers what is different.

## The problem: the chain's type is enormous, and infectious

`RTCPeerConnection<I>` is generic over its interceptor chain `I`. A chain built by `register_default_interceptors`
plus one custom layer has a type like:

```text
RtcpForwarderInterceptor<TwccReceiverInterceptor<SenderReportInterceptor<
    ReceiverReportInterceptor<NackResponderInterceptor<NackGeneratorInterceptor<
        NoopInterceptor>>>>>>
```

As long as the chain flows straight into a local variable, `impl Interceptor` hides this — that is what
`rtcp-processing` does:

```rust
fn create_rtc_peer() -> Result<RTCPeerConnection<impl Interceptor>> { /* ... */ }
```

That breaks down as soon as an application does anything more than hold the peer connection in a `let`:

| You want to…                                                            | With `impl Interceptor` |
|-------------------------------------------------------------------------|-------------------------|
| store the peer connection in your own struct                              | the struct must become `MyStruct<I: Interceptor>`, and `I` then spreads to every impl block and helper function |
| keep peers in a `Vec` / `HashMap` where chains differ per peer             | impossible — different chains are different types |
| choose the chain in an `if` / `match` at runtime                           | impossible — the arms have different types |
| write a trait-object-free API boundary (`fn handle(pc: &mut ...)`)         | must be generic |

The usual workaround is to hand-write an application-level `trait PeerConnection { … }` that mirrors the whole
`RTCPeerConnection` API and store a `Box<dyn PeerConnection>` — hundreds of lines of pure forwarding boilerplate.

## The fix: erase the chain, not the peer connection

`Interceptor` is object safe, so the chain itself can be boxed. [`Registry::boxed`] does that, and
`BoxedInterceptor` is the alias for `Box<dyn Interceptor>`:

```rust
use rtc::interceptor::{BoxedInterceptor, Registry};

fn build_peer_connection(
    forward_rtcp: bool,
    mut media_engine: MediaEngine,
) -> Result<RTCPeerConnection<BoxedInterceptor>> {
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;

    // Two different chain types, unified by `.boxed()`.
    let registry = if forward_rtcp {
        registry.with(RtcpForwarderBuilder::new().build()).boxed()
    } else {
        registry.boxed()
    };

    Ok(RTCPeerConnectionBuilder::new()
        .with_configuration(config)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build()?)
}
```

Every peer connection now has the same concrete type, so an ordinary struct can own one:

```rust
struct RtcpSession {
    peer_connection: RTCPeerConnection<BoxedInterceptor>,   // no type parameter needed
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    ssrc2kind: HashMap<u32, RtpCodecKind>,
    rtcp_count: u64,
}

impl RtcpSession {                      // a plain impl block
    async fn flush_writes(&mut self) { /* ... */ }
    fn drain_events(&mut self) -> Result<bool> { /* ... */ }
    fn drain_reads(&mut self) { /* ... */ }
}
```

Compare with `rtcp-processing`, where all of this logic has to live inline in `run()` because there is no nameable
type to hang it on.

**Cost:** one virtual call per interceptor-chain entry point (`handle_read`, `poll_write`, `handle_timeout`, …). The
chain's *interior* is untouched — the layers still call each other through static dispatch and inline as before. If
your chain is fixed at compile time, keep `RTCPeerConnection<I>`; nothing about it changed.

## Instructions

### Open the rtcp-processing example page

[jsfiddle.net](https://jsfiddle.net/zurq6j7x/) — the same page the `rtcp-processing` example uses. You should see two
text-areas, a 'Start Session' button and 'Copy browser SessionDescription to clipboard'.

### Run

```bash
cargo run --example rtcp-processing-boxed
```

Paste the browser's offer, then paste the printed answer back into the browser. RTCP packets are printed as media
flows, exactly as in `rtcp-processing`.

### Run with the forwarder omitted

```bash
cargo run --example rtcp-processing-boxed -- --no-rtcp-forwarding
```

The peer connection has the **same type** (`RTCPeerConnection<BoxedInterceptor>`) and the same code path drives it,
but the chain was built without the RTCP forwarder — so the default interceptors consume RTCP internally and nothing
is printed. This flag is the demonstration: the two chains are different Rust types, chosen at runtime, behind one
peer connection type.

### Other flags

```bash
cargo run --example rtcp-processing-boxed -- --debug                       # debug logging
cargo run --example rtcp-processing-boxed -- --input-sdp-file offer.txt    # read SDP from a file
```

## Example Output

```
Interceptor chain: defaults + RTCP forwarder (boxed)
Paste your offer here:
<paste base64 encoded offer>

Offer received: ...
RTCP Processing (boxed) listening on 127.0.0.1:54321...

Paste this answer in your browser:
eyJ0eXBlIjoiYW5zd2VyIiwic2RwIjoi...

Waiting for RTCP packets...
Press Ctrl-C to stop

Connection State has changed: connected
Connection established! Waiting for RTCP packets...

Track has started - track_id: video-track, receiver_id: 0
  Stream ID: my-stream, Track ID: video-track, Kind: video, Codec: video/VP8

=== RTCP Packet #1 (Track: video-track) ===
  [1] Type: SenderReport, Length: 12 words
      SenderReport from 1234567890
        ...

^C
Ctrl-C received, shutting down...
Total RTCP packets received: 42
Event loop exited
```

With `--no-rtcp-forwarding` the first line reads
`Interceptor chain: defaults only (boxed) — no RTCP will be printed`, and no `=== RTCP Packet ===` blocks appear.

## See also

- [`rtcp-processing`](../rtcp-processing) — the same example without type erasure
- `tests/rtcp_processing_boxed_interop.rs` — integration tests for the boxed chain, including two peers with
  *different* chains driven out of a single `Vec`

# Memory per peer connection, pion side

The counterpart of `tests/memory_per_connection.rs`: connect N pairs of peer connections with one
data channel each, and report live heap plus goroutine stacks per connection after a GC.

```sh
cd benchmarks/pion-compare/memory
go mod tidy && go run . 200          # or: go mod edit -replace github.com/pion/webrtc/v4=/path/to/pion
cargo test --release --test memory_per_connection -- --nocapture   # from the repo root
```

The figures are not the same kind of thing, and both favour pion slightly: pion's include
goroutine stacks and a real UDP socket per connection (the kernel's buffers are in neither
number), ours is only what the library asked the allocator for. The sans-I/O side owns no
threads and no sockets, which is the point of the design, but compare orders of magnitude, not
percentages.

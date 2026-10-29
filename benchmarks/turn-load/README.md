# rtc-turn against pion/turn on real sockets

`run.py` starts each server in turn, drives it with the same Go load generator (allocate relays,
bounce packets off a local echo peer through them) and reports the **server process's** CPU time and
memory per delivered round trip. The Rust side is the shipped tokio example
`rtc-turn/examples/turn_server_udp.rs`; the Go side is a ten-line `turn.NewServer` (`pionserver/`).

```sh
python3 benchmarks/turn-load/run.py                          # 20 relays, 20000 round trips each
python3 benchmarks/turn-load/run.py --relays 1 --window 1    # latency
```

Measured on a quiet Apple-silicon Mac (loopback, 1200 B, best of 3):

| | pion/turn | rtc-turn example |
|---|--:|--:|
| server CPU per round trip, 20 relays x 32 in flight | 40.7 µs | 33.7 µs (0.83x) |
| server CPU per round trip, 1 relay x 1 in flight | 42.0 µs | 38.0 µs (0.90x) |
| server memory | 18.1 MiB | 4.3 MiB |
| throughput, 20 relays x 32 in flight | 31k/s | 22k/s |

Both sit near the syscall floor (eight system calls per round trip). The example's lower deep-window
throughput is its host, not the library: it runs the sans-I/O server on one event loop, where pion
spreads its goroutines over every core. A host that shards allocations over threads is not limited
that way.

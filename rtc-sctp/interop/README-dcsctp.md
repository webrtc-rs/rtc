# WebRTC dcSCTP packet adapter

This test peer runs the actual C++ dcSCTP implementation from WebRTC. It is
separate from the newer `webrtc/dcsctp` Rust project. It is never built or linked
by an ordinary Cargo build of `rtc-sctp`.

Pinned sources:

| Dependency | Revision |
| --- | --- |
| [WebRTC](https://webrtc.googlesource.com/src/+/dab572fd15e3fb975ed14a9e9290f723bb6e3f30) | `dab572fd15e3fb975ed14a9e9290f723bb6e3f30` |
| [Abseil](https://github.com/abseil/abseil-cpp/tree/c2336f9b5cb94b877ae3e38629e3b4530e60c89f) | `c2336f9b5cb94b877ae3e38629e3b4530e60c89f` |

The Abseil revision is recorded by `third_party/abseil-cpp/README.chromium` at
Chromium third_party `3c7ceaeb6bd16f270f6938b22db67b164a5b7b1d`, selected by
the pinned WebRTC `DEPS`. Only `net/dcsctp`, `api`, and `rtc_base` are downloaded
from WebRTC; its audio/video engine, depot_tools, and GN are not needed. Upstream
sources are not patched. CMake builds dcSCTP, its small WebRTC support files,
and the required Abseil targets. Upstream licenses are retained in the build
directory. Downloaded sources and binaries stay outside the repository.

## Build and check

Requirements: Python 3.12 or newer, a C++20 compiler, CMake, and Make (or the
generator selected through CMake's normal environment). This was checked with
Apple Clang 16.0.0, CMake 3.31.6, and Make on arm64 macOS.

```sh
python3 rtc-sctp/interop/build_dcsctp.py \
  --build-dir /tmp/rtc-237-dcsctp --self-test
export RTC_DCSCTP_PEER=/tmp/rtc-237-dcsctp/build/dcsctp-peer
```

If CMake is unavailable, install only the test tool into the temporary build
directory, then pass the native executable directly:

```sh
python3 -m pip install --target /tmp/rtc-237-dcsctp/tools cmake==3.31.6
python3 rtc-sctp/interop/build_dcsctp.py \
  --build-dir /tmp/rtc-237-dcsctp \
  --cmake /tmp/rtc-237-dcsctp/tools/cmake/data/bin/cmake --self-test
```

`--self-test` starts two independent processes, establishes an association,
delivers fragmented reliable messages in both directions, drops the first
Timed DATA, drops a fragment of Rexmit(0), and loses a successful reset response.
It verifies subsequent message delivery and reset completion using the real
peer, and records commands, packets, events, and virtual timestamps in
`self-test.jsonl`. Reads and event loops have explicit limits so a broken peer
fails the check instead of hanging indefinitely.

## Line protocol

Each command ends with one `DONE` line. Packet and application callbacks occur
before that line. Commands are processed synchronously; no output is generated
between commands.

| Input | Meaning |
| --- | --- |
| `INIT client` or `INIT server` | Construct one peer; local and remote SCTP ports are both 5000. |
| `CONNECT` | Begin the ordinary SCTP handshake; a passive peer only needs `INIT server`. |
| `SEND sid ordered\|unordered reliable\|timed:N\|rexmit:N ppid hex` | Enqueue a message with the native dcSCTP policy. |
| `RESET sid[,sid...]` | Request an outgoing stream reset. |
| `INPUT hex` | Deliver an entire raw SCTP packet, including its common header and checksum. |
| `TICK delta_ms` | Advance virtual time by a nonnegative number of milliseconds. |
| `POLL` | Process timeouts due at the current virtual time. |
| `QUIT` | End the process after `DONE`. |

Output lines are `PACKET hex`, `MESSAGE sid ppid hex`, `EVENT ready`,
`EVENT closed`, `EVENT restarted`, `EVENT reset_in:SID`, `EVENT reset_out:SID`,
or `EVENT reset_failed:SID:reason`. An incoming all-stream reset is reported as
`EVENT reset_in:all`. Nonfatal native errors are `EVENT error:kind:reason`;
aborts also emit `EVENT closed`. Command validation failures are `ERROR text`
followed by `DONE`. A zero-length byte string is `-`; dcSCTP rejects zero-length
user messages through its normal send result.

Each outgoing packet is immediately preceded by `EVENT packet_time:MS`, carrying
the peer's virtual time at the actual send callback. Preserve that value with
the following packet: a timer may fire before the end of a large `TICK`, so the
driver's time after the command alone is not the time of the transmission attempt.

`RESET` represents the native outgoing SCTP operation. The adapter reports an
incoming reset but does not silently initiate the other direction; the scenario
driver controls both directions when modeling DataChannel close.

## Time, randomness, and settings

All dcSCTP time comes from `Now()`/`TimeMillis()` and callback-created timeouts.
`TICK` fires due callbacks in deadline order, moving virtual time to each
deadline before invoking the socket. Equal deadlines use timeout creation order.
There are no worker threads or calls to a wall clock in the adapter. During a
large tick, emitted packets can be held by the driver until it advances the
other peer; this represents network delay. Scenarios needing finer ordering
should use smaller ticks and record their delivery decisions.

The deterministic random generator uses an explicitly defined 32-bit LCG and
rejection sampling, with seeds `0x12345678` (client) and `0x87654321` (server).
It is solely test input, not a security mechanism. The same commands produce
the same raw handshake and DATA packets for the same pinned sources.

PR-SCTP is enabled; message interleaving is disabled so comparisons use DATA and
FORWARD-TSN. Heartbeats are disabled. The maximum message is 1 MiB and the send
buffer is 2 MiB. Other dcSCTP defaults, including MTU 1191, initial RTO 500 ms,
minimum RTO 400 ms, and maximum RTO 60 seconds, are retained. Checksum generation
and validation use upstream Abseil CRC32C and are enabled.

`timed:N` maps directly to `SendOptions.lifetime=N`. At this pinned revision,
dcSCTP computes its deadline as `now + N + 1 ms` and expires messages at or beyond
that deadline. In particular, `timed:0` can transmit during the enqueue
millisecond. This native difference must be accounted for when comparing with
the `rtc-sctp` API; the adapter does not alter peer policy to hide it.

# usrsctp test peer

This is a real usrsctp association, using its `AF_CONN` interface to exchange raw
SCTP packets over stdin/stdout. It does not open an IP socket or replace the
stack's SCTP algorithms. It is a test executable and is not linked into `rtc-sctp`.

The source is pinned to
[`fd070e05a7474f38c7fecdf4d4b6005d2547ee00`](https://github.com/sctplab/usrsctp/tree/fd070e05a7474f38c7fecdf4d4b6005d2547ee00).
The build script fetches it into a separate directory; no usrsctp source is
vendored in this repository. Dependencies are Python 3.9+, git and a C11 compiler
with POSIX threads (`clang` by default). The script supports macOS and Linux;
macOS was exercised during implementation.

From the repository root:

```sh
python3 rtc-sctp/interop/build_usrsctp.py --self-test
```

The default build directory is `/tmp/rtc-237-usrsctp`. The resulting executable
is `/tmp/rtc-237-usrsctp/build/usrsctp_peer`. `build/build.json` records the exact
source revision, adapter hash, compiler, flags and stack settings. A repeat build
can prohibit network access:

```sh
python3 rtc-sctp/interop/build_usrsctp.py --offline --self-test
```

Use `--build-dir PATH`, `--cc PATH`, and `--jobs N` to change build locations or
tools. No package installation, CMake, or change to the ordinary Cargo build is
required. The external checkout must be clean; the script refuses to overwrite
modified source.

## Command protocol

Each input line is one command. All output caused by that command precedes its
`DONE` line. Input numbers use decimal and packet/message bytes use hexadecimal.
`-` represents an empty byte string; SCTP send itself may reject an empty message.
Start a separate process for each association.

| Input | Meaning |
| --- | --- |
| `INIT client` / `INIT server` | Initialize once; server binds and listens immediately. |
| `CONNECT` | Initiate the client handshake. The server is passive. |
| `SEND sid ordered reliable ppid hex` | Queue an ordered reliable message. |
| `SEND sid unordered timed:100 ppid hex` | Queue an unordered message with TTL 100 ms. |
| `SEND sid ordered rexmit:0 ppid hex` | Queue a message with zero retransmissions. |
| `RESET sid[,sid...]` | Request reset of the specified outgoing directions. |
| `INPUT hex` | Deliver a complete SCTP packet, with its original checksum. |
| `TICK milliseconds` | Advance the test clock by a relative interval (0–3,600,000 ms). |
| `POLL` | Service nonblocking accept; callbacks otherwise run during commands. |
| `QUIT` | Close sockets, perform bounded cleanup, report `DONE`, and exit. |

The order and policy fields in `SEND` are independent: `ordered` or `unordered`
can be paired with `reliable`, `timed:N`, or `rexmit:N`. The adapter maps these to
`SCTP_PR_SCTP_NONE`, `SCTP_PR_SCTP_TTL`, and `SCTP_PR_SCTP_RTX` without normalizing
zero TTL; differences from the `rtc` or dcSCTP API belong in scenario expectations.

| Output | Meaning |
| --- | --- |
| `PACKET hex` | A complete packet emitted by the real stack; the harness chooses its delivery. |
| `MESSAGE sid ppid hex` | One complete message delivered to the application. |
| `EVENT ready` | Association established. |
| `EVENT reset_in:SID` / `EVENT reset_out:SID` | That direction's reset completed. |
| `EVENT send_failed:SID:code` | usrsctp send-failure notification, including PR abandonment. |
| `EVENT closed` | Association closure notification. |
| `EVENT error:text` | Asynchronous stack failure. |
| `ERROR text` | The command was rejected; the following `DONE` still ends it. |
| `DONE` | End of command output. |

Both SCTP ports are 5000. The peer negotiates 1024 streams each way, enables
PR-SCTP and stream reset, disables ECN, heartbeat and path-MTU discovery, uses a
1200-byte path MTU and 4 MiB socket buffers, and enables `SCTP_NODELAY`. usrsctp's
default RTO parameters remain in effect. `RESET` resets the outgoing direction;
the harness must request the opposite direction when modelling a full data
channel close. The peer does not automatically invent a reciprocal application
close. A complete incoming message is read immediately by the callback. Therefore
slow-reader/rwnd tests must put the slow reader on the `rtc` side; this adapter
does not expose a paused application read queue.

## Time and reproducibility

`usrsctp_init_nothreads` disables background workers. `TICK` advances both the
callout wheel (`usrsctp_handle_timers`) and the `gettimeofday` values used for
PR-SCTP deadlines. The test build injects a header into library translation units
which replaces `gettimeofday` with `rtc_usrsctp_gettimeofday`. It includes the
platform time header before defining the macro, avoiding Darwin symbol aliases
silently bypassing the hook. It makes no changes to upstream source files.

Time starts at the fixed nonzero epoch 1,700,000,000,000 ms and only advances on
`TICK`. Larger intervals are serviced in steps of at most 10 ms so a timer
scheduled by a callback has a meaningful intermediate timestamp. Exact boundary
tests can use 1 ms ticks. `POLL` and `INPUT` do not advance time. There is no
wall-clock sleep in this peer. The self-test deliberately loses a Timed packet,
advances virtual time, and checks that the stack emits FORWARD-TSN instead of
retransmitting DATA; it would fail if only the callout wheel were virtualized.

Randomness remains the stack's normal system entropy. The initial TSNs, tags and
cookies consequently differ across processes. A scenario replay can reproduce
application actions and loss choices by decoded chunk properties; byte-for-byte
replay must retain the original packet trace. Record `build.json`, commands,
virtual timestamps, network seed and original packet bytes with each run.

`--self-test` starts two independent peer processes and checks the real handshake,
reliable and timed messages in both directions, fragmented Rexmit(0), outgoing
and reciprocal reset, SID reuse, and virtual TTL expiry after a lost DATA packet.
It tests the adapter's plumbing; the shared Rust scenario suite supplies the
`rtc ↔ usrsctp` protocol/regression checks.

The limited reset-result cache used by interoperability scenarios is implemented
in the pinned stack's
[`sctp_handle_str_reset_request_out`](https://github.com/sctplab/usrsctp/blob/fd070e05a7474f38c7fecdf4d4b6005d2547ee00/usrsctplib/netinet/sctp_input.c):
the preceding two RSNs can replay a stored result, while older requests receive
`ErrorBadSequenceNumber`. This executable exercises that implementation directly;
an individually synthesized response in a Rust unit test is a separate check.

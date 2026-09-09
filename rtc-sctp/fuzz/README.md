# Stateful SCTP scenarios

`association_state` complements the packet/parameter parser targets. It establishes
two real sans-I/O endpoints, completes a valid handshake, and then uses the public
stream API. The network queue contains original packets emitted by the endpoints;
loss, duplication, and reordering do not invent invalid RSNs, verification tags or
checksums. The adapter interoperability suite is a separate test surface.

The shared driver in `src/fuzzing_state.rs` checks:

- Whole message contents and ownership, no duplicate application delivery, and
  ordered delivery on each SID.
- Timed policy at the instant `poll_transmit` emits DATA, including no Timed(0)
  retransmission; Rexmit budgets are checked for each transmitted TSN.
- Every accepted byte is counted on write, release events never exceed accepted
  bytes, and live send buffers return to zero after the network becomes fair.
  With no reset, release events must account for every accepted byte exactly.
- A fair network and an application reading all available messages must reach
  quiescence. Reliable messages must arrive unless the receiving application
  stopped its read half or the association exhausted its allowed failures.

Application and network choices are deterministic from the input. The driver is
given an `Instant` origin and advances only virtual time. The endpoint's normal
random handshake fields are not overridden; failure traces identify commands and
relative time instead of assuming constant TSNs. The generated packet trace is
protocol-valid for that particular association.

Each action occupies four bytes `op, side_and_sid, flags, size`. At most 128
actions are read; trailing incomplete actions are ignored. `side_and_sid & 1`
chooses the side, `(side_and_sid >> 1) % 3` the SID, and `size % 3` chooses 32,
1200 or 4000 payload bytes. `op % 12` selects:

| Operation | Effect |
| --- | --- |
| 0 / 1 / 2 | Send Reliable / Timed(0,1,100) / Rexmit(0,1,2). |
| 3 | Deliver a selected queued packet. |
| 4 / 5 | Drop / duplicate a selected packet. |
| 6 | Advance time by 0, 1, 100, 500 or 1100 ms. |
| 7 | Read a side's available messages. |
| 8 | Stop, finish or close the selected stream. |
| 9 | Try to open/reuse the selected SID. |
| 10 | Deliver the newest packet before older packets. |
| 11 | Poll output and application events. |

Command attempts rejected by the public API are not treated as successful writes.
After the actions, all packet loss stops and both applications read. Explicit
named regression tests additionally assert successful close/reopen and writable
half behavior; these expectations are not conditional on API success.

Run the critical matrix, short regressions, and 48 fixed seed scenarios without
installing a fuzzer:

```sh
cargo test -p rtc-sctp --lib model_
cargo test -p rtc-sctp --lib --release model_
```

With `cargo-fuzz` and a nightly toolchain available:

```sh
cd rtc-sctp
cargo +nightly fuzz run association_state -- -seed=237 -max_len=512 -max_total_time=60
```

The ordinary library has no new dependency. The separate existing fuzz package
uses `libfuzzer-sys`. A stable-toolchain smoke build is also possible, but does
not enable coverage instrumentation or sanitizers:

```sh
cargo build --manifest-path rtc-sctp/fuzz/Cargo.toml \
  --bin association_state --features rtc-sctp/bench
rtc-sctp/fuzz/target/debug/association_state -runs=1000 -seed=237 -max_len=512
```

`model_replay_input` accepts a hex input through `RTC_SCTP_MODEL_INPUT`:

```sh
RTC_SCTP_MODEL_INPUT=6832487ee4db0a22 \
  cargo test -p rtc-sctp --lib model_replay_input -- --nocapture
```

For a failure, `minimize_association_state.py` deletes whole commands and retains
only a still-failing sequence. Pass the actual test executable printed by Cargo
and an output path outside the source tree. It writes the minimized `.bin`, a
`.log`, and metadata with a binary hash; `--contains` keeps a particular failure.

```sh
python3 rtc-sctp/fuzz/minimize_association_state.py \
  --test-binary /path/to/debug/deps/rtc_sctp-HASH \
  --input-hex HEX_FROM_FAILURE --contains 'protocol did not quiesce' \
  --output /tmp/sctp-minimized
```

The bounded scenarios are a regression and fuzzing surface, not a proof of every
SCTP event ordering. Packet corruption remains covered by the parser targets;
peer cache size, external timers and interoperability are covered by the pinned
usrsctp/dcSCTP suite.

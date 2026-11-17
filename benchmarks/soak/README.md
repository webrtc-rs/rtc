# Soak: rtc against pion over hours

Users of an SFU built on this library report calls that start fine and later freeze or lose audio.
Short tests do not see that kind of fault, so this harness runs two peers over loopback for hours
(two by default), impairs the path with `tc netem` on a repeating cycle, and compares the start of
the run with the end:

* counter wraparound: every run starts RTP sequence numbers 300 packets before 65536 and
  timestamps 20 s before 2^32 (video and audio), so SRTP rollover, extended sequence numbers and
  jitter maths cross their wraps within seconds, and again every ~9 minutes (video) afterwards;
* slow leaks: RSS, threads and file descriptors per process;
* queues that grow: data-channel latency, jitter, CPU;
* recovery: audio and video after packet loss, burst loss, a bandwidth cap and a 5 s outage.

Pion (Go) is the reference. `rtc` is the implementation under test and is gated on being at least as
stable as pion on the same run (see Rules); pion is the baseline, never gated.
The harness is generic: any implementation that writes the JSONL below can use `netem.sh` and
`report.py` (the rtcd SFU harnesses do).

| File | Role |
|---|---|
| `go/` | the pion/webrtc v4 peer (`soak-pion`), pinned in `go/go.mod` |
| `src/`, `Cargo.toml` | the `rtc` peer (`soak-rtc`), a standalone crate outside the main workspace |
| `netem.sh` | drives `tc netem` through the phase cycle and logs `phase` lines |
| `run.sh` | builds and starts a pair, runs `netem.sh` on `lo`, collects JSONL, calls `report.py` |
| `report.py` | JSONL to `summary.md` and `report.html`: subject against baseline side by side; applies `rules.json`; exit 1 on a gate breach |
| `test_report.py` | self-test of `report.py` on generated runs (`python3 -m unittest discover -s benchmarks/soak`) |
| `rules.json`, `rules-abuse.json` | the `compare` pairs and thresholds (`call` and `abuse` profile); gate `rtc` only |

## Run it

Linux only (`tc`, `/proc`); needs Go, Rust, python3, iproute2, and root or sudo for `tc`.

```sh
benchmarks/soak/run.sh rtc-pion 120 out        # pair: rtc-rtc | pion-pion | rtc-pion, minutes, outdir
CYCLE_MIN=2 benchmarks/soak/run.sh rtc-rtc 3 out   # short smoke run
```

`rtc-pion` is bidirectional (each peer sends to the other), so it covers both directions. Output:
`out/<pair>.jsonl`, `out/<pair>.{offerer,answerer}.log`, `out/summary.md`, `out/report.html`.
`SOAK_RTC_BIN` / `SOAK_PION_BIN` use prebuilt peers; `IFACE` and `RULES` override the interface and
the rules file.

On a Mac, use a privileged Linux container (Colima's VM is aarch64, so this is also an arm64 run).
Build the two peers for Linux first (`cargo build --release` in a `rust` container, `go build` in a
`golang` one), then run in an image that has `iproute2` and `python3`:

```sh
docker run --rm --cap-add NET_ADMIN -v "$PWD":/rtc -v /path/to/peers:/peers -v /path/to/out:/out \
  -e SOAK_RTC_BIN=/peers/soak-rtc -e SOAK_PION_BIN=/peers/soak-pion -e CYCLE_MIN=2 \
  <image> /rtc/benchmarks/soak/run.sh rtc-pion 3 /out/run
```

Runs of a few minutes are smoke tests of the harness: the windows are too short to judge drift, so
the drift rules report `n/a` (see `min_clean_window_min`).

Each pair writes its own `<pair>.jsonl`; the comparison needs `rtc-rtc` and `pion-pion` (run both into
the same directory and `run.sh` reports, or call `report.py --rules rules.json --out DIR out/*.jsonl`).
`machine.txt` in the output records the architecture, kernel, cores and CPU.

`PROFILE=abuse` runs the same pairs as an abuse soak (see "The abuse profile of the peers");
`PROFILE=trace` runs the call over recorded cellular links (see "Trace replay").

CI runs the three
pairs of the `call` and `trace` profiles and `rtc-rtc` / `pion-pion` of the `abuse` profile on x64 and arm64
(`.github/workflows/soak.yml`): weekly for 120 minutes, by hand with a `minutes` input, and for pull
requests that touch this directory for 10 minutes with 5-minute cycles.

Windows of the report: after `warmup_min` the first `window_min` minutes are compared with the last
`window_min`, using clean-phase samples only. Short runs scale both down (window to a quarter of
the run, warmup to a sixth); a 3-minute smoke run therefore compares 45 s with 45 s.

## The peers

`soak-pion` (`go/`) and `soak-rtc` (`src/`) take the same flags and behave the same:

```
--role offerer|answerer   --signal HOST:PORT   --minutes N   --out FILE.jsonl   --id NAME
--profile call|abuse   --seed N   --only CLASS,...
```

The offerer listens on `--signal` (plain TCP, one length-prefixed JSON message each way:
`{"sdp": ..., "candidates": [...]}`), the answerer dials it. ICE runs over loopback host
candidates. After connecting each peer runs `--minutes` and appends to `--out`; `--id` defaults to
`<impl>-<role>`. Each peer sends:

* audio: Opus payload type 111, 50 packets/s of 80 bytes, with the `ssrc-audio-level` extension;
* video: VP8 payload type 96, 30 fps, about 1.2 Mbit/s, packetised by the library's VP8
  payloader at MTU 1200 with the marker bit on each frame's last packet and a picture id; a
  keyframe every 4 s and on every PLI or FIR (the payload is synthetic, only the frame tag's
  keyframe bit is meaningful);
* a data channel (negotiated, id 1) at 10 messages/s;
* NACK retransmissions from the library's responder, using its default interceptors, and PLIs of
  its own when a video track comes out of a freeze (at most one a second).

RTP sequence numbers start 300 packets before 65536, and timestamps 20 s before 2^32 (90 kHz for
video, 48 kHz for audio), so every run crosses every wrap early. Both sides log an `event` of kind
`wrap` as the sender crosses and as the receiver sees it.

`--profile abuse` adds the hostile side described in "The abuse profile of the peers"; `--seed` is its
seed and `--only` restricts it to the named attack classes.

## netem phases

`netem.sh <iface> <minutes> <cycle_minutes> <events.jsonl>` repeats one cycle until the time is up
and appends a `phase` line at every change. Fractions of the cycle length (20 minutes by default):

| Phase | Share | Impairment |
|---|---|---|
| `clean` | 40 % (8 min) | none |
| `loss` | 15 % (3 min) | 2 % random loss |
| `burst` | 15 % (3 min) | Gilbert-Elliott loss, about 5 % in bursts of about 5 packets |
| `bw` | 15 % (3 min) | 1.5 Mbit/s cap per direction and 80 ms delay |
| `outage` | 5 s | 100 % loss |
| `recover` | the rest | none |

What is shaped is chosen by `NETEM_PORTS`:

| `NETEM_PORTS` | Shaped | Use |
|---|---|---|
| unset | everything crossing `<iface>`, one flow | a peer pair: one participant per side, so per flow is per peer (`lo` is crossed by both directions, so its total cap is doubled) |
| `udp` | all UDP of the network namespace, one flow | one participant that has a namespace of its own (a browser in its own container) |
| `<base>:<count>` | `<count>` flows, flow k = the UDP ports `<base>+4k` to `<base>+4k+3` | many participants in one namespace, each with a cap, delay and loss of its own |

In the two flow modes (`tc` htb classes with a netem leaf, picked by a u32 filter on the UDP port; the
port is `sport` on what the shaped side sends and `dport` on what it receives through `ifb`) TCP and
all other UDP are left alone: the signaling websocket of a lesson stands for the LMS server's
connection on a datacenter link, and DC signaling (renegotiation) rides the shaped SCTP path. A
participant binds its sockets to its block of four ports (one per try, so a rejoin does not reuse the
port the SFU still knows): `lms-sim lesson --udp-base`. The bw phase caps what the shaped side sends
(`NETEM_BW_UP_MBIT`) and what it receives (`NETEM_BW_DOWN_MBIT`) separately, both defaulting to
`NETEM_BW_MBIT` (1.5; 3 on `lo`), with `NETEM_DELAY` (80ms) added. `NETEM_GROUP` (default `impaired`)
names the group the `phase` lines are for. Qdiscs are removed on exit. Egress is always shaped;
ingress too through an `ifb` device, except on `lo`, where a packet crosses egress and ingress both and
egress shaping already covers each direction once (`NETEM_INGRESS=0|1|auto` overrides). To impair
another network namespace, run the script inside it (`nsenter -t <pid> -n netem.sh ...`).

### The abuse profile

`NETEM_PROFILE=abuse NETEM_SEED=<n> [NETEM_NAMES='a b c'] netem.sh ...` replaces the cycle. Every flow
(the single flow in the whole-device and `udp` modes) runs its own schedule, independent of the
others and replayable: `RANDOM` is seeded with `NETEM_SEED + <flow number>`, so the same seed gives
the same sequence of scenes. A scene lasts 3 to 10 s and is chosen from: clean (about 30 %), `reorder`
(`delay 30ms 20ms reorder 30% 50%`), `duplicate` (10 %), `jitter` (`delay 100ms 80ms distribution
normal`), `asym-loss` (10 to 30 % loss, in one direction, up or down; up only on `lo`), `bw-flap`
(rate alternating between 3 Mbit and 300 kbit every 3 s) and, about once in 300 scenes (a few per
flow in two hours), an outage of 30, 60 or 120 s (`outage-30`, `outage-60`, `outage-120`: 100 % loss;
one per flow at a time, its length is the scene). Everything is cut at the deadline. Each scene
except clean writes an `attack` `start` and `end` line with the id `net-<group>-<flow>-<n>`; `who` is
the k-th name of `NETEM_NAMES` for flow k (all names in the whole-device and `udp` modes). At the start
the script writes an `event` `seed` line and one `phase` line named `abuse`, so the group is not
treated as clean. Every change of any profile resets reorder, duplicate, loss and rate first
(`tc qdisc replace` on a netem keeps them otherwise).

## Trace replay

`PROFILE=trace` (`NETEM_PROFILE=trace` in `netem.sh`) puts the call on real recorded links instead of
synthetic phases, the way Mahimahi-based evaluations of real-time video do (Winstein, Sivaraman,
Balakrishnan, "Stochastic Forecasts Achieve High Throughput and Low Delay over Cellular Networks",
NSDI 2013; Netravali et al., "Mahimahi: Accurate Record-and-Replay for HTTP", USENIX ATC 2015).

* **Traces.** The Mahimahi LTE driving traces of Verizon, AT&T and T-Mobile, uplink and downlink (six
  files), at commit `f1346c38c415abfc98626dd82450f49a57033603` of github.com/ravinet/mahimahi. A file is
  a list of millisecond timestamps, one per 1500-byte packet the link can deliver then, and loops. That
  repository is GPL-3.0, so the files are **not** committed here (this repository is MIT / Apache-2.0):
  `traces.sh` downloads them at run time into `TRACE_DIR` (default `<outdir>/traces`, in CI
  `$RUNNER_TEMP/soak-traces`) and fails when a file's sha256 is not the one hard-coded in it.
* **Replay.** `tracereplay.py` counts the packets of every `NETEM_TRACE_STEP_MS` (200) window, which is
  the kbit the link can deliver in it, and every step sets that rate (`tc qdisc change`, one
  `tc -batch` per step for all flows) on the flow's netem, with `NETEM_TRACE_DELAY` (40 ms, one way)
  of base delay. Each flow (the single flow in the whole-device and `udp` modes, every flow of
  `<base>:<count>`) takes a carrier and an offset into its uplink and its downlink from
  `NETEM_SEED` and the flow's number, so a seed replays; the replay loops. On `lo` (no ingress shaping)
  only the uplink is replayed, and both directions of the pair share it.
* **Queue.** `NETEM_TRACE_LIMIT` (100) packets, drop-tail: 150 kB, which at the median rates of these
  traces (1 to 20 Mbit/s) is 60 ms to 1.2 s. It holds a keyframe's burst but turns a stall into loss
  rather than seconds of delay. (`mm-link` queues without bound by default.)
* **Stalls.** A step in which the link delivers nothing is set as `loss 100%` (with `rate 0`, which
  in netem means no limit): what a stalled link does to the packets of a call is, over seconds, the
  same as an outage.
* **Timeline.** One `phase` line named `trace` at the start (so the group is not treated as clean), an
  `event` `trace` line per flow with the files and offsets, and `attack` windows per flow with `who`
  as in the abuse profile: `trace-stall` for no delivery for at least 1 s, `trace-low` for under
  300 kbit/s for at least 2 s (a stall is low too, so the two overlap). The windows follow what the
  flow's participant lives through: the lower of its uplink and downlink where both are shaped.
* **Rules.** `rules.json`, as for `call`. There is no clean phase, so the drift rules report `n/a`, as in
  the abuse profile. The long stalls of the traces (the AT&T uplink has one of 78 s, Verizon's 14 s)
  can end the ICE session for both libraries; the comparison only holds `rtc` to what `pion` shows.

Local: `PROFILE=trace SEED=7 benchmarks/soak/run.sh rtc-rtc 10 out` (Linux, root for `tc`), or look
at a trace alone, on any machine: `python3 benchmarks/soak/tracereplay.py stats "$(benchmarks/soak/traces.sh)"/*`.

## The abuse profile of the peers

The owner's requirement: the soaks must abuse rtc and pion as hard as possible and keep them there for
hours, so long-run faults surface; the abuse is the same for both libraries, deterministic from a
seed, and never leaves the machine. `PROFILE=abuse run.sh <pair> <minutes> <outdir>` runs the same
pair as the call profile, plus:

* the netem abuse profile on the interface (`NETEM_PROFILE=abuse`, see above): reorder, duplication,
  jitter, asymmetric loss, bandwidth flapping and outages of 30, 60 and 120 s, all at the same time as
  the rest. The measured call's ICE waits 240 s before it gives up (both libraries) so that it rides out
  the longest outage;
* in every peer process a victim service and three attack workers (`--profile abuse` of the peers,
  `src/abuse.rs` and `go/abuse.go`, the same behaviours with each library's API). The attacker of one
  peer works on the other peer; both attack each other. The measured call (audio, video and the data
  channel between the two peers, the `recv` lines as in the call profile, group `impaired`) is never
  touched: the attacks ride on extra peer connections and on raw sockets, and every window names the
  hostile connection in `who` (`<peer id>-abuser`), so each measured receiver counts as innocent in
  every window and `report.py` shows what it saw.

Extra connections signal over TCP on `--signal` port + 1 (the offerer's victim service) and + 2 (the
answerer's), one length-prefixed JSON message at a time (`offer`, `answer`, `glare`, `bye`).

| Worker | Class | What it does |
|---|---|---|
| `churn` | `conn-churn` | batches of 8 connections: negotiate, run 2 to 6 s with audio, video and a data channel, close; thousands over a two-hour run, so leaks show in the `proc` rows (RSS, threads, fds) and in the `churn` events (`made=`, `connected=`, `failed=`) |
| `churn` | `join-leave` | batches of 20 connections that are gone within 0 to 800 ms, most of them before they connect |
| `hostile` | `rtp-jump` | sequence number and timestamp jumps forward, backward and by one (a duplicate), on audio and video |
| `hostile` | `ssrc-change` | the video stream switches SSRC every 1.5 s (rtc: a second SSRC of the track; pion: an SSRC that was never signaled) and sometimes restarts its sequence number and timestamp |
| `hostile` | `pli-flood` | 3000 PLIs/s at the victim's video SSRC |
| `hostile` | `nack-flood` | about 1000 NACK pairs/s, half for recent packets (real retransmissions) and half random |
| `hostile` | `bogus-rtcp` | receiver reports with random blocks, REMB with 0, tiny and huge bitrates and random SSRCs, TWCC feedback with a random body, each in its own datagram |
| `hostile` | `rtp-size` | audio and video packets of 0, 1, 2, 100, 1188, 1400 and 1450 payload bytes |
| `hostile` | `rtcp-garbage` | raw RTCP: random bytes, a header that claims 65 000 words, shorter than a header, a real PLI followed by garbage, zeros and 0xFF |
| `hostile` | `dc-flood` | 5000 small messages/s on the data channel, and 5 data channels opened per 0.5 s (30 kept open, the oldest closed) |
| `hostile` | `dc-oversize` | messages of 1 KiB to 1 MiB, around the 256 KiB SCTP message limit, twice a second |
| `hostile` | `renego-storm` | an audio track added or removed and a new offer every 0.4 s |
| `hostile` | `glare` | an offer sent while the other side's offer is on its way (the victim is polite and rolls back; the attacker is not) |
| `hostile` | `late-answer` | renegotiation rounds, with the answer of the round before applied again and the offer of the round before sent again |
| `junk` | `udp-junk` | random UDP of 1 to 1400 bytes at the victim's media port, about 2000 datagrams/s, from 4 sockets |
| `junk` | `stun-flood` | STUN binding requests with unknown usernames and made-up integrity, from 200 source ports |
| `junk` | `dtls-junk` | DTLS records that open like a ClientHello and are garbage inside, or are other record types |

A hostile window lasts 8 to 20 s, followed by 3 to 8 s of normal media on the same connection; a
connection that dies (a failed ICE, the other side closing it) is replaced. The `end` row of a hostile
window says what it sent: `rtp 19500/0 rtcp 13691/0 dc 0/0 sdp 868/434` is `ok/refused` counts of RTP
packets, RTCP datagrams, data-channel messages and session-description operations; the libraries refuse
what they cannot express (an oversize message, a stale answer) and that is expected. Both libraries
accept the same attack list; a class that one of them cannot express is skipped there and logged once
as an `event` `attack-unsupported` (none today). Differences that remain: pion's raw RTCP path
rejects some of the garbage (visible as refused RTCP), and the `ssrc-change` SSRC is signaled for rtc
and not for pion.

Everything is deterministic from `SEED` (default: the UTC date; in CI the run id, so both libraries
of a run see the same schedule): every worker draws windows, classes and parameters from a splitmix64
generator seeded with the seed, the role and the worker, the same generator in both peers, and each
worker and the netem profile log an `event` `seed`. The timing inside a window depends on the machine, the
schedule does not. Replay one run, or one class:

```sh
SEED=7 PROFILE=abuse benchmarks/soak/run.sh rtc-rtc 3 out
SEED=7 PROFILE=abuse ONLY=glare,dc-oversize benchmarks/soak/run.sh pion-pion 3 out
```

Crashes: a peer that exits non-zero (a panic on any thread of the Rust peer exits 101; a Go panic exits 2),
or whose log has a `panic:`, `fatal error:` or `panicked` line, fails `run.sh`, and `run.sh` writes it as
an `error` `event` of id `sfu`, which the report counts as a process error and gates at zero. The
measured call has no tolerance for a failed connection either: a peer whose call fails exits 1. What the report gates is the same as for the call profile, with `rules-abuse.json`:
process errors, closes, freezes, stalls and the leak slopes of the subject against pion, and per attack
class what the measured receivers saw in the windows (`clean_zero` is empty: there is no unimpaired
group). Nothing leaves the machine: the peers use loopback, the hostile sockets send to 127.0.0.1 only.

## JSONL schema (the contract)

One JSON object per line. Every line has:

| Field | Type | Meaning |
|---|---|---|
| `ts` | integer | unix time, milliseconds |
| `impl` | string | `rtcd-rs`, `rtcd-go`, `rtc`, `pion`, `chrome-...`; free text. `netem` for phase lines |
| `arch` | string | `x86_64` or `aarch64` (`uname -m`) |
| `kind` | string | `recv`, `proc`, `dc`, `event` or `phase` |
| `id` | string | what the line is about: a track (`rtc-offerer-video`), a process, a peer |

`recv`, one per received track every 5 s, counters cumulative since start:

| Field | Meaning |
|---|---|
| `media` | `video` or `audio` |
| `group` | `clean` (a path that is never impaired, e.g. a control participant) or `impaired` (on the netem path). Samples of a `clean` group count as clean in every phase |
| `frames` | video: frames completed (marker packet received); audio: audio packets received |
| `freezes`, `freeze_ms` | WebRTC stats freeze: an inter-frame interval longer than max(3 x average, average + 150 ms), average over the last 30 frames; `freeze_ms` is the summed interval. A freeze still open at a report counts at once |
| `packets` | RTP packets received (retransmissions included) |
| `lost` | expected minus received, from extended sequence numbers; falls when a retransmission fills a gap |
| `nack`, `pli` | NACKs and PLIs this receiver sent (library statistics; pion's NACK generator bypasses its own stats, so `pion` reads 0 NACKs) |
| `bytes` | number, optional: RTP bytes received (header and payload); with the interval it gives the Mbit/s a participant received, the proof that a cap is applied to each participant |
| `duplicates` | number, optional: arrivals of a sequence number that had come already; `packets` counts them, `lost` does not take them off, so a copy does not hide a loss |
| `jitter_ms` | RFC 3550 interarrival jitter |
| `rtt_ms` | number or null: round trip from RTCP for the stream of the same kind that this peer sends; null when the library reports none (rtc never computes it) |
| `audio_gap_ms` | time the sender was sending but no audio packet arrived for more than 60 ms, summed |
| `stalled` | bool: no media packet for more than 2 s at some point since the previous report |

`proc`, one per process every 5 s: `rss_mb`, `cpu_pct`, `threads`, `fds`, `udp_rcvbuf_err`,
`udp_sndbuf_err` (the host's UDP `RcvbufErrors` / `SndbufErrors`).

`dc`, every 5 s: `sent`, `recv` (cumulative), `lat_ms_p50`, `lat_ms_p99` (this window; null when no
message arrived). The peers send `{"n":<count>,"ts":<unix microseconds>}` at 10 messages/s on a
negotiated channel, id 1, label `soak`.

`event`: `what` is `ice_state`, `wrap`, `join`, `leave` (`stop` when the participant was stopped at the
end; a run's `recv` samples end at its first one, since what follows is the lesson ending), `rejoin`, `error`, and in the abuse profile `seed`,
`churn` (cumulative `made=N connected=N failed=N` of the extra connections) and `attack-unsupported`,
with a `detail` string
and, from the lesson harness, the `group` of the participant (default `impaired`). `wrap` lines read
`send|recv audio|video seq|ts wrap`. The report counts these `error` details: `the SFU closed the
session`, `the signaling connection closed`, and the rest as lost seats (`the media path stayed
down`, `the call did not connect in time`); `ice_state` `ice:disconnected` and `ice:failed`; a
`rejoin` carries `downtime_ms` and `attempts`. A participant that takes its seat back after a loss
records the downtime, and one that never does costs the time to the end of the run.

`phase`: `name` is `clean`, `loss`, `burst`, `bw`, `outage` or `recover`; the phase lasts until the
next `phase` line of the same `group` (default `impaired`; `up` and `down` hold the netem arguments).
Samples are assigned to phases by `ts`, each by its own group: samples of a group without `phase`
lines (`clean`) are in `clean` throughout. A series id `name#N` is the N-th rejoin of `name`.

`attack`, one at the start and one at the end of an attack window, written by `netem.sh` and by the
abuse clients (`lms-sim`, the `rtc` and pion peers):

```json
{"ts":ms,"impl":"abuse","arch":"x86_64","kind":"attack","id":"<unique id>","name":"<class>","state":"start","group":"impaired","who":["s17"],"seed":7,"detail":"..."}
```

`state` is `start` or `end`; a window runs from a `start` to the `end` with the same `id`, and an
unmatched `start` to the end of the run. `group` is `impaired`, `clean` or `all`; `who` (optional)
lists the participants attacked, absent means the whole group. `name` is any string; the classes in use:
network `reorder duplicate jitter asym-loss bw-flap outage-30 outage-60 outage-120 nat-rebind mtu`;
churn `join-leave camera-toggle mic-toggle screen-toggle layer-flap teacher-reconnect renego-storm glare
late-answer`; hostile media `rtp-jump ssrc-change pli-flood nack-flood bogus-rtcp rtp-size rtcp-garbage
dc-flood dc-oversize`; junk `udp-junk stun-flood dtls-junk`; signaling `ws-storm dup-join unknown-call`;
load `load-hold`. A server-side failure is an `event` with `what` `error` and id `sfu`.

## What the report says

For every `compare` pair and architecture, the subject and the baseline side by side, per group
(`clean`, `impaired`) and phase (`all` and each netem phase), for: freezes per minute, freeze ms per
minute (in the `outage` phase, the freeze ms per outage instead: the freeze booked from the outage's
start to one sample after its recovery began, so the sampling clock cannot decide it; the `recover` phase
leaves that span out), the video frames per second (higher is better; not in the `outage` phase, which has too few intervals for a rate), audio gap %, residual loss % (after retransmission, from unique packets), duplicate %, stall
count and longest stall, recovery after an outage (median, p90, tracks that never recovered), SFU-closed
sessions, signaling closes, lost seats, rejoins and their total downtime, ICE disconnects and failures,
and the Mbit/s each participant received (all its tracks together; in the bw phase this is what shows
the cap per participant). The SFU process: CPU mean, RSS peak and slope, threads, fds, UDP buffer
errors, process errors (gone or crashed), per phase for the CPU. Then the absolute and drift rules and
the breaches. `report.html` charts subject against baseline over the run, with the phases shaded.

With `attack` rows, per architecture and per attack class (scope `attack`, the class in the phase
column) the metrics of the innocent receivers: every receiver of the `clean` group, and those of
other participants the window does not name (`who`; a window with `group` names that whole group),
over the intervals from the window's start to `recover_window_s` after its end, leaving out the time another window that names the
receiver overlaps (a class left with nothing to score reports n/a): freezes (count),
freeze rate and frozen ms per minute of video (over the same intervals, counted once per class), stalls and longest stall, SFU closes, signaling closes, ICE disconnects, `recover_s` (per
window the p90 over the innocent video tracks that were flowing at the start, seconds from the end of
the window until they flow again, 0 when never interrupted, `never` if not within `recover_window_s`;
the worst window of the class) and `never` (those tracks). `summary.md` has a table per architecture of
the classes and a list of the windows (class, id, start minute, duration, who, what the innocents saw;
only the ones with an impact when there are more than 200), so each breach can be attributed.
`report.html` shades the windows in the charts. The SFU process also reports `threads_slope` and
`fds_slope` (per hour after warmup, same span rule as the RSS slope) and `cpu_sat` (% of samples at or
above `cpu_sat_pct`, 190). Without `attack` rows none of this appears.

Recovery is measured over the tracks that are expected to flow: the participant was in the call at
the outage and stayed through `recover_window_s` after it. A track that ends because the SFU closed
the session, or the participant left, is not one of them: it is a close, counted as one, with the
participant's downtime until it rejoins (or until the run ends).
The recovery time is placed inside the sample interval that first shows frames by the freeze ms the
track counted since the outage began, so it does not round to the sampling clock (a track with no
freeze ms keeps the sample's time).

## Rules (`rules.json`)

`compare` lists `{"subject": impl, "baseline": impl}` pairs; `subject_run` / `baseline_run` restrict a
side to the input file with that name (`rtc-rtc`, `pion-pion`), and `"gate": false` reports the pair
without failing on it. For each architecture the subject is held to the baseline:

* rates (freezes, loss, gaps, recovery times, CPU, RSS, downtime ...): subject <= baseline x `ratio`
  (1.25) + a slack in the metric's unit (`slack` overrides it per metric key, `ratios` the ratio);
* counts (stalls, closes, ICE disconnects, rejoins ...): subject <= baseline + slack (0). An ICE
  disconnect that starts in an outage, or within one sample interval after it, is the outage's and is
  not counted; an ICE failure always is.
* frames per second (higher is better): subject >= baseline / `ratio` - slack (1). Freezes per minute
  breach only when the subject's freeze ms per minute is also above the baseline's: a stream that stays
  frozen has few freezes, one that plays and stutters has many.
  The attack classes follow the same rule: their freezes per minute breach only with their freeze ms per
  minute, which is gated like the scope's.

Data that is missing fails loudly: no baseline (or no subject) data for an architecture, a group the
subject must have (`require_groups`) without receivers, a side with SFU process samples where the other
has none. Absolute rules: in the `clean` group (a path that is never impaired) the metrics in
`clean_zero` (default zero stalls, freezes, SFU closes, ICE disconnects; a `compare` entry may set its
own list) must be zero, for the baseline too (reported only); the SFU process must not have errors. A
baseline whose samples end more than a minute before the subject's (killed for memory, crashed) is
compared over the minutes it ran, and the report says so; the subject's absolute rules still cover its
whole run. The self-drift of the subject: first clean
window against last (`freeze_rate_*`, `audio_gap_*`, judged only with `min_clean_window_min` of clean
time in each window), and `rss_slope_mb_per_h_max` (only on runs with `rss_slope_min_span_min`
minutes after `warmup_min`). During attacks the clean group is judged the same way (it is innocent in every window), with one
exception: the windows of the classes in `global_load` (default `load-hold`, `udp-junk`, `stun-flood`,
`dtls-junk`, plus `recover_window_s` after them) are left out of the `clean_zero` rules, because they load the
whole server; the comparison with the baseline still holds for them. The attack metrics are held like the
others (counts: baseline + slack 0; rates: ratio and slack, `recover_s` slack 3 s; `threads_slope` 20,
`fds_slope` 100, `cpu_sat` 10). Windows are `window_min` after `warmup_min`, scaled down on short runs
(a quarter of the run, and a sixth).

### Rules of the abuse profile (`rules-abuse.json`)

The same rules with the pairs the abuse profile runs (`rtc-rtc` against `pion-pion`), no `clean_zero`
(there is no unimpaired group) and wider slack, because the measured call shares a network that
reorders, duplicates, delays and drops, and an attack window overlaps whatever netem scene is running:
`stalls` +15, `stall_max` +10 s, `recover_s` +120 s, `ice_disc` +3, and `freezes` effectively not gated
as a count in the attack classes (the freeze rate is). `recover_window_s` is 240 s (the ICE patience): a
measured video track that has not come back that long after a window ended is `never`. A window is scored only up to the start of the next outage of the receiver's group (an outage's recovery is
judged on its own), and a stall that overlapping windows of one class (offerer and answerer) share counts once. Everything else is as strict as the call profile:
process errors (a crash) must be zero, `never` recovered, closes and ICE failures at the baseline.
The slack values are a first guess to be tuned from the first long runs.

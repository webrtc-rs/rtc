#!/usr/bin/env python3
"""Replay recorded cellular links on the soak's netem qdiscs (`NETEM_PROFILE=trace` of netem.sh).

    tracereplay.py stats FILE...   per file: step length, kbit per step (min / median / max), stalls
    tracereplay.py play ...        what netem.sh runs (see `play --help`); not meant to be called by hand

A Mahimahi trace is a list of millisecond timestamps, one per 1500-byte packet the link can deliver
then; the file loops (its last timestamp is the period). `convert` counts the packets of every
`step_ms` window, so a step is the kbit the link could deliver in it, and `play` sets that rate on
the flow's netem every step. Standard library only.

How a step becomes `tc`: a step of 1 or more packets is `rate <kbit/s>kbit`. A step with no packet is
a real stall, set as `loss 100% rate 0`: netem's `rate 0` means no limit, so the rate cannot be left
at zero, and what a stalled cellular link does to the packets of the call (they wait in a queue and
arrive late, or are lost) is, over seconds, the same as an outage for the call. The queue is the
netem `limit`, in packets.
"""
import argparse
import json
import math
import os
import random
import statistics
import subprocess
import sys
import time

PACKET_KBIT = 12  # one 1500-byte packet
STALL_S = 1  # a stretch of steps with no packet at least this long is a `trace-stall` attack window
LOW_S = 2  # a stretch under LOW_KBPS at least this long is a `trace-low` attack window
LOW_KBPS = 300


def convert(lines, step_ms):
    """The kbit a trace can deliver in each `step_ms` window of its period. The period is cut down to
    whole steps (the trailing part of a step is dropped), so the loop restarts on a step boundary."""
    stamps = [int(x) for x in lines if x.strip()]
    steps = max(stamps, default=0) // step_ms
    if steps < 1:
        raise ValueError("a trace needs at least one full step")
    kbit = [0] * steps
    for t in stamps:
        if t // step_ms < steps:
            kbit[t // step_ms] += PACKET_KBIT
    return kbit


def load(path, step_ms):
    with open(path) as f:
        return convert(f, step_ms)


def kbps(kbit, step_ms):
    return kbit * 1000 // step_ms


def windows(rates, step_ms):
    """[(first step, end step, name)] of the stretches of `rates` (kbit/s per step) that are attack
    windows: `trace-stall` (no packet for at least STALL_S) and `trace-low` (under LOW_KBPS for at
    least LOW_S). A stall is low too, so the windows of the two classes overlap."""
    out = []
    for name, bad, need in (
            ("trace-stall", lambda r: r == 0, math.ceil(STALL_S * 1000 / step_ms)),
            ("trace-low", lambda r: r < LOW_KBPS, math.ceil(LOW_S * 1000 / step_ms))):
        i = 0
        while i < len(rates):
            if not bad(rates[i]):
                i += 1
                continue
            j = i
            while j < len(rates) and bad(rates[j]):
                j += 1
            if j - i >= need:
                out.append((i, j, name))
            i = j
    return sorted(out)


def stats(args):
    for path in args.files:
        kbit = load(path, args.step_ms)
        stalls = [b - a for a, b, n in windows([kbps(k, args.step_ms) for k in kbit], args.step_ms)
                  if n == "trace-stall"]
        print("%s: %d steps of %d ms, kbit per step min %d median %d max %d, zero steps %.1f s, "
              "stalls >= %d s: %d (longest %.1f s)" % (
                  os.path.basename(path), len(kbit), args.step_ms, min(kbit), statistics.median(kbit), max(kbit),
                  kbit.count(0) * args.step_ms / 1000, STALL_S, len(stalls),
                  max(stalls, default=0) * args.step_ms / 1000))


class Flow:
    """One flow's replay: the trace and offset of each direction, from the seed and the flow number."""

    def __init__(self, k, args, cache):
        rng = random.Random("%s:%d" % (args.seed, k))
        carrier = rng.choice(args.carriers)
        self.k = k
        self.detail = []
        self.rates = {}
        steps = args.seconds * 1000 // args.step_ms
        for direction in ("up", "down"):
            name = "%s.%s" % (carrier, direction)
            if name not in cache:
                cache[name] = load(os.path.join(args.dir, name), args.step_ms)
            kbit = cache[name]
            offset = rng.randrange(len(kbit))
            self.rates[direction] = [kbps(kbit[(offset + i) % len(kbit)], args.step_ms) for i in range(steps)]
            self.detail.append("%s from %d s" % (name, offset * args.step_ms // 1000))
        # What the flow's participant lives through: its uplink, and its downlink where that is shaped.
        felt = [min(a, b) for a, b in zip(self.rates["up"], self.rates["down"])] if args.ifb else self.rates["up"]
        self.windows = windows(felt, args.step_ms)


def tc_line(verb, dev, k, flows, rate, args):
    where = "parent 1:%x handle %x:" % (k + 2, k + 2) if flows else "root"
    shape = "loss 100% rate 0" if rate == 0 else "loss 0%% rate %dkbit" % rate
    return "qdisc %s dev %s %s netem delay %s reorder 0%% duplicate 0%% %s limit %d" % (
        verb, dev, where, args.delay, shape, args.limit)


def play(args):
    args.carriers = sorted({n.rsplit(".", 1)[0] for n in os.listdir(args.dir) if n.endswith((".up", ".down"))})
    if not args.carriers:
        sys.exit("no traces in %s (run traces.sh)" % args.dir)
    names = args.names.split()
    nflows = max(args.flows, 1)
    cache = {}
    flows = [Flow(k, args, cache) for k in range(nflows)]
    steps = args.seconds * 1000 // args.step_ms
    events = open(args.events, "a", buffering=1)
    t0 = int(time.time() * 1000)
    monotonic0 = time.monotonic()

    def line(step, kind, **fields):
        row = {"ts": t0 + step * args.step_ms, "arch": args.arch, "kind": kind, **fields}
        events.write(json.dumps(row, separators=(",", ":")) + "\n")

    def who(k):
        if args.all_names or not args.flows:
            return names
        return names[k:k + 1]

    # Every window of every flow as a start and an end line at its step; they are written as the replay
    # passes them. Window ids run per flow in time order, like the abuse profile's.
    due = []
    for f in flows:
        for n, (a, b, name) in enumerate(sorted(f.windows), 1):
            wid = "net-%s-%d-%d" % (args.group, f.k, n)
            for step, state in ((a, "start"), (b, "end")):
                fields = {"impl": "trace", "id": wid, "name": name, "state": state, "group": args.group}
                if who(f.k):
                    fields["who"] = who(f.k)
                due.append((step, state == "end", f.k, {**fields, "seed": args.seed, "detail": ""}))
    due.sort(key=lambda d: d[:3])

    line(0, "event", impl="netem", id="netem", what="seed", detail=str(args.seed), group=args.group)
    for f in flows:
        line(0, "event", impl="netem", id="netem", what="trace", detail="flow %d: %s" % (f.k, ", ".join(f.detail)),
             group=args.group)
    line(0, "phase", impl="netem", id="netem", group=args.group, name="trace", up="trace", down="trace")

    sent, skipped, step = 0, 0, 0
    while True:
        if not args.dry_run:
            step = int((time.monotonic() - monotonic0) * 1000) // args.step_ms
        if step >= steps:
            break
        while sent < len(due) and due[sent][0] <= step:
            line(due[sent][0], "attack", **due[sent][3])
            sent += 1
        verb = "replace" if step == 0 else "change"
        batch = []
        for f in flows:
            batch.append(tc_line(verb, args.iface, f.k, args.flows, f.rates["up"][step], args))
            if args.ifb:
                batch.append(tc_line(verb, args.ifb, f.k, args.flows, f.rates["down"][step], args))
        text = "\n".join(batch) + "\n"
        if args.dry_run:
            sys.stdout.write("# step %d\n%s" % (step, text))
            step += 1
            continue
        done = subprocess.run(["tc", "-batch", "-"], input=text, text=True, capture_output=True)
        if done.returncode != 0:
            sys.exit("tc -batch failed at step %d: %s" % (step, done.stderr.strip()))
        after = int((time.monotonic() - monotonic0) * 1000) // args.step_ms
        skipped += max(after - step, 0)  # steps the batch overran: the replay jumps ahead, never lags
        time.sleep(max((step + 1) * args.step_ms / 1000 - (time.monotonic() - monotonic0), 0))
    while sent < len(due):
        line(min(due[sent][0], steps), "attack", **due[sent][3])
        sent += 1
    if skipped:
        print("tracereplay.py: %d steps skipped because tc fell behind" % skipped, file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("stats")
    st.add_argument("files", nargs="+")
    st.add_argument("--step-ms", type=int, default=200)
    st.set_defaults(fn=stats)
    pl = sub.add_parser("play")
    pl.add_argument("--dir", required=True, help="the directory traces.sh filled")
    pl.add_argument("--seed", type=int, required=True)
    pl.add_argument("--seconds", type=int, required=True, help="how long to replay")
    pl.add_argument("--iface", required=True)
    pl.add_argument("--ifb", default="", help="the device of what the shaped side receives; empty: not shaped")
    pl.add_argument("--flows", type=int, default=0, help="htb flow classes of netem.sh; 0: one netem at the root")
    pl.add_argument("--delay", default="40ms", help="one-way base delay")
    pl.add_argument("--limit", type=int, default=100, help="queue of the netem, in packets")
    pl.add_argument("--step-ms", type=int, default=200)
    pl.add_argument("--events", required=True)
    pl.add_argument("--group", default="impaired")
    pl.add_argument("--arch", required=True)
    pl.add_argument("--names", default="", help="participant names, space separated: flow k is the k-th")
    pl.add_argument("--all-names", action="store_true", help="every name belongs to every flow")
    pl.add_argument("--dry-run", action="store_true", help="print the tc batches instead of running them")
    pl.set_defaults(fn=play)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

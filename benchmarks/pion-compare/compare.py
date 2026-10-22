#!/usr/bin/env python3
"""Run the Rust and pion micro-benchmarks side by side and compare them.

    python3 benchmarks/pion-compare/compare.py            # print a table, enforce the gates
    python3 benchmarks/pion-compare/compare.py --no-gate  # print only
    python3 benchmarks/pion-compare/compare.py --backend aws-lc-rs --summary "$GITHUB_STEP_SUMMARY"

Both programs print one line per benchmark in the same format:

    <name>   <n> ns/op   <n> B/op   <n> allocs/op   [<n> MB/s]

Each is run `--runs` times and the fastest run of each benchmark is kept: the minimum is the
estimate least disturbed by a noisy neighbour, which matters on shared CI runners.

The gates (see GATES) encode what the project promises relative to pion:

* a benchmark marked `win` must stay at or below `1 + WIN_SLACK` of pion's time;
* a benchmark marked `gap` is a known shortfall: it must not get worse than its recorded ceiling
  (a ratchet), and the table flags it so it stays visible;
* either kind must not allocate more than its recorded count.

Exit status is non-zero when a gate fails.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
LINE = re.compile(
    r"^(?P<name>.+?)\s+(?P<ns>\d+) ns/op\s+(?P<bytes>\d+) B/op\s+(?P<allocs>\d+) allocs/op"
)

# Time noise on a shared runner is real; allocations are exact.
WIN_SLACK = float(os.environ.get("PION_COMPARE_WIN_SLACK", "0.25"))


def win(max_allocs):
    """We are faster than pion: stay within WIN_SLACK of it, and within `max_allocs` allocations."""
    return {"kind": "win", "max_allocs": max_allocs}


def gap(max_ratio, max_allocs):
    """A known shortfall: do not get worse than this ratio of pion's time (a ratchet, lower it
    when the gap closes) or this many allocations."""
    return {"kind": "gap", "max_ratio": max_ratio, "max_allocs": max_allocs}


# Per benchmark: what we promise relative to pion. Allocation ceilings are the counts measured
# when the entry was written; a benchmark missing from this table is held to a plain win with
# pion's own allocation count.
#
# The gaps are honest ones. RTCP unmarshal is allocation-bound (a compound packet is nine small
# boxes and vectors where pion's runtime hands out memory from its own arena) and the ratio
# depends on the platform's malloc: it is widest on macOS's. Run with `--allocator mimalloc` to
# see it on an allocator a server would deploy; there it is a win (OVERRIDES_MIMALLOC).
# `rtp unmarshal` is the borrowed `PacketView`, the counterpart of pion's struct of subslices; the
# owning, reference-counted `Packet::unmarshal_reuse` is reported beside it with no pion peer.
GATES = {
    "rtp unmarshal 1200B": win(max_allocs=0),
    "rtp unmarshal fresh 1200B": win(max_allocs=1),
    # Parity: both are a 1200-byte copy, so the ratio is dominated by runner noise.
    "rtp marshal 1200B": gap(max_ratio=1.4, max_allocs=0),
    "srtp cm-hmac-80 encrypt 1200B": win(max_allocs=0),
    "srtp cm-hmac-80 encrypt alloc 1200B": win(max_allocs=1),
    "srtp cm-hmac-80 decrypt 1200B": win(max_allocs=0),
    # Parity: ring's AES-GCM and Go's assembly GCM are within a few percent of each other.
    "srtp gcm-128 encrypt 1200B": gap(max_ratio=1.4, max_allocs=0),
    "stun decode+getters+integrity": win(max_allocs=2),
    "stun build binding request": win(max_allocs=6),
    "sdp unmarshal ~chrome offer": win(max_allocs=219),
    "sdp marshal": win(max_allocs=1),
    "sdp codec map": win(max_allocs=577),
    "rtcp unmarshal SR+SDES+REMB": gap(max_ratio=2.0, max_allocs=9),
    "vp8 payload 30KB mtu1200": win(max_allocs=32),
    "h264 payload 30KB mtu1200": win(max_allocs=32),
}

# What changes when the Rust side runs on mimalloc.
OVERRIDES_MIMALLOC = {
    "rtcp unmarshal SR+SDES+REMB": win(max_allocs=9),
}


def run(cmd, **kw):
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, **kw)


def parse(text):
    out = {}
    for line in text.splitlines():
        m = LINE.match(line)
        if m:
            out[m["name"].strip()] = {
                "ns": int(m["ns"]),
                "bytes": int(m["bytes"]),
                "allocs": int(m["allocs"]),
            }
    return out


def best_of(runs):
    merged = {}
    for r in runs:
        for name, v in r.items():
            if name not in merged or v["ns"] < merged[name]["ns"]:
                merged[name] = v
    return merged


def run_many(cmd, runs):
    results = []
    for _ in range(runs):
        p = subprocess.run(cmd, check=True, capture_output=True, text=True)
        results.append(parse(p.stdout))
    return best_of(results)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--runs", type=int, default=3, help="runs per implementation; fastest wins")
    ap.add_argument("--backend", default="ring", choices=["ring", "aws-lc-rs"])
    ap.add_argument("--allocator", default="system", choices=["system", "mimalloc"],
                    help="the global allocator of the Rust benchmark (default: the system's)")
    ap.add_argument("--no-gate", action="store_true", help="report only; never fail")
    ap.add_argument("--summary", help="append a markdown table to this file")
    ap.add_argument("--json", help="write the raw comparison to this file")
    ap.add_argument("--rust-only", action="store_true")
    args = ap.parse_args()

    sdp = os.path.join(HERE, "data", "offer.sdp")
    enabled = (["aws-lc-rs"] if args.backend == "aws-lc-rs" else []) + (
        ["mimalloc"] if args.allocator == "mimalloc" else []
    )
    features = ["--features", ",".join(enabled)] if enabled else []
    gates = {**GATES, **(OVERRIDES_MIMALLOC if args.allocator == "mimalloc" else {})}
    run(["cargo", "build", "--release", "--manifest-path", os.path.join(HERE, "Cargo.toml")] + features)
    rust_bin = os.path.join(HERE, "target", "release", "pion-compare")
    rust = run_many([rust_bin, sdp, "--backend", args.backend], args.runs)

    pion = {}
    if not args.rust_only:
        if shutil.which("go") is None:
            sys.exit("go is required to run pion's side (or pass --rust-only)")
        with tempfile.TemporaryDirectory() as tmp:
            go_bin = os.path.join(tmp, "pion-bench")
            run(["go", "build", "-o", go_bin, "."], cwd=os.path.join(HERE, "go"))
            pion = run_many([go_bin, sdp], args.runs)

    rows, failures = [], []
    for name, r in rust.items():
        p = pion.get(name)
        row = {"name": name, "rust": r, "pion": p}
        gate = gates.get(name)
        if p:
            row["ratio"] = r["ns"] / p["ns"]
            if gate is None:
                gate = win(max_allocs=p["allocs"])
            row["gate"] = gate["kind"]
            if gate["kind"] == "win" and row["ratio"] > 1 + WIN_SLACK:
                failures.append(f"{name}: {row['ratio']:.2f}x pion's time (a win may be at most {1 + WIN_SLACK:.2f}x)")
            if gate["kind"] == "gap" and row["ratio"] > gate["max_ratio"]:
                failures.append(f"{name}: regressed to {row['ratio']:.2f}x pion (ceiling {gate['max_ratio']:.2f}x)")
            if r["allocs"] > gate["max_allocs"]:
                failures.append(f"{name}: {r['allocs']} allocations (ceiling {gate['max_allocs']}; pion: {p['allocs']})")
        rows.append(row)

    width = max(len(r["name"]) for r in rows)
    print()
    print(f"{'benchmark':<{width}}  {'rust ns':>9} {'pion ns':>9} {'ratio':>6}  {'rust B/allocs':>14} {'pion B/allocs':>14}")
    for row in rows:
        r, p = row["rust"], row["pion"]
        if p:
            verdict = "faster" if row["ratio"] < 0.95 else ("slower" if row["ratio"] > 1.05 else "even")
            print(
                f"{row['name']:<{width}}  {r['ns']:>9} {p['ns']:>9} {row['ratio']:>5.2f}x"
                f"  {r['bytes']:>7}/{r['allocs']:<6} {p['bytes']:>7}/{p['allocs']:<6} {verdict}"
            )
        else:
            print(f"{row['name']:<{width}}  {r['ns']:>9} {'-':>9}")

    if args.summary:
        with open(args.summary, "a") as f:
            f.write(f"### rtc ({args.backend}, {args.allocator} allocator) vs pion — {platform_label()}\n\n")
            f.write("| benchmark | rtc ns/op | pion ns/op | rtc / pion | rtc allocs | pion allocs |\n")
            f.write("|---|--:|--:|--:|--:|--:|\n")
            for row in rows:
                r, p = row["rust"], row["pion"]
                if p:
                    mark = "✅" if row["ratio"] < 0.95 else ("⚠️" if row["ratio"] > 1.05 else "≈")
                    f.write(f"| {row['name']} | {r['ns']} | {p['ns']} | {row['ratio']:.2f}× {mark} | {r['allocs']} | {p['allocs']} |\n")
            f.write("\n")
            if failures:
                f.write("**Gate failures**\n\n" + "\n".join(f"- {x}" for x in failures) + "\n\n")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"backend": args.backend, "allocator": args.allocator, "platform": platform_label(), "rows": rows}, f, indent=2)

    if failures and not args.no_gate:
        print("\nGATE FAILURES:", file=sys.stderr)
        for x in failures:
            print(" -", x, file=sys.stderr)
        sys.exit(1)


def platform_label():
    import platform

    return f"{platform.system()} {platform.machine()}"


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""rtc-turn against pion/turn, on real sockets, under the same load.

Builds a Go load generator that allocates relays and bounces packets off a local echo peer through
them, then runs it against each server in turn and reports the *server's* CPU time and memory per
delivered round trip (each round trip is four datagrams through the server). The Rust server is the
tokio example `rtc-turn/examples/turn_server_udp.rs`, run as shipped.

What to read from it: CPU per round trip and memory (and, with `--relays 1 --window 1`, latency).
Both servers sit near the syscall floor: eight system calls per round trip. Throughput under a deep
window says more about the host than the library: the example drives the sans-I/O server from one
event loop, where pion spreads its goroutines over every core.

    python3 benchmarks/turn-load/run.py [--runs 3] [--relays 20] [--packets 20000]

Needs Go and a Rust toolchain. Linux and macOS.
"""
import argparse
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))


def cpu_seconds(pid):
    """User+system CPU time of a process, from ps (its resolution is 10 ms)."""
    out = subprocess.check_output(["ps", "-o", "time=", "-p", str(pid)], text=True).strip()
    seconds = 0.0
    for part in out.split(":"):
        seconds = seconds * 60 + float(part)
    return seconds


def rss_mib(pid):
    return int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True)) / 1024


def wait_for_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(0.2)
        # A STUN Binding request: any server of ours answers it.
        probe.sendto(bytes.fromhex("000100002112a442") + os.urandom(12), ("127.0.0.1", port))
        try:
            probe.recvfrom(1024)
            return
        except OSError:
            time.sleep(0.1)
        finally:
            probe.close()
    sys.exit(f"nothing answered on port {port}")


def measure(name, command, port, loadgen, args):
    proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_for_port(port)
        before = cpu_seconds(proc.pid)
        result = subprocess.run(
            [loadgen, "-server", f"127.0.0.1:{port}", "-relays", str(args.relays),
             "-packets", str(args.packets), "-size", str(args.size), "-window", str(args.window)],
            capture_output=True, text=True, check=True,
        ).stdout
        cpu = cpu_seconds(proc.pid) - before
        rss = rss_mib(proc.pid)
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
    m = re.search(r"delivered=(\d+) of (\d+) elapsed=([\d.]+)s", result)
    delivered, total, elapsed = int(m[1]), int(m[2]), float(m[3])
    return {"name": name, "delivered": delivered, "total": total, "elapsed": elapsed,
            "cpu_us_per_rt": cpu / max(delivered, 1) * 1e6, "rss": rss}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--relays", type=int, default=20)
    ap.add_argument("--packets", type=int, default=20000)
    ap.add_argument("--size", type=int, default=1200)
    ap.add_argument("--window", type=int, default=32, help="round trips in flight per relay")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp()
    loadgen, pion = os.path.join(tmp, "loadgen"), os.path.join(tmp, "pionserver")
    subprocess.run(["go", "build", "-o", loadgen, "./loadgen"], cwd=HERE, check=True)
    subprocess.run(["go", "build", "-o", pion, "./pionserver"], cwd=HERE, check=True)
    subprocess.run(["cargo", "build", "--release", "-p", "rtc-turn", "--example", "turn_server_udp"],
                   cwd=ROOT, check=True)
    target = subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--no-deps"],
                                     cwd=ROOT, text=True)
    target_dir = re.search(r'"target_directory":"([^"]+)"', target)[1]
    rust = os.path.join(target_dir, "release", "examples", "turn_server_udp")

    servers = [
        ("pion/turn", [pion, "-port", "3478"], 3478),
        ("rtc-turn", [rust, "--public-ip", "127.0.0.1", "--users", "user=pass", "--port", "3479"], 3479),
    ]
    best = {}
    for _ in range(args.runs):
        for name, command, port in servers:
            r = measure(name, command, port, loadgen, args)
            if name not in best or r["cpu_us_per_rt"] < best[name]["cpu_us_per_rt"]:
                best[name] = r
    print(f"\n{args.relays} relays x {args.packets} round trips of {args.size} B, best of {args.runs}\n")
    print(f"{'server':<10} {'delivered':>12} {'server CPU/rt':>14} {'server RSS':>11} {'throughput':>14}")
    for name, _, _ in servers:
        r = best[name]
        print(f"{name:<10} {r['delivered']:>6}/{r['total']:<5} {r['cpu_us_per_rt']:>11.1f} us {r['rss']:>8.1f} MiB"
              f" {r['delivered'] / r['elapsed']:>10.0f}/s")
    ratio = best["rtc-turn"]["cpu_us_per_rt"] / best["pion/turn"]["cpu_us_per_rt"]
    print(f"\nrtc-turn uses {ratio:.2f}x pion/turn's CPU per round trip")


if __name__ == "__main__":
    main()

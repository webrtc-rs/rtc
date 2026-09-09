#!/usr/bin/env python3
"""Build a pinned, test-only usrsctp AF_CONN peer without CMake or vendoring.

Requires Python 3.9+, git, and a C11 compiler on macOS or Linux. Source, objects,
and the executable live outside the repository unless --build-dir says otherwise.
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import subprocess

REVISION = "fd070e05a7474f38c7fecdf4d4b6005d2547ee00"
REPOSITORY = "https://github.com/sctplab/usrsctp.git"
SOURCES = [
    "netinet/sctp_asconf.c", "netinet/sctp_auth.c", "netinet/sctp_bsd_addr.c",
    "netinet/sctp_callout.c", "netinet/sctp_cc_functions.c", "netinet/sctp_crc32.c",
    "netinet/sctp_indata.c", "netinet/sctp_input.c", "netinet/sctp_output.c",
    "netinet/sctp_pcb.c", "netinet/sctp_peeloff.c", "netinet/sctp_sha1.c",
    "netinet/sctp_ss_functions.c", "netinet/sctp_sysctl.c", "netinet/sctp_timer.c",
    "netinet/sctp_userspace.c", "netinet/sctp_usrreq.c", "netinet/sctputil.c",
    "netinet6/sctp6_usrreq.c", "user_environment.c", "user_mbuf.c",
    "user_recv_thread.c", "user_socket.c",
]


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def checkout_source(source, offline):
    """Select the pinned revision without replacing local source changes."""
    if not (source / ".git").exists():
        if offline:
            raise RuntimeError(f"--offline requires an existing checkout at {source}")
        # Populate the index/worktree before the dirty check: --no-checkout
        # makes a fresh clone report every tracked path as deleted.
        run(["git", "clone", REPOSITORY, str(source)])
    exists = subprocess.run(
        ["git", "-C", str(source), "cat-file", "-e", REVISION + "^{commit}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if exists.returncode:
        if offline:
            raise RuntimeError(f"pinned revision {REVISION} is absent from {source}")
        run(["git", "-C", str(source), "fetch", "origin", REVISION])
    dirty = run(["git", "-C", str(source), "status", "--porcelain"],
                capture_output=True, text=True).stdout
    if dirty:
        raise RuntimeError(f"refusing to replace modified source checkout: {source}")
    run(["git", "-C", str(source), "checkout", "--detach", REVISION])


def build(args):
    root = args.build_dir.resolve()
    source = root / "source"
    root.mkdir(parents=True, exist_ok=True)
    checkout_source(source, args.offline)

    output = root / "build"
    output.mkdir(exist_ok=True)
    clock_header = output / "virtual_time.h"
    # Include the system declaration before the macro so Darwin's symbol aliases
    # cannot silently redirect the hook back to real gettimeofday.
    clock_header.write_text(
        "#include <sys/time.h>\n"
        "int rtc_usrsctp_gettimeofday(struct timeval *, void *);\n"
        "#define gettimeofday rtc_usrsctp_gettimeofday\n"
    )
    system = platform.system()
    if system not in ("Darwin", "Linux"):
        raise RuntimeError("this test build currently supports macOS and Linux")
    common = [
        args.cc, "-std=c11", "-O2", "-g", "-pthread", "-Wall", "-Wextra",
        "-Wno-unused-parameter", "-Wno-unused-function",
        "-Wno-address-of-packed-member", "-Wno-deprecated-declarations",
        "-D__Userspace__", "-DSCTP_SIMPLE_ALLOCATOR", "-DSCTP_PROCESS_LEVEL_LOCKS",
        "-DHAVE_STDATOMIC_H", "-DINET", "-DINET6", "-DINVARIANTS",
        "-I", str(source / "usrsctplib"),
    ]
    if system == "Darwin":
        common += [
            "-D__APPLE_USE_RFC_2292", "-DHAVE_SA_LEN", "-DHAVE_SIN_LEN",
            "-DHAVE_SIN6_LEN", "-DHAVE_SCONN_LEN", "-DHAVE_SYS_QUEUE_H",
            "-DHAVE_NETINET_IP_ICMP_H", "-DHAVE_NET_ROUTE_H",
        ]
    else:
        common += [
            "-D_GNU_SOURCE", "-DHAVE_LINUX_IF_ADDR_H", "-DHAVE_LINUX_RTNETLINK_H",
            "-DHAVE_NETINET_IP_ICMP_H", "-DHAVE_NET_ROUTE_H",
        ]
    jobs = []
    objects = []
    for relative in SOURCES:
        obj = output / (relative.replace("/", "_") + ".o")
        objects.append(str(obj))
        jobs.append(common + ["-include", str(clock_header), "-c",
                              str(source / "usrsctplib" / relative), "-o", str(obj)])
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        list(pool.map(run, jobs))
    executable = output / "usrsctp_peer"
    peer_source = Path(__file__).with_name("usrsctp_peer.c")
    run(common + ["-Werror", str(peer_source)] + objects + ["-o", str(executable)])
    metadata = {
        "repository": REPOSITORY,
        "revision": REVISION,
        "adapter_sha256": hashlib.sha256(peer_source.read_bytes()).hexdigest(),
        "compiler": run([args.cc, "--version"], capture_output=True, text=True).stdout,
        "platform": platform.platform(),
        "flags": common,
        "clock": "virtual gettimeofday + usrsctp_handle_timers, 10ms maximum step",
        "random": "system entropy; record initial TSN/vtag/cookie in packet traces",
        "ports": [5000, 5000],
        "streams": 1024,
        "mtu": 1200,
        "socket_buffers": 4 * 1024 * 1024,
    }
    (output / "build.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(executable, flush=True)
    return executable


class Peer:
    """Bounded line reader for --self-test, not the scenario harness."""

    def __init__(self, executable):
        self.process = subprocess.Popen(
            [str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            bufsize=0,
        )
        self.pending = bytearray()
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.events = []
        self.messages = []

    def command(self, text):
        self.process.stdin.write(text.encode() + b"\n")
        packets = []
        while True:
            while b"\n" not in self.pending:
                if not self.selector.select(timeout=5):
                    raise RuntimeError(f"peer timeout after {text[:80]}")
                data = os.read(self.process.stdout.fileno(), 65536)
                if not data:
                    raise RuntimeError(f"peer exited after {text[:80]}")
                self.pending.extend(data)
            line, _, rest = self.pending.partition(b"\n")
            self.pending = bytearray(rest)
            line = line.decode()
            if line == "DONE":
                return packets
            if line.startswith("PACKET "):
                packets.append(line.removeprefix("PACKET "))
            elif line.startswith("MESSAGE "):
                self.messages.append(line)
            elif line.startswith("EVENT "):
                self.events.append(line)
            elif line.startswith("ERROR "):
                raise RuntimeError(line)
            else:
                raise RuntimeError(f"unexpected adapter output: {line}")

    def close(self):
        if self.process.poll() is None:
            try:
                self.command("QUIT")
                self.process.communicate(timeout=5)
            except (RuntimeError, subprocess.TimeoutExpired, BrokenPipeError):
                self.process.kill()
                self.process.communicate()
        self.selector.close()


def self_test(executable):
    peers = [Peer(executable), Peer(executable)]

    def deliver(sender, packets):
        queue = [(1 - sender, packet) for packet in packets]
        for _ in range(10000):
            if not queue:
                return
            receiver, packet = queue.pop(0)
            queue.extend((1 - receiver, p)
                         for p in peers[receiver].command("INPUT " + packet))
        raise RuntimeError("self-test exceeded packet exchange bound")

    try:
        peers[0].command("INIT client")
        peers[1].command("INIT server")
        deliver(0, peers[0].command("CONNECT"))
        assert all("EVENT ready" in peer.events for peer in peers), "handshake failed"
        for sender, policy, ordering, data in [
            (0, "reliable", "ordered", b"client to server"),
            (1, "timed:100", "unordered", b"server to client"),
            (0, "rexmit:0", "unordered", bytes(range(256)) * 20),
        ]:
            command = f"SEND 1 {ordering} {policy} 53 {data.hex()}"
            deliver(sender, peers[sender].command(command))
            for index, peer in enumerate(peers):
                deliver(index, peer.command("TICK 200"))
            expected = f"MESSAGE 1 53 {data.hex()}"
            assert peers[1 - sender].messages.count(expected) == 1, "message not delivered exactly once"
        deliver(0, peers[0].command("RESET 1"))
        assert "EVENT reset_out:1" in peers[0].events, "outgoing reset not completed"
        assert "EVENT reset_in:1" in peers[1].events, "incoming reset not completed"
        deliver(1, peers[1].command("RESET 1"))
        assert "EVENT reset_out:1" in peers[1].events, "reciprocal outgoing reset not completed"
        assert "EVENT reset_in:1" in peers[0].events, "reciprocal incoming reset not completed"
        deliver(0, peers[0].command("SEND 1 ordered reliable 53 7265757365"))
        assert peers[1].messages[-1] == "MESSAGE 1 53 7265757365", "SID reuse failed"
        deliver(1, peers[1].command("TICK 200"))
        # Drop every packet from the first timed send. The virtual clock must
        # expire TTL as well as advance callouts; otherwise T3 emits DATA again.
        peers[0].command("SEND 2 ordered timed:100 53 657870697265")
        timed_out = peers[0].command("TICK 4000")
        kinds = []
        for packet in timed_out:
            raw = bytes.fromhex(packet)
            pos = 12
            while pos + 4 <= len(raw):
                kinds.append(raw[pos])
                length = int.from_bytes(raw[pos + 2:pos + 4], "big")
                if length < 4:
                    raise RuntimeError("invalid emitted SCTP chunk")
                pos += (length + 3) & ~3
        assert 192 in kinds, "expired timed DATA did not produce FORWARD-TSN"
        assert 0 not in kinds, "expired timed DATA was retransmitted"
        deliver(0, timed_out)
        print("usrsctp self-test: handshake, policies, fragmentation, reset, SID reuse, virtual TTL passed")
    finally:
        for peer in peers:
            peer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("/tmp/rtc-237-usrsctp"))
    parser.add_argument("--cc", default=os.environ.get("CC", "clang"))
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 1, 8))
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    executable = build(args)
    if args.self_test:
        self_test(executable)


if __name__ == "__main__":
    main()

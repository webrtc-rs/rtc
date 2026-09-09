#!/usr/bin/env python3
"""Fetch pinned dcSCTP sources and build the standalone test peer outside Cargo."""

import argparse
import base64
import concurrent.futures
import hashlib
import io
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import tarfile
import time
import urllib.request


WEBRTC_SHA = "dab572fd15e3fb975ed14a9e9290f723bb6e3f30"
# Chromium third_party 3c7ceaeb6bd16f270f6938b22db67b164a5b7b1d,
# selected by the WebRTC DEPS file above, records this Abseil revision.
ABSEIL_SHA = "c2336f9b5cb94b877ae3e38629e3b4530e60c89f"


def download(url):
    print(f"fetch {url}", flush=True)
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def extract(data, destination):
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        # Reject paths and links escaping the destination (Python >= 3.12).
        archive.extractall(destination, filter="data")


def fetch_webrtc(root, component):
    target = root / "webrtc" / component
    marker = target / ".rtc-interop-revision"
    if marker.exists() and marker.read_text().strip() == WEBRTC_SHA:
        return
    url = f"https://webrtc.googlesource.com/src/+archive/{WEBRTC_SHA}/{component}.tar.gz"
    extract(download(url), target)
    marker.write_text(WEBRTC_SHA + "\n")


def fetch_abseil(root):
    target = root / f"abseil-cpp-{ABSEIL_SHA}"
    marker = target / ".rtc-interop-revision"
    if marker.exists() and marker.read_text().strip() == ABSEIL_SHA:
        return
    url = f"https://github.com/abseil/abseil-cpp/archive/{ABSEIL_SHA}.tar.gz"
    extract(download(url), root)
    marker.write_text(ABSEIL_SHA + "\n")


def cmake_quote(path):
    return '"' + str(path).replace("\\", "/").replace('"', '\\"') + '"'


def self_test(binary, trace_path, other_binary=None):
    """Exercise the actual packet API of two adapters, with bounded I/O waits."""
    processes = [subprocess.Popen([str(executable)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, bufsize=0)
                 for executable in (binary, other_binary or binary)]
    buffers = [b"", b""]
    observed = [[], []]
    clocks = [0, 0]
    trace = trace_path.open("w")
    trace.write(json.dumps({
        "format_version": 1,
        "dcsctp_build": {"webrtc_sha": WEBRTC_SHA, "abseil_sha": ABSEIL_SHA,
                         "client_seed": 0x12345678, "server_seed": 0x87654321,
                         "clock": "virtual milliseconds", "ports": [5000, 5000],
                         "mtu": 1191, "message_interleaving": False,
                         "partial_reliability": True, "heartbeats": False},
        "binaries": [{"path": str(path),
                      "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                     for path in (binary, other_binary or binary)],
    }) + "\n")

    def command(peer, value):
        if value.startswith("TICK "):
            clocks[peer] += int(value.split()[1])
        trace.write(json.dumps({"peer": peer, "time_ms": clocks[peer],
                                "command": value}) + "\n")
        process = processes[peer]
        process.stdin.write((value + "\n").encode())
        result = []
        deadline = time.monotonic() + 5
        while True:
            if b"\n" not in buffers[peer]:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                    raise AssertionError(f"peer {peer} timed out after {value[:80]}")
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    raise AssertionError(f"peer {peer} exited after {value[:80]}")
                buffers[peer] += chunk
            if b"\n" not in buffers[peer]:
                continue
            line, buffers[peer] = buffers[peer].split(b"\n", 1)
            line = line.decode()
            trace.write(json.dumps({"peer": peer, "time_ms": clocks[peer],
                                    "output": line}) + "\n")
            if line == "DONE":
                observed[peer].extend(result)
                return result
            if line.startswith("ERROR ") or line.startswith("EVENT error:"):
                raise AssertionError(line)
            result.append(line)

    def pump(sender, output):
        queue = [(1 - sender, line[7:]) for line in output if line.startswith("PACKET ")]
        count = 0
        while queue:
            peer, packet = queue.pop(0)
            count += 1
            if count > 1000:
                raise AssertionError("packet loop did not converge")
            queue.extend((1 - peer, line[7:]) for line in command(peer, "INPUT " + packet)
                         if line.startswith("PACKET "))

    def advance(delta_ms):
        output = [command(peer, f"TICK {delta_ms}") for peer in (0, 1)]
        for peer in (0, 1):
            pump(peer, output[peer])

    try:
        command(0, "INIT client")
        command(1, "INIT server")
        pump(0, command(0, "CONNECT"))
        assert all("EVENT ready" in output for output in observed)
        # Actual fragmentation and reliable delivery, in both directions.
        for peer in (0, 1):
            payload = bytes([peer + 1]) * 4000
            pump(peer, command(peer, f"SEND 1 ordered reliable 53 {payload.hex()}"))
            assert f"MESSAGE 1 53 {payload.hex()}" in observed[1 - peer]

        # The first Timed DATA is deliberately dropped. T3 emits FORWARD-TSN,
        # and a following ordered reliable message must still be deliverable.
        dropped = command(0, "SEND 3 ordered timed:25 53 74696d6564")
        assert any(line.startswith("PACKET ") for line in dropped)
        advance(1000)
        assert not any(line.startswith("MESSAGE 3 ") for line in observed[1])
        pump(0, command(0, "SEND 3 ordered reliable 53 7375727669766f72"))
        assert "MESSAGE 3 53 7375727669766f72" in observed[1]

        # Drop the first fragment of a Rexmit(0) message, but deliver its tail.
        output = command(0, "SEND 4 unordered rexmit:0 53 " + "ab" * 4000)
        packets = [line for line in output if line.startswith("PACKET ")]
        assert len(packets) > 1
        pump(0, packets[1:])
        advance(1000)
        assert not any(line.startswith("MESSAGE 4 ") for line in observed[1])
        pump(0, command(0, "SEND 4 unordered reliable 53 6166746572"))
        assert "MESSAGE 4 53 6166746572" in observed[1]

        # Lose an explicit successful reset response and recover through the
        # real peer's result cache by repeating the original request.
        output = command(0, "RESET 1")
        requests = [line[7:] for line in output if line.startswith("PACKET ")]
        assert requests
        for packet in requests:
            command(1, "INPUT " + packet)  # Intentionally drop the reply.
        for _ in range(20):
            advance(500)
            if "EVENT reset_out:1" in observed[0]:
                break
        assert "EVENT reset_out:1" in observed[0]
        assert "EVENT reset_in:1" in observed[1]
        pump(0, command(0, "SEND 1 ordered reliable 53 7265757365"))
        assert "MESSAGE 1 53 7265757365" in observed[1]
        for peer in (0, 1):
            command(peer, "QUIT")
            assert processes[peer].wait(timeout=5) == 0
        print(f"dcSCTP packet self-test passed; trace: {trace_path}")
    finally:
        trace.close()
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("/tmp/rtc-237-dcsctp"))
    parser.add_argument("--cmake", default=os.environ.get("CMAKE", "cmake"))
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 2, 8))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    cmake = shutil.which(args.cmake)
    if cmake is None:
        parser.error("CMake is required; see README-dcsctp.md for a local installation")
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    root = args.build_dir.resolve()
    root.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        tasks = [pool.submit(fetch_webrtc, root, part)
                 for part in ("net/dcsctp", "api", "rtc_base")]
        tasks.append(pool.submit(fetch_abseil, root))
        for task in tasks:
            task.result()
    for name in ("DEPS", "LICENSE", "PATENTS", "AUTHORS"):
        target = root / "webrtc" / name
        if not target.exists():
            target.write_bytes(base64.b64decode(download(
                f"https://webrtc.googlesource.com/src/+/{WEBRTC_SHA}/{name}?format=TEXT")))

    webrtc = root / "webrtc"
    excluded = {"task_queue_timeout.cc", "text_pcap_packet_observer.cc",
                "dcsctp_socket_factory.cc"}
    sources = [path for path in (webrtc / "net/dcsctp").rglob("*.cc")
               if not any(part in ("testing", "fuzzers") for part in path.parts)
               and not any(term in path.name for term in ("test", "mock", "fuzzer"))
               and path.name not in excluded]
    sources += [webrtc / path for path in (
        "rtc_base/checks.cc", "rtc_base/strings/string_builder.cc",
        "rtc_base/strings/string_format.cc", "api/units/time_delta.cc",
        "api/units/timestamp.cc")]
    sources.append(Path(__file__).resolve().with_name("dcsctp_peer.cc"))
    source_list = "\n  ".join(cmake_quote(path) for path in sorted(sources))
    project = root / "project"
    project.mkdir(exist_ok=True)
    (project / "CMakeLists.txt").write_text(f"""cmake_minimum_required(VERSION 3.16)
project(rtc_dcsctp_interop LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL "" FORCE)
set(ABSL_BUILD_TESTING OFF CACHE BOOL "" FORCE)
add_subdirectory({cmake_quote(root / ('abseil-cpp-' + ABSEIL_SHA))} abseil EXCLUDE_FROM_ALL)
add_executable(dcsctp-peer
  {source_list})
target_include_directories(dcsctp-peer PRIVATE {cmake_quote(webrtc)})
target_compile_definitions(dcsctp-peer PRIVATE WEBRTC_POSIX RTC_DISABLE_LOGGING)
target_link_libraries(dcsctp-peer PRIVATE absl::crc32c absl::strings)
""")
    subprocess.run([cmake, "-S", str(project), "-B", str(root / "build"),
                    "-DCMAKE_BUILD_TYPE=Release"], check=True)
    subprocess.run([cmake, "--build", str(root / "build"), "--target", "dcsctp-peer",
                    "--parallel", str(args.jobs)], check=True)
    print(f"WEBRTC_SHA={WEBRTC_SHA}\nABSEIL_SHA={ABSEIL_SHA}")
    print(f"RTC_DCSCTP_PEER={root / 'build/dcsctp-peer'}")
    if args.self_test:
        self_test(root / "build/dcsctp-peer", root / "self-test.jsonl")


if __name__ == "__main__":
    main()

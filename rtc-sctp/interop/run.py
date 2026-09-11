#!/usr/bin/env python3
"""Bounded, packet-aware SCTP interop scenarios. Requires only Python stdlib."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import random
import selectors
import struct
import subprocess
import time


PINS = {
    "usrsctp": "fd070e05a7474f38c7fecdf4d4b6005d2547ee00",
    "dcsctp": "dab572fd15e3fb975ed14a9e9290f723bb6e3f30",
}
CHUNK_NAMES = {0: "DATA", 1: "INIT", 2: "INIT_ACK", 3: "SACK", 4: "HEARTBEAT",
               5: "HEARTBEAT_ACK", 6: "ABORT", 7: "SHUTDOWN", 8: "SHUTDOWN_ACK",
               9: "ERROR", 10: "COOKIE_ECHO", 11: "COOKIE_ACK", 14: "SHUTDOWN_COMPLETE",
               64: "I_DATA", 130: "RE_CONFIG", 192: "FORWARD_TSN", 194: "I_FORWARD_TSN"}


def crc32c(data: bytes) -> int:
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


def pad(data: bytes) -> bytes:
    return data + bytes((-len(data)) % 4)


def tlvs(data: bytes, offset: int = 0):
    while offset < len(data):
        if len(data) - offset < 4:
            raise AssertionError("truncated TLV header")
        kind, size = struct.unpack_from("!HH", data, offset)
        if size < 4 or offset + size > len(data):
            raise AssertionError("invalid TLV length")
        raw = data[offset:offset + size]
        yield kind, raw
        # Padding after the last parameter may belong to the enclosing chunk
        # padding, outside its declared length (e.g. Supported Extensions).
        offset = len(data) if offset + size == len(data) else offset + ((size + 3) & ~3)
    if offset != len(data):
        raise AssertionError("truncated TLV padding")


def chunks(packet: bytes):
    if len(packet) < 12:
        raise AssertionError("short SCTP header")
    offset = 12
    while offset < len(packet):
        if len(packet) - offset < 4:
            raise AssertionError("truncated chunk header")
        kind, flags, size = struct.unpack_from("!BBH", packet, offset)
        if size < 4 or offset + size > len(packet):
            raise AssertionError("invalid chunk length")
        raw = packet[offset:offset + size]
        yield kind, flags, raw
        offset += (size + 3) & ~3
    if offset != len(packet):
        raise AssertionError("truncated chunk padding")


def decode_parameter(kind: int, raw: bytes) -> dict:
    result = {"type": kind, "length": len(raw)}
    body = raw[4:]
    if kind == 13:
        if len(body) < 12 or len(body) % 2:
            raise AssertionError("invalid outgoing reset length")
        seq, response, last = struct.unpack_from("!III", body)
        result.update(request=seq, response=response, last_tsn=last,
                      sids=list(struct.unpack(f"!{(len(body)-12)//2}H", body[12:])))
    elif kind == 16:
        if len(body) not in (8, 16):
            raise AssertionError("invalid reconfig response length")
        seq, status = struct.unpack_from("!II", body)
        result.update(response=seq, result=status)
    return result


def decode_chunk(kind: int, flags: int, raw: bytes) -> dict:
    result = {"type": kind, "name": CHUNK_NAMES.get(kind, "UNKNOWN"),
              "flags": flags, "length": len(raw)}
    body = raw[4:]
    if kind == 0:
        if len(body) < 13:
            raise AssertionError("empty or truncated DATA")
        tsn, sid, ssn, ppid = struct.unpack_from("!IHHI", body)
        result.update(tsn=tsn, sid=sid, ssn=ssn, ppid=ppid, beginning=bool(flags & 2),
                      end=bool(flags & 1), unordered=bool(flags & 4),
                      payload_length=len(body)-12,
                      payload_sha256=hashlib.sha256(body[12:]).hexdigest())
    elif kind in (1, 2):
        tag, rwnd, outbound, inbound, tsn = struct.unpack_from("!IIHHI", body)
        result.update(tag=tag, rwnd=rwnd, outbound=outbound, inbound=inbound,
                      initial_tsn=tsn,
                      parameters=[{"type": k, "hex": p.hex()} for k, p in tlvs(body, 16)])
    elif kind == 3:
        cumulative, rwnd, gaps, duplicates = struct.unpack_from("!IIHH", body)
        if len(body) != 12 + gaps * 4 + duplicates * 4:
            raise AssertionError("invalid SACK length")
        result.update(cumulative=cumulative, rwnd=rwnd,
                      gaps=[list(struct.unpack_from("!HH", body, 12+4*i)) for i in range(gaps)],
                      duplicates=[struct.unpack_from("!I", body, 12+4*gaps+4*i)[0]
                                  for i in range(duplicates)])
    elif kind == 130:
        result["parameters"] = [decode_parameter(k, p) for k, p in tlvs(body)]
    elif kind == 192:
        if len(body) < 4 or len(body) % 4:
            raise AssertionError("invalid FORWARD-TSN length")
        result.update(cumulative=struct.unpack_from("!I", body)[0],
                      streams=[list(struct.unpack_from("!HH", body, i))
                               for i in range(4, len(body), 4)])
    return result


def decode(packet: bytes) -> dict:
    if len(packet) < 12:
        raise AssertionError("short SCTP packet")
    checksum = int.from_bytes(packet[8:12], "little")
    expected = crc32c(packet[:8] + bytes(4) + packet[12:])
    if checksum != expected:
        raise AssertionError(f"invalid CRC32C {checksum:08x}, expected {expected:08x}")
    source, destination, tag = struct.unpack_from("!HHI", packet)
    return {"source_port": source, "destination_port": destination, "vtag": tag,
            "checksum": checksum,
            "chunks": [decode_chunk(k, f, raw) for k, f, raw in chunks(packet)]}


def rewrite(packet: bytes, keep_chunk=lambda chunk: True,
            keep_parameter=lambda parameter: True) -> bytes | None:
    """Remove selected chunks/parameters, retaining association fields and CRC."""
    retained = []
    for kind, flags, raw in chunks(packet):
        if not keep_chunk(decode_chunk(kind, flags, raw)):
            continue
        if kind == 130:
            params = [pad(p) for k, p in tlvs(raw[4:])
                      if keep_parameter(decode_parameter(k, p))]
            if not params:
                continue
            body = b"".join(params)
            raw = struct.pack("!BBH", kind, flags, 4+len(body)) + body
        retained.append(pad(raw))
    if not retained:
        return None
    result = packet[:8] + bytes(4) + b"".join(retained)
    result = result[:8] + crc32c(result).to_bytes(4, "little") + result[12:]
    decode(result)
    return result


def correct_response_sequence(packet: bytes, sequence: int) -> bytes:
    """Normalize a peer's A4 field, keeping its actual request/TSN/SIDs intact."""
    result = bytearray(packet)
    chunk_offset = 12
    for kind, _, raw in chunks(packet):
        if kind == 130:
            parameter_offset = chunk_offset + 4
            for parameter_kind, parameter in tlvs(raw[4:]):
                if parameter_kind == 13:
                    struct.pack_into("!I", result, parameter_offset + 8, sequence)
                parameter_offset += (len(parameter) + 3) & ~3
        chunk_offset += (len(raw) + 3) & ~3
    result[8:12] = bytes(4)
    result[8:12] = crc32c(result).to_bytes(4, "little")
    decode(bytes(result))
    return bytes(result)


class Peer:
    def __init__(self, name: str, binary: Path, artifact: Path, command_timeout: float):
        self.name = name
        self.stderr = artifact.with_suffix(f".{name}.stderr").open("wb")
        self.process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=self.stderr)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.buffer = b""
        self.timeout = command_timeout

    def command(self, command: str) -> list[str]:
        self.process.stdin.write((command + "\n").encode())
        self.process.stdin.flush()
        until = time.monotonic() + self.timeout
        result = []
        while True:
            while b"\n" in self.buffer:
                raw, self.buffer = self.buffer.split(b"\n", 1)
                line = raw.decode().rstrip("\r")
                if line == "DONE":
                    return result
                result.append(line)
            remaining = until - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise AssertionError(f"{self.name}: command timed out: {command[:80]}")
            data = os.read(self.process.stdout.fileno(), 65536)
            if not data:
                raise AssertionError(f"{self.name}: exited {self.process.poll()}: {result[-5:]}")
            self.buffer += data
            if len(self.buffer) > 16 * 1024 * 1024:
                raise AssertionError("adapter response exceeds limit")

    def close(self):
        try:
            if self.process.poll() is None:
                self.command("QUIT")
                self.process.wait(timeout=2)
        except (AssertionError, BrokenPipeError, subprocess.TimeoutExpired):
            self.process.kill()
            self.process.wait()
        self.selector.close()
        self.process.stdin.close()
        self.process.stdout.close()
        self.stderr.close()


class Link:
    def __init__(self, rtc: Path, external: Path, rtc_client: bool,
                 artifact: Path, seed: int, command_timeout: float):
        self.trace = artifact.open("w", encoding="utf8")
        self.now = 0
        self.random = random.Random(seed)
        self.peers = {"rtc": Peer("rtc", rtc, artifact, command_timeout),
                      "peer": Peer("peer", external, artifact, command_timeout)}
        self.pending = collections.deque()
        self.held = []
        self.messages = {"rtc": [], "peer": []}
        self.events = {"rtc": [], "peer": []}
        self.next_packet_time = {"rtc": None, "peer": None}
        self.wire = []
        self.rules = []
        self.operations = 0
        self.wall_deadline = time.monotonic() + 45
        self.log("settings", seed=seed, rtc_client=rtc_client, mtu=1200,
                 ppid=53, step_ms=10, command_timeout=command_timeout,
                 rtc_binary_sha256=hashlib.sha256(rtc.read_bytes()).hexdigest(),
                 peer_binary_sha256=hashlib.sha256(external.read_bytes()).hexdigest())
        try:
            self.command("rtc", "INIT client" if rtc_client else "INIT server")
            self.command("peer", "INIT server" if rtc_client else "INIT client")
            self.command("rtc" if rtc_client else "peer", "CONNECT")
            self.until(lambda: all("ready" in events for events in self.events.values()), 8000)
        except Exception as error:
            self.log("failed_handshake", error=str(error))
            self.close()
            raise

    @staticmethod
    def other(name):
        return "peer" if name == "rtc" else "rtc"

    def log(self, kind, **data):
        self.trace.write(json.dumps({"time_ms": self.now, "kind": kind, **data},
                                    sort_keys=True) + "\n")

    def command(self, name: str, command: str):
        self.operations += 1
        if self.operations > 100_000 or time.monotonic() > self.wall_deadline:
            raise AssertionError("scenario execution bound exceeded")
        self.log("command", node=name, command=command)
        for line in self.peers[name].command(command):
            if line.startswith("PACKET "):
                packet = bytes.fromhex(line[7:])
                sent_at = self.next_packet_time[name]
                self.next_packet_time[name] = None
                if sent_at is None:
                    sent_at = self.now
                try:
                    parsed = decode(packet)
                except (AssertionError, struct.error) as error:
                    self.log("invalid_packet", source=name, hex=packet.hex(), error=str(error))
                    raise
                self.log("emit", source=name, hex=packet.hex(), packet=parsed,
                         send_time_ms=sent_at)
                self.wire.append((sent_at, name, packet, parsed))
                self.pending.append((name, packet))
            elif line.startswith("MESSAGE "):
                _, sid, ppid, payload = line.split(maxsplit=3)
                value = {"sid": int(sid), "ppid": int(ppid), "hex": payload}
                self.messages[name].append(value)
                self.log("message", node=name, **value)
            elif line.startswith("EVENT "):
                event = line[6:]
                if event.startswith("packet_time:"):
                    self.next_packet_time[name] = int(event.split(":", 1)[1])
                    self.log("packet_clock", node=name, send_time_ms=self.next_packet_time[name])
                    continue
                self.events[name].append(event)
                self.log("event", node=name, event=event)
                if event == "closed" or event.startswith("error:"):
                    raise AssertionError(f"unexpected peer error: {name}: {event}")
            elif line.startswith("ERROR "):
                self.log("adapter_error", node=name, error=line[6:])
                raise AssertionError(f"{name}: {line}; command={command[:80]}")
            else:
                raise AssertionError(f"unknown adapter output {name}: {line[:200]}")

    def pump(self):
        deliveries = 0
        while self.pending:
            source, packet = self.pending.popleft()
            original = packet
            for rule in self.rules:
                if packet is None:
                    break
                packet = rule(self, source, packet)
            if packet is not None:
                self.log("deliver", source=source, destination=self.other(source),
                         hex=packet.hex(), changed=packet != original, packet=decode(packet))
                self.command(self.other(source), "INPUT " + packet.hex())
            deliveries += 1
            if deliveries > 10_000:
                raise AssertionError("packet feedback loop")

    def advance(self, milliseconds=10):
        # Both clocks advance before newly generated packets are delivered.
        # Trace time is the end of the command's <=10ms interval, not a claim
        # that every internal callback in an external peer ran at that instant.
        self.now += milliseconds
        self.command("rtc", f"TICK {milliseconds}")
        self.command("peer", f"TICK {milliseconds}")
        self.pump()

    def until(self, predicate, timeout=12_000):
        limit = self.now + timeout
        self.pump()
        while not predicate():
            if self.now >= limit:
                raise AssertionError(f"condition not reached by virtual time {limit}ms")
            self.advance(min(10, limit-self.now))

    def settle(self, milliseconds=250):
        self.pump()
        limit = self.now + milliseconds
        while self.now < limit:
            self.advance(min(10, limit-self.now))

    def send(self, name, sid, data, policy="reliable", order="ordered", pump=True):
        self.command(name, f"SEND {sid} {order} {policy} 53 {data.hex()}")
        if pump:
            self.pump()

    def received(self, name, sid, data):
        return self.messages[name].count({"sid": sid, "ppid": 53, "hex": data.hex()})

    def expect_message(self, source, sid, data):
        target = self.other(source)
        self.until(lambda: self.received(target, sid, data) == 1)
        assert self.received(target, sid, data) == 1, "duplicate application delivery"

    def release_held(self, reverse=False, duplicate=False):
        held, self.held = self.held, []
        if reverse:
            held.reverse()
        for source, packet in held:
            self.log("release_held", source=source, hex=packet.hex(), duplicate=duplicate)
            self.pending.append((source, packet))
            if duplicate:
                self.pending.append((source, packet))
        self.pump()

    def close(self):
        for peer in self.peers.values():
            peer.close()
        self.trace.close()


class DropFirstData:
    def __init__(self, source, sid):
        self.source, self.sid = source, sid
        self.dropped = None

    def __call__(self, link, source, packet):
        if source != self.source or self.dropped is not None:
            return packet

        def keep(chunk):
            if (self.dropped is None and chunk["type"] == 0 and
                    chunk["sid"] == self.sid and chunk["beginning"]):
                self.dropped = chunk["tsn"]
                link.log("drop_DATA", source=source, tsn=self.dropped,
                         original_hex=packet.hex())
                return False
            return True
        return rewrite(packet, keep_chunk=keep)


class DropResetResult:
    def __init__(self, requester, sid, limit=1):
        self.requester, self.sid = requester, sid
        self.limit = limit
        self.request = None
        self.request_packet = None
        self.dropped = 0

    def __call__(self, link, source, packet):
        if source == self.requester and self.request is None:
            for chunk in decode(packet)["chunks"]:
                for param in chunk.get("parameters", []):
                    if param["type"] == 13 and self.sid in param["sids"]:
                        self.request = param["request"]
                        # Retain only this request for a genuinely delayed duplicate.
                        self.request_packet = rewrite(
                            packet, keep_chunk=lambda c: c["type"] == 130,
                            keep_parameter=lambda p: p.get("request") == self.request)
        if (source == self.requester or self.request is None or
                (self.limit is not None and self.dropped >= self.limit)):
            return packet

        def keep(param):
            if ((self.limit is None or self.dropped < self.limit) and param["type"] == 16 and
                    param["response"] == self.request and param["result"] in (0, 1)):
                self.dropped += 1
                link.log("drop_reset_result", source=source, sequence=self.request,
                         original_hex=packet.hex())
                return False
            return True
        return rewrite(packet, keep_parameter=keep)


def reliable(link):
    for source, sid, size, order in [("rtc", 1, 16_384, "ordered"),
                                      ("peer", 2, 4000, "unordered")]:
        payload = link.random.randbytes(size)
        link.send(source, sid, payload, order=order)
        link.expect_message(source, sid, payload)
    # Ordered delivery under delayed/duplicated DATA, chosen by content/SID.
    held_once = False

    def hold(link, source, packet):
        nonlocal held_once
        if not held_once and source == "rtc" and any(
                c["type"] == 0 and c["sid"] == 3 for c in decode(packet)["chunks"]):
            held_once = True
            link.held.append((source, packet))
            link.log("hold", source=source, hex=packet.hex())
            return None
        return packet
    link.rules.append(hold)
    link.send("rtc", 3, b"ordered first")
    link.send("rtc", 3, b"ordered second")
    assert not link.received("peer", 3, b"ordered second")
    link.release_held(reverse=True, duplicate=True)
    link.expect_message("rtc", 3, b"ordered first")
    link.expect_message("rtc", 3, b"ordered second")
    sequence = [m["hex"] for m in link.messages["peer"] if m["sid"] == 3]
    assert sequence == [b"ordered first".hex(), b"ordered second".hex()]


def partial_reliability(link, source, policy):
    sid = 5
    # Two timed fragments cannot trigger three immediate Gap ACK reports before
    # the 100ms deadline. A large message can legitimately recover via fast
    # retransmit at virtual time zero, so that is a different test scenario.
    payload = link.random.randbytes(9000 if policy == "rexmit:0" else 2000)
    rule = DropFirstData(source, sid)
    link.rules.append(rule)
    begin, start = link.now, len(link.wire)
    link.send(source, sid, payload, policy, "unordered")
    assert rule.dropped is not None, "did not observe first DATA"
    link.until(lambda: any(origin == source and any(c["type"] == 192 for c in p["chunks"])
                           for _, origin, _, p in link.wire[start:]))
    link.settle(500)
    relevant = [(at, c) for at, origin, _, p in link.wire[start:] if origin == source
                for c in p["chunks"] if c["type"] == 0 and c["sid"] == sid]
    if policy == "rexmit:0":
        tsns = [c["tsn"] for _, c in relevant]
        assert len(tsns) == len(set(tsns)), "Rexmit(0) retransmitted DATA"
    else:
        assert all(at < begin+100 for at, _ in relevant), "DATA sent after Timed(100) deadline"
    assert not link.received(link.other(source), sid, payload), "lost unreliable message delivered"
    sentinel = b"reliable message after abandonment"
    link.send(source, sid, sentinel)
    link.expect_message(source, sid, sentinel)
    assert not link.received(link.other(source), sid, payload)


def prime_stream(link, sid):
    for source in ["rtc", "peer"]:
        payload = f"before reset {source} {sid}".encode()
        link.send(source, sid, payload)
        link.expect_message(source, sid, payload)
    link.settle()


def lost_reset_response(link, requester):
    sid = 7
    prime_stream(link, sid)
    rule = DropResetResult(requester, sid)
    link.rules.append(rule)
    link.command(requester, f"RESET {sid}")
    link.pump()
    assert rule.dropped == 1, "no successful reset response was dropped"
    link.settle(6500)
    payload = b"after lost reset response"
    link.send(requester, sid, payload)
    link.expect_message(requester, sid, payload)


def simultaneous_reset(link):
    sid = 8
    prime_stream(link, sid)
    link.command("rtc", f"RESET {sid}")
    link.command("peer", f"RESET {sid}")
    link.pump()
    link.settle(3500)
    for source in ["rtc", "peer"]:
        payload = f"new incarnation {source}".encode()
        link.send(source, sid, payload)
        link.expect_message(source, sid, payload)


def sequential_resets(link):
    sid = 9
    prime_stream(link, sid)
    rule = DropResetResult("rtc", sid)
    link.rules.append(rule)
    link.command("rtc", f"RESET {sid}")
    link.pump()
    assert rule.dropped == 1
    # A real peer-generated request supplies a correctly sequenced implicit ACK.
    link.command("peer", "RESET 10")
    link.pump()
    link.settle(6500)
    for other_sid in [11, 12]:
        link.command("rtc", f"RESET {other_sid}")
        link.pump()
        link.settle(500)
    # A held network duplicate can arrive after either peer's bounded result
    # cache evicts N. Its response must not change a finished/newer procedure.
    link.pending.append(("rtc", rule.request_packet))
    link.log("delayed_duplicate_request", hex=rule.request_packet.hex(), sequence=rule.request)
    link.pump()
    for suffix in [b"zero", b"one"]:
        payload = b"after sequential resets " + suffix
        link.send("rtc", sid, payload)
        link.expect_message("rtc", sid, payload)


def forgotten_result_recovery(link):
    sid = 20
    prime_stream(link, sid)
    start = len(link.wire)
    rule = DropResetResult("rtc", sid, limit=None)
    link.rules.append(rule)
    link.command("rtc", f"RESET {sid}")
    queued = b"queued behind a lost result"
    link.send("rtc", sid, queued, pump=False)
    link.pump()
    assert rule.dropped > 0

    def normalize_a4(link, source, packet):
        # usrsctp already emits the expected A4 value. The pinned dcSCTP emits
        # its own request sequence instead; keep this explicit fault-normalized
        # case separate from the unmodified sequential_resets scenario.
        if source == "peer" and any(p["type"] == 13 and 21 in p["sids"]
                                     for c in decode(packet)["chunks"]
                                     for p in c.get("parameters", [])):
            changed = correct_response_sequence(packet, rule.request)
            if changed != packet:
                link.log("normalize_peer_A4", original_hex=packet.hex(),
                         replacement_hex=changed.hex(), response_sequence=rule.request)
            return changed
        return packet

    link.rules.append(normalize_a4)
    link.command("peer", "RESET 21")
    link.pump()
    for other_sid in [22, 23]:
        link.command("rtc", f"RESET {other_sid}")
        link.pump()
    assert not link.received("peer", sid, queued), "implicit ACK prematurely released DATA"

    def requests():
        return [p for _, source, _, packet in link.wire[start:] if source == "rtc"
                for c in packet["chunks"] for p in c.get("parameters", []) if p["type"] == 13]

    # Keep dropping N's result through a real retry. Other requests must remain
    # queued, so neither peer's bounded result cache can evict the unknown N.
    dropped_before_retry = rule.dropped
    link.until(lambda: rule.dropped > dropped_before_retry)
    outstanding = requests()
    assert len(outstanding) >= 2, "the unknown result was not queried again"
    assert all(p == outstanding[0] for p in outstanding), "a newer or changed reset escaped before N's result"
    assert outstanding[0]["request"] == rule.request
    assert not link.received("peer", sid, queued), "a query prematurely released DATA"

    # Restore responses; Success for the same immutable N establishes the SSN
    # boundary, releases DATA, and permits the queued requests to start.
    rule.limit = rule.dropped
    link.expect_message("rtc", sid, queued)
    link.until(lambda: {22, 23}.issubset({sid for p in requests() for sid in p["sids"]}))
    link.settle(1000)
    sentinel = b"next SSN after result recovery"
    link.send("rtc", sid, sentinel)
    link.expect_message("rtc", sid, sentinel)
    bad_sequence = [p for _, source, _, packet in link.wire if source == "peer"
                    for c in packet["chunks"] for p in c.get("parameters", [])
                    if p["type"] == 16 and p.get("response") == rule.request and p.get("result") == 5]
    assert not bad_sequence, "new reset requests evicted the unresolved result"
    link.log("recovery_path", first_request=rule.request,
             repeated_request_count=len(outstanding), subsequent_sids=[22, 23],
             forgotten_result=False, a4_normalization="only if peer field differed")


SCENARIOS = {
    "reliable": reliable,
    "timed_rtc": lambda link: partial_reliability(link, "rtc", "timed:100"),
    "timed_peer": lambda link: partial_reliability(link, "peer", "timed:100"),
    "rexmit_rtc": lambda link: partial_reliability(link, "rtc", "rexmit:0"),
    "rexmit_peer": lambda link: partial_reliability(link, "peer", "rexmit:0"),
    "lost_response_rtc": lambda link: lost_reset_response(link, "rtc"),
    "lost_response_peer": lambda link: lost_reset_response(link, "peer"),
    "simultaneous_reset": simultaneous_reset,
    "sequential_resets": sequential_resets,
    "forgotten_result_recovery": forgotten_result_recovery,
}


def self_test():
    assert crc32c(b"123456789") == 0xE3069283
    header = struct.pack("!HHII", 5000, 5000, 123, 0)
    data = struct.pack("!BBHIHHI", 0, 3, 19, 7, 1, 0, 53) + b"abc"
    response = struct.pack("!HHII", 16, 12, 9, 1)
    request = struct.pack("!HHIIIH", 13, 18, 10, 9, 7, 1)
    reconfig = struct.pack("!BBH", 130, 0, 36) + response + pad(request)
    packet = header + pad(data) + reconfig
    packet = packet[:8] + crc32c(packet).to_bytes(4, "little") + packet[12:]
    assert len(decode(packet)["chunks"]) == 2
    filtered = rewrite(packet, keep_parameter=lambda p: p["type"] != 16)
    assert decode(filtered)["chunks"][1]["parameters"][0]["request"] == 10
    assert rewrite(packet, keep_chunk=lambda c: False) is None
    assert decode(rewrite(packet, keep_chunk=lambda c: c["type"] != 0))["chunks"][0]["type"] == 130
    try:
        decode(packet[:-1] + bytes([packet[-1] ^ 1]))
    except AssertionError:
        pass
    else:
        raise AssertionError("corrupted packet passed CRC")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rtc", type=Path, required=True)
    parser.add_argument("--usrsctp", type=Path)
    parser.add_argument("--dcsctp", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", action="append", choices=SCENARIOS)
    parser.add_argument("--role", action="append", choices=["client", "server"])
    parser.add_argument("--seed", type=int, default=237)
    parser.add_argument("--command-timeout", type=float, default=5)
    args = parser.parse_args()
    self_test()
    peers = {name: getattr(args, name) for name in PINS if getattr(args, name)}
    if not peers:
        parser.error("provide --usrsctp and/or --dcsctp")
    for binary in [args.rtc, *peers.values()]:
        if not binary.is_file():
            parser.error(f"missing adapter binary: {binary}")
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    for peer_name, binary in peers.items():
        for role in args.role or ["client", "server"]:
            for scenario in args.scenario or SCENARIOS:
                name = f"{peer_name}-rtc-{role}-{scenario}"
                artifact = args.output / (name + ".jsonl")
                link = None
                started = time.monotonic()
                try:
                    link = Link(args.rtc.resolve(), binary.resolve(), role == "client",
                                artifact, args.seed, args.command_timeout)
                    SCENARIOS[scenario](link)
                    link.log("passed", scenario=scenario)
                    result = {"case": name, "status": "passed", "virtual_ms": link.now}
                except Exception as error:
                    if link:
                        link.log("failed", error=str(error))
                    result = {"case": name, "status": "failed", "error": str(error)}
                finally:
                    if link:
                        link.close()
                result.update(peer_revision=PINS[peer_name], seed=args.seed,
                              seconds=round(time.monotonic()-started, 3), trace=str(artifact))
                results.append(result)
                print(json.dumps(result, sort_keys=True), flush=True)
                (args.output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    if any(result["status"] != "passed" for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

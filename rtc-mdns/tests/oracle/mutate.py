#!/usr/bin/env python3
"""Mutates the oracle's seed messages: truncations, bit flips, bytes set to interesting values,
inserted compression pointers, edited header counts. Prints JSONL {"in": hex}, deduplicated."""
import random
import subprocess
import sys

random.seed(0x6d646e73)  # "mdns"
seeds = [bytes.fromhex(l) for l in subprocess.check_output(["go", "run", ".", "-gen"], env={"GOFLAGS": "-mod=mod", "PATH": __import__("os").environ["PATH"], "HOME": __import__("os").environ["HOME"], "GOCACHE": __import__("os").environ.get("GOCACHE", __import__("os").path.expanduser("~/Library/Caches/go-build"))}, text=True).split()]
seen = set()
out = []

def add(b):
    if b not in seen:
        seen.add(b)
        out.append(b)

for s in seeds:
    add(s)
    for n in range(len(s)):  # every truncation
        add(s[:n])
    for i in range(len(s)):  # every single-bit flip
        for bit in range(8):
            if random.random() < 0.25:
                t = bytearray(s); t[i] ^= 1 << bit; add(bytes(t))
    for i in range(len(s)):  # interesting byte values
        for v in (0x00, 0xC0, 0xFF, 0x3F, 0x40, 0x80):
            if random.random() < 0.3:
                t = bytearray(s); t[i] = v; add(bytes(t))
    for _ in range(40):  # pointers into the message, including loops and forward references
        if len(s) > 14:
            t = bytearray(s); i = random.randrange(12, len(s) - 1)
            t[i] = 0xC0 | random.randrange(0, 4); t[i + 1] = random.randrange(0, len(s) + 8); add(bytes(t))
    for i in (4, 6, 8, 10):  # section counts
        for v in (0, 1, 2, 5, 255):
            t = bytearray(s)
            if len(t) > i + 1:
                t[i] = 0; t[i + 1] = v; add(bytes(t))
    add(s + b"\x00")
    add(s + bytes(random.randrange(256) for _ in range(5)))
    if len(s) >= 12:
        add(s[:12] + s[12:][::-1])
random.shuffle(out)
for b in out[:int(sys.argv[1]) if len(sys.argv) > 1 else 6000]:
    print('{"in":"%s"}' % b.hex())

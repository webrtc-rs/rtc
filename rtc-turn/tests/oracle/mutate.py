#!/usr/bin/env python3
"""Mutates the oracle's seed messages: truncations, bit flips, bytes set to interesting values, and
edited lengths. Prints JSONL {"in": hex}, deduplicated."""
import os, random, subprocess, sys

random.seed(0x7475726e)  # "turn"
env = dict(os.environ, GOFLAGS="-mod=mod")
seeds = [bytes.fromhex(l) for l in subprocess.check_output(["go", "run", ".", "-gen"], env=env, text=True).split()]
seen, out = set(), []

def add(b):
    if b not in seen:
        seen.add(b)
        out.append(b)

for s in seeds:
    add(s)
    for n in range(len(s)):
        add(s[:n])
    for i in range(len(s)):
        for bit in range(8):
            if random.random() < 0.3:
                t = bytearray(s); t[i] ^= 1 << bit; add(bytes(t))
        for v in (0x00, 0x01, 0x03, 0x04, 0x06, 0x11, 0x3f, 0x40, 0x7f, 0x80, 0xff):
            if random.random() < 0.25:
                t = bytearray(s); t[i] = v; add(bytes(t))
    if len(s) >= 20 and s[0] < 0x40:  # STUN: shorten/lengthen the declared message length
        for delta in (-8, -4, -1, 1, 4, 8, 64):
            t = bytearray(s); ln = (t[2] << 8 | t[3]) + delta
            if 0 <= ln < 65536:
                t[2], t[3] = ln >> 8, ln & 255; add(bytes(t))
    add(s + b"\x00")
    add(s + bytes(random.randrange(256) for _ in range(7)))
random.shuffle(out)
for b in out[:int(sys.argv[1]) if len(sys.argv) > 1 else 6000]:
    print('{"in":"%s"}' % b.hex())

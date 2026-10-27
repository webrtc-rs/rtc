#!/usr/bin/env python3
"""Mutates the oracle's seed candidate lines at the token and byte level. Prints JSONL {"in": text}."""
import json, os, random, subprocess, sys

random.seed(0x696365)  # "ice"
env = dict(os.environ, GOFLAGS="-mod=mod")
seeds = [json.loads(l) for l in subprocess.check_output(["go", "run", ".", "-gen"], env=env, text=True).splitlines()]
swaps = ["host", "srflx", "prflx", "relay", "udp", "tcp", "UDP", "typ", "raddr", "rport", "tcptype",
         "active", "passive", "so", "generation", "ufrag", "network-id", "network-cost", "0", "1", "65535",
         "65536", "4294967295", "4294967296", "-1", "::1", "127.0.0.1", "0.0.0.0", "1.2.3", "a.local", "", " ",
         "fe80::1%x", "2001:db8::1", "999.1.1.1", "typ typ", "candidate:"]
seen, out = set(), []

def add(s):
    if s not in seen:
        seen.add(s)
        out.append(s)

for s in seeds:
    add(s)
    toks = s.split(" ")
    for i in range(len(toks)):
        add(" ".join(toks[:i] + toks[i + 1:]))            # drop a token
        add(" ".join(toks[:i + 1] + toks[i:]))            # duplicate a token
        for r in random.sample(swaps, 6):                 # replace a token
            t = list(toks); t[i] = r; add(" ".join(t))
    for n in range(len(s)):
        add(s[:n])                                         # every truncation
    for _ in range(25):                                    # byte-level edits
        if s:
            t = bytearray(s.encode()); i = random.randrange(len(t))
            t[i] = random.choice(b" :.%/-0123456789abcdefxyz\t\x00")
            add(t.decode("utf-8", "replace"))
    add(s + " ")
    add(" " + s)
    add(s + "\r\n")
    add(s.replace(" ", "  ", 1))
random.shuffle(out)
for s in out[:int(sys.argv[1]) if len(sys.argv) > 1 else 5000]:
    print(json.dumps({"in": s}))

#!/usr/bin/env python3
"""Turn soak JSONL (see README.md) into summary.md and a self-contained report.html, and gate on
"the subject is at least as stable as the baseline".

    report.py --rules rules.json --out DIR file.jsonl...

The rules file lists `compare` pairs ({"subject": "rtcd-rs", "baseline": "rtcd-go"}); for each
architecture, group and phase the subject is held against the baseline (see README.md, "Rules").
Exit code: 0 all gates held, 1 a gated rule was broken, 2 unusable input.
Python 3 standard library only.
"""
import argparse
import copy
import html
import json
import math
import os
import sys
from bisect import bisect_left, bisect_right
from collections import defaultdict

DEFAULTS = {
    "compare": [],
    # Groups the subject must have receiver samples for (a run without them proves nothing).
    "require_groups": [],
    # Subject <= baseline x ratio + slack, per metric; counts: subject <= baseline + slack.
    "ratio": 1.25,
    "ratios": {},
    "slack": {},
    # What the clean group (a path that is never impaired) must show, absolutely.
    "clean_zero": ["stalls", "freezes", "closes", "ice_disc"],
    # Drift of the subject over the run: last clean window against the first.
    "warmup_min": 15,
    "window_min": 20,
    "freeze_rate_ratio_max": 2.0,
    "freeze_rate_abs_slack_per_min": 0.5,
    "audio_gap_ratio_max": 2.0,
    "audio_gap_abs_slack_pct": 0.5,
    "rss_slope_mb_per_h_max": 30,
    "rss_slope_min_span_min": 30,
    "min_clean_window_min": 5,
    # A track is expected to flow after an outage when its participant stays in the call this long
    # after it; a track that has not recovered by then never did.
    "recover_window_s": 60,
    # Attack classes that load the whole server (not a participant): the clean group may show
    # freezes and stalls during them, the comparison with the baseline still applies.
    "global_load": ["load-hold", "udp-junk", "stun-flood", "dtls-junk"],
    # A proc sample at or above this CPU % (of a core) counts as saturated.
    "cpu_sat_pct": 190,
}
# (key, title, decimals, kind, default slack): `rate` metrics are held to ratio and slack, `count`
# metrics to the baseline plus slack. Lower is better for every one but `higher` (the subject must
# reach the baseline divided by the ratio, less the slack).
METRICS = [
    ("freeze_rate", "Freezes / min (video)", 2, "rate", 0.5),
    ("freeze_ms", "Freeze ms / min (video)", 0, "rate", 300),
    ("outage_freeze_ms", "Freeze ms per outage (video)", 0, "count", 1000),
    ("video_fps", "Video frames / s (mean, higher is better)", 1, "higher", 1.0),
    ("audio_gap", "Audio gap %", 2, "rate", 0.5),
    ("loss", "Residual loss %", 2, "rate", 0.5),
    ("dup", "Duplicate packets %", 2, "rate", 0.5),
    ("stalls", "Stalls outside outage", 0, "count", 0),
    ("stall_max", "Longest stall s", 1, "rate", 2),
    ("rec_med", "Recovery after outage, median s", 1, "rate", 2),
    ("rec_p90", "Recovery after outage, p90 s", 1, "rate", 3),
    ("never", "Tracks that never recovered", 0, "count", 0),
    ("recover_s", "Recovery after an attack, s (p90, worst window)", 1, "rate", 3),
    ("closes", "SFU-closed sessions", 0, "count", 0),
    ("sig_closes", "Signaling connection closes", 0, "count", 0),
    ("lost_seats", "Seats lost to the media path or a failed join", 0, "count", 0),
    ("rejoins", "Rejoins", 0, "count", 0),
    ("downtime", "Rejoin downtime, total s", 1, "rate", 5),
    ("ice_disc", "ICE disconnects", 0, "count", 0),
    ("ice_fail", "ICE failures", 0, "count", 0),
    ("rx_mbps", "Receive Mbit/s per participant (mean)", 2, None, 0),
    ("rx_max", "Receive Mbit/s per participant (max)", 2, None, 0),
    ("freezes", "Freezes (count)", 0, None, 0),
]
SFU_METRICS = [
    ("cpu", "SFU CPU % of a core (mean)", 1, "rate", 5),
    ("rss_peak", "SFU RSS peak MB", 1, "rate", 50),
    ("rss_slope", "SFU RSS slope MB/h", 1, "rate", 10),
    ("threads_max", "SFU threads (max)", 0, "rate", 50),
    ("fds_max", "SFU file descriptors (max)", 0, "rate", 200),
    ("threads_slope", "SFU threads slope /h", 1, "rate", 20),
    ("fds_slope", "SFU file descriptors slope /h", 1, "rate", 100),
    ("cpu_sat", "SFU samples saturated (CPU % at or above the limit), %", 1, "rate", 10),
    ("udp_err", "UDP buffer errors of the host", 0, "rate", 100),
    ("sfu_errors", "SFU process errors (gone, crashed)", 0, "count", 0),
]
TITLE = {k: t for k, t, *_ in METRICS + SFU_METRICS}
DEC = {k: d for k, _, d, *_ in METRICS + SFU_METRICS}
KIND = {k: kind for k, _, _, kind, _ in METRICS + SFU_METRICS}
SLACK = {k: s for k, _, _, _, s in METRICS + SFU_METRICS}
PHASES = ["clean", "loss", "burst", "bw", "outage", "recover"]
SAMPLE_S = 5
RECOVER_SETTLE_S = 15  # the start of `recover` is the outage's own aftermath, not steady state
COUNTERS = ("frames", "freezes", "freeze_ms", "packets", "lost", "nack", "pli", "audio_gap_ms", "bytes",
            "duplicates")
PALETTE = ["#2563eb", "#dc2626", "#059669", "#d97706"]
ATTACK_KEYS = ("freezes", "freeze_rate", "freeze_ms", "stalls", "stall_max", "closes", "sig_closes", "ice_disc",
               "recover_s",
               "never")
ATTACK_FILL = "#a855f7"
EARLY_STOP_S = 60  # a baseline whose samples end this much before the subject's stopped early
WINDOW_LIST_MAX = 200  # the per-window table lists every window up to this many, then only those with an impact
PHASE_FILL = {"loss": "#facc15", "burst": "#fb923c", "bw": "#60a5fa", "outage": "#ef4444"}
CLOSES = ("the SFU closed the session",)
SIG = ("the signaling connection closed",)


# ---------------------------------------------------------------- loading

class Run:
    """One input file: its rows and the phase timeline of each group."""

    def __init__(self, path):
        self.path = path
        self.stem = os.path.splitext(os.path.basename(path))[0]
        self.rows = []
        self.bad = 0
        self.t0 = self.t1 = 0.0
        self.timeline = {}  # group -> ([t], [(t, name)])
        self.attacks = []  # {id, name, start, end, group, who, seed, arch, detail}: the attack windows
        self._attack_index = None

    def finish(self):
        if not self.rows:
            return
        self.t0 = min(r["ts"] for r in self.rows) / 1000.0
        self.t1 = max(r["ts"] for r in self.rows) / 1000.0
        per = defaultdict(list)
        for r in self.rows:
            r["t"] = r["ts"] / 1000.0 - self.t0
            if r["kind"] == "phase":
                per[str(r.get("group") or "impaired")].append((r["t"], str(r.get("name"))))
        opened, order = {}, []
        for r in self.rows:
            if r["kind"] != "attack":
                continue
            aid = str(r.get("id", ""))
            if r.get("state") == "start" and aid not in opened:
                opened[aid] = {"id": aid, "name": str(r.get("name", "")), "start": r["t"], "end": None,
                               "group": str(r.get("group") or "all"), "seed": r.get("seed"),
                               "who": [str(w) for w in r.get("who") or []], "arch": str(r.get("arch", "unknown")),
                               "detail": str(r.get("detail", ""))}
                order.append(aid)
            elif r.get("state") == "end" and aid in opened and opened[aid]["end"] is None:
                opened[aid]["end"] = r["t"]
        for aid in order:
            w = opened[aid]
            if w["end"] is None:  # an unmatched start runs to the end of the run
                w["end"] = self.t1 - self.t0
            w["end"] = max(w["end"], w["start"])
            self.attacks.append(w)
        for g, ph in per.items():
            ph.sort()
            self.timeline[g] = ([p[0] for p in ph], ph)

    def attack_index(self):
        """The attack windows sorted by start, their starts, and the longest one's length: what
        finding the windows that overlap a span needs."""
        if self._attack_index is None:
            by_start = sorted(self.attacks, key=lambda w: w["start"])
            self._attack_index = ([w["start"] for w in by_start], by_start,
                                  max((w["end"] - w["start"] for w in by_start), default=0.0))
        return self._attack_index

    def phase_at(self, group, t):
        """(phase name, its start) for a sample of `group` at t: a group without a timeline is never impaired."""
        if group not in self.timeline:
            return "clean", 0.0
        pt, ph = self.timeline[group]
        i = bisect_right(pt, t) - 1
        return ("pre", 0.0) if i < 0 else (ph[i][1], ph[i][0])

    def cleanish(self, group, t):
        name, start = self.phase_at(group, t)
        return name == "clean" or (name == "recover" and t - start >= RECOVER_SETTLE_S)

    def phases(self, group="impaired"):
        return self.timeline.get(group, ([], []))[1]


def participant(sid):
    """Who a series is about: `s17/video:teacher#2` -> `s17`; `rtc-offerer-video` -> `rtc-offerer`."""
    who = sid.split("/")[0].split("#")[0]
    for suffix in ("-video", "-audio"):
        if "/" not in sid and who.endswith(suffix):
            return who[: -len(suffix)]
    return who


class Series:
    def __init__(self, ent, kind, sid):
        self.ent, self.kind, self.id = ent, kind, sid
        self.run = ent.run
        self.s = []
        self.media = None
        self.group = "impaired"
        self.who = participant(sid)
        self.regress = 0
        self.ivs = []

    def build(self):
        self.s.sort(key=lambda r: r["t"])
        if self.kind != "recv":
            return
        for a, b in zip(self.s, self.s[1:]):
            dt = b["t"] - a["t"]
            if dt <= 0:
                continue
            iv = {"t": b["t"], "dt": dt, "jitter": b.get("jitter_ms"), "rtt": b.get("rtt_ms")}
            for k in COUNTERS:
                d = (b.get(k) or 0) - (a.get(k) or 0)
                if d < 0:
                    if k != "lost":
                        self.regress += 1
                    d = 0
                iv[k] = d
            iv["phase"] = self.run.phase_at(self.group, b["t"])[0]
            iv["clean"] = self.run.cleanish(self.group, a["t"]) and self.run.cleanish(self.group, b["t"])
            self.ivs.append(iv)


class Ent:
    """Everything one implementation did on one architecture in one input file."""

    def __init__(self, impl, arch, run):
        self.impl, self.arch, self.run = impl, arch, run
        self.series = {}
        self.events = []
        self.t1 = 0.0

    def recv(self, group):
        return [s for s in self.series.values() if s.kind == "recv" and s.group == group]

    def proc(self):
        return [s for s in self.series.values() if s.kind == "proc"]


def load(paths):
    runs = []
    for p in paths:
        r = Run(p)
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except ValueError:
                    r.bad += 1
                    continue
                if not (isinstance(o, dict) and isinstance(o.get("ts"), (int, float)) and "kind" in o):
                    r.bad += 1
                    continue
                r.rows.append(o)
        r.finish()
        runs.append(r)
    return runs


def lesson_end(run):
    """When the first participant of a run stopped (`leave` with detail `stop`): from then on its
    receivers measure the end of the lesson, not the server, so their samples stop there."""
    stops = [o["t"] for o in run.rows if o["kind"] == "event" and o.get("what") == "leave"
             and o.get("detail") == "stop"]
    return min(stops, default=math.inf)


def build_entities(runs):
    ents = {}
    for r in runs:
        end = lesson_end(r)
        for o in r.rows:
            k = o["kind"]
            if k not in ("recv", "proc", "dc", "event") or not o.get("impl"):
                continue
            if k == "recv" and o["t"] > end:
                continue
            key = (str(o["impl"]), str(o.get("arch", "unknown")), r.stem)
            e = ents.get(key)
            if e is None:
                e = ents[key] = Ent(key[0], key[1], r)
            e.t1 = max(e.t1, o["t"])
            if k == "event":
                e.events.append(o)
                continue
            sid = str(o.get("id", ""))
            s = e.series.get((k, sid))
            if s is None:
                s = e.series[(k, sid)] = Series(e, k, sid)
            s.s.append(o)
            if k == "recv":
                s.media = o.get("media", s.media)
                s.group = str(o.get("group", s.group))
    for e in ents.values():
        for s in e.series.values():
            s.build()
    return list(ents.values())


# ---------------------------------------------------------------- measures

def clipped(ents, t_end):
    """The same entities with everything after `t_end` (seconds into their run) left out: what the
    subject did while a baseline that stopped early was still running."""
    out, runs = [], {}
    for e in ents:
        run = runs.get(id(e.run))
        if run is None:
            run = runs[id(e.run)] = copy.copy(e.run)
            run.attacks = [dict(w, end=min(w["end"], t_end)) for w in e.run.attacks if w["start"] < t_end]
            run._attack_index = None
            run.t1 = min(run.t1, run.t0 + t_end)
        c = Ent(e.impl, e.arch, run)
        c.events = [ev for ev in e.events if ev["t"] <= t_end]
        c.t1 = min(e.t1, t_end)
        for key, s in e.series.items():
            n = Series(c, s.kind, s.id)
            n.media, n.group = s.media, s.group
            n.s = [r for r in s.s if r["t"] <= t_end]
            if n.s:
                n.build()
                c.series[key] = n
        out.append(c)
    return out


def server_span(ents):
    """Seconds into the run to the last sample of the SFU process (the last row of any client when
    the side has no process samples): how long the server was there to be measured."""
    last = [s.s[-1]["t"] for e in ents for s in e.proc() if s.s]
    return max(last) if last else max(e.t1 for e in ents)


def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def quantile(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(math.ceil(q * len(xs))) - 1)]


def per_track_rate(sers, field, scale, pred, media):
    rates = []
    for s in sers:
        if s.media != media:
            continue
        ivs = [i for i in s.ivs if pred(i)]
        dt = sum(i["dt"] for i in ivs)
        if dt > 0:
            rates.append(sum(i[field] for i in ivs) * scale / dt)
    return mean(rates)


def outage_spans(run, group):
    """(start, end) of what an outage of `group` costs: from its start to one sample interval after
    its recovery began, where its freeze is booked whichever way the sampling clock falls."""
    ph = run.phases(group)
    return [(t, end + SAMPLE_S) for (t, name), (end, _) in zip(ph, ph[1:]) if name == "outage"]


def in_span(i, spans):
    return any(i["t"] > a and i["t"] - i["dt"] < b for a, b in spans)


def outage_freezes(sers, group, keep=lambda i: True):
    """Freeze ms each video track counted per outage of `group`: one value per (track, outage); a
    track with no interval in the outage's span adds none."""
    out = []
    for s in sers:
        if s.media != "video":
            continue
        for span in outage_spans(s.run, group):
            ivs = [i for i in s.ivs if keep(i) and in_span(i, [span])]
            if ivs:
                out.append(sum(i["freeze_ms"] for i in ivs))
    return out


def stalls(s):
    """Stall episodes outside outage: list of (start t, duration s).

    A `stalled` sample means media stopped for more than 2 s somewhere in the 5 s before it, so an
    episode lasts from its first stalled sample to its last, plus one sample interval. An episode
    whose first window overlaps an outage is the outage's aftermath (see recoveries), not a stall.
    """
    out, ep = [], None
    outages = [t for t, name in s.run.phases(s.group) if name == "outage"]

    def excused(t):
        if s.group not in s.run.timeline:
            return False
        if s.run.phase_at(s.group, t)[0] == "outage" or s.run.phase_at(s.group, t - SAMPLE_S)[0] == "outage":
            return True
        return any(t - SAMPLE_S < pt <= t for pt in outages)

    for r in s.s:
        if r.get("stalled"):
            if ep is None:
                ep = [r["t"], r["t"], excused(r["t"])]
            else:
                ep[1] = r["t"]
        elif ep is not None:
            if not ep[2]:
                out.append((ep[0], ep[1] - ep[0] + SAMPLE_S))
            ep = None
    if ep is not None and not ep[2]:
        out.append((ep[0], ep[1] - ep[0] + SAMPLE_S))
    return out


def departures(ent):
    """{(group, who): [t]} of the moments a participant lost its seat (closed by the SFU, signaling
    dropped, the media path gone, a join that never connected) or left."""
    out = defaultdict(list)
    for e in ent.events:
        if e.get("what") == "leave" or (e.get("what") == "error" and e.get("id") != "sfu"):
            out[(str(e.get("group") or "impaired"), str(e.get("id")))].append(e["t"])
    return out


def recoveries(ent, group, rules, gone):
    """Seconds from each outage's end until frames grow again (inf = never), over the tracks that
    are expected to flow: the participant was in the call at the outage and stayed through
    `recover_window_s` after it. A track that ends because the session was closed is not one of
    them: it is counted as a close.

    Frames are only seen at samples, so the sample that shows them growing would put the answer on
    the sampling clock. The frames resumed inside that sample's interval, and the freeze it closes
    lasted from the outage's start (frames stopped there) until they did: the freeze ms the track
    counted from the outage's start to that sample place the moment inside the interval. A track
    that counted no freeze keeps the sample's time."""
    out = []
    window = rules["recover_window_s"]
    ph = ent.run.phases(group)
    for i, (t, name) in enumerate(ph):
        if name != "outage" or i + 1 >= len(ph):
            continue
        end = ph[i + 1][0]
        for s in ent.recv(group):
            if s.media != "video" or not s.s or s.s[0]["t"] > t or s.s[-1]["t"] < end:
                continue
            if any(t < d <= end + window for d in gone.get((group, s.who), [])):
                continue
            hit = next(((prev, r) for prev, r in zip(s.s, s.s[1:])
                        if r["t"] > end and prev["t"] >= t and (r.get("frames") or 0) > (prev.get("frames") or 0)), None)
            if hit is not None:
                prev, r = hit
                froze = sum(i["freeze_ms"] for i in s.ivs if t < i["t"] <= r["t"]) / 1000.0
                resumed = t + froze if froze > 0 else r["t"]
                out.append(max(0.0, min(r["t"], max(prev["t"], resumed)) - end))
            elif s.s[-1]["t"] - end >= window:
                out.append(math.inf)
    return out


def slope_mb_per_h(s, t_from, field="rss_mb"):
    """Least-squares slope per hour of a `proc` field after t_from, and the minutes it spans."""
    pts = [(r["t"] / 3600.0, r[field]) for r in s.s if r["t"] >= t_from and r.get(field) is not None]
    if len(pts) < 3:
        return None, 0.0
    n = len(pts)
    mx = sum(p[0] for p in pts) / n
    my = sum(p[1] for p in pts) / n
    den = sum((p[0] - mx) ** 2 for p in pts)
    if den == 0:
        return None, 0.0
    return sum((p[0] - mx) * (p[1] - my) for p in pts) / den, (pts[-1][0] - pts[0][0]) * 60.0


def classify(e):
    """The kind of event a row is, for the counts."""
    what, detail = e.get("what"), str(e.get("detail", ""))
    if what == "error" and any(c in detail for c in CLOSES):
        return "closes"
    if what == "error" and any(c in detail for c in SIG):
        return "sig_closes"
    if what == "error" and e.get("id") != "sfu" and "gave up" not in detail:
        return "lost_seats"
    if what == "ice_state" and detail == "ice:disconnected":
        return "ice_disc"
    if what == "ice_state" and detail == "ice:failed":
        return "ice_fail"
    if what == "rejoin":
        return "rejoins"
    return None


def outage_disconnect(run, group, t):
    """An ICE disconnect at t that the outage caused: the path was cut, any agent loses it. One that
    starts within a sample interval after the outage counts too (the clocks of two shapers differ by
    that much). An ICE failure in an outage phase is not excused (see `own_outage`)."""
    return run.phase_at(group, t)[0] == "outage" or run.phase_at(group, t - SAMPLE_S)[0] == "outage"


def own_outage(run, group, who, t):
    """An ICE failure at t while an outage attack (`outage-30`, `outage-60`, ...) had cut the path of
    the participant that failed, or a sample interval after it ended: the path was down longer than
    any agent waits before it gives up (about 30 s), so failing is what it should do, whichever SFU
    it talks to. A rejoined participant (`s17#2`) is the same participant."""
    who = who.split("#")[0]
    return any(w["name"].startswith("outage") and attacked(w, group, who)
               and w["start"] <= t <= w["end"] + SAMPLE_S for w in run.attacks)


def downtimes(ent):
    """[(t, group, seconds)]: every rejoin's downtime, and for every seat lost and never taken back
    the time from the loss to the end of the run."""
    out = []
    by_who = defaultdict(list)
    for e in sorted(ent.events, key=lambda x: x["t"]):
        if e.get("id") == "sfu":
            continue
        by_who[(str(e.get("group") or "impaired"), str(e.get("id")))].append(e)
    for (group, who), evs in by_who.items():
        pending = None
        for e in evs:
            kind = classify(e)
            if kind == "rejoins":
                out.append((e["t"], group, (e.get("downtime_ms") or 0) / 1000.0))
                pending = None
            elif kind in ("closes", "sig_closes", "lost_seats") and pending is None:
                pending = e["t"]
            elif e.get("what") == "leave":
                pending = None
        if pending is not None:
            out.append((pending, group, max(0.0, ent.run.t1 - ent.run.t0 - pending)))
    return out


def rx_rates(sers, pred):
    """Mbit/s each participant received over the intervals that pass pred, all its tracks together."""
    got = defaultdict(lambda: [0.0, 0.0])
    for s in sers:
        ivs = [i for i in s.ivs if pred(i)]
        if not ivs:
            continue
        g = got[s.who]
        g[0] += sum(i["bytes"] for i in ivs)
        g[1] = max(g[1], sum(i["dt"] for i in ivs))
    return [b * 8 / dt / 1e6 for b, dt in got.values() if dt > 0 and b > 0]


def global_drop(rules):
    """drop(run, a, b): whether [a, b] touches an attack window of a global-load class (plus the recovery window)."""
    glob = set(rules["global_load"])
    rw = rules["recover_window_s"]
    return lambda run, a, b: any(w["name"] in glob and w["start"] < b and a < w["end"] + rw for w in run.attacks)


def scope_metrics(ents, group, phase, rules, drop=None):
    """The metrics of the receivers of `group` in `phase` (all of them when None) over the entities;
    intervals, stalls and events that `drop(run, a, b)` selects are left out."""
    sers = [s for e in ents for s in e.recv(group)]
    if not sers:
        return None
    pred = (lambda i: True) if phase is None else (lambda i: i["phase"] == phase)
    keep = lambda i: True
    if drop is not None:
        dropped = {id(i) for s in sers for i in s.ivs if drop(s.run, i["t"] - i["dt"], i["t"])}
        keep = lambda i: id(i) not in dropped
        base = pred
        pred = lambda i: base(i) and keep(i)
    ivs = [i for s in sers for i in s.ivs if pred(i)]
    packets = sum(i["packets"] for i in ivs)
    dup = sum(i["duplicates"] for i in ivs)
    lost = sum(i["lost"] for i in ivs)
    unique = packets - dup
    m = {
        "freeze_rate": per_track_rate(sers, "freezes", 60, pred, "video"),
        "freeze_ms": per_track_rate(sers, "freeze_ms", 60, pred, "video"),
        "outage_freeze_ms": None,
        "video_fps": per_track_rate(sers, "frames", 1, pred, "video"),
        "audio_gap": per_track_rate(sers, "audio_gap_ms", 0.1, pred, "audio"),
        "loss": 100.0 * lost / (unique + lost) if unique + lost > 0 else None,
        "dup": 100.0 * dup / packets if packets else None,
        "freezes": sum(i["freezes"] for i in ivs) if ivs else None,
    }
    if phase == "outage":
        # An outage is a few samples long, so a rate per minute would be decided by where the sampling
        # clock falls: score the freeze per episode instead.
        m["freeze_rate"] = m["freeze_ms"] = m["video_fps"] = None
        m["outage_freeze_ms"] = mean(outage_freezes(sers, group, keep))
    if phase == "recover":
        # The tail of the outage's own freeze is booked in the first interval after it.
        spans = {id(s): outage_spans(s.run, group) for s in sers}
        after = lambda s: (lambda i: pred(i) and not in_span(i, spans[id(s)]))
        for key, field, scale in (("freeze_rate", "freezes", 60), ("freeze_ms", "freeze_ms", 60)):
            rates = [r for s in sers if (r := per_track_rate([s], field, scale, after(s), "video")) is not None]
            m[key] = mean(rates)
    rates = rx_rates(sers, pred)
    m["rx_mbps"], m["rx_max"] = mean(rates), max(rates, default=None)
    st = []
    for e in ents:
        for s in e.recv(group):
            for start, d in stalls(s):
                if drop is not None and drop(e.run, start, start + d):
                    continue
                if phase is None or e.run.phase_at(group, start)[0] == phase:
                    st.append(d)
    m["stalls"], m["stall_max"] = len(st), max(st, default=0.0)
    if phase in (None, "outage"):
        rec = [x for e in ents for x in recoveries(e, group, rules, departures(e))]
        m["rec_med"], m["rec_p90"] = (quantile(rec, 0.5), quantile(rec, 0.9)) if rec else (None, None)
        m["never"] = sum(1 for x in rec if math.isinf(x))
    else:
        m["rec_med"] = m["rec_p90"] = m["never"] = None
    counts = defaultdict(int)
    down = 0.0
    for e in ents:
        for ev in e.events:
            kind = classify(ev)
            if kind and ev.get("id") != "sfu" and str(ev.get("group") or "impaired") == group:
                if drop is not None and drop(e.run, ev["t"], ev["t"]):
                    continue
                if kind == "ice_disc" and outage_disconnect(e.run, group, ev["t"]):
                    continue
                if kind == "ice_fail" and own_outage(e.run, group, str(ev.get("id")), ev["t"]):
                    continue
                if phase is None or e.run.phase_at(group, ev["t"])[0] == phase:
                    counts[kind] += 1
        for t, g, secs in downtimes(e):
            if g == group and (phase is None or e.run.phase_at(group, t)[0] == phase):
                down += secs
    for k in ("closes", "sig_closes", "lost_seats", "rejoins", "ice_disc", "ice_fail"):
        m[k] = counts[k]
    m["downtime"] = down
    return m


def sfu_metrics(ents, rules, phase=None):
    """The SFU process's metrics over the entities (those that have `proc` samples) in a phase of the impaired timeline."""
    procs = [s for e in ents for s in e.proc()]
    if not procs:
        return None

    def in_phase(s, r):
        return phase is None or s.run.phase_at("impaired", r["t"])[0] == phase

    rows = [r for s in procs for r in s.s if in_phase(s, r)]
    m = {k: None for k, *_ in SFU_METRICS}
    m["cpu"] = mean([r.get("cpu_pct") for r in rows])
    m["rss_peak"] = max([r.get("rss_mb") or 0 for r in rows], default=None)
    m["threads_max"] = max([r.get("threads") or 0 for r in rows], default=None)
    m["fds_max"] = max([r.get("fds") or 0 for r in rows], default=None)
    cpus = [r["cpu_pct"] for r in rows if r.get("cpu_pct") is not None]
    m["cpu_sat"] = 100.0 * sum(1 for c in cpus if c >= rules["cpu_sat_pct"]) / len(cpus) if cpus else None
    if phase is None:
        for key, field in (("rss_slope", "rss_mb"), ("threads_slope", "threads"), ("fds_slope", "fds")):
            spans = []
            for s in procs:
                warm = min(rules["warmup_min"], (s.ent.t1 / 60.0) / 6.0) * 60.0
                sl, span = slope_mb_per_h(s, warm, field)
                if sl is not None and span >= rules["rss_slope_min_span_min"]:
                    spans.append(sl)
            m[key] = max(spans) if spans else None
        errs = [r.get("udp_rcvbuf_err") for s in procs for r in s.s if r.get("udp_rcvbuf_err") is not None]
        m["udp_err"] = (max(errs) - min(errs)) if errs else None
        m["sfu_errors"] = sum(1 for e in ents for ev in e.events if ev.get("id") == "sfu" and ev.get("what") == "error")
    return m


def phase_names(ents):
    seen = {n for e in ents for _, ph in e.run.timeline.values() for _, n in ph}
    return [n for n in PHASES if n in seen] + sorted(seen - set(PHASES))


# ---------------------------------------------------------------- attacks

def attacked(win, group, who):
    """Whether a participant of `group` called `who` is a target of the attack window."""
    if win["group"] not in ("all", group):
        return False
    return not win["who"] or who in win["who"]


def window_metrics(ent, win, rules, clean_only=False):
    """What the innocent receivers of one attack window saw between its start and `recover_window_s`
    after its end, cut at the start of the receiver group's next outage (an outage's recovery is judged
    by `recoveries`, not charged to the attack). Innocent: every participant of the clean group, and
    those of the other groups that the window does not name (`clean_only`: the clean group alone),
    each only for the time no other window that names it overlaps."""
    rw = rules["recover_window_s"]
    a, b = win["start"], win["end"]
    z = b + rw

    def innocent(group, who):
        return group == "clean" or (not clean_only and not attacked(win, group, who))

    def cut(group):
        """End of the scored span for a receiver group: `z`, or the start of its next outage."""
        nxt = [t for t, name in ent.run.phases(group) if name == "outage" and t > a]
        return min([z] + nxt)

    starts, by_start, longest = ent.run.attack_index()

    def shared(group, who, t0, t1):
        """Whether another attack window that names the receiver overlaps [t0, t1]: what it saw then
        is that window's doing. The clean group is innocent whatever else runs. Only the windows
        that start in (t0 - longest, t1) can overlap, so a 2-hour run with hundreds of windows
        looks at a few per interval."""
        if group == "clean":
            return False
        lo, hi = bisect_left(starts, t0 - longest), bisect_left(starts, t1)
        return any(w is not win and w["arch"] == ent.arch and t0 < w["end"] and attacked(w, group, who)
                   for w in by_start[lo:hi])

    m = {"freezes": 0, "n_iv": 0, "vid_dt": 0.0, "stalls": [], "closes": 0, "sig_closes": 0, "ice_disc": 0, "rec": [],
         "fz": [], "fzms": [], "vdt": [], "ev": [], "never_at": []}
    for s in ent.series.values():
        if s.kind != "recv" or not innocent(s.group, s.who):
            continue
        zs = cut(s.group)
        ivs = [i for i in s.ivs if i["t"] > a and i["t"] - i["dt"] < zs
               and not shared(s.group, s.who, i["t"] - i["dt"], i["t"])]
        m["n_iv"] += len(ivs)
        m["freezes"] += sum(i["freezes"] for i in ivs)
        m["fz"] += [((s.id, i["t"]), i["freezes"]) for i in ivs if i["freezes"]]
        if s.media == "video":
            m["vid_dt"] += sum(i["dt"] for i in ivs)
            m["fzms"] += [((s.id, i["t"]), i["freeze_ms"]) for i in ivs]
            m["vdt"] += [((s.id, i["t"]), i["dt"]) for i in ivs]
        m["stalls"] += [(s.id, st, d) for st, d in stalls(s)
                      if a <= st <= zs and not shared(s.group, s.who, st, st + d)]
        if s.media != "video" or s.s[-1]["t"] < b or zs <= b:
            continue
        before = [i for i in s.ivs if i["t"] <= a]
        if not before or before[-1]["frames"] <= 0:
            continue  # not flowing when the attack began
        inside = [i for i in ivs if i["t"] <= zs]
        bad = [i for i in inside if i["frames"] <= 0]
        if not bad:
            m["rec"].append(0.0)
            continue
        nxt = next((i for i in inside if i["t"] > bad[-1]["t"]), None)
        if nxt is not None:
            m["rec"].append(max(0.0, nxt["t"] - b))
        elif zs == z and s.s[-1]["t"] >= z:
            m["rec"].append(math.inf)
            m["never_at"].append((s.id, bad[-1]["t"]))
    for ev in ent.events:
        kind = classify(ev)
        group = str(ev.get("group") or "impaired")
        if kind in ("closes", "sig_closes", "ice_disc") and ev.get("id") != "sfu" and a <= ev["t"] <= cut(group) \
                and innocent(group, str(ev.get("id"))) and not shared(group, str(ev.get("id")), ev["t"], ev["t"]):
            m[kind] += 1
            m["ev"].append((kind, ev.get("id"), ev["t"], ev.get("detail")))
    return m


def attack_windows(ents, pick_name):
    return [(e, w) for e in ents for w in e.run.attacks if w["arch"] == e.arch and pick_name(w["name"])]


def attack_metrics(ents, pick_name, rules, clean_only=False):
    """ATTACK_KEYS over the windows of the classes `pick_name` accepts; None without a window."""
    wins = attack_windows(ents, pick_name)
    if not wins:
        return None
    per = [window_metrics(e, w, rules, clean_only) for e, w in wins]
    # Windows of one class overlap (offerer and answerer, or back to back), and a stall, freeze, close
    # or lost track that falls in several of them is one thing that happened: count it once per class.
    def once(field):
        return {(w["name"], k): v for (_, w), p in zip(wins, per) for k, v in p[field]}

    def events(kind):
        return len({(w["name"], x) for (_, w), p in zip(wins, per) for x in p["ev"] if x[0] == kind})

    fz = sum(once("fz").values())
    dt = sum(once("vdt").values())
    fzms = sum(once("fzms").values())
    st = list({(w["name"], sid, t): d for (_, w), p in zip(wins, per) for sid, t, d in p["stalls"]}.values())
    never = len({(w["name"], x) for (_, w), p in zip(wins, per) for x in p["never_at"]})
    p90 = [quantile(p["rec"], 0.9) for p in per if p["rec"]]
    used = any(p["n_iv"] for p in per)  # a class whose receivers were all under another attack has no verdict
    return {"freezes": fz if used else None,
            "freeze_rate": fz * 60.0 / dt if dt > 0 else None,
            "freeze_ms": fzms * 60.0 / dt if dt > 0 else None,
            "stalls": len(st) if used else None, "stall_max": max(st, default=0.0) if used else None,
            "closes": events("closes"), "sig_closes": events("sig_closes"), "ice_disc": events("ice_disc"),
            "recover_s": max(p90) if p90 else None,
            "never": never if p90 else None}


def attack_classes(ents):
    return sorted({w["name"] for _, w in attack_windows(ents, lambda n: True)})


# ---------------------------------------------------------------- comparison

def pick(ents, spec, side):
    impl = spec[side]
    run = spec.get(side + "_run")
    return [e for e in ents if e.impl == impl and (run is None or e.run.stem == run)]


def fmt(v, nd=2):
    if v is None:
        return "-"
    if isinstance(v, float) and math.isinf(v):
        return "never"
    return "%.*f" % (nd, v)


def judge(key, s, b, rules, kind=None):
    """(verdict, limit) of a subject value against the baseline's."""
    if s is None or b is None:
        return "n/a", None
    slack = rules["slack"].get(key, SLACK.get(key, 0))
    kind = kind or KIND.get(key)
    if kind == "higher":
        lim = b / rules["ratios"].get(key, rules["ratio"]) - slack
        return ("ok" if s >= lim else "BREACH"), lim
    if kind == "count":
        lim = b + slack
    else:
        lim = b * rules["ratios"].get(key, rules["ratio"]) + slack
    return ("ok" if s <= lim else "BREACH"), lim


def freezes_only_if_frozen(key, verdict, s_m, b_m):
    """More freezes of less frozen time is a stream that plays, not one that breaks: freezes per
    minute breach only when the freeze ms per minute is worse too."""
    if key == "freeze_rate" and verdict == "BREACH" and not (s_m["freeze_ms"] or 0) > (b_m["freeze_ms"] or 0):
        return "ok"
    return verdict


def compare(ents, rules):
    """All comparisons: {"rows": [...], "checks": [...]} where a check is a gated pass/fail."""
    rows, checks = [], []

    def add(gated, rule, value, limit, ok):
        status = "n/a" if ok is None else ("PASS" if ok else ("FAIL" if gated else "breach"))
        checks.append({"rule": rule, "value": value, "limit": limit, "status": status, "gated": gated})

    for spec in rules["compare"]:
        gated = spec.get("gate", True)
        subj, base = pick(ents, spec, "subject"), pick(ents, spec, "baseline")
        name = "%s vs %s" % (label(spec, "subject"), label(spec, "baseline"))
        archs = sorted({e.arch for e in subj} | {e.arch for e in base})
        if not archs:
            add(gated, name, "no data for either side", "both sides need data", False)
        for arch in archs:
            s_ents = [e for e in subj if e.arch == arch]
            b_ents = [e for e in base if e.arch == arch]
            where = "%s [%s]" % (name, arch)
            if not s_ents or not b_ents:
                missing = "baseline" if not b_ents else "subject"
                add(gated, where, "no %s data on %s" % (missing, arch), "both sides need data", False)
                continue
            # A baseline whose server stopped early (killed, crashed) is compared over the time it ran:
            # its clients keep logging without a server, and the subject's later minutes would be held
            # against nothing. The subject's absolute checks below (clean group, process errors, drift)
            # still cover its whole run.
            full_ents = s_ents
            s_span, b_span = server_span(s_ents), server_span(b_ents)
            if b_span < max(e.t1 for e in b_ents):
                b_ents = clipped(b_ents, b_span)
            if b_span < s_span - EARLY_STOP_S:
                add(False, where + ": the baseline stopped early", "after %.1f of %.1f min" % (
                    b_span / 60.0, s_span / 60.0), "compared over its %.1f min" % (b_span / 60.0), None)
                s_ents = clipped(s_ents, b_span)
            groups = sorted({s.group for e in s_ents + b_ents for s in e.series.values() if s.kind == "recv"},
                            key=lambda g: (g != "clean", g))
            for g in rules["require_groups"] if spec.get("require", True) else []:
                if not any(e.recv(g) for e in s_ents):
                    add(gated, where + ": receivers of the %s group" % g, "none", "some", False)
            names = phase_names(s_ents + b_ents)
            for g in groups:
                phases = [None] + (names if g in {k for e in s_ents + b_ents for k in e.run.timeline} else [])
                for ph in phases:
                    sm = scope_metrics(s_ents, g, ph, rules)
                    bm = scope_metrics(b_ents, g, ph, rules)
                    if (sm is None) != (bm is None):
                        if ph is None:
                            add(gated, where + ": %s group" % g, "%s has no receivers" % (
                                "baseline" if bm is None else "subject"), "both sides need data", False)
                        continue
                    if sm is None:
                        continue
                    for key, _, nd, kind, _ in METRICS:
                        s_v, b_v = sm.get(key), bm.get(key)
                        if s_v is None and b_v is None:
                            continue
                        verdict, lim = judge(key, s_v, b_v, rules) if kind else ("", None)
                        verdict = freezes_only_if_frozen(key, verdict, sm, bm)
                        rows.append({"arch": arch, "pair": name, "scope": g, "phase": ph or "all", "key": key,
                                     "subject": s_v, "baseline": b_v, "verdict": verdict, "limit": lim,
                                     "gated": gated, "where": where})
            names_sfu = [None] + [n for n in names if any(e.proc() for e in s_ents)]
            if any(e.proc() for e in s_ents + b_ents):
                for ph in names_sfu:
                    sm, bm = sfu_metrics(s_ents, rules, ph), sfu_metrics(b_ents, rules, ph)
                    if (sm is None) != (bm is None):
                        add(gated, where + ": SFU process samples", "%s has none" % (
                            "baseline" if bm is None else "subject"), "both sides need data", False)
                        break
                    for key, _, nd, kind, _ in SFU_METRICS:
                        s_v, b_v = sm.get(key), bm.get(key)
                        if s_v is None and b_v is None:
                            continue
                        verdict, lim = judge(key, s_v, b_v, rules)
                        rows.append({"arch": arch, "pair": name, "scope": "sfu", "phase": ph or "all", "key": key,
                                     "subject": s_v, "baseline": b_v, "verdict": verdict, "limit": lim,
                                     "gated": gated, "where": where})
            for cls in sorted(set(attack_classes(s_ents)) | set(attack_classes(b_ents))):
                is_cls = lambda n, cls=cls: n == cls
                sm, bm = attack_metrics(s_ents, is_cls, rules), attack_metrics(b_ents, is_cls, rules)
                if (sm is None) != (bm is None):
                    add(gated, "%s: attack %s" % (where, cls), "only the %s has it" % (
                        "baseline" if sm is None else "subject"), "both sides need it", None)
                    continue
                for key in ATTACK_KEYS:
                    s_v, b_v = sm[key], bm[key]
                    if s_v is None and b_v is None:
                        continue
                    kind = "count" if key == "freezes" else KIND.get(key)
                    verdict, lim = judge(key, s_v, b_v, rules, kind)
                    verdict = freezes_only_if_frozen(key, verdict, sm, bm)
                    rows.append({"arch": arch, "pair": name, "scope": "attack", "phase": cls, "key": key,
                                 "subject": s_v, "baseline": b_v, "verdict": verdict, "limit": lim,
                                 "gated": gated, "where": where})
            # The clean group is never impaired: whatever it shows is the server's, except while an
            # attack that loads the whole server (`global_load`) runs.
            drop = global_drop(rules)
            for side, side_ents, g_ in (("subject", full_ents, gated), ("baseline", b_ents, False)):
                cm = scope_metrics(side_ents, "clean", None, rules, drop)
                if cm is None:
                    continue
                for key in spec.get("clean_zero", rules["clean_zero"]):
                    v = cm.get(key)
                    if v is not None:
                        add(g_, "%s: clean group, %s %s must be zero" % (where, side, TITLE[key]), fmt(v, 0), "0", v == 0)
            for side, side_ents, g_ in (("subject", full_ents, gated), ("baseline", b_ents, False)):
                sm = sfu_metrics(side_ents, rules)
                if sm is not None:
                    add(g_, "%s: %s SFU process errors (gone, crashed) must be zero" % (where, side),
                        fmt(sm["sfu_errors"], 0), "0", sm["sfu_errors"] == 0)
            drift_checks(full_ents, rules, where, gated, add)
    return rows, checks


def label(spec, side):
    run = spec.get(side + "_run")
    return spec[side] + (" [%s]" % run if run else "")


def drift_metrics(ents, a, b):
    """The freeze and audio gap rates over the clean intervals between a and b (all groups)."""
    def pred(i):
        return i["clean"] and a <= i["t"] <= b
    sers = [s for e in ents for s in e.series.values() if s.kind == "recv"]
    return {"freeze_rate": per_track_rate(sers, "freezes", 60, pred, "video"),
            "audio_gap": per_track_rate(sers, "audio_gap_ms", 0.1, pred, "audio"),
            "clean_s": mean([sum(i["dt"] for i in s.ivs if pred(i)) for s in sers])}


def drift_checks(ents, rules, where, gated, add):
    """The subject against itself: its first clean window against its last."""
    span = max(e.t1 for e in ents)
    tot = span / 60.0
    warm = min(rules["warmup_min"], tot / 6.0) * 60.0
    win = min(rules["window_min"], tot / 4.0) * 60.0
    f, l = drift_metrics(ents, warm, warm + win), drift_metrics(ents, span - win, span)
    need = rules["min_clean_window_min"] * 60
    for rule, key, ratio, slack in (
            ("freeze rate", "freeze_rate", rules["freeze_rate_ratio_max"], rules["freeze_rate_abs_slack_per_min"]),
            ("audio gap %", "audio_gap", rules["audio_gap_ratio_max"], rules["audio_gap_abs_slack_pct"])):
        name = "%s: drift, %s (last clean window <= first x ratio + slack)" % (where, rule)
        a, b = f[key], l[key]
        if (f["clean_s"] or 0) < need or (l["clean_s"] or 0) < need:
            add(gated, name, "clean time first %s s, last %s s" % (fmt(f["clean_s"], 0), fmt(l["clean_s"], 0)),
                "needs %s min each" % rules["min_clean_window_min"], None)
        elif a is None or b is None:
            add(gated, name, "first %s, last %s" % (fmt(a), fmt(b)), "-", None)
        else:
            lim = a * ratio + slack
            add(gated, name, "first %s, last %s" % (fmt(a), fmt(b)), "<= %s" % fmt(lim), b <= lim)
    m = sfu_metrics(ents, rules)
    if m is not None:
        name = "%s: drift, SFU RSS slope MB/h" % where
        if m["rss_slope"] is None:
            add(gated, name, "-", "needs %s min after warmup" % rules["rss_slope_min_span_min"], None)
        else:
            add(gated, name, fmt(m["rss_slope"], 1), "<= %s" % rules["rss_slope_mb_per_h_max"],
                m["rss_slope"] <= rules["rss_slope_mb_per_h_max"])


# ---------------------------------------------------------------- output

def verdict_checks(rows, checks):
    """Every breach as a check: the comparison rows that broke their rule, then the absolute rules."""
    out = []
    for r in rows:
        if r["verdict"] == "BREACH":
            out.append({"rule": "%s: %s / %s / %s" % (r["where"], r["scope"], r["phase"], TITLE[r["key"]]),
                        "value": "subject %s, baseline %s" % (fmt(r["subject"], DEC[r["key"]]),
                                                              fmt(r["baseline"], DEC[r["key"]])),
                        "limit": "<= %s" % fmt(r["limit"], DEC[r["key"]]),
                        "status": "FAIL" if r["gated"] else "breach", "gated": r["gated"]})
    return out + checks


def window_table(ents, rules):
    """The attack windows with what their innocent receivers saw: every window up to WINDOW_LIST_MAX,
    beyond that the ones with an impact."""
    body = []
    for e in sorted(ents, key=lambda x: (x.arch, x.impl, x.run.stem)):
        for w in e.run.attacks:
            if w["arch"] != e.arch:
                continue
            m = window_metrics(e, w, rules)
            rec = quantile(m["rec"], 0.9) if m["rec"] else None
            impact = m["freezes"] + len(m["stalls"]) + m["closes"] + m["sig_closes"] + m["ice_disc"] > 0 or \
                (rec is not None and math.isinf(rec))
            body.append((impact, [e.impl, e.arch, w["name"], w["id"], "%.1f" % (w["start"] / 60.0),
                                  "%.0f" % (w["end"] - w["start"]), ",".join(w["who"]) or "(group %s)" % w["group"],
                                  str(m["freezes"]), str(len(m["stalls"])), str(m["closes"] + m["sig_closes"]),
                                  str(m["ice_disc"]), fmt(rec, 1)]))
    if not body:
        return None
    total = len(body)
    if total > WINDOW_LIST_MAX:
        body = [b for b in body if b[0]]
    return ("Attack windows (%d listed of %d; innocent receivers, to the end of the recovery window)" % (len(body), total),
            ["Impl", "Arch", "Class", "Id", "Start min", "Seconds", "Who", "Freezes", "Stalls", "Closes", "ICE disc",
             "Recover s"], [b[1] for b in body])


def tables(rows, extra, runs, ents=None, rules=None):
    """List of (title, header, rows) shared by the markdown and html renderers."""
    out = []
    infos = []
    for r in runs:
        archs = sorted({str(o.get("arch", "?")) for o in r.rows if o["kind"] in ("recv", "proc")})
        impls = sorted({str(o.get("impl")) for o in r.rows if o["kind"] in ("recv", "proc")})
        n = sum(1 for o in r.rows if o["kind"] == "recv")
        infos.append([r.stem, ", ".join(impls), ", ".join(archs), "%.1f" % ((r.t1 - r.t0) / 60.0), str(n)])
    out.append(("Inputs", ["File", "Implementations", "Architectures", "Minutes", "Receiver samples"], infos))
    groups = defaultdict(list)
    for r in rows:
        groups[(r["arch"], r["pair"])].append(r)
    for (arch, pair), rs in groups.items():
        body, atk = [], []
        for r in rs:
            nd = DEC[r["key"]]
            verdict = r["verdict"] if r["verdict"] != "BREACH" or r["gated"] else "BREACH (not gated)"
            if r["scope"] == "attack":
                atk.append([r["phase"], TITLE[r["key"]], fmt(r["subject"], nd), fmt(r["baseline"], nd), verdict])
            else:
                body.append([r["scope"], r["phase"], TITLE[r["key"]], fmt(r["subject"], nd), fmt(r["baseline"], nd), verdict])
        out.append(("%s on %s" % (pair, arch), ["Scope", "Phase", "Metric", "Subject", "Baseline", "Verdict"], body))
        if atk:
            out.append(("Attacks: %s on %s (innocent receivers)" % (pair, arch),
                        ["Class", "Metric", "Subject", "Baseline", "Verdict"], atk))
    wt = window_table(ents, rules) if ents else None
    if wt:
        out.append(wt)
    out.append(("Rules (absolute, drift and missing data)", ["Rule", "Value", "Limit", "Result"],
                [[c["rule"], c["value"], c["limit"], c["status"] + ("" if c["gated"] or c["status"] == "n/a" else " (not gated)")]
                 for c in extra]))
    return out


def markdown(rows, checks, runs, failed, ents=None, rules=None):
    breaches = [c for c in verdict_checks(rows, checks) if c["status"] in ("FAIL", "breach")]
    lines = ["# Soak report", "", "**%s**" % ("GATE FAILED" if failed else "gates held"), ""]
    lines += ["## Breaches", ""] + (["- %s: %s (%s, limit %s)" % (c["status"], c["rule"], c["value"], c["limit"])
                                     for c in breaches] or ["None."]) + [""]
    for title, head, body in tables(rows, checks, runs, ents, rules):
        lines += ["## " + title, "", "| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
        lines += ["| " + " | ".join(str(c).replace("|", "/") for c in r) + " |" for r in body]
        lines.append("")
    return "\n".join(lines)


def chart_points(ents, group, metric, bin_s):
    """[(minute, value)] of one receiver metric, binned, over the entities' series of `group`."""
    acc = defaultdict(lambda: [0.0, 0.0])
    for e in ents:
        for s in e.recv(group):
            for i in s.ivs:
                num = den = None
                dt = i["dt"]
                if metric == "freeze_rate" and s.media == "video":
                    num, den = i["freezes"], dt / 60.0
                elif metric == "audio_gap" and s.media == "audio":
                    num, den = i["audio_gap_ms"], dt * 10.0
                elif metric == "loss":
                    num, den = i["lost"] * 100.0, i["packets"] - i["duplicates"] + i["lost"]
                elif metric == "rx_mbps":
                    num, den = i["bytes"] * 8 / 1e6, dt
                if num is not None and den:
                    b = int(i["t"] // bin_s)
                    acc[b][0] += num
                    acc[b][1] += den
    pts = [((b + 0.5) * bin_s / 60.0, v[0] / v[1]) for b, v in sorted(acc.items()) if v[1] > 0]
    if metric == "rx_mbps":  # summed over the tracks of every participant: per participant
        who = {s.who for e in ents for s in e.recv(group)}
        pts = [(x, y / max(1, len(who))) for x, y in pts]
    return pts


def proc_points(ents, field, bin_s):
    acc = defaultdict(lambda: [0.0, 0.0])
    for e in ents:
        for s in e.proc():
            for r in s.s:
                if r.get(field) is not None:
                    b = int(r["t"] // bin_s)
                    acc[b][0] += r[field]
                    acc[b][1] += 1
    return [((b + 0.5) * bin_s / 60.0, v[0] / v[1]) for b, v in sorted(acc.items())]


def attack_spans(runs_):
    """Merged [(start s, end s)] of the attack windows of the runs."""
    spans = sorted((w["start"], w["end"]) for r in runs_ for w in r.attacks)
    out = []
    for a, b in spans:
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def svg_chart(title, data, colors, phases, span_min, attacks=()):
    W, H, L, R, T, B = 860, 200, 54, 12, 22, 28
    ymax = max([y for pts in data.values() for _, y in pts], default=0) * 1.1 or 1.0
    xs = lambda x: L + (W - L - R) * x / span_min
    ys = lambda y: T + (H - T - B) * (1 - y / ymax)
    o = ['<svg viewBox="0 0 %d %d" role="img" aria-label="%s">' % (W, H, html.escape(title)),
         '<text x="%d" y="14" class="t">%s</text>' % (L, html.escape(title))]
    for i, (t, name) in enumerate(phases):
        if name in PHASE_FILL:
            end = phases[i + 1][0] if i + 1 < len(phases) else span_min * 60
            x0, x1 = xs(t / 60.0), xs(end / 60.0)
            o.append('<rect x="%.1f" y="%d" width="%.1f" height="%d" fill="%s" opacity="0.22"/>' % (
                x0, T, max(x1 - x0, 1.0), H - T - B, PHASE_FILL[name]))
    for a, b in attacks:
        x0, x1 = xs(a / 60.0), xs(b / 60.0)
        o.append('<rect x="%.1f" y="%d" width="%.1f" height="%d" fill="%s" opacity="0.16"/>' % (
            x0, T, max(x1 - x0, 1.0), H - T - B, ATTACK_FILL))
    for k in range(5):
        y = ymax * k / 4
        o.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" class="g"/><text x="%d" y="%.1f" class="a" text-anchor="end">%s</text>'
                 % (L, W - R, ys(y), ys(y), L - 4, ys(y) + 3, ("%.3g" % y)))
    for k in range(7):
        x = span_min * k / 6
        o.append('<text x="%.1f" y="%d" class="a" text-anchor="middle">%.0f</text>' % (xs(x), H - 10, x))
    o.append('<text x="%d" y="%d" class="a" text-anchor="end">minutes</text>' % (W - R, H - 1))
    for lb, pts in data.items():
        if pts:
            o.append('<polyline fill="none" stroke="%s" stroke-width="1.5" points="%s"/>' % (
                colors[lb], " ".join("%.1f,%.1f" % (xs(x), ys(y)) for x, y in pts)))
    o.append("</svg>")
    return "".join(o)


def html_report(rows, checks, runs, ents, rules, failed):
    parts = ["<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
             "<title>Soak report</title><style>"
             ":root{--bg:#fff;--fg:#111;--mut:#666;--grid:#ddd;--bd:#ccc}"
             "@media(prefers-color-scheme:dark){:root{--bg:#111;--fg:#eee;--mut:#999;--grid:#333;--bd:#444}}"
             "body{background:var(--bg);color:var(--fg);font:14px system-ui,sans-serif;margin:0 auto;max-width:900px;padding:0 16px 40px}"
             "table{border-collapse:collapse;margin:8px 0 24px;display:block;overflow-x:auto}td,th{border:1px solid var(--bd);padding:3px 8px;text-align:left}"
             "svg{width:100%;height:auto;margin:6px 0}.t{fill:var(--fg);font-size:12px;font-weight:600}.a{fill:var(--mut);font-size:10px}"
             ".g{stroke:var(--grid);stroke-width:1}.k{display:inline-block;width:12px;height:3px;margin:0 4px 3px 12px}"
             ".sw{display:inline-block;width:10px;height:10px;margin:0 4px -1px 12px;opacity:.5}"
             ".f{color:#dc2626;font-weight:600}</style>",
             "<h1>Soak report</h1><p class=%s>%s</p>" % ('"f"' if failed else '"m"', "GATE FAILED" if failed else "Gates held.")]
    legend = dict(PHASE_FILL)
    if any(r.attacks for r in runs):
        legend["attack"] = ATTACK_FILL
    parts.append("<p>" + "".join('<span class=sw style="background:%s"></span>%s' % (c, n) for n, c in legend.items()) + "</p>")
    for spec in rules["compare"]:
        subj, base = pick(ents, spec, "subject"), pick(ents, spec, "baseline")
        for arch in sorted({e.arch for e in subj} & {e.arch for e in base}):
            s_ents = [e for e in subj if e.arch == arch]
            b_ents = [e for e in base if e.arch == arch]
            colors = {"subject": PALETTE[0], "baseline": PALETTE[1]}
            span = max([e.t1 for e in s_ents + b_ents] or [60.0]) / 60.0 or 1.0
            bin_s = max(5, int(math.ceil(span * 60 / 240 / 5.0) * 5))
            ref = max(s_ents + b_ents, key=lambda e: len(e.run.phases()))
            atk = attack_spans([ref.run])
            parts.append("<h2>%s vs %s on %s</h2><p><span class=k style='background:%s'></span>%s"
                         "<span class=k style='background:%s'></span>%s</p>" % (
                             html.escape(label(spec, "subject")), html.escape(label(spec, "baseline")), html.escape(arch),
                             colors["subject"], html.escape(label(spec, "subject")), colors["baseline"],
                             html.escape(label(spec, "baseline"))))
            groups = sorted({s.group for e in s_ents + b_ents for s in e.series.values() if s.kind == "recv"})
            for g in groups:
                for metric, title in (("freeze_rate", "Freezes / min"), ("audio_gap", "Audio gap %"),
                                      ("loss", "Residual loss %"), ("rx_mbps", "Receive Mbit/s per participant")):
                    data = {"subject": chart_points(s_ents, g, metric, bin_s),
                            "baseline": chart_points(b_ents, g, metric, bin_s)}
                    if any(data.values()):
                        parts.append(svg_chart("%s (%s group)" % (title, g), data, colors, ref.run.phases(g), span, atk))
            for field, title in (("cpu_pct", "SFU CPU % of a core"), ("rss_mb", "SFU RSS MB")):
                data = {"subject": proc_points(s_ents, field, bin_s), "baseline": proc_points(b_ents, field, bin_s)}
                if any(data.values()):
                    parts.append(svg_chart(title, data, colors, ref.run.phases(), span, atk))
    for title, head, body in tables(rows, checks, runs, ents, rules):
        parts.append("<h2>%s</h2><table><tr>%s</tr>%s</table>" % (
            html.escape(title), "".join("<th>%s</th>" % html.escape(h) for h in head),
            "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % html.escape(str(c)) for c in r) for r in body)))
    parts.append("</html>")
    return "".join(parts)


def analyse(runs, rules):
    ents = build_entities(runs)
    rows, checks = compare(ents, rules)
    return ents, rows, checks


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("files", nargs="+")
    a = ap.parse_args(argv)
    rules = dict(DEFAULTS)
    with open(a.rules) as f:
        rules.update(json.load(f))
    runs = load(a.files)
    if not any(r.rows for r in runs):
        print("report.py: no usable samples in the input", file=sys.stderr)
        return 2
    for r in runs:
        if r.bad:
            print("report.py: %s: skipped %d malformed lines" % (r.path, r.bad), file=sys.stderr)
    ents, rows, checks = analyse(runs, rules)
    if not ents or not any(e.series for e in ents):
        print("report.py: no recv/proc/dc samples in the input", file=sys.stderr)
        return 2
    if not rules["compare"]:
        print("report.py: the rules have no `compare` pair", file=sys.stderr)
        return 2
    allc = verdict_checks(rows, checks)
    failed = any(c["status"] == "FAIL" for c in allc)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "summary.md"), "w") as f:
        f.write(markdown(rows, checks, runs, failed, ents, rules))
    with open(os.path.join(a.out, "report.html"), "w") as f:
        f.write(html_report(rows, checks, runs, ents, rules, failed))
    for c in allc:
        if c["status"] in ("FAIL", "breach"):
            print("%s %s (%s, limit %s)" % (c["status"], c["rule"], c["value"], c["limit"]), file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

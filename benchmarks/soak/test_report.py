#!/usr/bin/env python3
"""Self-test of report.py on small generated runs: python3 -m unittest -v benchmarks/soak/test_report.py"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report  # noqa: E402

T0 = 1_700_000_000_000  # ms
STEP = 5  # s between samples


def ts(t):
    return T0 + int(t * 1000)


def phase(t, name, group="impaired"):
    return {"ts": ts(t), "impl": "netem", "arch": "x86_64", "kind": "phase", "id": "netem", "group": group, "name": name}


def event(impl, t, who, what, detail="", group="impaired", **more):
    return {"ts": ts(t), "impl": impl, "arch": "x86_64", "kind": "event", "id": who, "what": what, "detail": detail,
            "group": group, **more}


def track(impl, rid, group, end, flowing=lambda t: True, start=0, media="video", bytes_per_s=0, freezes=lambda t: 0,
          arch="x86_64", frames_of=lambda t: 150, freeze_ms=lambda t: 0):
    """recv rows every 5 s from start to end; counters grow while `flowing(t)` (`frames_of(t)` a step);
    `freezes` and `freeze_ms` give the cumulative counters."""
    rows, frames, packets, nbytes = [], 0, 0, 0
    t = start
    while t <= end:
        if flowing(t) and t > start:
            frames += frames_of(t)
            packets += 400
            nbytes += int(bytes_per_s * STEP)
        rows.append({"ts": ts(t), "impl": impl, "arch": arch, "kind": "recv", "id": rid, "media": media,
                     "group": group, "frames": frames, "freezes": freezes(t), "freeze_ms": freeze_ms(t), "packets": packets,
                     "lost": 0, "nack": 0, "pli": 0, "jitter_ms": 1.0, "rtt_ms": None, "audio_gap_ms": 0,
                     "bytes": nbytes, "duplicates": 0, "stalled": False})
        t += STEP
    return rows


def attack(t, aid, name, state, who=None, group="impaired", impl="abuse"):
    row = {"ts": ts(t), "impl": impl, "arch": "x86_64", "kind": "attack", "id": aid, "name": name, "state": state,
           "group": group, "seed": 7}
    if who is not None:
        row["who"] = who
    return row


def window(t0, t1, aid, name, who=None, group="impaired"):
    return [attack(t0, aid, name, "start", who, group), attack(t1, aid, name, "end", who, group)]


def proc(impl, end, cpu=50.0, rss=100.0, arch="x86_64"):
    return [{"ts": ts(t), "impl": impl, "arch": arch, "kind": "proc", "id": "sfu", "rss_mb": rss, "cpu_pct": cpu,
             "threads": 10, "fds": 20, "udp_rcvbuf_err": 0, "udp_sndbuf_err": 0} for t in range(0, end + 1, STEP)]


TIMELINE = [phase(0, "clean"), phase(60, "bw"), phase(120, "outage"), phase(125, "recover")]
END = 240
RULES = {"compare": [{"subject": "rtcd-rs", "baseline": "rtcd-go"}], "require_groups": ["clean", "impaired"],
         "min_clean_window_min": 1, "warmup_min": 0, "window_min": 1}


def side(impl, **kw):
    """A lesson-like run: a clean student, two impaired ones, the SFU process."""
    rows = list(TIMELINE) + proc(impl, END, **{k: kw[k] for k in ("cpu", "rss") if k in kw})
    rows += track(impl, "c01/video:teacher", "clean", END, bytes_per_s=kw.get("clean_bps", 200_000),
                  freezes=kw.get("clean_freezes", lambda t: 0), flowing=kw.get("clean_flow", lambda t: True))
    rows += track(impl, "s17/video:teacher", "impaired", END, bytes_per_s=300_000,
                  flowing=lambda t: not (120 <= t < 125))
    rows += kw.get("extra", [])
    return rows


def write(rows):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "x.jsonl")
    with open(p, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return p


def run_report(subject_rows, baseline_rows, rules=None):
    d = tempfile.mkdtemp()
    paths = [write(subject_rows), write(baseline_rows)]
    # One file per side, as the CI has them: the file name is the run.
    named = []
    for name, p in zip(("rtcd-rs-x86_64", "rtcd-go-x86_64"), paths):
        q = os.path.join(d, name + ".jsonl")
        os.rename(p, q)
        named.append(q)
    rules_path = os.path.join(d, "rules.json")
    with open(rules_path, "w") as f:
        json.dump(rules or RULES, f)
    status = report.main(["--rules", rules_path, "--out", os.path.join(d, "out")] + named)
    with open(os.path.join(d, "out", "summary.md")) as f:
        return status, f.read(), report.build_entities(report.load(named)), d


class Fixture(unittest.TestCase):
    def rows(self, **kw):
        """The subject's run with `extra` rows, and a plain baseline."""
        base = {k: v for k, v in kw.items() if k != "extra"}
        return side("rtcd-rs", **kw), side("rtcd-go", **base)


class PhaseAssignment(Fixture):
    def test_each_participant_follows_its_own_group(self):
        s, b = self.rows()
        _, _, ents, _ = run_report(s, b)
        e = next(e for e in ents if e.impl == "rtcd-rs")
        clean = next(x for x in e.series.values() if x.id.startswith("c01"))
        imp = next(x for x in e.series.values() if x.id.startswith("s17"))
        # The clean student is in `clean` whatever the network is doing to the others.
        self.assertEqual({i["phase"] for i in clean.ivs}, {"clean"})
        self.assertEqual({i["phase"] for i in imp.ivs}, {"clean", "bw", "outage", "recover"})
        self.assertEqual(next(i["phase"] for i in imp.ivs if 70 < i["t"] < 80), "bw")

    def test_receive_rate_is_per_participant_not_per_track(self):
        extra = track("rtcd-rs", "s17/screen:teacher", "impaired", END, bytes_per_s=100_000, media="video")
        s, b = self.rows(extra=extra)
        _, md, _, _ = run_report(s, b)
        # 300 + 100 kB/s on s17 = 3.2 Mbit/s in the bw phase; the baseline has one track (2.4).
        line = next(l for l in md.splitlines() if l.startswith("| impaired | bw | Receive Mbit/s per participant (mean)"))
        self.assertIn("| 3.20 |", line)


def lone_track(impl, start, **kw):
    """A lesson-like side whose only impaired receiver is the given track."""
    rows = list(TIMELINE) + proc(impl, END)
    rows += track(impl, "c01/video:teacher", "clean", END, bytes_per_s=200_000)
    return rows + track(impl, "s17/video:teacher", "impaired", END, start=start, bytes_per_s=300_000, **kw)


def lerp(t, t0, t1, total):
    """A counter that grows evenly from 0 at t0 to `total` at t1."""
    return total * min(max(t - t0, 0.0), t1 - t0) / (t1 - t0)


class OutageEpisode(Fixture):
    def side(self, impl, start):
        # A 4.9 s freeze from the outage's start; an open freeze counts at once, so it is booked
        # across the samples that see it.
        return lone_track(impl, start, flowing=lambda t: not (120 <= t < 125),
                          freeze_ms=lambda t: int(lerp(t, 120, 124.9, 4900)))

    def test_the_freeze_per_outage_does_not_depend_on_the_sampling_clock(self):
        code, md, ents, _ = run_report(self.side("rtcd-rs", 3.9), self.side("rtcd-go", 4.9))
        got = {e.impl: report.scope_metrics([e], "impaired", "outage", dict(report.DEFAULTS))["outage_freeze_ms"]
               for e in ents}
        self.assertAlmostEqual(got["rtcd-rs"], 4900, delta=49)
        self.assertAlmostEqual(got["rtcd-go"], 4900, delta=49)
        self.assertEqual(code, 0, md)


class FrozenStream(Fixture):
    def side(self, impl, fps, freezes_per_step, ms_per_step):
        """In the bw phase (60 to 120 s) the track plays `fps` frames a second and freezes
        `freezes_per_step` times and `ms_per_step` ms in every sample."""
        return lone_track(impl, 0, frames_of=lambda t: int(fps * 5) if 60 < t <= 120 else 150,
                          freezes=lambda t: int(lerp(t, 60, 120, 12 * freezes_per_step)),
                          freeze_ms=lambda t: int(lerp(t, 60, 120, 12 * ms_per_step)))

    def test_a_dead_baseline_does_not_make_a_live_stuttering_subject_breach(self):
        # The baseline froze once for 96 % of the phase at 1 fps; the subject plays 6 fps in many short freezes.
        code, md, _, _ = run_report(self.side("rtcd-rs", 6, 1, 1000), self.side("rtcd-go", 1, 0.084, 4800))
        self.assertEqual(code, 0, md)

    def test_a_subject_that_plays_less_and_freezes_longer_breaches(self):
        code, md, _, _ = run_report(self.side("rtcd-rs", 1, 0.084, 4800), self.side("rtcd-go", 6, 1, 1000))
        self.assertEqual(code, 1, md)
        self.assertIn("Video frames / s", md)


    def test_the_outage_phase_has_no_frame_rate(self):
        # Too few intervals for a rate; the outage is scored per episode.
        slow = lone_track("rtcd-rs", 0, frames_of=lambda t: 5 if 120 < t <= 125 else 150)
        code, md, _, _ = run_report(slow, lone_track("rtcd-go", 0))
        self.assertEqual(code, 0, md)
        self.assertNotIn("| impaired | outage | Video frames", md)
        self.assertIn("| impaired | bw | Video frames", md)


class AttackFrozenTime(Fixture):
    RULES = dict(RULES, slack={"freezes": 1000})

    def side(self, impl, freezes, ms):
        """An innocent impaired receiver that freezes `freezes` times, `ms` ms in all, in a window (100 to 110 s)."""
        rows = list(TIMELINE) + proc(impl, END) + window(100, 110, "a1", "reorder", ["s17"])
        rows += track(impl, "c01/video:teacher", "clean", END, bytes_per_s=200_000)
        rows += track(impl, "s17/video:teacher", "impaired", END, bytes_per_s=300_000)
        return rows + track(impl, "s18/video:teacher", "impaired", END, bytes_per_s=300_000,
                            freezes=lambda t: int(lerp(t, 100, 110, freezes)),
                            freeze_ms=lambda t: int(lerp(t, 100, 110, ms)))

    def test_many_short_freezes_are_not_a_breach_when_the_frozen_time_is_less(self):
        code, md, _, _ = run_report(self.side("rtcd-rs", 4, 400), self.side("rtcd-go", 1, 4000), self.RULES)
        self.assertEqual(code, 0, md)
        self.assertIn("| reorder | Freeze ms / min (video) |", md)

    def test_more_frozen_time_breaches(self):
        code, md, _, _ = run_report(self.side("rtcd-rs", 4, 4000), self.side("rtcd-go", 1, 400), self.RULES)
        self.assertEqual(code, 1, md)
        self.assertIn("attack / reorder / Freeze ms / min (video)", md)


class Recovery(Fixture):
    def test_tracks_of_departed_participants_are_not_unrecovered(self):
        # s18's session is closed by the SFU during the outage: its track ends; s19 stays but never gets media back.
        gone = track("rtcd-rs", "s18/video:teacher", "impaired", 128)
        stuck = track("rtcd-rs", "s19/video:teacher", "impaired", END, flowing=lambda t: t < 120)
        ev = [event("rtcd-rs", 127, "s18", "error", "the SFU closed the session")]
        s, b = self.rows(extra=gone + stuck + ev)
        _, _, ents, _ = run_report(s, b)
        e = next(e for e in ents if e.impl == "rtcd-rs")
        rec = report.recoveries(e, "impaired", dict(report.DEFAULTS), report.departures(e))
        # s17 recovered within one sample, s19 never did, s18 is not a track that should have.
        self.assertEqual(len(rec), 2)
        self.assertEqual(sum(1 for x in rec if x == float("inf")), 1)
        m = report.scope_metrics([e], "impaired", None, dict(report.DEFAULTS))
        self.assertEqual((m["closes"], m["never"]), (1, 1))

    def test_unrecovered_seat_costs_downtime_until_the_end_of_the_run(self):
        ev = [event("rtcd-rs", 100, "s18", "error", "the SFU closed the session")]
        s, b = self.rows(extra=ev)
        _, _, ents, _ = run_report(s, b)
        e = next(e for e in ents if e.impl == "rtcd-rs")
        m = report.scope_metrics([e], "impaired", None, dict(report.DEFAULTS))
        self.assertAlmostEqual(m["downtime"], END - 100, delta=1)
        ev.append(event("rtcd-rs", 104, "s18", "rejoin", "connected again", downtime_ms=4000, attempts=1))
        s, b = self.rows(extra=ev)
        _, _, ents, _ = run_report(s, b)
        e = next(e for e in ents if e.impl == "rtcd-rs")
        m = report.scope_metrics([e], "impaired", None, dict(report.DEFAULTS))
        self.assertEqual((m["closes"], m["rejoins"]), (1, 1))
        self.assertAlmostEqual(m["downtime"], 4.0, delta=0.01)


class Compare(Fixture):
    def test_equal_runs_pass(self):
        s, b = self.rows()
        status, md, _, _ = run_report(s, b)
        self.assertEqual(status, 0, md)
        self.assertIn("gates held", md)

    def test_a_worse_subject_breaches(self):
        s, b = side("rtcd-rs", cpu=90.0), side("rtcd-go", cpu=50.0)
        status, md, _, _ = run_report(s, b)
        self.assertEqual(status, 1)
        self.assertIn("SFU CPU % of a core (mean)", md.split("## Breaches")[1].split("## ")[0])

    def test_within_the_ratio_passes_and_a_close_is_a_breach(self):
        s, b = side("rtcd-rs", cpu=60.0), side("rtcd-go", cpu=50.0)  # 60 <= 50 x 1.25 + 5
        self.assertEqual(run_report(s, b)[0], 0)
        close = [event("rtcd-rs", 70, "s17", "error", "the SFU closed the session"),
                 event("rtcd-rs", 72, "s17", "rejoin", "connected again", downtime_ms=2000, attempts=1)]
        status, md, _, _ = run_report(side("rtcd-rs", extra=close), side("rtcd-go"))
        self.assertEqual(status, 1)
        self.assertIn("SFU-closed sessions", md.split("## Breaches")[1].split("## ")[0])

    def test_a_better_subject_passes(self):
        close = [event("rtcd-go", 70, "s17", "error", "the SFU closed the session")]
        self.assertEqual(run_report(side("rtcd-rs"), side("rtcd-go", extra=close))[0], 0)

    def test_missing_baseline_fails_loudly(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "rtcd-rs-x86_64.jsonl")
        with open(p, "w") as f:
            for r in side("rtcd-rs"):
                f.write(json.dumps(r) + "\n")
        rules = os.path.join(d, "rules.json")
        with open(rules, "w") as f:
            json.dump(RULES, f)
        status = report.main(["--rules", rules, "--out", os.path.join(d, "out"), p])
        self.assertEqual(status, 1)
        with open(os.path.join(d, "out", "summary.md")) as f:
            self.assertIn("no baseline data on x86_64", f.read())

    def test_baseline_on_another_architecture_does_not_count(self):
        d = tempfile.mkdtemp()
        p, q = os.path.join(d, "rtcd-rs-x86_64.jsonl"), os.path.join(d, "rtcd-go-aarch64.jsonl")
        for path, rows in ((p, side("rtcd-rs")), (q, [dict(r, arch="aarch64") for r in side("rtcd-go")])):
            with open(path, "w") as f:
                for r in rows:
                    f.write(json.dumps(r) + "\n")
        rules = os.path.join(d, "rules.json")
        with open(rules, "w") as f:
            json.dump(RULES, f)
        self.assertEqual(report.main(["--rules", rules, "--out", os.path.join(d, "out"), p, q]), 1)


class CleanGroup(Fixture):
    def test_a_freeze_in_the_clean_group_fails_even_when_the_baseline_has_it_too(self):
        both = {"clean_freezes": lambda t: 1 if t > 100 else 0}
        status, md, _, _ = run_report(side("rtcd-rs", **both), side("rtcd-go", **both))
        self.assertEqual(status, 1)
        self.assertIn("clean group, subject Freezes (count) must be zero", md)

    def test_impaired_group_freezes_have_no_absolute_rule(self):
        imp = track("rtcd-rs", "s20/video:teacher", "impaired", END, freezes=lambda t: int(t // 10))
        impg = track("rtcd-go", "s20/video:teacher", "impaired", END, freezes=lambda t: int(t // 10))
        self.assertEqual(run_report(side("rtcd-rs", extra=imp), side("rtcd-go", extra=impg))[0], 0)

    def test_sfu_process_errors_fail(self):
        crash = [event("rtcd-rs", 200, "sfu", "error", "the SFU process is gone", group=None)]
        crash[0].pop("group")
        status, md, _, _ = run_report(side("rtcd-rs", extra=crash), side("rtcd-go"))
        self.assertEqual(status, 1)
        self.assertIn("SFU process errors", md)


class LessonEnd(Fixture):
    def test_receivers_stop_measuring_when_the_first_participant_stops(self):
        # The teacher stops at 200 s; the student's receiver sees nothing after that until its own
        # stop, which is the end of the lesson, not a stall of the server.
        rows = [r for r in side("rtcd-rs") if not (r["kind"] == "recv" and r["id"] == "s17/video:teacher")]
        tail = track("rtcd-rs", "s17/video:teacher", "impaired", END, flowing=lambda t: not (120 <= t < 125) and t < 200)
        rows += [dict(r, stalled=r["ts"] > ts(205)) for r in tail]
        rows += [event("rtcd-rs", 200, "c01", "leave", "stop", group="clean"),
                 event("rtcd-rs", 240, "s17", "leave", "stop")]
        status, md, _, _ = run_report(rows, side("rtcd-go"))
        self.assertEqual(status, 0, md)


class OutageDisconnects(Fixture):
    def test_an_ice_disconnect_the_outage_caused_is_not_counted(self):
        blip = [event("rtcd-rs", 124, "s17", "ice_state", "ice:disconnected"),
                event("rtcd-rs", 124.1, "s17", "ice_state", "ice:connected")]
        status, md, _, _ = run_report(side("rtcd-rs", extra=blip), side("rtcd-go"))
        self.assertEqual(status, 0, md)

    def test_an_ice_disconnect_outside_the_outage_counts(self):
        blip = [event("rtcd-rs", 90, "s17", "ice_state", "ice:disconnected"),
                event("rtcd-rs", 91, "s17", "ice_state", "ice:connected")]
        status, md, _, _ = run_report(side("rtcd-rs", extra=blip), side("rtcd-go"))
        self.assertEqual(status, 1)
        self.assertIn("ICE disconnects", md.split("## Breaches")[1].split("## ")[0])


    def test_an_ice_failure_in_an_outage_aimed_at_the_participant_is_not_counted(self):
        cut = window(80, 140, "o1", "outage-60", ["s17"]) + [
            event("rtcd-rs", 109, "s17", "ice_state", "ice:failed")]
        status, md, _, _ = run_report(side("rtcd-rs", extra=cut), side("rtcd-go"))
        self.assertEqual(status, 0, md)

    def test_an_ice_failure_outside_its_own_outage_counts(self):
        cut = window(80, 140, "o1", "outage-60", ["s18"]) + [
            event("rtcd-rs", 109, "s17", "ice_state", "ice:failed")]
        status, md, _, _ = run_report(side("rtcd-rs", extra=cut), side("rtcd-go"))
        self.assertEqual(status, 1)
        self.assertIn("ICE failures", md.split("## Breaches")[1].split("## ")[0])


class EarlyStop(Fixture):
    """A baseline killed part way (OOM, crash) is compared over the minutes it ran."""

    @staticmethod
    def stopped(t_end):
        gone = event("rtcd-go", t_end, "sfu", "error", "the SFU process is gone")
        gone.pop("group")
        return [r for r in side("rtcd-go") if r["ts"] <= ts(t_end)] + [gone]

    def test_what_the_subject_did_after_the_baseline_stopped_is_not_compared(self):
        late = [event("rtcd-rs", 200, "s17", "error", "the SFU closed the session")]
        status, md, _, _ = run_report(side("rtcd-rs", extra=late), self.stopped(100))
        self.assertEqual(status, 0, md)
        self.assertIn("the baseline stopped early", md)

    def test_what_the_subject_did_while_the_baseline_ran_is_still_compared(self):
        early = [event("rtcd-rs", 70, "s17", "error", "the SFU closed the session")]
        status, md, _, _ = run_report(side("rtcd-rs", extra=early), self.stopped(100))
        self.assertEqual(status, 1)
        self.assertIn("SFU-closed sessions", md.split("## Breaches")[1].split("## ")[0])

    def test_the_subjects_absolute_rules_cover_its_whole_run(self):
        late = {"clean_freezes": lambda t: 1 if t > 200 else 0}
        status, md, _, _ = run_report(side("rtcd-rs", **late), self.stopped(100))
        self.assertEqual(status, 1)
        self.assertIn("clean group, subject Freezes (count) must be zero", md)


class CleanZeroPerPair(Fixture):
    def test_a_pair_may_leave_freezes_to_the_comparison(self):
        both = {"clean_freezes": lambda t: 1 if t > 100 else 0}
        rules = dict(RULES, compare=[{"subject": "rtcd-rs", "baseline": "rtcd-go",
                                      "clean_zero": ["stalls", "closes", "ice_disc"]}])
        status, md, _, _ = run_report(side("rtcd-rs", **both), side("rtcd-go", **both), rules)
        self.assertEqual(status, 0, md)
        self.assertNotIn("Freezes (count) must be zero", md)


class Attacks(Fixture):
    def ents(self, rows, impl="rtcd-rs"):
        _, _, ents, _ = run_report(rows, side("rtcd-go"))
        return [e for e in ents if e.impl == impl]

    def test_windows_are_parsed_and_an_unmatched_start_runs_to_the_end(self):
        rows = side("rtcd-rs", extra=window(100, 110, "a1", "pli-flood", ["s17"]) + [
            attack(200, "a2", "reorder", "start")])
        e = self.ents(rows)[0]
        w = {x["id"]: x for x in e.run.attacks}
        self.assertEqual((w["a1"]["name"], w["a1"]["start"], w["a1"]["end"], w["a1"]["who"]),
                         ("pli-flood", 100.0, 110.0, ["s17"]))
        self.assertEqual((w["a2"]["end"], w["a2"]["who"], w["a2"]["group"]), (float(END), [], "impaired"))

    def test_innocents_exclude_who_and_include_the_clean_group(self):
        hit = track("rtcd-rs", "s17/video:teacher", "impaired", END, bytes_per_s=300_000,
                    freezes=lambda t: 1 if t > 100 else 0)
        other = track("rtcd-rs", "s18/video:teacher", "impaired", END, freezes=lambda t: 2 if t > 100 else 0)
        base = side("rtcd-rs", extra=other)
        base = [r for r in base if not r["id"].startswith("s17")] + hit
        rows = base + window(100, 110, "a1", "pli-flood", ["s17"])
        e = self.ents(rows)[0]
        m = report.attack_metrics([e], lambda n: n == "pli-flood", dict(report.DEFAULTS))
        self.assertEqual(m["freezes"], 2)  # s18's, not s17's
        none = report.attack_metrics([e], lambda n: n == "pli-flood", dict(report.DEFAULTS), clean_only=True)
        self.assertEqual(none["freezes"], 0)

    def test_a_receiver_is_innocent_only_while_no_other_window_names_it(self):
        def ents(freezes):
            rows = lone_track("rtcd-rs", 0, freezes=freezes)
            rows += window(20, 100, "a1", "rtcp-garbage", ["s18"]) + window(30, 40, "a2", "bw-flap", ["s17"])
            return self.ents(rows)
        count = lambda e: report.attack_metrics(e, lambda n: n == "rtcp-garbage", dict(report.DEFAULTS))["freezes"]
        self.assertEqual(count(ents(lambda t: 1 if t >= 35 else 0)), 0)  # during bw-flap, which names s17
        self.assertEqual(count(ents(lambda t: (1 if t >= 35 else 0) + (1 if t >= 70 else 0))), 1)  # outside it

    def test_a_clean_freeze_fails_in_pli_flood_but_not_in_load_hold(self):
        freeze = {"clean_freezes": lambda t: 1 if t > 100 else 0}
        for name, status in (("pli-flood", 1), ("load-hold", 0)):
            win = window(100, 110, "a1", name)
            s = side("rtcd-rs", extra=win, **freeze)
            b = side("rtcd-go", extra=[dict(r, impl="abuse") for r in win], **freeze)
            code, md, _, _ = run_report(s, b)
            self.assertEqual(code, status, (name, md))
            if status:
                self.assertIn("clean group, subject Freezes (count) must be zero", md)

    def test_recover_s_is_the_time_from_the_end_until_the_innocents_flow_again(self):
        win = window(100, 110, "a1", "pli-flood", ["s17"])
        slow = {"clean_flow": lambda t: not 102 <= t < 135}
        e = self.ents(side("rtcd-rs", extra=win, **slow))[0]
        m = report.attack_metrics([e], lambda n: n == "pli-flood", dict(report.DEFAULTS))
        self.assertEqual((m["recover_s"], m["never"]), (25.0, 0))
        e = self.ents(side("rtcd-rs", extra=win))[0]
        self.assertEqual(report.attack_metrics([e], lambda n: n == "pli-flood", dict(report.DEFAULTS))["recover_s"], 0.0)
        stuck = {"clean_flow": lambda t: t < 102}
        e = self.ents(side("rtcd-rs", extra=win, **stuck))[0]
        m = report.attack_metrics([e], lambda n: n == "pli-flood", dict(report.DEFAULTS))
        self.assertEqual((m["recover_s"], m["never"]), (float("inf"), 1))

    def late_outage_rows(self, wins, stalled=()):
        """An impaired receiver of a run with the outage at 250 s; `stalled` samples are flagged."""
        rows = [phase(0, "clean"), phase(250, "outage"), phase(400, "recover")] + proc("rtcd-rs", 500)
        rows += track("rtcd-rs", "s17/video:teacher", "impaired", 500, bytes_per_s=300_000,
                      flowing=lambda t: not 250 <= t < 400)
        for r in rows:
            if r["kind"] == "recv" and r["ts"] in {ts(t) for t in stalled}:
                r["stalled"] = True
        return rows + wins

    def test_an_attack_ending_before_an_outage_is_not_charged_with_it(self):
        win = window(20, 50, "a1", "pli-flood", ["s99"])
        e = self.ents(self.late_outage_rows(win))[0]
        m = report.attack_metrics([e], lambda n: n == "pli-flood", dict(report.DEFAULTS))
        self.assertEqual((m["never"], m["recover_s"]), (0, 0.0))

    def test_overlapping_windows_of_one_class_count_a_stall_once(self):
        wins = window(20, 50, "a1", "pli-flood", ["s99"]) + window(25, 55, "a2", "pli-flood", ["s99"])
        e = self.ents(self.late_outage_rows(wins, stalled=(30, 35)))[0]
        m = report.attack_metrics([e], lambda n: n == "pli-flood", dict(report.DEFAULTS))
        self.assertEqual(m["stalls"], 1)

    def test_an_event_in_two_overlapping_windows_of_one_class_counts_once(self):
        wins = window(20, 50, "a1", "pli-flood", ["s99"]) + window(25, 55, "a2", "pli-flood", ["s99"])
        ev = [event("rtcd-rs", 30, "s17", "error", "the SFU closed the session")]
        e = self.ents(self.late_outage_rows(wins) + ev)[0]
        m = report.attack_metrics([e], lambda n: n == "pli-flood", dict(report.DEFAULTS))
        self.assertEqual(m["closes"], 1)
        other = window(25, 55, "a2", "reorder", ["s99"])
        e = self.ents(self.late_outage_rows(window(20, 50, "a1", "pli-flood", ["s99"]) + other) + ev)[0]
        total = sum(report.attack_metrics([e], lambda n, c=c: n == c, dict(report.DEFAULTS))["closes"]
                    for c in ("pli-flood", "reorder"))
        self.assertEqual(total, 2)  # once per class

    def test_slow_recovery_breaches_equal_runs_pass(self):
        win = window(100, 110, "a1", "pli-flood", ["s17"])
        slow = {"clean_flow": lambda t: not 102 <= t < 135}
        code, md, _, _ = run_report(side("rtcd-rs", extra=win, **slow), side("rtcd-go", extra=win))
        self.assertEqual(code, 1)
        self.assertIn("Recovery after an attack", md.split("## Breaches")[1].split("## ")[0])
        self.assertIn("## Attack windows", md)
        self.assertIn("| pli-flood | a1 |", md)
        code, md, _, _ = run_report(side("rtcd-rs", extra=win, **slow), side("rtcd-go", extra=win, **slow))
        self.assertEqual(code, 0, md)  # equal runs hold, however slow

    def test_missing_baseline_fails_with_attacks(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "rtcd-rs-x86_64.jsonl")
        with open(p, "w") as f:
            for r in side("rtcd-rs", extra=window(100, 110, "a1", "reorder")):
                f.write(json.dumps(r) + "\n")
        rules = os.path.join(d, "rules.json")
        with open(rules, "w") as f:
            json.dump(RULES, f)
        self.assertEqual(report.main(["--rules", rules, "--out", os.path.join(d, "out"), p]), 1)

    def test_classes_after_the_baseline_server_stopped_are_not_compared(self):
        flood = window(100, 110, "a1", "pli-flood") + window(220, 230, "a2", "reorder")
        s = side("rtcd-rs", extra=flood)
        b = [r for r in side("rtcd-go", extra=[dict(r, impl="rtcd-go") for r in flood])
             if not (r["kind"] == "proc" and r["ts"] > ts(200))]
        _, md, _, _ = run_report(s, b)
        self.assertIn("| pli-flood | Freezes (count) | 0 | 0 | ok |", md)
        self.assertNotIn("| reorder | Freezes", md)
        self.assertIn("attack reorder | only the subject has it | both sides need it | n/a", md)

    def test_sfu_slopes_and_saturation(self):
        grow = [dict(r, threads=10 + (r["ts"] - T0) // 1000 // STEP, cpu_pct=200.0) for r in proc("rtcd-rs", END)]
        rows = [r for r in side("rtcd-rs") if r["kind"] != "proc"] + grow
        d = tempfile.mkdtemp()
        p = os.path.join(d, "rtcd-rs-x86_64.jsonl")
        with open(p, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        ents = report.build_entities(report.load([p]))
        m = report.sfu_metrics(ents, dict(report.DEFAULTS, warmup_min=0, rss_slope_min_span_min=1))
        self.assertAlmostEqual(m["threads_slope"], 720.0, delta=1)
        self.assertEqual((m["cpu_sat"], m["fds_slope"]), (100.0, 0.0))


if __name__ == "__main__":
    unittest.main()

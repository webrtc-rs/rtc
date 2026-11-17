import argparse
import contextlib
import json
import os
import tempfile
import unittest

import tracereplay as trace


class Convert(unittest.TestCase):
    def test_counts_packets_per_step(self):
        # 100 ms steps over a 600 ms period: 3 packets in step 0, none in 1, 2 and 4, 1 in 3, 2 in 5
        kbit = trace.convert("1 5 90 305 500 599 600".split(), 100)
        self.assertEqual(kbit, [36, 0, 0, 12, 0, 24])

    def test_trailing_part_of_a_step_is_dropped(self):
        self.assertEqual(trace.convert(["10", "150", "250"], 100), [12, 12])

    def test_shorter_than_a_step_is_an_error(self):
        with self.assertRaises(ValueError):
            trace.convert(["10", "50"], 100)

    def test_rate(self):
        self.assertEqual(trace.kbps(12, 200), 60)
        self.assertEqual(trace.kbps(0, 200), 0)


class Windows(unittest.TestCase):
    def test_stall_and_low_need_their_length(self):
        # 200 ms steps: a stall needs 5 zero steps, a low stretch 10 steps under 300 kbit/s
        rates = [1000] * 3 + [0] * 4 + [1000] * 2 + [0] * 5 + [100] * 5 + [1000]
        self.assertEqual(trace.windows(rates, 200), [(9, 14, "trace-stall"), (9, 19, "trace-low")])

    def test_a_stretch_to_the_end_is_cut_there(self):
        self.assertEqual(trace.windows([1000] + [0] * 5, 200), [(1, 6, "trace-stall")])


def args_for(directory, events, **kw):
    base = dict(dir=directory, seed=7, seconds=60, iface="eth0", ifb="", flows=0, delay="40ms", limit=100,
                step_ms=200, events=events, group="impaired", arch="x86_64", names="a b", all_names=False,
                dry_run=True)
    base.update(kw)
    return argparse.Namespace(**base)


class Play(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # a link that delivers 10 packets per 200 ms step for 20 s, then nothing for 6 s, looped
        stamps = [t for t in range(0, 20000, 20)] + [26000]
        for d in ("up", "down"):
            with open(os.path.join(self.tmp.name, "Test-LTE.%s" % d), "w") as f:
                f.write("\n".join(str(t) for t in stamps) + "\n")
        self.events = os.path.join(self.tmp.name, "events.jsonl")

    def run_play(self, **kw):
        out = os.path.join(self.tmp.name, "out.txt")
        with open(out, "w") as f:
            with contextlib.redirect_stdout(f):
                trace.play(args_for(self.tmp.name, self.events, **kw))
        with open(out) as f:
            tc = f.read().splitlines()
        with open(self.events) as f:
            rows = [json.loads(x) for x in f]
        return tc, rows

    def test_root_netem_without_flows(self):
        tc, rows = self.run_play(seconds=30)
        batches = [x for x in tc if not x.startswith("#")]
        self.assertEqual(len(batches), 150)
        self.assertTrue(batches[0].startswith("qdisc replace dev eth0 root netem delay 40ms"))
        self.assertTrue(batches[1].startswith("qdisc change dev eth0 root netem"))
        self.assertTrue(any("loss 100% rate 0 limit 100" in x for x in batches))
        self.assertTrue(any("loss 0% rate 600kbit limit 100" in x for x in batches))

    def test_flows_and_ingress_write_a_line_per_class_and_device(self):
        tc, _ = self.run_play(seconds=1, flows=2, ifb="ifb-soak")
        step0 = tc[1:5]
        self.assertEqual([x.split(" parent ")[1].split(" netem")[0] for x in step0],
                         ["1:2 handle 2:", "1:2 handle 2:", "1:3 handle 3:", "1:3 handle 3:"])
        self.assertEqual([x.split(" dev ")[1].split()[0] for x in step0], ["eth0", "ifb-soak"] * 2)

    def test_timeline_lines(self):
        _, rows = self.run_play(seconds=60)
        self.assertEqual([r["name"] for r in rows if r["kind"] == "phase"], ["trace"])
        attacks = [r for r in rows if r["kind"] == "attack"]
        self.assertTrue(attacks)
        self.assertEqual({r["name"] for r in attacks}, {"trace-stall", "trace-low"})
        for r in attacks:
            self.assertEqual(r["who"], ["a", "b"])
            self.assertEqual(r["seed"], 7)
        by_id = {}
        for r in attacks:
            by_id.setdefault(r["id"], []).append(r["state"])
        self.assertTrue(all(v == ["start", "end"] for v in by_id.values()))

    def test_replay_is_deterministic(self):
        a = self.run_play(seconds=30, flows=2)[0]
        os.remove(self.events)
        b = self.run_play(seconds=30, flows=2)[0]
        self.assertEqual(a, b)

    def test_who_follows_the_flow(self):
        _, rows = self.run_play(seconds=60, flows=2)
        who = {r["id"].split("-")[2]: r["who"] for r in rows if r["kind"] == "attack"}
        self.assertEqual(who, {"0": ["a"], "1": ["b"]})


if __name__ == "__main__":
    unittest.main()

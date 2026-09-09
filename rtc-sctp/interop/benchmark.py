#!/usr/bin/env python3
"""Compare prebuilt SCTP release binaries without sharing Cargo target state."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import time


WORKLOADS = {
    "micro_small": ("sctp_micro", ["32", "1", "5000000"]),
    "micro_bundled": ("sctp_micro", ["1200", "4", "1000000"]),
    # Stay below one full SSN wrap: a86147a deadlocks at 16B x 131072.
    # That correctness case is tracked separately, not treated as a timing run.
    "e2e_small": ("sctp_e2e", ["16", "60000"]),
    "e2e_fragmented": ("sctp_e2e", ["12000", "32768"]),
}
# Each public-API scenario is compiled from identical source for both snapshots.
# The runner reports its own timed interval; process setup stays in wall_ns/RSS.
EXTRA_WORKLOADS = {
    "small_rwnd": ["--scenario", "small-rwnd", "--messages", "32768", "--size", "256",
                   "--streams", "1", "--iterations", "1", "--seed", "237", "--rwnd", "4096"],
    "multi_stream": ["--scenario", "multi-stream", "--messages", "60000", "--size", "32",
                     "--streams", "32", "--iterations", "1", "--seed", "237", "--rwnd", "65536"],
    "many_resets": ["--scenario", "reset-reuse", "--size", "32", "--streams", "512",
                    "--cycles", "1", "--iterations", "4", "--seed", "237", "--rwnd", "65536"],
    "sid_reuse": ["--scenario", "reset-reuse", "--size", "32", "--streams", "1",
                  "--cycles", "512", "--iterations", "4", "--seed", "237", "--rwnd", "65536"],
}
QUEUE_TEST = "association::association_test::benchmark_pending_data_before_reset"
SACK_WORKLOADS = {
    f"sack_{policy}_{budget}": [
        "--scenario", "multi-stream", "--messages", "60000", "--size", "32",
        "--streams", "1", "--iterations", "1", "--seed", "237", "--rwnd", "1048576",
        "--packet-budget", str(budget),
        "--reliability", "reliable" if policy == "reliable" else "rexmit:0",
        "--unordered", "0" if policy == "reliable" else "1",
    ]
    for policy in ("reliable", "rexmit0") for budget in (1, 32)
}


def describe(binary):
    return {"path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "bytes": binary.stat().st_size}


def measure(command):
    # Darwin reports bytes, GNU time reports KiB. Keep the raw stderr as well.
    timer = Path("/usr/bin/time")
    if timer.exists() and platform.system() == "Darwin":
        invocation = [str(timer), "-l", *command]
    elif timer.exists() and platform.system() == "Linux":
        invocation = [str(timer), "-f", "RTC_BENCH_RSS_KB=%M", *command]
    else:
        invocation = command
    started = time.perf_counter_ns()
    result = subprocess.run(invocation, capture_output=True, text=True, timeout=120)
    wall_ns = time.perf_counter_ns() - started
    if result.returncode != 0:
        raise RuntimeError(f"{command} failed ({result.returncode}):\n{result.stderr}")
    rss = None
    if platform.system() == "Darwin":
        match = re.search(r"(\d+)\s+maximum resident set size", result.stderr)
        if match:
            rss = int(match[1])
    elif platform.system() == "Linux":
        match = re.search(r"RTC_BENCH_RSS_KB=(\d+)", result.stderr)
        if match:
            rss = int(match[1]) * 1024
    queue = {int(count): int(micros) for count, micros in re.findall(
        r"queued_messages=(\d+) payload_bytes=\d+ send_queue_us=(\d+)", result.stderr)}
    scenario = None
    for line in result.stdout.splitlines():
        if line.startswith("{"):
            value = json.loads(line)
            if "elapsed_ns" in value:
                scenario = value
    return {"command": command, "wall_ns": wall_ns, "max_rss_bytes": rss,
            "queue_us": queue, "scenario": scenario,
            "stdout": result.stdout, "stderr": result.stderr}


def summary(values):
    median = statistics.median(values)
    mad = statistics.median(abs(value - median) for value in values)
    return {"median": median, "min": min(values), "max": max(values),
            "mad": mad, "relative_mad": mad / median if median else 0}


def sack_matrix(args, parser):
    """Rotate three frozen source snapshots over the exact same public workload."""
    names = [variant[0] for variant in args.matrix_variant]
    if len(names) < 2 or len(set(names)) != len(names):
        parser.error("matrix variants need at least two unique names")
    cases = args.cases or list(SACK_WORKLOADS)
    if any(case not in SACK_WORKLOADS for case in cases):
        parser.error("matrix mode supports only the fixed sack_* workloads")
    report = {
        "format_version": 2, "host": platform.platform(), "cpu_count": os.cpu_count(),
        "scope": "public SCTP associations; not the full Linux DataChannel benchmark from PR #111",
        "policy": {"samples": args.samples, "warmups": 1, "allocation_samples": 5,
                   "max_regression": args.max_regression,
                   "max_relative_mad": args.max_relative_mad,
                   "minimum_observed_remaining_inflight": 1024},
        "workloads": {case: SACK_WORKLOADS[case] for case in cases},
        "variants": {}, "comparisons": {}, "allocation_probes": {},
    }
    commands = {}
    allocation_commands = {}
    runner_hashes = set()
    lock_hashes = set()
    for name, revision, normal, allocation in args.matrix_variant:
        binary = Path(normal).resolve()
        alloc_binary = Path(allocation).resolve()
        metadata = json.loads(binary.with_name(f"{binary.name}-build.json").read_text())
        alloc_metadata = json.loads(alloc_binary.with_name(f"{alloc_binary.name}-build.json").read_text())
        for artifact, details in ((binary, metadata), (alloc_binary, alloc_metadata)):
            if details["source_revision"] != revision:
                parser.error(f"{name}: source revision mismatch")
            if details["binary_sha256"] != describe(artifact)["sha256"]:
                parser.error(f"{name}: binary hash mismatch")
            runner_hashes.add(details["runner_sha256"])
        lock_hashes.add(hashlib.sha256(binary.with_name("Cargo.lock").read_bytes()).hexdigest())
        commands[name] = {case: [str(binary), *SACK_WORKLOADS[case]] for case in cases}
        allocation_commands[name] = {
            case: [str(alloc_binary), *SACK_WORKLOADS[case]] for case in cases}
        report["variants"][name] = {
            "revision": revision, "binary": describe(binary), "build": metadata,
            "measurements": {}, "summary": {},
        }
        report["allocation_probes"][name] = {
            "binary": describe(alloc_binary), "build": alloc_metadata,
            "measurements": {}, "summary": {},
        }
    if len(runner_hashes) != 1 or len(lock_hashes) != 1:
        parser.error("all variants must use the same runner source and Cargo.lock")
    report["runner_sha256"] = runner_hashes.pop()
    report["cargo_lock_sha256"] = lock_hashes.pop()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        args.output.write_text(json.dumps(report, indent=2) + "\n")

    def validate(sample):
        value = sample["scenario"]
        if not value or value["sent_messages"] != 120_000 or value["delivered_messages"] != 120_000:
            raise RuntimeError("fixed-work delivery count mismatch")
        if value["retransmitted_data_chunks"] or value["gap_sack_chunks"]:
            raise RuntimeError("no-loss workload unexpectedly entered DATA recovery")
        if value["max_remaining_after_sack_chunks"] < 1024:
            raise RuntimeError("SACK workload did not retain a substantial inflight window")

    wire_metrics = ("data_chunks", "retransmitted_data_chunks", "sack_chunks", "gap_sack_chunks",
                    "forward_tsn_chunks", "packets", "timer_firings", "max_wire_inflight_chunks",
                    "sack_observations", "remaining_after_sack_sum", "max_remaining_after_sack_chunks")
    for case in cases:
        for name in names:
            validate(measure(commands[name][case]))
            report["variants"][name]["measurements"][case] = []
        for iteration in range(args.samples):
            pivot = iteration % len(names)
            order = names[pivot:] + names[:pivot]
            if iteration // len(names) % 2:
                order.reverse()
            for name in order:
                sample = measure(commands[name][case])
                validate(sample)
                report["variants"][name]["measurements"][case].append(sample)
        for name in names:
            samples = report["variants"][name]["measurements"][case]
            metrics = {key: summary([sample["scenario"][key] for sample in samples])
                       for key in ("elapsed_ns", *wire_metrics)}
            metrics["wall_ns"] = summary([sample["wall_ns"] for sample in samples])
            if all(sample["max_rss_bytes"] is not None for sample in samples):
                metrics["max_rss_bytes"] = summary([sample["max_rss_bytes"] for sample in samples])
            report["variants"][name]["summary"][case] = metrics
            elapsed = metrics["elapsed_ns"]
            print(f"{name} {case}: {elapsed['median'] / 1e6:.3f} ms median; "
                  f"MAD {elapsed['relative_mad']:.2%}", flush=True)
        for index, name in enumerate(names):
            for reference in names[:index]:
                current = report["variants"][name]["summary"][case]["elapsed_ns"]
                base = report["variants"][reference]["summary"][case]["elapsed_ns"]
                ratio = current["median"] / base["median"]
                noisy = max(current["relative_mad"], base["relative_mad"]) > args.max_relative_mad
                verdict = "inconclusive" if noisy else (
                    "regression" if ratio > 1 + args.max_regression else "pass")
                report["comparisons"][f"{case}.{name}_over_{reference}"] = {
                    "ratio": ratio, "verdict": verdict,
                }
                print(f"{case}: {name}/{reference} {ratio:.3f}x {verdict}", flush=True)
        save()
    print("latency phase complete; starting separate allocation probes", flush=True)
    for name in names:
        probe = report["allocation_probes"][name]
        for case in cases:
            samples = [measure(allocation_commands[name][case]) for _ in range(5)]
            for sample in samples:
                validate(sample)
                if not sample["scenario"]["allocation_probe"]:
                    raise RuntimeError("allocation binary has no instrumentation")
            probe["measurements"][case] = samples
            probe["summary"][case] = {
                metric: summary([sample["scenario"][metric] for sample in samples])
                for metric in ("allocations", "reallocations", "allocated_bytes")}
        save()
    print(f"raw measurements: {args.output}")
    # Always retain all comparisons, including a known slow pre-fix snapshot.
    # A matrix is evidence, not a gate that may select only favorable variants.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-target", type=Path)
    parser.add_argument("--baseline-test-bin", type=Path)
    parser.add_argument("--baseline-rev")
    parser.add_argument("--matrix-variant", action="append", nargs=4,
                        metavar=("NAME", "REVISION", "BINARY", "ALLOCATION_BINARY"),
                        help="compare frozen snapshots on the fixed SACK workloads")
    parser.add_argument("--candidate-target", type=Path)
    parser.add_argument("--candidate-test-bin", type=Path)
    parser.add_argument("--candidate-rev")
    parser.add_argument("--baseline-workloads-bin", type=Path)
    parser.add_argument("--candidate-workloads-bin", type=Path)
    parser.add_argument("--baseline-allocations-bin", type=Path)
    parser.add_argument("--candidate-allocations-bin", type=Path)
    parser.add_argument("--cases", nargs="+", choices=[*WORKLOADS, "pending_reset", *EXTRA_WORKLOADS, *SACK_WORKLOADS],
                        help="run only these fixed workloads (default: all available)")
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--max-regression", type=float, default=0.15)
    parser.add_argument("--max-relative-mad", type=float, default=0.05)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.samples < 5:
        parser.error("at least five measured samples are required")
    if args.matrix_variant:
        sack_matrix(args, parser)
        return
    if not (args.baseline_target and args.baseline_test_bin and args.baseline_rev):
        parser.error("the paired mode requires baseline target, test binary and revision")
    if args.cases and any(case in SACK_WORKLOADS for case in args.cases):
        parser.error("sack_* workloads require --matrix-variant")
    if args.candidate_target and (not args.candidate_test_bin or not args.candidate_rev):
        parser.error("a candidate needs both --candidate-test-bin and --candidate-rev")
    if args.candidate_target and args.baseline_target.resolve() == args.candidate_target.resolve():
        parser.error("baseline and candidate Cargo targets must be separate")

    if args.candidate_target and bool(args.baseline_workloads_bin) != bool(args.candidate_workloads_bin):
        parser.error("scenario comparisons need both workload binaries")
    if args.candidate_target and bool(args.baseline_allocations_bin) != bool(args.candidate_allocations_bin):
        parser.error("allocation comparisons need both instrumented binaries")
    if args.baseline_allocations_bin and not args.baseline_workloads_bin:
        parser.error("allocation probes also require the ordinary workload binaries")
    allocation_binaries = {"baseline": args.baseline_allocations_bin,
                           "candidate": args.candidate_allocations_bin}
    cases = args.cases or [*WORKLOADS, "pending_reset", *(
        EXTRA_WORKLOADS if args.baseline_workloads_bin else ())]
    if any(case in EXTRA_WORKLOADS for case in cases) and not args.baseline_workloads_bin:
        parser.error("scenario workloads require --baseline-workloads-bin")
    workload_binaries = {"baseline": args.baseline_workloads_bin,
                         "candidate": args.candidate_workloads_bin}
    variants = {"baseline": (args.baseline_target, args.baseline_test_bin, args.baseline_rev)}
    if args.candidate_target:
        variants["candidate"] = (args.candidate_target, args.candidate_test_bin,
                                 args.candidate_rev)
    report = {
        "format_version": 1,
        "host": platform.platform(),
        "cpu_count": os.cpu_count(),
        "policy": {"samples": args.samples, "warmups": 1,
                   "max_regression": args.max_regression,
                   "max_relative_mad": args.max_relative_mad},
        "variants": {}, "comparisons": {}, "allocation_probes": {},
    }
    commands = {}
    for name, (target, test_binary, revision) in variants.items():
        binaries = {bench: (target / "release/examples" / bench).resolve()
                    for bench in ("sctp_micro", "sctp_e2e")}
        commands[name] = {case: [str(binaries[bench]), *arguments]
                          for case, (bench, arguments) in WORKLOADS.items()}
        commands[name]["pending_reset"] = [str(test_binary.resolve()), QUEUE_TEST,
                                             "--exact", "--ignored", "--nocapture"]
        if workload_binaries[name]:
            binaries["perf_scenarios"] = workload_binaries[name].resolve()
            commands[name].update({case: [str(binaries["perf_scenarios"]), *arguments]
                                   for case, arguments in EXTRA_WORKLOADS.items()})
        report["variants"][name] = {
            "revision": revision,
            "binaries": {key: describe(binary) for key, binary in binaries.items()},
            "test_binary": describe(test_binary.resolve()),
            "measurements": {}, "summary": {},
        }

    # Warm each workload, then alternate A/B and B/A per round. Both versions
    # perform exactly the same fixed work and run outside Cargo compilation.
    for case in cases:
        for name in variants:
            measure(commands[name][case])
            report["variants"][name]["measurements"][case] = []
        for iteration in range(args.samples):
            order = list(variants)
            if iteration % 2:
                order.reverse()
            for name in order:
                sample = measure(commands[name][case])
                if case == "pending_reset" and set(sample["queue_us"]) != {2048, 4096, 8192, 16384}:
                    raise RuntimeError("queue benchmark did not report all four workloads")
                if case in EXTRA_WORKLOADS and sample["scenario"] is None:
                    raise RuntimeError("public-API scenario did not report elapsed_ns JSON")
                report["variants"][name]["measurements"][case].append(sample)
        for name in variants:
            samples = report["variants"][name]["measurements"][case]
            metrics = {"wall_ns": summary([sample["wall_ns"] for sample in samples])}
            if all(sample["max_rss_bytes"] is not None for sample in samples):
                metrics["max_rss_bytes"] = summary([sample["max_rss_bytes"] for sample in samples])
            if case in EXTRA_WORKLOADS:
                metrics["elapsed_ns"] = summary([sample["scenario"]["elapsed_ns"] for sample in samples])
            if case == "pending_reset":
                for count in (2048, 4096, 8192, 16384):
                    metrics[f"queue_{count}_us"] = summary([sample["queue_us"][count] for sample in samples])
            report["variants"][name]["summary"][case] = metrics
            wall = metrics["wall_ns"]
            print(f"{name} {case}: {wall['median'] / 1e6:.3f} ms median, "
                  f"{wall['min'] / 1e6:.3f}..{wall['max'] / 1e6:.3f} ms range", flush=True)

    failed = False
    inconclusive = False
    if "candidate" in variants:
        for case in cases:
            # The queue's internal timer isolates queue processing from test
            # setup and process launch. It is the performance gate for that case.
            if case == "pending_reset":
                metrics = [f"queue_{count}_us" for count in (2048, 4096, 8192, 16384)]
            else:
                metrics = ["elapsed_ns" if case in EXTRA_WORKLOADS else "wall_ns"]
            for metric in metrics:
                base = report["variants"]["baseline"]["summary"][case][metric]
                candidate = report["variants"]["candidate"]["summary"][case][metric]
                ratio = candidate["median"] / base["median"]
                noisy = max(base["relative_mad"], candidate["relative_mad"]) > args.max_relative_mad
                verdict = "inconclusive" if noisy else (
                    "regression" if ratio > 1 + args.max_regression else "pass")
                failed |= verdict == "regression"
                inconclusive |= verdict == "inconclusive"
                report["comparisons"][f"{case}.{metric}"] = {
                    "candidate_over_baseline": ratio, "verdict": verdict}
                print(f"{case}.{metric}: {ratio:.3f}x {verdict}")
    # Allocation counting is a separate compilation feature. Never use these
    # instrumented binaries for the latency acceptance gate above.
    if args.baseline_allocations_bin:
        for name in variants:
            binary = allocation_binaries[name].resolve()
            probe = {"binary": describe(binary), "samples": {}, "summary": {}}
            for case in (case for case in cases if case in EXTRA_WORKLOADS):
                command = [str(binary), *EXTRA_WORKLOADS[case]]
                samples = [measure(command) for _ in range(5)]
                if any(not sample["scenario"] or not sample["scenario"].get("allocation_probe")
                       for sample in samples):
                    raise RuntimeError("allocation probe did not report instrumented JSON")
                probe["samples"][case] = samples
                probe["summary"][case] = {
                    metric: summary([sample["scenario"][metric] for sample in samples])
                    for metric in ("allocations", "reallocations", "allocated_bytes")}
                count = probe["summary"][case]["allocations"]["median"]
                size = probe["summary"][case]["allocated_bytes"]["median"]
                print(f"{name} {case}: {count:g} allocations, {size:g} allocated bytes")
            report["allocation_probes"][name] = probe

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"raw measurements: {args.output}")
    if failed:
        raise SystemExit(1)
    if inconclusive:
        raise SystemExit(2)


if __name__ == "__main__":
    main()

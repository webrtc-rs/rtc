#!/usr/bin/env python3
"""Run, record and compare the workspace's benchmarks.

The benchmarks themselves are ordinary criterion targets in each crate's `benches/` and in
`benchmarks/rtc-bench`. This script is the part that is easy to get wrong by hand: running every
one of them with identical settings, recording what machine and toolchain produced the numbers,
and comparing two revisions *on the same machine in the same session*, which
`docs/benchmarking-crypto-migration.md` found to be the difference between a correct conclusion
and an inverted one.

Usage:

    python3 scripts/bench.py list
    python3 scripts/bench.py check [--providers all]
    python3 scripts/bench.py run [--quick] [--package P] [--bench P:T] [--filter REGEX]
    python3 scripts/bench.py compare BASE [--head REV] [--rounds N] [--overlay-benches] [...]
    python3 scripts/bench.py upstream [--branch B] [--rounds N] [--quick] [...]
    python3 scripts/bench.py report BASELINE [OTHER] [--criterion-home DIR]
    python3 scripts/bench.py external

`run` saves a named criterion baseline — by default the short commit, with `-dirty` appended for
uncommitted changes — and prints a table of it. `report A B` compares any two saved baselines.
Prefer `compare` for before/after questions: it builds BASE in a separate worktree and alternates
BASE and HEAD runs in one session, which is the only comparison this workspace trusts.

`external` builds `benchmarks/external-consumer` the way an application depending on rtc would —
from outside this repository, so without its `.cargo/config.toml` — and checks that its AES paths
run the same hardware backend as a build inside the repository.

`upstream` is `compare` against webrtc-rs/rtc: it fetches the upstream branch, overlays this
tree's benchmark sources onto it so both sides run identical benchmark code, and compares it with
this fork.

See docs/benchmarking.md for the suite this drives and how to read what it prints.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, TextIO

ROOT = Path(__file__).resolve().parent.parent

# Features a package needs for its benchmarks to cover everything they can. Applied only where the
# package defines the feature, so an older revision without it still builds.
EXTRA_FEATURES = {
    # Exposes the packet codec to `SCTP/Packet/*` through the `fuzzing` shims.
    "rtc-sctp": ["bench"],
}

# Enabled together under `--providers all`, on every package that defines both.
PROVIDER_FEATURES = ["crypto-ring", "crypto-aws-lc-rs"]

# Criterion's own defaults, spelled out so they are recorded with the results and are identical on
# both sides of a comparison even if a future criterion changes its defaults.
CRITERION_ARGS = {
    "full": ["--warm-up-time", "3", "--measurement-time", "5"],
    "quick": ["--warm-up-time", "1", "--measurement-time", "2"],
}

# Where `compare` keeps base-revision worktrees. Deliberately outside the repository: cargo merges
# `.cargo/config.toml` from every parent directory, so a worktree nested in this checkout would
# build the base revision with *this* revision's rustflags.
DEFAULT_WORKTREE_DIR = Path(
    os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")
) / "rtc-bench" / "worktrees"

META_DIR = "rtc-bench-meta"

# What `upstream` compares this fork against. The fetched branch is kept under a private ref
# rather than a remote, so fetching adds no remote or branch to the repository.
UPSTREAM_URL = "https://github.com/webrtc-rs/rtc.git"
UPSTREAM_BRANCH = "master"
UPSTREAM_REF_PREFIX = "refs/bench/upstream/"


# --------------------------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Bench:
    """One `[[bench]]` target in a workspace member."""

    package: str
    target: str
    path: Path
    required_features: tuple
    package_features: frozenset
    criterion: bool

    @property
    def key(self) -> str:
        return f"{self.package}:{self.target}"

    @property
    def kind(self) -> str:
        return "criterion" if self.criterion else "report"


def workspace_packages(root: Path) -> list:
    """`cargo metadata` for every workspace member under `root`."""
    output = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    metadata = json.loads(output)
    members = set(metadata["workspace_members"])
    return [package for package in metadata["packages"] if package["id"] in members]


def discover(root: Path) -> list:
    """Every bench target of every workspace member under `root`.

    A target is a criterion benchmark if its source invokes `criterion_main!`. Anything else —
    `rtc-interceptor`'s congestion-control report, for instance — prints its own results, takes
    no criterion arguments, and is only run when selected by name.
    """
    benches = []
    for package in workspace_packages(root):
        for target in package["targets"]:
            if "bench" not in target["kind"]:
                continue
            path = Path(target["src_path"])
            source = path.read_text(errors="replace") if path.exists() else ""
            benches.append(
                Bench(
                    package=package["name"],
                    target=target["name"],
                    path=path,
                    required_features=tuple(target.get("required-features", [])),
                    package_features=frozenset(package["features"]),
                    criterion="criterion_main!" in source,
                )
            )
    return sorted(benches, key=lambda bench: bench.key)


def select(benches: list, specs: list, packages: list, include_reports: bool = False) -> list:
    """The benches named by `--bench` specs, else every criterion bench in `packages` (or all).

    A spec is `package:target` or a bare `package`. Naming a report-style bench selects it;
    otherwise only criterion benches run, since only they produce comparable results, unless
    `include_reports` asks for everything.
    """
    if not specs:
        chosen = [bench for bench in benches if bench.criterion or include_reports]
        if packages:
            unknown = set(packages) - {bench.package for bench in benches}
            if unknown:
                raise SystemExit(f"no benchmarks in package(s): {', '.join(sorted(unknown))}")
            chosen = [bench for bench in chosen if bench.package in packages]
        return chosen

    chosen = []
    for spec in specs:
        package, _, target = spec.partition(":")
        matches = [
            bench
            for bench in benches
            if bench.package == package and (not target or bench.target == target)
        ]
        if not matches:
            raise SystemExit(
                f"no benchmark matches {spec!r}; run `scripts/bench.py list` to see them"
            )
        chosen.extend(match for match in matches if match not in chosen)
    return chosen


def package_features(benches: list, providers: str) -> dict:
    """Features to build each package's benches with, identical across its targets.

    One feature set per package, so running its targets one after another never triggers a
    rebuild between them.
    """
    features: dict = {}
    for bench in benches:
        wanted = features.setdefault(bench.package, [])
        candidates = list(EXTRA_FEATURES.get(bench.package, [])) + list(bench.required_features)
        if providers == "all" and all(f in bench.package_features for f in PROVIDER_FEATURES):
            candidates += PROVIDER_FEATURES
        for feature in candidates:
            if feature in bench.package_features and feature not in wanted:
                wanted.append(feature)
    return features


# --------------------------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------------------------


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    ).stdout.strip()


def is_dirty(root: Path) -> bool:
    return bool(git(root, "status", "--porcelain", "--untracked-files=no"))


def revision_label(root: Path) -> str:
    label = git(root, "rev-parse", "--short", "HEAD")
    return f"{label}-dirty" if is_dirty(root) else label


def cpu_model() -> str:
    try:
        if sys.platform == "darwin":
            return subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        if sys.platform.startswith("linux"):
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.lower().startswith(("model name", "hardware")):
                    return line.split(":", 1)[1].strip()
    except (OSError, subprocess.CalledProcessError):
        pass
    return platform.processor() or "unknown"


def os_description() -> str:
    if sys.platform == "darwin":
        return f"macOS {platform.mac_ver()[0]}"
    return platform.platform(terse=True)


def environment(root: Path) -> dict:
    """What produced a set of numbers. Stored with every run and printed with every report."""
    rustc = subprocess.run(
        ["rustc", "--version"], cwd=root, capture_output=True, text=True, check=False
    ).stdout.strip()
    return {
        "revision": git(root, "rev-parse", "HEAD"),
        "label": revision_label(root),
        "subject": git(root, "log", "-1", "--format=%s"),
        "dirty": is_dirty(root),
        "cpu": cpu_model(),
        "os": os_description(),
        "arch": platform.machine(),
        "rustc": rustc,
        "rustflags": os.environ.get("RUSTFLAGS"),
        "encoded_rustflags": os.environ.get("CARGO_ENCODED_RUSTFLAGS"),
        "date": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    }


def warn_about_environment() -> None:
    if os.environ.get("RUSTFLAGS") or os.environ.get("CARGO_ENCODED_RUSTFLAGS"):
        print(
            "warning: RUSTFLAGS is set. It replaces, rather than extends, the rustflags in "
            ".cargo/config.toml, and whatever it adds (target-cpu, codegen options) applies to "
            "every crate, so these numbers may not match a default build.",
            file=sys.stderr,
        )


def lock_versions(root: Path) -> dict:
    """`name -> {versions}` from `root`'s Cargo.lock, for external packages only."""
    lock = root / "Cargo.lock"
    if not lock.exists():
        return {}
    versions: dict = {}
    for block in lock.read_text().split("[[package]]")[1:]:
        name = re.search(r'^name = "([^"]+)"', block, re.M)
        version = re.search(r'^version = "([^"]+)"', block, re.M)
        if name and version and re.search(r"^source = ", block, re.M):
            versions.setdefault(name.group(1), set()).add(version.group(1))
    return versions


# --------------------------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------------------------


def stream(
    command: list, cwd: Path, env: dict, log: Optional[TextIO], check: bool = True
) -> int:
    """Runs `command`, echoing its output live and into `log`, and returns its exit code. Exits
    on failure unless `check` is false."""
    banner = f"$ (cd {cwd} && {shlex.join(command)})\n"
    sys.stdout.write(banner)
    sys.stdout.flush()
    if log:
        log.write(banner)
    with subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    ) as process:
        assert process.stdout is not None
        for line in process.stdout:
            sys.stdout.write(line)
            if log:
                log.write(line)
    if check and process.returncode != 0:
        raise SystemExit(f"command failed with exit code {process.returncode}: {banner.strip()}")
    return process.returncode


def feature_args(features: list) -> list:
    return ["--features", ",".join(features)] if features else []


def build(
    root: Path,
    benches: list,
    features: dict,
    env: dict,
    log: Optional[TextIO],
    tolerate_failures: bool = False,
) -> list:
    """Compiles every selected target before anything is measured, returning those that failed.

    Compile errors surface before a long run rather than halfway through, and compilation never
    heats the machine between two measurements. A failure exits, unless `tolerate_failures`: then
    a package that fails is retried target by target, and the targets that still fail are
    returned so the caller can leave them out. That is for a base built with overlaid benchmark
    sources, where a benchmark written against head's API may not compile against base's.
    """
    by_package: dict = {}
    for bench in benches:
        by_package.setdefault(bench.package, []).append(bench)
    failed = []
    for package, members in by_package.items():
        command = ["cargo", "bench", "--package", package, "--no-run"]
        command += feature_args(features[package])
        targets = [arg for bench in members for arg in ("--bench", bench.target)]
        if stream(command + targets, root, env, log, check=not tolerate_failures) == 0:
            continue
        if len(members) == 1:
            failed += members
            continue
        for bench in members:
            if stream(command + ["--bench", bench.target], root, env, log, check=False) != 0:
                failed.append(bench)
    return failed


def run_benches(
    root: Path,
    benches: list,
    features: dict,
    criterion_args: list,
    baseline: str,
    filter_regex: Optional[str],
    env: dict,
    log: Optional[TextIO],
    failures: Optional[list] = None,
) -> None:
    """Runs each target on its own, so criterion's arguments reach criterion and nothing else.

    `cargo bench -p P -- ARGS` also passes ARGS to the library's libtest harness, which rejects
    criterion's options and aborts the whole run; `--bench T` avoids that.

    A target that fails exits, unless `failures` is given: then it is recorded there and the
    remaining targets still run. A comparison runs for an hour or more, and one benchmark process
    killed from outside should cost that benchmark's round, not every result gathered so far.
    """
    for bench in benches:
        command = ["cargo", "bench", "--package", bench.package, "--bench", bench.target]
        command += feature_args(features[bench.package])
        command.append("--")
        if bench.criterion:
            command += criterion_args + ["--save-baseline", baseline]
            if filter_regex:
                command.append(filter_regex)
        code = stream(command, root, env, log, check=failures is None)
        if code != 0 and failures is not None:
            print(f"\nwarning: {bench.key} failed (exit code {code}); continuing\n")
            failures.append((bench.key, code))


def criterion_args_from(args: argparse.Namespace) -> list:
    criterion = list(CRITERION_ARGS["quick" if args.quick else "full"])
    if not args.plots:
        criterion.append("--noplot")
    return criterion + list(args.criterion_arg or [])


def bench_env(criterion_home: Path) -> dict:
    env = dict(os.environ)
    env["CRITERION_HOME"] = str(criterion_home)
    return env


def write_meta(criterion_home: Path, baseline: str, meta: dict) -> None:
    directory = criterion_home / META_DIR
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{baseline}.json").write_text(json.dumps(meta, indent=2) + "\n")


def read_meta(criterion_home: Path, baseline: str) -> Optional[dict]:
    path = criterion_home / META_DIR / f"{baseline}.json"
    return json.loads(path.read_text()) if path.exists() else None


# --------------------------------------------------------------------------------------------
# Benchmark overlay
# --------------------------------------------------------------------------------------------
#
# A revision that predates part of the suite — upstream webrtc-rs/rtc, an old release — has only
# some of these benchmarks, so a plain comparison against it measures only those. The overlay
# copies head's benchmark sources into base's worktree and adds the manifest entries they need, so
# both sides compile the same benchmark code and the one thing that differs is the library under
# it. Manifests are read with `tomllib` but edited as text, so everything else in them is left
# exactly as base has it.

TABLE_HEADER = re.compile(r"^\[(\[?)\s*([^\]]+?)\s*\]\]?\s*(#.*)?$")
ENTRY_KEY = re.compile(r'^\s*"?([A-Za-z0-9_-]+)"?\s*[.=]')
STRING_OR_COMMENT = re.compile(r'"(?:\\.|[^"\\])*"|\'[^\']*\'|#.*')


def split_tables(text: str) -> list:
    """A manifest as `[header, body]` pairs in order, where `header` is a table's header line
    (`""` for the keys before the first header) and `body` its lines, newlines kept. Joining
    every header and body gives back the text exactly."""
    tables: list = [["", []]]
    for line in text.splitlines(keepends=True):
        if TABLE_HEADER.match(line):
            tables.append([line, []])
        else:
            tables[-1][1].append(line)
    return tables


def join_tables(tables: list) -> str:
    return "".join(header + "".join(body) for header, body in tables)


def table_name(header: str) -> tuple:
    """`("array", "bench")` for `[[bench]]`, `("table", "features")` for `[features]`."""
    match = TABLE_HEADER.match(header)
    if not match:
        return ("table", "")
    return ("array" if match.group(1) else "table", match.group(2))


def table_entries(body: list) -> list:
    """`(key, start, end)` for each entry in a table body: the lines `body[start:end]`, with
    multi-line arrays and inline tables kept together. `key` is a dotted key's first segment, so
    `criterion.workspace = true` is an entry for `criterion`."""
    entries: list = []
    depth = 0
    for index, line in enumerate(body):
        if depth > 0 and entries:
            entries[-1][2] = index + 1
        else:
            match = ENTRY_KEY.match(line)
            if not match:
                continue
            entries.append([match.group(1), index, index + 1])
        code = STRING_OR_COMMENT.sub("", line)
        opened = code.count("[") + code.count("{")
        closed = code.count("]") + code.count("}")
        depth = max(0, depth + opened - closed)
    return [tuple(entry) for entry in entries]


def entry_text(tables: list, section: str, key: str) -> Optional[str]:
    """The text of every entry for `key` in table `[section]`, or `None`."""
    for header, body in tables:
        if table_name(header) == ("table", section):
            text = "".join(
                "".join(body[start:end]) for name, start, end in table_entries(body) if name == key
            )
            return text or None
    return None


def insert_entry(tables: list, section: str, text: str) -> None:
    """Adds `text` at the end of table `[section]`, creating the table if there is none."""
    for header, body in tables:
        if table_name(header) == ("table", section):
            last = max((i for i, line in enumerate(body) if line.strip()), default=-1)
            body.insert(last + 1, text)
            return
    append_table(tables, f"[{section}]\n", [text])


def append_table(tables: list, header: str, body: list) -> None:
    """Adds a table at the end, separated from what precedes it by a blank line."""
    body = list(body)
    while body and not body[-1].strip():
        body.pop()
    if body and not body[-1].endswith("\n"):
        body[-1] += "\n"
    previous_body = tables[-1][1]
    if previous_body and not previous_body[-1].endswith("\n"):
        previous_body[-1] += "\n"
    tables.append(["\n" + header, body])


def workspace_dependencies(manifest: dict, tables: tuple) -> set:
    """Names that `manifest` takes from `[workspace.dependencies]` in the given tables."""
    return {
        name
        for table in tables
        for name, spec in manifest.get(table, {}).items()
        if isinstance(spec, dict) and spec.get("workspace")
    }


def merge_manifest(head_manifest: Path, base_manifest: Path, features: list) -> tuple:
    """Adds to `base_manifest` the `[[bench]]` targets and dev-dependencies that `head_manifest`
    has and it lacks, and any of `features` that it does not define.

    Returns what was added, for the report, and the names of the added dev-dependencies that come
    from `[workspace.dependencies]`, which base's root manifest must then define too.
    """
    head_text, base_text = head_manifest.read_text(), base_manifest.read_text()
    head, base = tomllib.loads(head_text), tomllib.loads(base_text)
    head_tables, tables = split_tables(head_text), split_tables(base_text)
    added = []

    base_benches = {bench.get("name") for bench in base.get("bench", [])}
    for header, body in head_tables:
        if table_name(header) == ("array", "bench"):
            name = tomllib.loads("".join(body)).get("name")
            if name not in base_benches:
                append_table(tables, header, body)
                added.append(f"`[[bench]] {name}`")

    dev_dependencies = sorted(
        set(head.get("dev-dependencies", {})) - set(base.get("dev-dependencies", {}))
    )
    missing_features = [
        feature
        for feature in features
        if feature in head.get("features", {}) and feature not in base.get("features", {})
    ]
    for section, keys in (("dev-dependencies", dev_dependencies), ("features", missing_features)):
        for key in keys:
            text = entry_text(head_tables, section, key)
            if text:
                insert_entry(tables, section, text)
                added.append(f"`{section}.{key}`")

    if added:
        base_manifest.write_text(join_tables(tables))
    needs = workspace_dependencies(
        {"dev-dependencies": {k: head["dev-dependencies"][k] for k in dev_dependencies}},
        ("dev-dependencies",),
    )
    return added, needs


def merge_workspace(
    head_manifest: Path, base_manifest: Path, members: list, dependencies: set
) -> list:
    """Adds `members` to base's workspace, and every name in `dependencies` that base's
    `[workspace.dependencies]` lacks, taking each entry's text from head's root manifest."""
    head_text, base_text = head_manifest.read_text(), base_manifest.read_text()
    base = tomllib.loads(base_text)
    head_tables, tables = split_tables(head_text), split_tables(base_text)
    added = []

    new_members = [m for m in members if m not in base.get("workspace", {}).get("members", [])]
    if new_members:
        for header, body in tables:
            if table_name(header) != ("table", "workspace"):
                continue
            for name, start, end in table_entries(body):
                if name != "members":
                    continue
                text = "".join(body[start:end])
                close = text.rfind("]")
                before = text[:close].rstrip()
                separator = "" if before.endswith(("[", ",")) else ","
                listed = "".join(f'\n    "{member}",' for member in new_members)
                body[start:end] = [before + separator + listed + "\n" + text[close:]]
                added += [f"workspace member `{member}`" for member in new_members]
                break

    have = set(base.get("workspace", {}).get("dependencies", {}))
    for name in sorted(dependencies - have):
        text = entry_text(head_tables, "workspace.dependencies", name)
        if text:
            insert_entry(tables, "workspace.dependencies", text)
            added.append(f"`workspace.dependencies.{name}`")

    if added:
        base_manifest.write_text(join_tables(tables))
    return added


def copy_changed(source: Path, destination: Path) -> int:
    """Copies the files under `source` that are missing or different under `destination`,
    skipping build output, and returns how many were copied."""
    copied = 0
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if not path.is_file() or "target" in relative.parts:
            continue
        target = destination / relative
        if target.exists() and target.read_bytes() == path.read_bytes():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        copied += 1
    return copied


def overlay_benchmarks(head_root: Path, base_root: Path) -> list:
    """Makes `base_root` build and run head's benchmarks, returning notes for the report.

    For every head package with bench targets: a package base does not have at all — the
    benchmark-only `benchmarks/rtc-bench` — is copied whole and added to base's workspace;
    otherwise the directories holding its bench sources are copied over base's, and base's
    manifest gains the bench targets, dev-dependencies and bench features it lacks.
    """
    base_packages = {package["name"]: package for package in workspace_packages(base_root)}
    copied: list = []
    manifest_changes: list = []
    new_members: list = []
    dependencies: set = set()

    for package in workspace_packages(head_root):
        targets = [target for target in package["targets"] if "bench" in target["kind"]]
        if not targets:
            continue
        head_dir = Path(package["manifest_path"]).parent
        relative = head_dir.relative_to(head_root)

        if package["name"] not in base_packages:
            if copy_changed(head_dir, base_root / relative):
                copied.append(f"`{relative.as_posix()}/`")
            new_members.append(relative.as_posix())
            head_manifest = tomllib.loads((head_dir / "Cargo.toml").read_text())
            dependencies |= workspace_dependencies(
                head_manifest, ("dependencies", "dev-dependencies", "build-dependencies")
            )
            continue

        base_dir = Path(base_packages[package["name"]]["manifest_path"]).parent
        for source_dir in sorted({Path(target["src_path"]).parent for target in targets}):
            if source_dir == head_dir or not source_dir.is_relative_to(head_dir):
                continue
            destination = base_dir / source_dir.relative_to(head_dir)
            if copy_changed(source_dir, destination):
                copied.append(f"`{source_dir.relative_to(head_root).as_posix()}/`")

        features = list(EXTRA_FEATURES.get(package["name"], []))
        features += [f for target in targets for f in target.get("required-features", [])]
        added, needs = merge_manifest(
            head_dir / "Cargo.toml", base_dir / "Cargo.toml", features
        )
        dependencies |= needs
        if added:
            manifest_changes.append(f"{package['name']}: {', '.join(added)}")

    added = merge_workspace(
        head_root / "Cargo.toml", base_root / "Cargo.toml", new_members, dependencies
    )
    if added:
        manifest_changes.append(f"workspace: {', '.join(added)}")

    notes = [
        "Base ran head's benchmark sources, overlaid onto it, so both sides run identical "
        "benchmark code: " + (", ".join(copied) if copied else "no source differed") + "."
    ]
    if manifest_changes:
        notes.append("Added to base's manifests for them: " + "; ".join(manifest_changes) + ".")
    return notes


# --------------------------------------------------------------------------------------------
# Reading criterion's output
# --------------------------------------------------------------------------------------------


@dataclass
class Estimate:
    """One benchmark's headline time from one saved baseline, in nanoseconds."""

    point: float
    low: float
    high: float
    throughput: Optional[dict]


def load_baseline(criterion_home: Path, name: str) -> dict:
    """`full_id -> [Estimate]` for baseline `name`, or its rounds `name-1`, `name-2`, ….

    The headline is the one criterion prints: the slope of the linear regression when the
    benchmark used linear sampling, otherwise the mean. Both come with criterion's 95% confidence
    interval.
    """
    pattern = re.compile(rf"^{re.escape(name)}(?:-\d+)?$")
    results: dict = {}
    for benchmark_file in sorted(criterion_home.rglob("benchmark.json")):
        directory = benchmark_file.parent
        estimates_file = directory / "estimates.json"
        if not pattern.match(directory.name) or not estimates_file.exists():
            continue
        benchmark = json.loads(benchmark_file.read_text())
        estimates = json.loads(estimates_file.read_text())
        headline = estimates.get("slope") or estimates["mean"]
        interval = headline["confidence_interval"]
        results.setdefault(benchmark["full_id"], []).append(
            Estimate(
                point=headline["point_estimate"],
                low=interval["lower_bound"],
                high=interval["upper_bound"],
                throughput=benchmark.get("throughput"),
            )
        )
    return results


def summarize(samples: list) -> tuple:
    """`(point, low, high)` across rounds.

    One round: criterion's estimate and confidence interval. Several: the median of the rounds'
    estimates, with the spread between the fastest and slowest round as the range — run-to-run
    variation is the noise that matters for a before/after question, and a single run's
    confidence interval understates it.
    """
    if len(samples) == 1:
        sample = samples[0]
        return sample.point, sample.low, sample.high
    points = [sample.point for sample in samples]
    return statistics.median(points), min(points), max(points)


def natural(full_id: str) -> list:
    """Sort key that orders `in-order/64` before `in-order/1024`."""
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", full_id)]


def format_time(nanoseconds: float) -> str:
    for unit, scale in (("s", 1e9), ("ms", 1e6), ("µs", 1e3)):
        if nanoseconds >= scale:
            return f"{nanoseconds / scale:.4g} {unit}"
    return f"{nanoseconds:.4g} ns"


def format_throughput(throughput: Optional[dict], nanoseconds: float) -> str:
    if not throughput or nanoseconds <= 0:
        return ""
    kind, amount = next(iter(throughput.items()))
    if isinstance(amount, dict):
        # `ElementsAndBytes { elements, bytes }`: report the elements.
        kind, amount = "Elements", amount.get("elements", 0)
    per_second = amount / (nanoseconds * 1e-9)
    if kind in ("Bytes", "BytesDecimal"):
        base, units = (1000, ["B/s", "kB/s", "MB/s", "GB/s"]) if kind == "BytesDecimal" else (
            1024,
            ["B/s", "KiB/s", "MiB/s", "GiB/s"],
        )
    elif kind == "Bits":
        base, units = 1000, ["b/s", "Kb/s", "Mb/s", "Gb/s"]
    else:
        base, units = 1000, ["elem/s", "Kelem/s", "Melem/s", "Gelem/s"]
    unit = 0
    while per_second >= base and unit < len(units) - 1:
        per_second /= base
        unit += 1
    return f"{per_second:.4g} {units[unit]}"


# --------------------------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------------------------


def describe_environment(meta: Optional[dict]) -> list:
    if not meta:
        return ["| Environment | not recorded (baseline was not saved by this script) |"]
    rustflags = meta.get("rustflags") or meta.get("encoded_rustflags")
    return [
        f"| Machine | {meta['cpu']}, {meta['os']} ({meta['arch']}) |",
        f"| Toolchain | `{meta['rustc']}` |",
        "| RUSTFLAGS | "
        + (f"`{rustflags}` (replaces .cargo/config.toml rustflags)" if rustflags else "unset")
        + " |",
        f"| Criterion | `{' '.join(meta.get('criterion_args', []))}` |",
        f"| Date | {meta['date']} |",
    ]


def describe_revision(meta: Optional[dict], fallback: str) -> str:
    if not meta:
        return f"`{fallback}`"
    title = f"{meta['title']}: " if meta.get("title") else ""
    suffix = " + uncommitted changes" if meta.get("dirty") else ""
    return f"{title}`{meta['revision'][:10]}` {meta['subject']}{suffix}"


def summary_report(criterion_home: Path, baseline: str) -> str:
    results = load_baseline(criterion_home, baseline)
    if not results:
        raise SystemExit(f"no results for baseline {baseline!r} under {criterion_home}")
    meta = read_meta(criterion_home, baseline)
    lines = [
        f"## Benchmarks: {baseline}",
        "",
        "| | |",
        "|---|---|",
        f"| Revision | {describe_revision(meta, baseline)} |",
        *describe_environment(meta),
        "",
        "| Benchmark | Time | Range | Throughput |",
        "|---|---:|---:|---:|",
    ]
    for full_id in sorted(results, key=natural):
        point, low, high = summarize(results[full_id])
        throughput = format_throughput(results[full_id][0].throughput, point)
        lines.append(
            f"| `{full_id}` | {format_time(point)} | "
            f"{format_time(low)} – {format_time(high)} | {throughput} |"
        )
    return "\n".join(lines) + "\n"


def comparison_report(
    criterion_home: Path,
    base: str,
    head: str,
    threshold: float,
    base_meta: Optional[dict],
    head_meta: Optional[dict],
    notes: list,
) -> str:
    base_results = load_baseline(criterion_home, base)
    head_results = load_baseline(criterion_home, head)
    if not base_results and not head_results:
        raise SystemExit(f"no results for {base!r} or {head!r} under {criterion_home}")

    rounds = max((len(samples) for samples in base_results.values()), default=1)
    rows = []
    counts = {"slower": 0, "faster": 0, "~": 0}
    for full_id in sorted(set(base_results) & set(head_results), key=natural):
        base_point, base_low, base_high = summarize(base_results[full_id])
        head_point, head_low, head_high = summarize(head_results[full_id])
        change = (head_point - base_point) / base_point * 100
        overlap = head_low <= base_high and base_low <= head_high
        if overlap or abs(change) < threshold:
            verdict = "~"
        else:
            verdict = "slower" if change > 0 else "faster"
        counts[verdict] += 1
        rows.append(
            f"| `{full_id}` | {format_time(base_point)} | {format_time(head_point)} | "
            f"{change:+.1f}% | {verdict} |"
        )

    titles = [
        (meta or {}).get("title", "").split(" (")[0] or name
        for meta, name in ((base_meta, base), (head_meta, head))
    ]
    lines = [
        f"## Benchmark comparison: {titles[0]} → {titles[1]}",
        "",
        "| | |",
        "|---|---|",
        f"| Base | {describe_revision(base_meta, base)} |",
        f"| Head | {describe_revision(head_meta, head)} |",
        *describe_environment(head_meta or base_meta),
        f"| Rounds | {rounds}" + (", base and head alternating |" if rounds > 1 else " |"),
        *(f"| Note | {note} |" for note in notes),
        "",
        f"**{counts['slower']} slower, {counts['faster']} faster, {counts['~']} within noise.** "
        + (
            "Ranges are the fastest and slowest round."
            if rounds > 1
            else "Ranges are criterion's 95% confidence interval."
        )
        + f" `~` means the ranges overlap or the change is under {threshold:g}%.",
        "",
        "| Benchmark | Base | Head | Change | |",
        "|---|---:|---:|---:|---|",
        *rows,
    ]
    only_base = sorted(set(base_results) - set(head_results), key=natural)
    only_head = sorted(set(head_results) - set(base_results), key=natural)
    if only_base:
        lines += ["", f"Only in base ({len(only_base)}): " + ", ".join(f"`{i}`" for i in only_base)]
    if only_head:
        lines += ["", f"Only in head ({len(only_head)}): " + ", ".join(f"`{i}`" for i in only_head)]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------------


def command_list(args: argparse.Namespace) -> None:
    benches = discover(ROOT)
    width = max(len(bench.key) for bench in benches)
    for bench in benches:
        extra = EXTRA_FEATURES.get(bench.package, [])
        notes = []
        if extra:
            notes.append(f"built with --features {','.join(extra)}")
        if not bench.criterion:
            notes.append("run only when named")
        relative = bench.path.relative_to(ROOT) if bench.path.is_relative_to(ROOT) else bench.path
        print(f"{bench.key:<{width}}  {bench.kind:<9}  {relative}  {'; '.join(notes)}".rstrip())


def command_run(args: argparse.Namespace) -> None:
    warn_about_environment()
    benches = select(discover(ROOT), args.bench, args.package)
    features = package_features(benches, args.providers)
    criterion_home = Path(args.criterion_home).resolve()
    baseline = args.save_baseline or revision_label(ROOT)
    criterion = criterion_args_from(args)
    env = bench_env(criterion_home)

    criterion_home.mkdir(parents=True, exist_ok=True)
    log_path = criterion_home / META_DIR / f"{baseline}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w") as log:
        build(ROOT, benches, features, env, log)
        run_benches(ROOT, benches, features, criterion, baseline, args.filter, env, log)

    meta = environment(ROOT)
    meta.update(
        criterion_args=criterion,
        benches=[bench.key for bench in benches],
        features=features,
        filter=args.filter,
    )
    write_meta(criterion_home, baseline, meta)

    if any(bench.criterion for bench in benches):
        print()
        print(summary_report(criterion_home, baseline))
    print(f"Saved as baseline {baseline!r} under {criterion_home}.")


def command_check(args: argparse.Namespace) -> None:
    """Builds every selected benchmark and runs each exactly once. What CI runs.

    Criterion targets get `--test`: one iteration per benchmark, nothing timed, nothing saved. That
    is enough to catch a benchmark that no longer builds, panics, or whose harness stalls, which
    is otherwise only discovered by whoever next tries to measure something. Report-style targets
    run as they are.
    """
    benches = select(discover(ROOT), args.bench, args.package, include_reports=True)
    features = package_features(benches, args.providers)
    env = dict(os.environ)
    build(ROOT, benches, features, env, None)
    for bench in benches:
        command = ["cargo", "bench", "--package", bench.package, "--bench", bench.target]
        command += feature_args(features[bench.package])
        if bench.criterion:
            command += ["--", "--test"]
        stream(command, ROOT, env, None)
    print(f"\nAll {len(benches)} benchmark targets built and ran once.")


def prepare_worktree(revision: str, worktree_dir: Path, overlay: bool = False) -> Path:
    """A detached worktree at `revision`, reused across comparisons against the same revision so
    its `target/` stays warm.

    An `overlay` worktree is kept apart from the plain one and restored to `revision` each time —
    tracked files reset, untracked ones removed, ignored ones such as `target/` kept — so a
    previous overlay never leaks into this one, and never into a plain comparison.
    """
    sha = git(ROOT, "rev-parse", "--verify", f"{revision}^{{commit}}")
    path = worktree_dir / f"{ROOT.name}-{sha[:12]}{'-overlay' if overlay else ''}"
    git(ROOT, "worktree", "prune")
    if path.exists():
        if git(path, "rev-parse", "HEAD") != sha:
            raise SystemExit(f"{path} exists but is not at {sha}; remove it and retry")
        if overlay:
            git(path, "reset", "--hard", "--quiet")
            git(path, "clean", "-d", "--force", "--quiet")
        print(f"Reusing worktree {path}")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        git(ROOT, "worktree", "add", "--detach", str(path), sha)
        print(f"Created worktree {path} at {sha[:12]}")
    return path


def seed_lockfile(source: Path, destination: Path) -> Optional[str]:
    """Copies `source`'s Cargo.lock into `destination` when the lockfile is not tracked.

    This repository ignores Cargo.lock, so a fresh worktree would resolve every dependency anew —
    possibly to newer releases of `ring` or `aws-lc-rs` than the tree it is compared with, which
    would be measured as a change in `rtc`. Seeding pins shared dependencies to the same versions;
    cargo still adjusts entries for workspace members that differ.
    """
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "Cargo.lock"],
        cwd=destination,
        capture_output=True,
        check=False,
    ).returncode == 0
    if tracked or not (source / "Cargo.lock").exists():
        return None
    shutil.copyfile(source / "Cargo.lock", destination / "Cargo.lock")
    return "Base built with head's Cargo.lock (untracked here), so shared dependencies match."


def dependency_drift(base_root: Path, head_root: Path) -> list:
    base, head = lock_versions(base_root), lock_versions(head_root)
    drift = []
    for name in sorted(set(base) & set(head)):
        if base[name] != head[name]:
            drift.append(
                f"{name} {'/'.join(sorted(base[name]))} → {'/'.join(sorted(head[name]))}"
            )
    return drift


def command_compare(args: argparse.Namespace) -> None:
    compare_revisions(args, args.base, overlay=args.overlay_benches)


def repository_name(url: str) -> str:
    """`owner/repo` for an HTTPS or SSH remote URL, such as
    `https://github.com/webrtc-rs/rtc.git` or `git@github.com:webrtc-rs/rtc.git`."""
    path = re.sub(r"\.git$", "", url.rstrip("/"))
    return "/".join(re.split(r"[/:]", path)[-2:])


def fetch_upstream(url: str, branch: str, fetch: bool) -> str:
    """Fetches `branch` from `url` into a private ref and returns that ref."""
    ref = UPSTREAM_REF_PREFIX + branch
    if fetch:
        print(f"Fetching {branch} from {url}")
        subprocess.run(
            ["git", "fetch", "--no-tags", "--quiet", url, f"+refs/heads/{branch}:{ref}"],
            cwd=ROOT,
            check=True,
        )
    elif subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", ref], cwd=ROOT, capture_output=True
    ).returncode != 0:
        raise SystemExit(f"{ref} has not been fetched yet; run without --no-fetch")
    return ref


def command_upstream(args: argparse.Namespace) -> None:
    ref = fetch_upstream(args.url, args.branch, fetch=not args.no_fetch)
    try:
        origin = repository_name(git(ROOT, "remote", "get-url", "origin"))
    except subprocess.CalledProcessError:
        origin = "this repository"
    compare_revisions(
        args,
        ref,
        overlay=True,
        titles=(
            f"upstream ({repository_name(args.url)} {args.branch})",
            f"fork ({origin}{'' if args.head else ', working tree'})",
        ),
        results_prefix="upstream-",
    )


def compare_revisions(
    args: argparse.Namespace,
    base_revision: str,
    overlay: bool,
    titles: tuple = (None, None),
    results_prefix: str = "",
) -> None:
    """Builds `base_revision` in a worktree and compares it with head — `args.head`, or the
    working tree — alternating the two for `args.rounds` rounds.

    With `overlay`, base first gets head's benchmark sources (see `overlay_benchmarks`), and a
    benchmark that does not compile against base's API is left out of base rather than failing
    the comparison.
    """
    warn_about_environment()
    worktree_dir = Path(args.worktree_dir).expanduser().resolve()
    base_root = prepare_worktree(base_revision, worktree_dir, overlay=overlay)
    head_root = prepare_worktree(args.head, worktree_dir) if args.head else ROOT
    notes = [note for note in [seed_lockfile(head_root, base_root)] if note]
    if overlay:
        notes += overlay_benchmarks(head_root, base_root)

    base_label = git(base_root, "rev-parse", "--short", "HEAD")
    head_label = revision_label(head_root)
    criterion_home = (
        Path(args.criterion_home).resolve()
        if args.criterion_home
        else ROOT / "target" / "bench-compare" / f"{results_prefix}{base_label}-vs-{head_label}"
    )
    if criterion_home.exists():
        shutil.rmtree(criterion_home)
    criterion_home.mkdir(parents=True)
    env = bench_env(criterion_home)
    criterion = criterion_args_from(args)

    # The selection is defined against head; base runs whatever part of it exists there, so a
    # benchmark added since base shows up as "only in head" rather than failing the comparison.
    head_chosen = select(discover(head_root), args.bench, args.package)
    wanted = {bench.key for bench in head_chosen}
    base_chosen = [bench for bench in discover(base_root) if bench.key in wanted]
    missing = wanted - {bench.key for bench in base_chosen}
    if missing:
        notes.append(f"Not present at base: {', '.join(f'`{key}`' for key in sorted(missing))}")
    sides = {
        name: (root, chosen, package_features(chosen, args.providers))
        for name, root, chosen in (
            ("base", base_root, base_chosen),
            ("head", head_root, head_chosen),
        )
    }

    with (criterion_home / "compare.log").open("w") as log:
        # Build both sides before measuring either.
        for name, (root, chosen, features) in list(sides.items()):
            tolerate = overlay and name == "base"
            failed = build(root, chosen, features, env, log, tolerate_failures=tolerate)
            if failed:
                keys = ", ".join(f"`{bench.key}`" for bench in failed)
                print(f"\nwarning: {keys} did not build at base; comparing the rest\n")
                notes.append(f"Did not build at base, so measured at head only: {keys}")
                chosen = [bench for bench in chosen if bench not in failed]
                sides[name] = (root, chosen, features)

        drift = dependency_drift(base_root, head_root)
        if drift:
            notes.append(
                f"{len(drift)} dependencies resolved differently: " + "; ".join(drift[:8])
                + ("; …" if len(drift) > 8 else "")
            )

        for round_index in range(1, args.rounds + 1):
            for name, (root, chosen, features) in sides.items():
                print(f"\n=== round {round_index}/{args.rounds}: {name} ({root}) ===\n")
                failures: list = []
                run_benches(
                    root,
                    chosen,
                    features,
                    criterion,
                    f"{name}-{round_index}",
                    args.filter,
                    env,
                    log,
                    failures,
                )
                for key, code in failures:
                    notes.append(
                        f"`{key}` failed at {name} in round {round_index} (exit code {code}); "
                        "its rows cover the rounds, and the benchmarks within that round, that "
                        "completed"
                    )

    metas = {}
    for (name, (root, chosen, features)), title in zip(sides.items(), titles):
        meta = environment(root)
        meta.update(criterion_args=criterion, benches=[b.key for b in chosen], features=features)
        if title:
            meta["title"] = title
        if overlay and name == "base":
            # The overlay's edits are not changes to the revision being measured.
            meta["dirty"] = False
        write_meta(criterion_home, name, meta)
        metas[name] = meta

    report = comparison_report(
        criterion_home, "base", "head", args.threshold, metas["base"], metas["head"], notes
    )
    (criterion_home / "report.md").write_text(report)
    print()
    print(report)
    print(f"Report saved to {criterion_home / 'report.md'}")


def command_report(args: argparse.Namespace) -> None:
    criterion_home = Path(args.criterion_home).resolve()
    if args.other is None:
        print(summary_report(criterion_home, args.baseline))
        return
    print(
        comparison_report(
            criterion_home,
            args.baseline,
            args.other,
            args.threshold,
            read_meta(criterion_home, args.baseline),
            read_meta(criterion_home, args.other),
            [],
        )
    )


# --------------------------------------------------------------------------------------------
# External consumer
# --------------------------------------------------------------------------------------------

EXTERNAL_CONSUMER = ROOT / "benchmarks" / "external-consumer"

# How much slower than the in-repository build a consumer build may time before it is reported as
# not getting the same backend. The software backend measured ~14x slower on Apple M1; noise between
# two hardware-backend runs is a few percent.
EXTERNAL_TOLERANCE = 1.5


def without_rustflags(env: dict) -> dict:
    """`env` minus every variable that would replace the rustflags a build otherwise gets."""
    return {
        key: value
        for key, value in env.items()
        if key not in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS")
        and not (key.startswith("CARGO_TARGET_") and key.endswith("_RUSTFLAGS"))
    }


def run_consumer(label: str, cwd: Path, env: dict, target_dir: Path) -> dict:
    """Builds and runs the consumer from `cwd`, returning `case -> ns` plus its `cfg` lines."""
    command = [
        "cargo",
        "run",
        "--release",
        "--quiet",
        "--manifest-path",
        str(EXTERNAL_CONSUMER / "Cargo.toml"),
    ]
    print(f"\n== {label} ==")
    print(f"$ (cd {cwd} && {shlex.join(command)})")
    output = subprocess.run(
        command,
        cwd=cwd,
        env={**env, "CARGO_TARGET_DIR": str(target_dir)},
        capture_output=True,
        text=True,
        check=False,
    )
    if output.returncode != 0:
        sys.stderr.write(output.stderr)
        raise SystemExit(f"{label}: the consumer build failed")
    sys.stdout.write(output.stdout)
    results: dict = {"times": {}, "info": {}}
    for line in output.stdout.splitlines():
        name, _, value = line.rpartition(": ")
        if value.endswith(" ns"):
            results["times"][name] = float(value[:-3])
        elif name:
            results["info"][name] = value
    return results


def command_external(args: argparse.Namespace) -> None:
    """Times rtc's RustCrypto AES paths as built by a project that depends on rtc.

    Cargo reads `.cargo/config.toml` from the directory it runs in and that directory's ancestors,
    never from a dependency's, so an application does not get this repository's rustflags. Any
    acceleration that depended on them would silently be missing there. Three builds of the same
    consumer crate answer whether any does:

    * consumer — run from outside the repository with no rustflags from any source: an empty
      `CARGO_ENCODED_RUSTFLAGS` overrides the environment and every config file, including a
      user-wide `~/.cargo/config.toml`, whose `target-cpu=native` could otherwise supply target
      features an application's build would not have;
    * repository — run from the repository root, so its `.cargo/config.toml` applies;
    * software — the consumer build with `--cfg aes_backend="soft"`, forcing RustCrypto's
      constant-time software AES: what a build without hardware AES looks like.
    """
    cache = Path(args.cache_dir)
    outside = cache / "cwd"
    outside.mkdir(parents=True, exist_ok=True)
    if ROOT in outside.resolve().parents or outside.resolve() == ROOT:
        raise SystemExit(f"--cache-dir must be outside {ROOT}: cargo would read its config")
    # Pin shared dependencies to this tree's versions; the consumer is its own workspace.
    if (ROOT / "Cargo.lock").exists():
        shutil.copyfile(ROOT / "Cargo.lock", EXTERNAL_CONSUMER / "Cargo.lock")

    clean = without_rustflags(dict(os.environ))
    runs = {
        "consumer": run_consumer(
            "consumer build (outside the repository, no rustflags)",
            outside,
            {**clean, "CARGO_ENCODED_RUSTFLAGS": ""},
            cache / "target-consumer",
        ),
        "repository": run_consumer(
            "repository build (its .cargo/config.toml applies)",
            ROOT,
            clean,
            cache / "target-repository",
        ),
        "software": run_consumer(
            "software AES reference",
            outside,
            {**clean, "RUSTFLAGS": '--cfg aes_backend="soft"'},
            cache / "target-software",
        ),
    }

    cases = list(runs["consumer"]["times"])
    print(f"\n{'case':<30} {'consumer':>10} {'repository':>11} {'software':>10}  consumer/repository")
    slower = []
    for case in cases:
        consumer, repository, software = (runs[name]["times"].get(case, float("nan")) for name in runs)
        ratio = consumer / repository
        print(f"{case:<30} {consumer:>8.1f}ns {repository:>9.1f}ns {software:>8.1f}ns  {ratio:.2f}x")
        # The control (AES-GCM on ring/aws-lc-rs) is unaffected by any AES cfg by design.
        if "control" not in case and ratio > EXTERNAL_TOLERANCE:
            slower.append(case)
    if slower:
        raise SystemExit(
            f"\nA consumer build is more than {EXTERNAL_TOLERANCE}x slower than the repository "
            f"build for: {', '.join(slower)}. Its AES backend likely depends on the repository's "
            "rustflags, which applications do not inherit."
        )
    print(
        f"\nConsumer builds get the repository build's AES backend (within {EXTERNAL_TOLERANCE}x "
        "on every RustCrypto path). No consumer-side configuration is required."
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("list", help="list every benchmark target in the workspace")

    def targets(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--package", "-p", action="append", default=[], help="only this package's benches"
        )
        sub.add_argument(
            "--bench",
            action="append",
            default=[],
            metavar="PACKAGE[:TARGET]",
            help="only this target; may repeat. Selects report-style targets too",
        )
        sub.add_argument(
            "--providers",
            choices=["default", "all"],
            default="default",
            help="`all` enables both crypto backends where a package supports both",
        )

    def selection(sub: argparse.ArgumentParser) -> None:
        targets(sub)
        sub.add_argument(
            "--filter", help="criterion filter: a regex matched against benchmark ids"
        )
        sub.add_argument(
            "--quick",
            action="store_true",
            help="1 s warm-up, 2 s measurement: for spotting gross changes, not for quoting",
        )
        sub.add_argument("--plots", action="store_true", help="let criterion draw its plots")
        sub.add_argument(
            "--criterion-arg",
            action="append",
            metavar="ARG",
            help="extra argument passed to every criterion bench; may repeat",
        )

    check = commands.add_parser(
        "check", help="build every benchmark and run each once, untimed (what CI runs)"
    )
    targets(check)

    run = commands.add_parser("run", help="run benchmarks and save a named baseline")
    selection(run)
    run.add_argument(
        "--save-baseline",
        metavar="NAME",
        help="baseline name (default: short commit, with -dirty for uncommitted changes)",
    )
    run.add_argument(
        "--criterion-home",
        default=str(ROOT / "target" / "criterion"),
        help="where criterion writes results (default: target/criterion)",
    )

    def comparison(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--head", help="a revision to use instead of the current working tree"
        )
        selection(sub)
        sub.add_argument(
            "--rounds",
            type=int,
            default=1,
            help="alternate base and head this many times; 3 is advisable for quoting",
        )
        sub.add_argument(
            "--threshold",
            type=float,
            default=3.0,
            metavar="PERCENT",
            help="changes smaller than this are reported as noise (default: 3)",
        )
        sub.add_argument(
            "--worktree-dir",
            default=str(DEFAULT_WORKTREE_DIR),
            help=f"where base worktrees live (default: {DEFAULT_WORKTREE_DIR})",
        )
        sub.add_argument(
            "--criterion-home",
            help="results directory (default: under target/bench-compare/, emptied first)",
        )

    compare = commands.add_parser(
        "compare", help="build BASE in a worktree and compare it with HEAD on this machine"
    )
    compare.add_argument("base", help="the revision to compare against")
    comparison(compare)
    compare.add_argument(
        "--overlay-benches",
        action="store_true",
        help="run head's benchmark sources at base too, for a base that predates part of the suite",
    )

    upstream = commands.add_parser(
        "upstream",
        help="fetch upstream webrtc-rs/rtc and compare this fork with it, both sides running "
        "this tree's benchmarks",
    )
    comparison(upstream)
    upstream.add_argument(
        "--url", default=UPSTREAM_URL, help=f"upstream repository (default: {UPSTREAM_URL})"
    )
    upstream.add_argument(
        "--branch",
        default=UPSTREAM_BRANCH,
        help=f"upstream branch to compare against (default: {UPSTREAM_BRANCH})",
    )
    upstream.add_argument(
        "--no-fetch",
        action="store_true",
        help=f"use the branch as last fetched into {UPSTREAM_REF_PREFIX}BRANCH",
    )

    report = commands.add_parser(
        "report", help="print one saved baseline, or compare two"
    )
    report.add_argument("baseline")
    report.add_argument("other", nargs="?")
    report.add_argument(
        "--criterion-home",
        default=str(ROOT / "target" / "criterion"),
        help="where the baselines were saved (default: target/criterion)",
    )
    report.add_argument("--threshold", type=float, default=3.0, metavar="PERCENT")

    external = commands.add_parser(
        "external",
        help="build benchmarks/external-consumer as an application would (outside this "
        "repository) and check its AES paths match the in-repository build",
    )
    external.add_argument(
        "--cache-dir",
        default=str(DEFAULT_WORKTREE_DIR.parent / "external-consumer"),
        help="outside the repository: where the consumer is built and run from "
        f"(default: {DEFAULT_WORKTREE_DIR.parent / 'external-consumer'})",
    )

    args = parser.parse_args()
    if getattr(args, "rounds", 1) < 1:
        parser.error("--rounds must be at least 1")
    {
        "list": command_list,
        "check": command_check,
        "run": command_run,
        "compare": command_compare,
        "upstream": command_upstream,
        "report": command_report,
        "external": command_external,
    }[args.command](args)


if __name__ == "__main__":
    main()

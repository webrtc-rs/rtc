#!/usr/bin/env python3
"""Build the same public-API runner against a selected rtc source snapshot."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tomllib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="rtc workspace snapshot")
    parser.add_argument("--source-revision", help="exact revision for a git-archive source snapshot")
    parser.add_argument("--build-dir", type=Path, required=True, help="external benchmark project")
    parser.add_argument("--target-dir", type=Path, help="optional existing Cargo target cache")
    parser.add_argument("--allocation-probe", action="store_true")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.build_dir.resolve()
    if output.is_relative_to(source):
        parser.error("--build-dir must be outside the selected source checkout")
    runner = Path(__file__).with_name("perf_scenarios.rs")
    workspace = tomllib.loads((source / "Cargo.toml").read_text())
    bytes_version = workspace["workspace"]["dependencies"]["bytes"]
    if not isinstance(bytes_version, str):
        parser.error("expected a version string for the workspace bytes dependency")
    (output / "src").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(runner, output / "src/main.rs")
    manifest = f'''[package]
name = "rtc-sctp-perf-scenarios"
version = "0.0.0"
edition = "2024"
publish = false

[features]
allocation-probe = []

[dependencies]
rtc-sctp = {{ path = {json.dumps(str(source / "rtc-sctp"))} }}
shared = {{ package = "rtc-shared", path = {json.dumps(str(source / "rtc-shared"))}, default-features = false }}
bytes = {json.dumps(bytes_version)}
'''
    (output / "Cargo.toml").write_text(manifest)
    target = args.target_dir.resolve() if args.target_dir else output / "target"
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL="0")
    command = ["cargo", "build", "--manifest-path", str(output / "Cargo.toml"), "--release"]
    if args.offline:
        command.append("--offline")
    if args.allocation_probe:
        command += ["--features", "allocation-probe"]
    subprocess.run(command, env=env, check=True)
    name = "perf-scenarios-alloc" if args.allocation_probe else "perf-scenarios"
    binary = output / name
    shutil.copy2(target / "release/rtc-sctp-perf-scenarios", binary)
    revision = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False,
    )
    metadata = {
        "source": str(source),
        "source_revision": args.source_revision or (revision.stdout.strip() if revision.returncode == 0 else None),
        "runner_sha256": hashlib.sha256((output / "src/main.rs").read_bytes()).hexdigest(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "allocation_probe": args.allocation_probe,
        "command": command,
        "target_dir": str(target),
        "cargo_incremental": env["CARGO_INCREMENTAL"],
        "rustc": subprocess.check_output(["rustc", "--version", "--verbose"], text=True),
    }
    (output / f"{name}-build.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(binary)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Reduce a failing Association scenario by removing whole four-byte actions.

Build the rtc-sctp library tests first and pass the executable Cargo prints after
`Running unittests`. This runs the public model replay test in fresh subprocesses;
it never changes the repository, production state, or a global Rust panic hook.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-binary", type=Path, required=True)
    parser.add_argument("--input-hex", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--contains", default="", help="retain this failure text")
    args = parser.parse_args()
    data = bytes.fromhex(args.input_hex)
    if len(data) % 4:
        parser.error("input must contain whole four-byte actions")
    binary = args.test_binary.resolve()
    command = [str(binary), "--exact", "association::model_test::model_replay_input", "--nocapture"]
    calls = 0

    def fails(actions):
        nonlocal calls
        calls += 1
        environment = os.environ.copy()
        environment["RTC_SCTP_MODEL_INPUT"] = b"".join(actions).hex()
        result = subprocess.run(command, env=environment, capture_output=True,
                                text=True, timeout=30)
        text = result.stdout + result.stderr
        return result.returncode != 0 and args.contains in text, text

    actions = [data[index:index + 4] for index in range(0, len(data), 4)]
    if not fails(actions)[0]:
        parser.error("the supplied input does not reproduce the requested failure")
    size = max(1, len(actions) // 2)
    while size:
        index = 0
        while index + size <= len(actions):
            candidate = actions[:index] + actions[index + size:]
            if fails(candidate)[0]:
                actions = candidate
            else:
                index += size
        size //= 2
    failed, trace = fails(actions)
    if not failed:
        raise RuntimeError("reduced input did not replay consistently")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.with_suffix(".bin").write_bytes(b"".join(actions))
    args.output.with_suffix(".log").write_text(trace)
    metadata = {
        "input_hex": b"".join(actions).hex(),
        "actions": len(actions),
        "subprocess_runs": calls,
        "test_binary": str(binary),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "failure_filter": args.contains,
    }
    args.output.with_suffix(".json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()

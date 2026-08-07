#!/usr/bin/env python3
"""Enforce the G4 deterministic-time boundary: sans-I/O protocol code is *told* the time, it does not ask.

A sans-I/O core that calls `Instant::now()` is not sans-I/O. It also cannot be tested against a
virtual clock, which is the property `MockRuntime` advertises and does not yet deliver. Every
protocol decision must be made against an instant the caller supplied — through
`handle_timeout(now)`, through `msg.now` / `evt.now` on an inbound payload, or through the instant
retained from the last of those.

This script fails on any ambient clock read in non-test code that is not recorded in
`docs/sans-io-deterministic-time-allowlist.txt`.

Two categories are permanently allow-listed:

* **Wall-clock observations**: `SystemInstant`'s own construction, `Instant` <-> epoch conversion,
  and protocol or format fields that are *specified* as wall-clock time (DTLS `gmt_unix_time`, SDP
  session version, X.509 validity). These are real-world observations and are correctly not
  reproducible under replay.
* Nothing else. Once the migration completes, those are the only entries left.

Every other entry is temporary and shrinks as the migration phases land. The allow-list records a
per-file *count* rather than a line number, so that unrelated edits do not shift a pinned line and
break CI during a migration that touches these files constantly. A count that no longer matches
fails, and the script prints the exact lines it found so the diff is obvious.

Usage:

    python3 scripts/check-sans-io-deterministic-time.py              # verify (what CI runs)
    python3 scripts/check-sans-io-deterministic-time.py --snapshot   # rewrite the allow-list from the tree

`--snapshot` is for seeding the file and for recording a *reduction* after a migration PR. Never
run it to silence a failure: if the count went up, the new read is the bug.

Run from the workspace root. Exits non-zero and prints offenders on failure.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ALLOWLIST = Path("docs/sans-io-deterministic-time-allowlist.txt")

# Roots holding sans-I/O protocol code. Integration tests under `tests/` are not scanned.
SOURCE_ROOTS = ["src"]
SOURCE_GLOB = "rtc-*/src"

# Matched *without* requiring the call parentheses, because a clock read does not need them:
# `unwrap_or_else(Instant::now)` passes the constructor as a function value and reads the ambient
# clock exactly as `Instant::now()` does. An earlier version of this pattern anchored on `\(\)`
# and missed `handler/sctp.rs`'s deferred-flush fallback for the whole of C1-C3.
#
# `\b` before `Instant` is load-bearing: it stops `Instant::now` matching inside
# `SystemInstant::now`, which is the *injected* form — it takes the caller's monotonic instant
# and only reads the system clock, and is allow-listed once, in `rtc-shared/src/time.rs`.
CLOCK_READS = re.compile(
    r"\bInstant::now\b"
    r"|\bSystemTime::now\b"
    r"|\bSystemInstant::now\(\)"
    r"|\.elapsed\(\)"
)

# `.elapsed()` matters as much as `Instant::now()`: on a retained `Instant` field,
# `self.now.elapsed()` compiles, looks entirely plausible, and reads the ambient clock.

# `foo_test.rs` and `foo_tests.rs` are both used in this workspace, as are `tests/` directories.
TEST_FILE = re.compile(r"_tests?\.rs$|(^|/)tests?/")

# Test items are not always wrapped in `#[cfg(test)] mod tests`: a bare `#[test]` fn is only
# compiled under `cfg(test)` too, and several modules here use that form directly.
TEST_ATTR = re.compile(r"^\s*#\[(?:cfg\(test\)|(?:[\w:]+::)?(?:test|bench))\]")

LINE_COMMENT = re.compile(r"^\s*(//|/\*|\*)")


def source_files() -> list[Path]:
    """Every non-test `.rs` file under the protocol source roots."""
    roots = [Path(r) for r in SOURCE_ROOTS if Path(r).is_dir()]
    roots += sorted(p for p in Path(".").glob(SOURCE_GLOB) if p.is_dir())
    files: list[Path] = []
    for root in roots:
        for path in root.rglob("*.rs"):
            if not TEST_FILE.search(path.as_posix()):
                files.append(path)
    return sorted(files)


def clock_reads(path: Path) -> list[tuple[int, str]]:
    """Ambient clock reads in `path`, skipping comments and test items.

    Test items are found by attribute (`#[cfg(test)]`, `#[test]`, `#[tokio::test]`, `#[bench]`)
    and skipped by brace depth, so a bare `#[test]` fn outside any `mod tests` is skipped too.
    """
    found: list[tuple[int, str]] = []
    lines = path.read_text().splitlines()
    skipping = False
    pending = False  # saw #[cfg(test)], waiting for the item's opening brace
    depth = 0

    for number, line in enumerate(lines, start=1):
        if skipping:
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                skipping = False
            continue

        if pending:
            opened = line.count("{")
            if opened:
                depth = opened - line.count("}")
                if depth > 0:
                    skipping, pending = True, False
                    continue
                pending = False
            elif line.rstrip().endswith(";"):
                # `#[cfg(test)] mod foo;` declares a module in another file; nothing to skip here.
                pending = False
            # Otherwise an attribute may sit above further attributes or a doc comment: keep waiting.
            continue

        if TEST_ATTR.match(line):
            pending = True
            continue

        if LINE_COMMENT.match(line):
            continue

        if CLOCK_READS.search(line):
            found.append((number, line.strip()))

    return found


def scan() -> dict[str, list[tuple[int, str]]]:
    return {
        path.as_posix(): reads
        for path in source_files()
        if (reads := clock_reads(path))
    }


def load_allowlist() -> dict[str, int]:
    """Parse `path:count:reason` lines. Blank lines and `#` comments are ignored."""
    if not ALLOWLIST.exists():
        return {}
    allowed: dict[str, int] = {}
    for raw in ALLOWLIST.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 2)
        if len(parts) < 2:
            print(f"Malformed allow-list line (want path:count:reason): {raw}")
            sys.exit(2)
        allowed[parts[0].strip()] = int(parts[1].strip())
    return allowed


# Reads that are wall-clock *by definition* and stay after the migration completes. Anything not
# listed here is temporary and must eventually reach zero.
#
# Keyed by path, value is (permanent count, reason). A file may hold both kinds; none does today,
# but the allow-list format supports it and the packetizer and sender-report stream both did
# before C2 collapsed their NTP baselines into `SystemInstant::now(now)`.
PERMANENT: dict[str, tuple[int, str]] = {
    # `SystemInstant` itself: the primitive that pairs a monotonic reading with a wall-clock one.
    # An RTCP sender report carries real wall-clock time in NTP format, and a virtual instant
    # would put a fictional timestamp on the wire — so this reads the system clock. The monotonic
    # half is the caller's `now`, which is why the four sites that used to hold an NTP baseline of
    # their own (rtc-media ×2, rtc-rtp/packetizer, rtc-interceptor/report/sender_stream) no longer
    # read a clock at all.
    "rtc-shared/src/time.rs": (1, "SystemInstant's own construction"),

    # Serializing an `Instant` requires anchoring it to the wall clock: `Instant` is opaque, so a
    # portable absolute timestamp can only be derived from a `SystemTime` taken alongside it.
    # Both directions need the pair.
    "rtc-shared/src/serde.rs": (4, "Instant <-> epoch conversion anchor"),

    # Protocol fields specified as wall-clock time.
    "rtc-dtls/src/handshake/handshake_random.rs": (1, "gmt_unix_time, RFC 5246 s7.4.1.2"),
    "rtc-sdp/src/description/session.rs": (1, "SDP session version, RFC 4566 s5.2"),

    # X.509 validity windows are wall-clock by definition; a virtual instant would accept an
    # expired certificate.
    "src/peer_connection/certificate/mod.rs": (1, "X.509 validity window"),
    "src/peer_connection/configuration/mod.rs": (1, "X.509 expiry check, W3C constructor step 3"),
    "src/peer_connection/transport/dtls/mod.rs": (1, "X.509 validity window"),
}

HEADER = """\
# Ambient clock reads permitted in non-test sans-I/O code.
#
# Format: path:count:reason
#
# A per-file count rather than a line number, so that unrelated edits do not shift a pinned line
# and break CI during a migration that touches these files constantly. Regenerate with:
#
#     python3 scripts/check-sans-io-deterministic-time.py --snapshot
#
# Only ever to record a REDUCTION. If a count went up, the new read is the bug — see
# docs/sans-io-deterministic-time.md.
"""


def write_snapshot(found: dict[str, list[tuple[int, str]]]) -> None:
    permanent: list[str] = []
    mixed: list[str] = []
    temporary: list[str] = []

    for path in sorted(found):
        total = len(found[path])
        keep, reason = PERMANENT.get(path, (0, ""))
        if keep and total == keep:
            permanent.append(f"{path}:{total}:{reason}")
        elif keep:
            mixed.append(
                f"{path}:{total}:{keep} permanent ({reason}) + {total - keep} awaiting injection"
            )
        else:
            temporary.append(f"{path}:{total}:awaiting clock injection")

    out = [HEADER]
    out.append("# --- Permanent: wall-clock is correct here -----------------------------------------")
    out.append("# These stay after the migration completes. See docs/sans-io-deterministic-time.md for why each")
    out.append("# category is a real-world observation rather than a protocol decision.")
    out.append("")
    out += permanent
    out.append("")
    out.append("# --- Mixed: a permanent read sharing a file with one that migrates -----------------")
    out.append("")
    out += mixed
    out.append("")
    out.append("# --- Temporary: awaiting migration -------------------------------------------------")
    out.append("# Each phase deletes lines from here. See sans-io-deterministic-time-work-plan.md.")
    out.append("# Target end state: this section is empty.")
    out.append("")
    out += temporary

    ALLOWLIST.parent.mkdir(parents=True, exist_ok=True)
    ALLOWLIST.write_text("\n".join(out) + "\n")

    total = sum(len(r) for r in found.values())
    keep = sum(min(len(found[p]), PERMANENT.get(p, (0, ""))[0]) for p in found)
    print(f"Wrote {ALLOWLIST} - {len(found)} files, {total} reads")
    print(f"  permanent: {keep}")
    print(f"  to migrate: {total - keep}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--snapshot",
        action="store_true",
        help="rewrite the allow-list from the current tree (to record a reduction)",
    )
    args = parser.parse_args()

    # A gate that can silently pass is worse than no gate. If the scan found no source at all we
    # are not at the workspace root, so report a configuration error rather than success — and in
    # particular never let `--snapshot` overwrite the allow-list with nothing.
    if not source_files():
        print("No sans-I/O source found. Run from the workspace root, where src/ and rtc-*/ live.")
        return 2

    found = scan()
    if args.snapshot:
        write_snapshot(found)
        return 0

    allowed = load_allowlist()
    new_reads: list[str] = []
    stale: list[str] = []

    for path, reads in sorted(found.items()):
        budget = allowed.get(path, 0)
        if len(reads) > budget:
            new_reads.append(f"{path}: {len(reads)} clock reads, {budget} allowed")
            for number, text in reads:
                new_reads.append(f"    {path}:{number}  {text}")
        elif len(reads) < budget:
            stale.append(f"{path}: {len(reads)} clock reads, {budget} still allowed")

    for path, budget in sorted(allowed.items()):
        if path not in found and budget:
            stale.append(f"{path}: no clock reads left, {budget} still allowed")

    if new_reads:
        print("Ambient clock reads in sans-I/O code that the allow-list does not permit:")
        print()
        for line in new_reads:
            print(f"  {line}")
        print()
        print("Sans-I/O protocol code is told the time; it does not ask. Take the instant from")
        print("`handle_timeout(now)`, from `msg.now` / `evt.now` on the inbound payload, or from")
        print("the instant retained from the last of those. Use `saturating_duration_since`")
        print("rather than `.elapsed()`. See docs/sans-io-deterministic-time.md.")
        return 1

    if stale:
        print("Clock reads were removed but the allow-list still budgets for them:")
        print()
        for line in stale:
            print(f"  {line}")
        print()
        print("Good news — record it: python3 scripts/check-sans-io-deterministic-time.py --snapshot")
        return 1

    total = sum(len(r) for r in found.values())
    print(f"Sans-I/O deterministic-time boundary holds: {total} allow-listed reads, no new ones.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

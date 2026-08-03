#!/usr/bin/env python3
"""Enforce the G3 crypto boundary: `rtc-crypto` is the only crate that names a crypto
implementation.

Checks each crate's `[dependencies]` / `[dev-dependencies]` / `[build-dependencies]` and
`[target.*.dependencies]` sections. Deliberately ignored:

* `[features]` entries such as `ring = ["crypto/ring"]`, which are provider-feature forwarding
  and are how a standalone crate exposes backend selection.
* `[workspace.dependencies]` in the root manifest, which declares versions on behalf of
  `rtc-crypto`.
* `rand`. It is an entropy source, not a crypto implementation, appears in no public signature,
  and is a documented exception (see `docs/crypto-provider-decisions.md`).

Run from the workspace root. Exits non-zero and prints offenders on failure.
"""

from __future__ import annotations

import glob
import re
import sys
from pathlib import Path

CRYPTO_IMPLEMENTATIONS = {
    "ring",
    "aws-lc-rs",
    "aes",
    "aes-gcm",
    "sha1",
    "sha2",
    "hmac",
    "hkdf",
    "p256",
    "p384",
    "ctr",
    "cbc",
    "ccm",
    "md-5",
    "subtle",
    "x25519-dalek",
    "chacha20poly1305",
    "sec1",
    "ed25519-dalek",
    "rsa",
    "openssl",
}

# Certificate format and trust policy are deliberately outside the provider (design section 5.2),
# so these stay in the crates that own X.509 handling.
CERTIFICATE_FORMAT_ALLOWED = {"rcgen", "rustls", "x509-parser", "der-parser", "pem"}

DEPENDENCY_SECTION = re.compile(
    r"^\[(?:target\.[^\]]+\.)?(?:dev-|build-)?dependencies\]$"
)
SECTION = re.compile(r"^\[.*\]$")
DEPENDENCY_NAME = re.compile(r"^([A-Za-z0-9_-]+)\s*[.=]")


def dependencies_of(manifest: Path) -> set[str]:
    names: set[str] = set()
    in_dependencies = False
    for line in manifest.read_text().splitlines():
        stripped = line.strip()
        if SECTION.match(stripped):
            in_dependencies = bool(DEPENDENCY_SECTION.match(stripped))
            continue
        if not in_dependencies:
            continue
        match = DEPENDENCY_NAME.match(stripped)
        if match:
            names.add(match.group(1))
    return names


def main() -> int:
    offenders: list[str] = []
    for manifest_path in sorted(glob.glob("rtc-*/Cargo.toml")) + ["Cargo.toml"]:
        manifest = Path(manifest_path)
        crate = manifest.parent.name if manifest.parent.name else "rtc"
        if crate == "rtc-crypto":
            continue
        found = dependencies_of(manifest) & CRYPTO_IMPLEMENTATIONS
        for dependency in sorted(found):
            offenders.append(f"{manifest_path}: {dependency}")

    if offenders:
        print("Crypto implementation dependencies found outside rtc-crypto:")
        for offender in offenders:
            print(f"  {offender}")
        print()
        print("Route the operation through rtc-crypto's provider traits instead.")
        print(f"Certificate-format crates remain allowed: {sorted(CERTIFICATE_FORMAT_ALLOWED)}")
        return 1

    print("Crypto boundary holds: no crypto implementation outside rtc-crypto.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

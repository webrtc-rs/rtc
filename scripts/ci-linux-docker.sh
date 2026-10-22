#!/usr/bin/env bash
# Run a command in a Linux container against this working tree — to reproduce a Linux CI failure
# from a Mac, or to test Linux before pushing.
#
#   scripts/ci-linux-docker.sh                                  # cargo test --workspace, native arch
#   scripts/ci-linux-docker.sh -p linux/amd64                   # x86-64 under emulation (slow)
#   scripts/ci-linux-docker.sh -w . -- cargo clippy --workspace --lib -- -D warnings
#
# The tree is copied into a Docker volume rather than bind-mounted, because Docker-on-Mac VMs
# cannot always mount protected folders such as ~/Documents. The target directory and cargo
# registry live in volumes too, so repeat runs are incremental.
set -euo pipefail

PLATFORM="linux/$(uname -m | sed 's/x86_64/amd64/; s/arm64/arm64/; s/aarch64/arm64/')"
IMAGE="${IMAGE:-rust:1}"
WORKDIR=""
while getopts "p:w:i:" opt; do
  case $opt in
    p) PLATFORM="$OPTARG" ;;
    w) WORKDIR="$OPTARG" ;;
    i) IMAGE="$OPTARG" ;;
    *) exit 2 ;;
  esac
done
shift $((OPTIND - 1))
[ "${1:-}" = "--" ] && shift
CMD=("$@")
[ ${#CMD[@]} -eq 0 ] && CMD=(cargo test --workspace --no-fail-fast)

# Inside the webrtc superproject the whole tree is copied (the `webrtc` crate needs it); a
# standalone checkout of rtc copies just itself.
RTC="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "$RTC/../Cargo.toml" ] && grep -q '^name = "webrtc"' "$RTC/../Cargo.toml"; then
  ROOT="$(cd "$RTC/.." && pwd)"
  : "${WORKDIR:=rtc}"
else
  ROOT="$RTC"
  : "${WORKDIR:=.}"
fi
TAG="${PLATFORM//\//-}"
SRC="webrtc-src-$TAG"; TGT="webrtc-target-$TAG"
docker volume create "$SRC" >/dev/null
docker volume create "$TGT" >/dev/null
docker volume create webrtc-cargo-home >/dev/null

tar -C "$ROOT" \
  --exclude='./target' --exclude='./rtc/target' --exclude='./.git' --exclude='./rtc/.git' \
  --exclude='*/benchmarks/*/target' --exclude='*/fuzz/target' \
  -cf - . 2>/dev/null |
  docker run --rm -i --platform "$PLATFORM" -v "$SRC":/work "$IMAGE" \
    bash -c 'find /work -mindepth 1 -maxdepth 1 -exec rm -rf {} + ; tar -xf - -C /work 2>/dev/null'

exec docker run --rm --platform "$PLATFORM" \
  -v "$SRC":/work -v "$TGT":/target -v webrtc-cargo-home:/cargo-home \
  -e CARGO_HOME=/cargo-home -e CARGO_TARGET_DIR=/target -e CARGO_TERM_COLOR=always \
  -w "/work/$WORKDIR" "$IMAGE" "${CMD[@]}"

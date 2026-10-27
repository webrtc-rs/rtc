#!/usr/bin/env bash
# Run, on this machine, the checks CI runs on every pull request.
#
#   scripts/ci-local.sh                 # everything below
#   scripts/ci-local.sh lint test       # only the named steps
#   BACKEND=crypto-aws-lc-rs scripts/ci-local.sh test
#
# Steps: lint, test, golden, docs, deny, bench
# Works on Linux and macOS (x86-64 and arm64). See docs/ci.md for how these map to workflows.
set -euo pipefail

cd "$(dirname "$0")/.."

BACKEND="${BACKEND:-crypto-ring}"
PROFILE_FLAG="${PROFILE_FLAG:-}"        # set to --release to test optimised code
STEPS=("$@")
[ ${#STEPS[@]} -eq 0 ] && STEPS=(lint test golden docs deny)

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

lint() {
  step "rustfmt"
  cargo fmt --all -- --check
  step "clippy (library code, warnings are errors)"
  cargo clippy --workspace --lib --bins -- -D warnings
  step "clippy (all targets, correctness lints are errors)"
  cargo clippy --workspace --all-targets -- -A clippy::all -D clippy::correctness
}

test_all() {
  step "test workspace ($BACKEND ${PROFILE_FLAG:-debug})"
  # shellcheck disable=SC2086
  cargo test --workspace --no-fail-fast $PROFILE_FLAG --no-default-features --features "rtc/$BACKEND"
}

golden() {
  step "pion differential corpus (release)"
  cargo test --release \
    -p rtc-sdp -p rtc-rtcp -p rtc-rtp -p rtc-stun -p rtc-datachannel -p rtc-dtls -p rtc-srtp \
    -p rtc-turn --test pion_golden
  cargo test --release -p rtc-ice --test pion_candidate_golden
  # The crates that keep their parsers private are tested from inside.
  cargo test --release -p rtc-sctp -p rtc-mdns -p rtc-interceptor --lib pion_golden
}

docs() {
  step "rustdoc (warnings are errors)"
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
}

deny() {
  step "cargo deny"
  if command -v cargo-deny >/dev/null; then
    cargo deny check
  else
    echo "cargo-deny is not installed (cargo install cargo-deny --locked); skipping"
  fi
}

bench() {
  step "benchmark against pion"
  python3 benchmarks/pion-compare/compare.py --backend "${BACKEND#crypto-}"
}

for s in "${STEPS[@]}"; do
  case "$s" in
    lint) lint ;;
    test) test_all ;;
    golden) golden ;;
    docs) docs ;;
    deny) deny ;;
    bench) bench ;;
    *) echo "unknown step: $s (lint test golden docs deny bench)" >&2; exit 2 ;;
  esac
done

printf '\n\033[1;32mAll requested steps passed.\033[0m\n'

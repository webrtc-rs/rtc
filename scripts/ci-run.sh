#!/usr/bin/env bash
# Run a command; if it fails, also publish the interesting lines and the tail of its output as a
# workflow annotation, so the cause is readable from the run's check annotations (which are public
# and scriptable) and not only from the raw log.
#
#   scripts/ci-run.sh cargo test --workspace
set -uo pipefail

log="$(mktemp)"
"$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}

if [ "$status" -ne 0 ]; then
  {
    grep -E '^(error(\[|:)|warning: unused)|panicked at|^test .* FAILED|^failures:|^---- |assertion|FAIL|GATE' "$log" | head -60
    echo '--- tail ---'
    tail -n 30 "$log"
  } > "$log.summary"
  msg="$(cat "$log.summary")"
  msg="${msg//'%'/'%25'}"
  msg="${msg//$'\r'/'%0D'}"
  msg="${msg//$'\n'/'%0A'}"
  echo "::error title=command failed (exit ${status})::${msg:0:30000}"
fi
exit "$status"

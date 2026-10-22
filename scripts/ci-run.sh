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
  # Colour codes and cargo's `--verbose` command lines bury the cause; drop them.
  clean="$(mktemp)"
  sed $'s/\x1b\\[[0-9;]*[A-Za-z]//g' "$log" \
    | grep -vE '^[[:space:]]*(Running|Fresh|Dirty|Compiling|Checking|Documenting|Downloaded|Downloading|Blocking|Locking|Adding|Updating)[[:space:]]' \
    > "$clean" || true
  {
    # The failure itself, with what follows it (a panic message is on the lines after "panicked at").
    grep -nE 'panicked at|^error(\[|:)|^test .* FAILED|^failures:|assertion|GATE|Traceback|Error:' "$clean" \
      | cut -d: -f1 | head -12 | while read -r n; do sed -n "${n},$((n + 4))p" "$clean"; echo '...'; done
    echo '--- tail ---'
    tail -n 40 "$clean"
  } > "$log.summary"
  msg="$(cat "$log.summary")"
  msg="${msg//%/%25}"
  msg="${msg//$'\r'/%0D}"
  msg="${msg//$'\n'/%0A}"
  echo "::error title=command failed (exit ${status})::${msg:0:30000}"
fi
exit "$status"

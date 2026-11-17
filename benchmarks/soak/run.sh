#!/usr/bin/env bash
# Run one soak pair over loopback with netem impairment, then report.
#
#   run.sh <rtc-rtc|pion-pion|rtc-pion> <minutes> <outdir>
#
# Environment: CYCLE_MIN (netem cycle length, default 20), IFACE (default lo), RULES (default
# rules.json next to this script; rules-abuse.json for PROFILE=abuse), SOAK_RTC_BIN / SOAK_PION_BIN
# (prebuilt peers; skips the build).
# PROFILE=call (default) is the call under the netem phases. PROFILE=abuse runs the same call under
# abuse: the peers add hostile connections and traffic (see README.md, "The abuse profile of the
# peers") while netem.sh runs its abuse profile on the interface. Everything is replayable from SEED
# (default: today's date, UTC; printed and logged): `SEED=7 PROFILE=abuse run.sh rtc-rtc 3 out`. ONLY
# (comma separated attack classes) restricts the peers' attacks, for looking at one class.
# The comparison needs the same SEED for both pairs.
# PROFILE=trace runs the call over recorded cellular links instead of the netem phases: netem.sh replays
# Mahimahi LTE traces (SEED picks the trace and offset of each direction), which this script fetches
# with traces.sh into TRACE_DIR (default <outdir>/traces) and checks against pinned hashes; the rules
# are the call profile's. See README.md, "Trace replay".
# Needs Linux, python3, iproute2 and root (or sudo) for tc. Writes machine.txt (architecture, cores, CPU).
# Exits non-zero when a peer exits non-zero or logs a panic or fatal error (a crash is a failure; it is
# also written to the JSONL as an `error` event of id `sfu`, which the report gates at zero) or, when rtc-rtc.jsonl and
# pion-pion.jsonl are both in <outdir> (run both pairs into the same directory), when report.py's
# comparison of the two fails (the CI compares in its report job instead).
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <rtc-rtc|pion-pion|rtc-pion> <minutes> <outdir>" >&2
  exit 2
fi
pair=$1 minutes=$2 outdir=$3
case "$pair" in rtc-rtc | pion-pion | rtc-pion) ;; *)
  echo "unknown pair: $pair" >&2
  exit 2
  ;;
esac

here=$(cd "$(dirname "$0")" && pwd)
cycle=${CYCLE_MIN:-20}
iface=${IFACE:-lo}
profile=${PROFILE:-call}
case "$profile" in call | abuse | trace) ;; *)
  echo "PROFILE is call, abuse or trace, not $profile" >&2
  exit 2
  ;;
esac
seed=${SEED:-$(date -u +%Y%m%d)}
rules=${RULES:-$here/$([ "$profile" = abuse ] && echo rules-abuse.json || echo rules.json)}
peer_args=()
if [ "$profile" = abuse ]; then
  peer_args=(--profile abuse --seed "$seed")
  [ -n "${ONLY:-}" ] && peer_args+=(--only "$ONLY")
  echo "run.sh: profile abuse, seed $seed (replay: SEED=$seed PROFILE=abuse $0 $pair $minutes $outdir)"
fi
# A recorded link stalls for up to 78 s: the peers keep ICE patient as in the abuse profile.
[ "$profile" = trace ] && peer_args=(--profile trace)
mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
if [ "$profile" = trace ]; then
  trace_dir=$("$here/traces.sh" "${TRACE_DIR:-$outdir/traces}")
  echo "run.sh: profile trace, seed $seed, traces in $trace_dir (replay: SEED=$seed PROFILE=trace $0 $pair $minutes $outdir)"
fi
jsonl=$outdir/$pair.jsonl
: >"$jsonl"
{
  echo "arch: $(uname -m)"
  echo "kernel: $(uname -sr)"
  echo "cores: $(nproc)"
  grep -m3 -iE '^(model name|hardware|cpu implementer|cpu part)' /proc/cpuinfo || true
} >"$outdir/machine.txt"
sudo=""
[ "$(id -u)" -ne 0 ] && sudo=sudo

rtc_bin=${SOAK_RTC_BIN:-}
pion_bin=${SOAK_PION_BIN:-}
if [[ "$pair" == *rtc* ]] && [ -z "$rtc_bin" ]; then
  cargo build --release --manifest-path "$here/Cargo.toml"
  rtc_bin=$(cargo metadata --no-deps --format-version 1 --manifest-path "$here/Cargo.toml" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/release/soak-rtc
fi
if [[ "$pair" == *pion* ]] && [ -z "$pion_bin" ]; then
  bindir=$(mktemp -d)
  pion_bin=$bindir/soak-pion
  (cd "$here/go" && go build -o "$pion_bin" .)
fi
bin() { if [ "$1" = rtc ]; then echo "$rtc_bin"; else echo "$pion_bin"; fi; }

offerer=${pair%-*} answerer=${pair#*-}
port=$((7100 + 4 * (RANDOM % 125))) # the abuse profile also uses port+1 and port+2
pids=()
cleanup() {
  trap - EXIT INT TERM
  [ -n "${bindir:-}" ] && rm -rf "$bindir"
  for p in "${pids[@]}"; do $sudo kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 143' INT TERM

"$(bin "$offerer")" --role offerer --signal "127.0.0.1:$port" --minutes "$minutes" --out "$jsonl" \
  --id "$offerer-offerer" ${peer_args[@]+"${peer_args[@]}"} 2>"$outdir/$pair.offerer.log" &
pids+=($!)
"$(bin "$answerer")" --role answerer --signal "127.0.0.1:$port" --minutes "$minutes" --out "$jsonl" \
  --id "$answerer-answerer" ${peer_args[@]+"${peer_args[@]}"} 2>"$outdir/$pair.answerer.log" &
pids+=($!)

# Impair only once both sides are connected, so the rendezvous and the handshake run clean.
for _ in $(seq 1 90); do
  [ "$(grep -c '"what":"join"' "$jsonl" || true)" -ge 2 ] && break
  kill -0 "${pids[0]}" 2>/dev/null && kill -0 "${pids[1]}" 2>/dev/null || break
  sleep 1
done
if [ "$profile" = abuse ]; then
  $sudo env NETEM_PROFILE=abuse NETEM_SEED="$seed" NETEM_NAMES="$offerer-offerer $answerer-answerer" \
    "$here/netem.sh" "$iface" "$minutes" "$cycle" "$jsonl" &
elif [ "$profile" = trace ]; then
  $sudo env NETEM_PROFILE=trace NETEM_SEED="$seed" NETEM_NAMES="$offerer-offerer $answerer-answerer" \
    NETEM_TRACE_DIR="$trace_dir" "$here/netem.sh" "$iface" "$minutes" "$cycle" "$jsonl" &
else
  $sudo "$here/netem.sh" "$iface" "$minutes" "$cycle" "$jsonl" &
fi
pids+=($!)

# A peer that exits non-zero or logs a panic is a crash: the report gates `error` events of id `sfu`
# at zero, so that is where it is written.
crash() { # <impl> <role> <detail>
  printf '{"ts":%s,"impl":"%s","arch":"%s","kind":"event","id":"sfu","what":"error","detail":"%s"}\n' \
    "$(date +%s%3N)" "$1" "$(uname -m)" "$3" >>"$jsonl"
  echo "run.sh: $3 (see $outdir/$pair.$2.log)" >&2
}
status=0
declare -A exited=([offerer]=0 [answerer]=0)
wait "${pids[0]}" || exited[offerer]=$?
wait "${pids[1]}" || exited[answerer]=$?
for role in offerer answerer; do
  impl=$offerer
  [ "$role" = answerer ] && impl=$answerer
  if [ "${exited[$role]}" -ne 0 ]; then
    status=${exited[$role]}
    crash "$impl" "$role" "peer $role exited ${exited[$role]}"
  elif grep -qE '^(panic:|fatal error:|thread .* panicked)' "$outdir/$pair.$role.log" 2>/dev/null; then
    status=1
    crash "$impl" "$role" "peer $role logged a panic"
  fi
done
$sudo kill "${pids[2]}" 2>/dev/null || true
wait "${pids[2]}" 2>/dev/null || true
pids=()

if [ -s "$outdir/rtc-rtc.jsonl" ] && [ -s "$outdir/pion-pion.jsonl" ]; then
  report=0
  python3 "$here/report.py" --rules "$rules" --out "$outdir" "$outdir"/*.jsonl || report=$?
  [ "$status" -ne 0 ] && exit "$status"
  exit "$report"
fi
echo "run.sh: $pair done; the comparison needs rtc-rtc and pion-pion in $outdir (python3 $here/report.py --rules $rules --out DIR FILES)"
exit "$status"

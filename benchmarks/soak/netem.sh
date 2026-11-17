#!/usr/bin/env bash
# Drive `tc netem` through a repeating phase cycle and log every change as a JSONL `phase` line.
#
#   netem.sh <iface> <minutes> <cycle_minutes> <events.jsonl>
#
# One cycle is clean 40 %, loss (2 % random) 15 %, burst (Gilbert-Elliott, ~5 % in bursts of ~5
# packets) 15 %, bw (a bandwidth cap plus 80 ms delay) 15 %, outage (100 % loss) 5 s, and clean
# again (recover) for the rest. At the default 20-minute cycle that is 8 / 3 / 3 / 3 minutes,
# 5 s, ~3 minutes. The cycle repeats until <minutes> have passed. Qdiscs are removed on exit.
#
# What is shaped (NETEM_PORTS):
#
#   unset            everything that crosses <iface>: one flow, the path of a peer pair. The caps are
#                    per direction. `lo` is one device that both directions cross, so there the
#                    cap is doubled and each direction gets about the set cap.
#   udp              all UDP of the namespace, one flow: a participant (a browser) that has a
#                    namespace of its own. TCP, such as its signaling websocket, is not touched.
#   <base>:<count>   <count> flows, each with its own cap, delay and loss: flow k is the UDP packets
#                    to and from the ports <base>+4k to <base>+4k+3 (<base> a multiple of four).
#                    `lms-sim lesson --udp-base <base>` binds participant k to its block, so every
#                    participant gets the cap to itself instead of sharing one with the others.
#                    Everything else (TCP, other UDP) is not shaped.
#
# The bw cap per direction: NETEM_BW_UP_MBIT (what the shaped side sends) and NETEM_BW_DOWN_MBIT
# (what it receives), both default to NETEM_BW_MBIT (1.5; 3 on `lo`). NETEM_DELAY (80ms) is added
# in the bw phase. NETEM_GROUP names the group the phase lines are for (default `impaired`); the
# samples of that group are assigned to these phases, other groups are not impaired.
#
# NETEM_PROFILE=abuse (NETEM_SEED=<n>, default 1) replaces the cycle with an abuse profile: every flow
# (the single flow in the whole-device and udp modes) runs its own schedule, seeded from the seed and
# the flow's number so a run replays, changing scene every 3-10 s: clean (~30 %), reorder,
# duplicate, jitter, asym-loss (10-30 % in one direction), bw-flap (3 Mbit / 300 kbit every 3 s)
# and, rarely, an outage of 30, 60 or 120 s. Each scene logs an `attack` start and end line (see
# README.md); NETEM_NAMES (space separated) names the participant of flow k, the k-th name.
#
# NETEM_PROFILE=trace (NETEM_SEED, NETEM_NAMES, NETEM_GROUP as above) replays recorded cellular links
# instead (traces.sh fetches them into NETEM_TRACE_DIR; tracereplay.py does the replay): every flow gets an
# uplink and a downlink trace and an offset into each, chosen from the seed and the flow's number,
# and the rate of its netem follows the trace in steps of NETEM_TRACE_STEP_MS (200). The base one-way
# delay is NETEM_TRACE_DELAY (40ms) and the queue NETEM_TRACE_LIMIT packets (100: 150 kB, a drop-tail
# that holds a keyframe burst but turns a stall into loss, not seconds of delay). A step the link
# delivers nothing in is a stall (100 % loss). Stretches without delivery for 1 s and under 300 kbit/s
# for 2 s are logged as `attack` windows named `trace-stall` and `trace-low`, with a `trace` phase line
# at the start. Without ingress shaping (`lo`) only the uplink trace is replayed.
#
# Egress is always impaired. Ingress is impaired too, through an `ifb` device, except on `lo`
# (a packet crosses lo's egress and ingress both, so the egress shaping already covers each
# direction once). Override with NETEM_INGRESS=0|1|auto. Linux only; needs root/NET_ADMIN (and
# sch_htb, cls_u32 for flows). To impair another network namespace, run this inside it:
# nsenter -t <pid> -n netem.sh ...
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <iface> <minutes> <cycle_minutes> <events.jsonl>" >&2
  exit 2
fi
iface=$1 minutes=$2 cycle_min=$3 events=$4
ifb='ifb-soak'
ingress=${NETEM_INGRESS:-auto}
if [ "$ingress" = auto ]; then
  if [ "$iface" = lo ]; then ingress=0; else ingress=1; fi
fi

bw_mbit=${NETEM_BW_MBIT:-$([ "$iface" = lo ] && echo 3 || echo 1.5)}
bw_up=${NETEM_BW_UP_MBIT:-$bw_mbit}
bw_down=${NETEM_BW_DOWN_MBIT:-$bw_mbit}
delay=${NETEM_DELAY:-80ms}
group=${NETEM_GROUP:-impaired}
ports=${NETEM_PORTS:-}
nflows=0
if [ -n "$ports" ] && [ "$ports" != udp ]; then
  port_base=${ports%%:*}
  nflows=${ports#*:}
  if [ "$port_base" = "$ports" ] || [ $((port_base % 4)) -ne 0 ] || [ "$nflows" -lt 1 ]; then
    echo "NETEM_PORTS is udp or <base>:<count>, <base> a multiple of four" >&2
    exit 2
  fi
fi

now_ms() { date +%s%3N; }
arch=$(uname -m)

pids=()
cleanup() {
  trap - EXIT INT TERM
  if [ "${#pids[@]}" -gt 0 ]; then
    kill "${pids[@]}" 2>/dev/null || true
    wait "${pids[@]}" 2>/dev/null || true
  fi
  tc qdisc del dev "$iface" root 2>/dev/null || true
  if [ "$ingress" = 1 ]; then
    tc qdisc del dev "$iface" ingress 2>/dev/null || true
    tc qdisc del dev "$ifb" root 2>/dev/null || true
    ip link del "$ifb" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 143' INT TERM

# A class per flow under an htb that lets everything else through (class 1:1), a netem leaf in each,
# picked out by the packet's UDP port (`sport` on what the shaped side sends, `dport` on what it
# receives).
setup_flows() { # <dev> <sport|dport>
  local dev=$1 field=$2 k minor
  tc qdisc add dev "$dev" root handle 1: htb default 1
  tc class add dev "$dev" parent 1: classid 1:1 htb rate 10gbit quantum 1514
  for ((k = 0; k < flows; k++)); do
    minor=$(printf '%x' $((k + 2)))
    tc class add dev "$dev" parent 1: classid "1:$minor" htb rate 10gbit quantum 1514
    tc qdisc add dev "$dev" parent "1:$minor" handle "$minor:" netem
    if [ "$ports" = udp ]; then
      tc filter add dev "$dev" parent 1: protocol ip prio 1 u32 match ip protocol 17 0xff flowid "1:$minor"
    else
      tc filter add dev "$dev" parent 1: protocol ip prio 1 u32 match ip protocol 17 0xff \
        match ip "$field" $((port_base + 4 * k)) 0xfffc flowid "1:$minor"
    fi
  done
}

flows=$nflows
[ "$ports" = udp ] && flows=1

if [ "$ingress" = 1 ]; then
  modprobe ifb 2>/dev/null || true
  ip link add "$ifb" type ifb
  ip link set "$ifb" up
  tc qdisc add dev "$iface" handle ffff: ingress
  tc filter add dev "$iface" parent ffff: protocol all u32 match u32 0 0 \
    action mirred egress redirect dev "$ifb"
fi
if [ "$flows" -gt 0 ]; then
  setup_flows "$iface" sport
  [ "$ingress" = 1 ] && setup_flows "$ifb" dport
fi

# `tc qdisc replace` keeps the reorder and rate of the netem it replaces when the new arguments do not
# name them, so every change starts from these.
reset='delay 0ms reorder 0% duplicate 0% loss 0% rate 0'

# shape <dev> <netem args...>: the impairment on one device, on every flow of it in flow mode.
shape() {
  local dev=$1 k minor
  shift
  if [ "$flows" -gt 0 ]; then
    for ((k = 0; k < flows; k++)); do
      minor=$(printf '%x' $((k + 2)))
      # shellcheck disable=SC2086 # reset is words
      tc qdisc replace dev "$dev" parent "1:$minor" handle "$minor:" netem $reset "$@"
    done
  elif [ "$#" -eq 0 ]; then
    tc qdisc del dev "$dev" root 2>/dev/null || true
  else
    # shellcheck disable=SC2086
    tc qdisc replace dev "$dev" root netem $reset "$@"
  fi
}

# phase <name> <seconds> <up netem args> <down netem args>: what the shaped side sends (egress) and
# what it receives (ingress, when enabled) are impaired separately; the arguments are words.
phase() {
  local name=$1 secs=$2 up=$3 down=$4
  # shellcheck disable=SC2086
  shape "$iface" $up
  # shellcheck disable=SC2086
  if [ "$ingress" = 1 ]; then shape "$ifb" $down; fi
  printf '{"ts":%s,"impl":"netem","arch":"%s","kind":"phase","id":"netem","group":"%s","name":"%s","up":"%s","down":"%s"}\n' \
    "$(now_ms)" "$arch" "$group" "$name" "$up" "$down" >>"$events"
  sleep "$secs" &
  wait $!
}

: >>"$events"
end=$(($(date +%s) + minutes * 60))
cycle=$(awk -v m="$cycle_min" 'BEGIN { printf "%d", m * 60 }')
clean=$((cycle * 40 / 100))
slot=$((cycle * 15 / 100))
outage=5
[ "$outage" -gt $((cycle / 20)) ] && outage=$((cycle / 20 > 0 ? cycle / 20 : 1))
recover=$((cycle - clean - 3 * slot - outage))

# Each phase is cut short at the deadline so the run length is exact.
left() { local l=$((end - $(date +%s))); [ "$l" -gt "$1" ] && echo "$1" || echo "$l"; }

# --- abuse profile ------------------------------------------------------------------------------

profile=${NETEM_PROFILE:-cycle}
seed=${NETEM_SEED:-1}
read -r -a names <<<"${NETEM_NAMES:-}"

# shape_flow <dev> <flow> <netem args...>: one flow's class (the device's root without flows).
shape_flow() {
  local dev=$1 k=$2 minor
  shift 2
  if [ "$flows" -gt 0 ]; then
    minor=$(printf '%x' $((k + 2)))
    # shellcheck disable=SC2086
    tc qdisc replace dev "$dev" parent "1:$minor" handle "$minor:" netem $reset "$@"
  else
    shape "$dev" "$@"
  fi
}

# who_json <flow>: the participants of a flow as a JSON array body, empty when unknown.
who_json() {
  local k=$1 n out=''
  if [ "$ports" = udp ] || [ "$flows" -eq 0 ]; then
    for n in "${names[@]}"; do out="$out${out:+,}\"$n\""; done
  elif [ -n "${names[$k]:-}" ]; then
    out="\"${names[$k]}\""
  fi
  echo "$out"
}

# attack <flow> <id> <name> <state> <detail>: one `attack` line.
attack() {
  local who
  who=$(who_json "$1")
  printf '{"ts":%s,"impl":"abuse","arch":"%s","kind":"attack","id":"%s","name":"%s","state":"%s","group":"%s",%s"seed":%s,"detail":"%s"}\n' \
    "$(now_ms)" "$arch" "$2" "$3" "$4" "$group" "${who:+\"who\":[$who],}" "$seed" "$5" >>"$events"
}

# apply <flow> <up args> <down args>: what the flow sends and receives (ingress, when enabled).
apply() {
  local k=$1 up=$2 down=$3
  # shellcheck disable=SC2086
  shape_flow "$iface" "$k" $up
  # shellcheck disable=SC2086
  if [ "$ingress" = 1 ]; then shape_flow "$ifb" "$k" $down; fi
}

nap() { # <seconds>: sleep, cut at the deadline
  local l
  l=$(left "$1")
  [ "$l" -gt 0 ] || return 0
  sleep "$l" &
  wait $!
}

# abuse_flow <flow>: the scenes of one flow until the deadline, in a subshell of its own.
abuse_flow() {
  local k=$1 n=0 r len name up down detail pct s
  RANDOM=$((seed + k))
  trap 'kill $(jobs -p) 2>/dev/null; exit 0' TERM INT
  while [ "$(date +%s)" -lt "$end" ]; do
    r=$((RANDOM % 1000))
    len=$((3 + RANDOM % 8))
    up='' down='' detail='' name=clean
    if [ "$r" -lt 300 ]; then
      name=clean
    elif [ "$r" -lt 450 ]; then
      name=reorder up='delay 30ms 20ms reorder 30% 50%' down=$up
    elif [ "$r" -lt 580 ]; then
      name=duplicate up='duplicate 10%' down=$up
    elif [ "$r" -lt 710 ]; then
      name=jitter up='delay 100ms 80ms distribution normal' down=$up
    elif [ "$r" -lt 840 ]; then
      name=asym-loss
      pct=$((10 + RANDOM % 21))
      if [ $((RANDOM % 2)) -eq 0 ] || [ "$ingress" != 1 ]; then
        up="loss $pct%" detail="up $pct%"
      else
        down="loss $pct%" detail="down $pct%"
      fi
    elif [ "$r" -lt 997 ]; then
      name=bw-flap
    else
      len=$((30 << (RANDOM % 3)))
      name="outage-$len"
      up='loss 100%' down=$up
    fi
    if [ "$name" = clean ]; then
      apply "$k" "" ""
      nap "$len"
      continue
    fi
    n=$((n + 1))
    attack "$k" "net-$group-$k-$n" "$name" start "$detail"
    if [ "$name" = bw-flap ]; then
      for ((s = 0; s < len; s += 3)); do
        if [ $((s / 3 % 2)) -eq 0 ]; then up='rate 3mbit limit 300'; else up='rate 300kbit limit 300'; fi
        apply "$k" "$up" "$up"
        nap $((len - s < 3 ? len - s : 3))
      done
    else
      apply "$k" "$up" "$down"
      nap "$len"
    fi
    attack "$k" "net-$group-$k-$n" "$name" end "$detail"
  done
}

run_abuse() {
  local k nf=$flows
  [ "$nf" -gt 0 ] || nf=1
  printf '{"ts":%s,"impl":"netem","arch":"%s","kind":"event","id":"netem","what":"seed","detail":"%s","group":"%s"}\n' \
    "$(now_ms)" "$arch" "$seed" "$group" >>"$events"
  printf '{"ts":%s,"impl":"netem","arch":"%s","kind":"phase","id":"netem","group":"%s","name":"abuse","up":"abuse","down":"abuse"}\n' \
    "$(now_ms)" "$arch" "$group" >>"$events"
  for ((k = 0; k < nf; k++)); do
    abuse_flow "$k" &
    pids+=("$!")
  done
  wait "${pids[@]}"
}

if [ "$profile" = abuse ]; then
  run_abuse
  exit 0
fi

# --- trace profile ------------------------------------------------------------------------------

# One process steps every flow's rate with a single `tc -batch` per step, so five steps a second for
# many flows stay cheap, and it writes the `trace` phase and the `attack` lines.
run_trace() {
  local args=()
  [ "$ingress" = 1 ] && args+=(--ifb "$ifb")
  if [ "$ports" = udp ]; then args+=(--all-names); fi
  python3 "$(dirname "$0")/tracereplay.py" play --dir "${NETEM_TRACE_DIR:?NETEM_TRACE_DIR is where traces.sh put the traces}" \
    --seed "$seed" --seconds "$(left "$((minutes * 60))")" --iface "$iface" --flows "$flows" \
    --delay "${NETEM_TRACE_DELAY:-40ms}" --limit "${NETEM_TRACE_LIMIT:-100}" --step-ms "${NETEM_TRACE_STEP_MS:-200}" \
    --events "$events" --group "$group" --arch "$arch" --names "${names[*]}" ${args[@]+"${args[@]}"} &
  pids+=("$!")
  wait "${pids[@]}"
}

if [ "$profile" = trace ]; then
  run_trace
  exit 0
fi

while [ "$(date +%s)" -lt "$end" ]; do
  phase clean "$(left "$clean")" "" ""
  [ "$(date +%s)" -ge "$end" ] && break
  phase loss "$(left "$slot")" "loss 2%" "loss 2%"
  [ "$(date +%s)" -ge "$end" ] && break
  phase burst "$(left "$slot")" "loss gemodel 1% 20% 100% 0%" "loss gemodel 1% 20% 100% 0%"
  [ "$(date +%s)" -ge "$end" ] && break
  phase bw "$(left "$slot")" "delay $delay rate ${bw_up}mbit limit 300" "delay $delay rate ${bw_down}mbit limit 300"
  [ "$(date +%s)" -ge "$end" ] && break
  phase outage "$(left "$outage")" "loss 100%" "loss 100%"
  [ "$(date +%s)" -ge "$end" ] && break
  phase recover "$(left "$recover")" "" ""
done

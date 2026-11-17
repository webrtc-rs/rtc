#!/usr/bin/env bash
# Fetch the recorded cellular links that `NETEM_PROFILE=trace` replays, and print the directory.
#
#   traces.sh [dir]        dir defaults to $TRACE_DIR, else $RUNNER_TEMP/soak-traces, else ${TMPDIR:-/tmp}/soak-traces
#
# The Mahimahi LTE driving traces (Verizon, AT&T, T-Mobile; uplink and downlink), at one pinned commit
# of github.com/ravinet/mahimahi. The repository is GPL-3.0, so the files are fetched at run time and
# never committed here (README.md, "Trace replay"). Each file is checked against the sha256 below: a
# file that is missing is downloaded, one that does not match (a cache gone wrong, a changed upstream)
# fails the script. Needs curl and sha256sum or shasum.
set -euo pipefail

commit=f1346c38c415abfc98626dd82450f49a57033603
dir=${1:-${TRACE_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/soak-traces}}

traces=(
  "ATT-LTE-driving.down 73c58f41bf7a3f0fac82810ca61307521be1cf6b77a0e98093fd340bddfd161f"
  "ATT-LTE-driving.up d58a640b9bccd131a421bff6eaf727aba324d9258b35009655bbf68e087b9b29"
  "TMobile-LTE-driving.down d48ff134fc29c36cc3c3dee203464246bd698f0faede42534a27b0cbe3057055"
  "TMobile-LTE-driving.up 556620f1c11a61c7766678b08325ef4fc8d1bd774fbc98fb96854ae3d3795b61"
  "Verizon-LTE-driving.down 79f1860b7b195496d7d388d090edb3eaa9cecbbdfb489bf4a5a73d95d8c2e7ce"
  "Verizon-LTE-driving.up 669840f626966d7490a27629d4227eb2a866d40f104a6217c53b3f4b5a207d1f"
)

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

mkdir -p "$dir"
for entry in "${traces[@]}"; do
  read -r name want <<<"$entry"
  file=$dir/$name
  if [ ! -f "$file" ]; then
    curl --fail --silent --show-error --location --retry 3 --output "$file.part" \
      "https://raw.githubusercontent.com/ravinet/mahimahi/$commit/traces/$name"
    mv "$file.part" "$file"
  fi
  got=$(sha256 "$file")
  if [ "$got" != "$want" ]; then
    echo "traces.sh: $file has sha256 $got, expected $want" >&2
    exit 1
  fi
done
echo "$dir"

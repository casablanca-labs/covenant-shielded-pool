#!/usr/bin/env bash
# Measures the one-command simulated re-run on test circuits: wall time and
# peak resident memory of `apnt-pool-ceremony rerun` and of the standalone
# verifier, per domain size. Test circuits only; never the pool action circuit.
#
# usage: scripts/measure-rerun.sh <ppot-dir> <out-dir>
#   <ppot-dir> holds PSE Perpetual Powers of Tau prepared files
#   ppot_0080_<power>.ptau; each is pinned by the SHA-256 this script computes
#   with shasum before use, and the pin is recorded in the output.
set -euo pipefail
ppot="$1"
out="$2"
here="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$out/bin"
export GOMAXPROCS="${GOMAXPROCS:-4}" GOPROXY=off
(cd "$here" && go build -o "$out/bin/" ./cmd/...)
cer="$out/bin/apnt-pool-ceremony"
ver="$out/bin/apnt-pool-ceremony-verify"
beacon=a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00

# label circuit size ptau-power
runs=(
  "chain-700 chain 700 10"
  "chain-12000 chain 12000 14"
  "chain-50000 chain 50000 16"
  "committed-50000 committed 50000 16"
  "chain-200000 chain 200000 18"
  "chain-200001-changed chain 200001 18"
)

printf 'label\tconstraints\tdomain\trerun_s\trerun_maxrss_mib\tverify_s\tverify_maxrss_mib\tstage_seconds\n' >"$out/results.tsv"
for r in "${runs[@]}"; do
  read -r label circuit size power <<<"$r"
  f="$ppot/ppot_0080_$power.ptau"
  pin="sha256:$(shasum -a 256 "$f" | cut -d' ' -f1)"
  "$cer" compile-test-circuit --circuit "$circuit" --size "$size" --out "$out/$label.r1cs" >"$out/$label.circuit.json"
  rm -rf "$out/$label"
  /usr/bin/time -l nice "$cer" rerun --ptau "$f" --ptau-pin "$pin" \
    --ptau-source "PSE Perpetual Powers of Tau, contribution 0080, prepared, ppot_0080_$power.ptau" \
    --r1cs "$out/$label.r1cs" --label "$label" --out "$out/$label" --ceremony-id "measure-$label" \
    --beacon "$beacon" --beacon-source "fixed measurement beacon (not a public randomness source)" \
    >"$out/$label.summary.json" 2>"$out/$label.rerun.time"
  /usr/bin/time -l nice "$ver" --transcript "$out/$label/transcript.json" --ptau "$f" --r1cs "$out/$label.r1cs" \
    --expect-phase1-pin "$pin" --expect-beacon "$beacon" >"$out/$label.verify.txt" 2>"$out/$label.verify.time"
  python3 - "$out" "$label" >>"$out/results.tsv" <<'PY'
import json, re, sys
out, label = sys.argv[1], sys.argv[2]
s = json.load(open(f"{out}/{label}.summary.json"))
def t(name):
    txt = open(f"{out}/{label}.{name}.time").read()
    real = float(re.search(r"([\d.]+) real", txt).group(1))
    rss = int(re.search(r"(\d+)\s+maximum resident set size", txt).group(1)) / 2**20
    return real, rss
rr, rm = t("rerun"); vr, vm = t("verify")
st = ",".join(f"{k}={v:.2f}" for k, v in s["seconds"].items())
print(f"{label}\t{s['circuit']['nbConstraints']}\t{s['report']['domainSize']}\t{rr:.2f}\t{rm:.0f}\t{vr:.2f}\t{vm:.0f}\t{st}")
PY
  # Keep only the small records; the phase-2 states and keys stay out.
  du -sh "$out/$label" | sed "s|^|$label ceremony dir: |" >>"$out/sizes.txt"
done
cat "$out/results.tsv"

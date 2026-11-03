#!/bin/bash
# ENG-443: the ceremony verifier's report under the two builds that matter.
#
# usage: scripts/test-verifier-build-identity.sh SCRATCH-DIR [CHECKOUT]
#
# CHECKOUT (default: the checkout holding this script) must be a clean git
# checkout or worktree. The script builds apnt-pool-ceremony-verify
#   (a) in place, in CHECKOUT, and
#   (b) in a fresh shared clone of CHECKOUT's HEAD (sparse: tools/apnt-pool-ceremony),
# runs both on one toy ceremony with --json and both anchors, and requires:
#   both  exit 0, VALID, transcriptSha256 = the SHA-256 of the transcript file;
#   (a)   in a git worktree (.git is a file): verifierBuild.status "unverified",
#         vcsRevision "" (Go records no VCS revision there); in a checkout with
#         a .git directory: "verified" with HEAD;
#   (b)   "verified", vcsRevision = HEAD, vcsModified "false", the ceremony
#         module, gnark v0.16.3, gnark-crypto v0.21.0.
# It writes go version -m of both binaries and both reports to SCRATCH-DIR.
# Toy ceremony only (INSECURE fixture), no proof. Exit 0 only if all hold.
set -euo pipefail
[[ $# -ge 1 && $# -le 2 ]] || { sed -n '2,22p' "$0" >&2; exit 2; }
scratch=$1
here="$(cd "$(dirname "$0")" && pwd -P)"
checkout="${2:-$(git -C "$here" rev-parse --show-toplevel)}"
checkout="$(cd "$checkout" && pwd -P)"
mod=tools/apnt-pool-ceremony
die() { echo "test-verifier-build-identity: $*" >&2; exit 1; }

mkdir -p "$scratch"
scratch="$(cd "$scratch" && pwd -P)"
[[ -z "$(ls -A "$scratch")" ]] || die "$scratch is not empty"
! git -C "$scratch" rev-parse --git-dir >/dev/null 2>&1 || die "$scratch is inside a git repository"
head="$(git -C "$checkout" rev-parse HEAD)"
[[ -z "$(git -C "$checkout" status --porcelain)" ]] || die "$checkout is modified"
if [[ -f $checkout/.git ]]; then kind=worktree; else kind=checkout; fi
echo "checkout $checkout ($kind) at $head" | tee "$scratch/summary.txt"

build() { (cd "$1/$mod" && GOPROXY=off GOFLAGS=-mod=readonly GODEBUG='' go build -o "$2/" "${@:3}"); }
build "$checkout" "$scratch/inplace" ./cmd/apnt-pool-ceremony ./cmd/apnt-pool-ceremony-verify
git clone --quiet --shared --no-checkout "$checkout" "$scratch/clone"
git -C "$scratch/clone" sparse-checkout set --cone "$mod"
git -C "$scratch/clone" checkout --quiet --detach "$head"
build "$scratch/clone" "$scratch/cloned" ./cmd/apnt-pool-ceremony-verify
for b in inplace cloned; do go version -m "$scratch/$b/apnt-pool-ceremony-verify" >"$scratch/$b.buildinfo.txt"; done

cer="$scratch/inplace/apnt-pool-ceremony"
toy="$scratch/toy"
mkdir -p "$toy"
"$cer" write-toy-ptau --power 5 --out "$toy/toy.ptau" >/dev/null
"$cer" compile-test-circuit --circuit committed --size 3 --out "$toy/committed.r1cs" >/dev/null
pin="$("$cer" hash --file "$toy/toy.ptau" | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')"
beacon=a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00
"$cer" rerun --ptau "$toy/toy.ptau" --ptau-pin "$pin" --ptau-source "toy fixture (INSECURE)" \
	--r1cs "$toy/committed.r1cs" --label committed --out "$toy/ceremony" --ceremony-id build-identity \
	--contributions 1 --beacon "$beacon" --beacon-source "fixed test beacon" >"$toy/rerun.json" 2>"$toy/rerun.stderr"

for b in inplace cloned; do
	status=0
	"$scratch/$b/apnt-pool-ceremony-verify" --transcript "$toy/ceremony/transcript.json" --ptau "$toy/toy.ptau" \
		--r1cs "$toy/committed.r1cs" --expect-phase1-pin "$pin" --expect-beacon "$beacon" --json \
		>"$scratch/$b.report.json" 2>"$scratch/$b.stderr" || status=$?
	echo "$b exit $status" >>"$scratch/summary.txt"
done

/usr/bin/python3 - "$scratch" "$kind" "$head" "$toy/ceremony/transcript.json" <<'PY' | tee -a "$scratch/summary.txt"
import hashlib, json, sys
scratch, kind, head, tpath = sys.argv[1:]
digest = hashlib.sha256(open(tpath, "rb").read()).hexdigest()
module = "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony"
exits = dict(l.split(" exit ") for l in open(f"{scratch}/summary.txt").read().splitlines() if " exit " in l)
failed = 0
def check(name, ok, detail):
    global failed
    print(("PASS " if ok else "FAIL ") + name + ": " + detail)
    failed += not ok
for b in ("inplace", "cloned"):
    try:
        r = json.load(open(f"{scratch}/{b}.report.json"))
    except Exception as e:
        check(b, False, f"report does not decode: {e}")
        continue
    vb = r.get("verifierBuild")
    check(f"{b} verdict", exits[b] == "0" and r.get("verdict") == "VALID", f"exit {exits[b]}, verdict {r.get('verdict')}")
    check(f"{b} transcriptSha256", r.get("transcriptSha256") == digest, f"{r.get('transcriptSha256')} vs file {digest}")
    if b == "cloned" or kind == "checkout":
        want = {"status": "verified", "module": module, "vcsRevision": head, "vcsModified": "false", "gnark": "v0.16.3", "gnarkCrypto": "v0.21.0"}
        check(f"{b} verifierBuild", isinstance(vb, dict) and all(vb.get(k) == v for k, v in want.items()) and "reason" not in vb, json.dumps(vb))
    else:
        check(f"{b} verifierBuild", isinstance(vb, dict) and vb.get("status") == "unverified" and vb.get("vcsRevision") == "" and bool(vb.get("reason")), json.dumps(vb))
print(f"failed: {failed}")
sys.exit(1 if failed else 0)
PY

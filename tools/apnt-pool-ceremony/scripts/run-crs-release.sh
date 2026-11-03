#!/usr/bin/env bash
# The once-per-ceremony CRS release gate (ENG-441, reviewed by REV-206): runs
# crscheck/cmd/apnt-pool-crscheck once on a sealed ceremony and archives its
# release report beside the ceremony's evidence.
#
# usage: scripts/run-crs-release.sh OUT-DIR \
#          --ceremony-dir DIR --r1cs F --ptau F --ceremony-report F \
#          --r1cs-sha256 H --ptau-sha256 H --pk-sha256 H --vk-sha256 H --ceremony-report-sha256 H
#
#   OUT-DIR            new or empty, outside any git repository: the archive
#                      destination beside the ceremony's evidence, such as
#                      <evidence>/crs-release. The release report
#                      (crs-release-report.json), its .sha256, the run's
#                      measurements and SHA256SUMS land here.
#   --ceremony-dir     the sealed ceremony: transcript.json, keys.meta.json,
#                      proving.key and verifying.key (copy-on-write clones are
#                      fine; nothing in it is written)
#   --ceremony-report  the ceremony verifier's archived --json output, such as
#                      run-phased.sh's results/verify.stdout
#   --*-sha256         out-of-band SHA-256 digests (the ceremony's published
#                      record, a wallet's pin); the gate requires each to
#                      equal the transcript's and the file's
#
# It refuses a modified checkout, and builds the gate in a fresh shared git
# clone of HEAD (sparse: tools/apnt-pool-ceremony). Go stamps a binary's VCS
# revision only when its repository has a .git directory; in a git worktree,
# where .git is a file, Go 1.26.5 records none, and the gate refuses a build
# with no revision (CHECKER_BUILD_UNVERIFIED). It then runs the gate
# exactly once through crscheck/scripts/run-crscheck.sh, which holds the
# machine-wide prover lock (fd 9 flock on /private/tmp/apnt-gnark-r2-proof-$UID.lock
# and ~/proof-scratch/.prover.lock), requires MIN_AVAILABLE_GIB (default 12)
# available, and runs with GOMAXPROCS=4, GOMEMLIMIT=9GiB, nice 10 and an RSS
# trip of RSS_TRIP_GIB (default 12). While the lock, the marker, another
# prover or the memory floor refuses (status 75: nothing ran), it waits
# WAIT_SECONDS (default 60) and retries, up to MAX_WAIT_SECONDS (default
# 21600). It never breaks or deletes a lock or marker it did not create.
#
# Exit status: the gate's (0 only for RELEASE-OK; see crscheck/release);
# 75 if the lock stayed busy past MAX_WAIT_SECONDS; 2 on a usage error; 1 if
# the build failed or no report was written.
set -euo pipefail

# Bash reads a script while it runs it; run from a private copy (ENG-331).
if [[ -z ${RUN_CRS_RELEASE_SELF:-} ]]; then
	self_copy="$(/usr/bin/mktemp -t run-crs-release)"
	/bin/cp "$0" "$self_copy"
	RUN_CRS_RELEASE_SELF=$self_copy RUN_CRS_RELEASE_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)" \
		RUN_CRS_RELEASE_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/$(basename "$0")" \
		exec /bin/bash "$self_copy" "$@"
fi
here=$RUN_CRS_RELEASE_HERE
bindir=""
cleanup() {
	rm -f "$RUN_CRS_RELEASE_SELF"
	[[ -z $bindir ]] || rm -rf "$bindir"
}
trap cleanup EXIT

usage() {
	sed -n '2,40p' "$RUN_CRS_RELEASE_SELF" >&2
	exit 2
}
die() {
	echo "run-crs-release: $*" >&2
	exit 1
}

[[ $# -ge 1 ]] || usage
out=$1
shift
ceremony="" r1cs="" ptau="" report="" r1cs_sha="" ptau_sha="" pk_sha="" vk_sha="" report_sha=""
while [[ $# -gt 0 ]]; do
	[[ $# -ge 2 ]] || usage
	case $1 in
	--ceremony-dir) ceremony=$2 ;;
	--r1cs) r1cs=$2 ;;
	--ptau) ptau=$2 ;;
	--ceremony-report) report=$2 ;;
	--r1cs-sha256) r1cs_sha=$2 ;;
	--ptau-sha256) ptau_sha=$2 ;;
	--pk-sha256) pk_sha=$2 ;;
	--vk-sha256) vk_sha=$2 ;;
	--ceremony-report-sha256) report_sha=$2 ;;
	*) usage ;;
	esac
	shift 2
done
for v in ceremony r1cs ptau report; do
	[[ -n ${!v} ]] || usage
done
for v in r1cs_sha ptau_sha pk_sha vk_sha report_sha; do
	[[ ${!v} =~ ^[0-9a-f]{64}$ ]] || { echo "run-crs-release: --${v%_sha}-sha256 must be 64 lowercase hex characters" >&2; exit 2; }
done
for f in "$ceremony/transcript.json" "$ceremony/keys.meta.json" "$ceremony/proving.key" "$ceremony/verifying.key" "$r1cs" "$ptau" "$report"; do
	[[ -f $f ]] || { echo "run-crs-release: $f is not a file" >&2; exit 2; }
done
wait_seconds=${WAIT_SECONDS:-60} max_wait=${MAX_WAIT_SECONDS:-21600}
[[ $wait_seconds =~ ^[1-9][0-9]*$ && $max_wait =~ ^[0-9]+$ ]] || { echo "run-crs-release: WAIT_SECONDS and MAX_WAIT_SECONDS must be integers" >&2; exit 2; }

mkdir -p "$out"
out="$(cd "$out" && pwd -P)"
[[ -z "$(ls -A "$out")" ]] || { echo "run-crs-release: $out is not empty" >&2; exit 2; }
! git -C "$out" rev-parse --git-dir >/dev/null 2>&1 || { echo "run-crs-release: $out is inside a git repository" >&2; exit 2; }

# ---- build, from a clone of HEAD ----
repo="$(git -C "$here" rev-parse --show-toplevel)"
head="$(git -C "$repo" rev-parse HEAD)"
[[ -z "$(git -C "$repo" status --porcelain)" ]] || die "the checkout $repo is modified; the gate is built only from a committed tree"
bindir="$(/usr/bin/mktemp -d -t crs-release-bin)"
bin="$bindir/apnt-pool-crscheck"
src="$bindir/src"
git clone --quiet --shared --no-checkout "$repo" "$src"
git -C "$src" sparse-checkout set --cone tools/apnt-pool-ceremony
git -C "$src" checkout --quiet --detach "$head"
(cd "$src/tools/apnt-pool-ceremony" && GOPROXY=off GOFLAGS=-mod=readonly GODEBUG='' go build -o "$bin" ./crscheck/cmd/apnt-pool-crscheck) || die "the build failed"
[[ -x $bin ]] || die "the build produced no binary"
go version -m "$bin" >"$out/binary-buildinfo.txt"
grep -q "vcs.revision=$head\$" "$out/binary-buildinfo.txt" || die "the binary does not record HEAD $head"
grep -q 'vcs.modified=false$' "$out/binary-buildinfo.txt" || die "the binary does not record an unmodified tree"

RUN_OUT=$out RUN_HEAD=$head RUN_REPO=$repo RUN_BIN=$bin RUN_SCRIPT=$RUN_CRS_RELEASE_SCRIPT RUN_SELF=$RUN_CRS_RELEASE_SELF \
	RUN_CEREMONY=$ceremony RUN_R1CS=$r1cs RUN_PTAU=$ptau RUN_REPORT=$report RUN_R1CS_SHA=$r1cs_sha RUN_PTAU_SHA=$ptau_sha \
	RUN_PK_SHA=$pk_sha RUN_VK_SHA=$vk_sha RUN_REPORT_SHA=$report_sha \
	RUN_MIN=${MIN_AVAILABLE_GIB:-12} RUN_RSS=${RSS_TRIP_GIB:-12} RUN_WAIT=$wait_seconds RUN_MAX_WAIT=$max_wait \
	/usr/bin/python3 - "$out/harness.json" <<'PY'
import hashlib, json, os, subprocess, sys
e = os.environ
def sh(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout.strip()
def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()
json.dump({
    "script": "tools/apnt-pool-ceremony/scripts/run-crs-release.sh",
    "scriptSha256": sha(e["RUN_SELF"]),
    "headCommit": e["RUN_HEAD"], "repo": e["RUN_REPO"], "outDir": e["RUN_OUT"],
    "startedUtc": sh("/bin/date", "-u", "+%Y-%m-%dT%H:%M:%SZ"),
    "binarySha256": sha(e["RUN_BIN"]),
    "binaryNote": "built in a fresh shared git clone of headCommit (sparse: tools/apnt-pool-ceremony) in a temporary directory, removed after the run; the digest is path-dependent (Go embeds absolute paths)",
    "inputs": {"ceremonyDir": e["RUN_CEREMONY"], "r1cs": e["RUN_R1CS"], "ptau": e["RUN_PTAU"], "ceremonyReport": e["RUN_REPORT"]},
    "expected": {"r1csSha256": e["RUN_R1CS_SHA"], "ptauSha256": e["RUN_PTAU_SHA"], "provingKeySha256": e["RUN_PK_SHA"],
                 "verifyingKeySha256": e["RUN_VK_SHA"], "ceremonyReportSha256": e["RUN_REPORT_SHA"]},
    "goVersion": sh("go", "version"),
    "hwMemsizeBytes": int(sh("/usr/sbin/sysctl", "-n", "hw.memsize")),
    "cpu": sh("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"),
    "os": sh("/usr/bin/sw_vers", "-productVersion"),
    "thresholds": {"minAvailableGiB": int(e["RUN_MIN"]), "rssTripGiB": int(e["RUN_RSS"]), "waitSeconds": int(e["RUN_WAIT"]),
                   "maxWaitSeconds": int(e["RUN_MAX_WAIT"])},
}, open(sys.argv[1], "w"), indent=2)
PY

# ---- the gate, once, under the lock ----
rep="$out/crs-release-report.json"
deadline=$(($(/bin/date +%s) + max_wait))
status=0
while :; do
	status=0
	MIN_AVAILABLE_GIB=${MIN_AVAILABLE_GIB:-12} RSS_TRIP_GIB=${RSS_TRIP_GIB:-12} \
		"$here/crscheck/scripts/run-crscheck.sh" "$out/run" "$bin" \
		--pk "$ceremony/proving.key" --vk "$ceremony/verifying.key" --r1cs "$r1cs" --ptau "$ptau" \
		--transcript "$ceremony/transcript.json" --keys-meta "$ceremony/keys.meta.json" --ceremony-report "$report" \
		--r1cs-sha256 "$r1cs_sha" --ptau-sha256 "$ptau_sha" --pk-sha256 "$pk_sha" --vk-sha256 "$vk_sha" \
		--ceremony-report-sha256 "$report_sha" --out "$rep" || status=$?
	# 75 from the lock wrapper means nothing ran: no sample, no report.
	if ((status == 75)) && [[ -z "$(ls -A "$out/run" 2>/dev/null)" && ! -e $rep ]]; then
		(($(/bin/date +%s) < deadline)) || { echo "run-crs-release: the prover lock stayed busy for $max_wait s; nothing ran" >&2; exit 75; }
		echo "run-crs-release: waiting $wait_seconds s for the prover lock ($(/bin/date))" >&2
		sleep "$wait_seconds"
		continue
	fi
	break
done

[[ -f $rep && -f $rep.sha256 ]] || { echo "run-crs-release: no report was written (status $status); see $out/run" >&2; exit $((status == 0 ? 1 : status)); }
(cd "$out" && /usr/bin/shasum -a 256 -c crs-release-report.json.sha256 >/dev/null) || die "the report does not match its .sha256"
(cd "$out" && /usr/bin/find . -type f ! -name SHA256SUMS -print0 | /usr/bin/sort -z | /usr/bin/xargs -0 /usr/bin/shasum -a 256 >SHA256SUMS)
echo "run-crs-release: gate exit $status; $(cat "$out/run/stdout.txt" 2>/dev/null)"
echo "run-crs-release: archived in $out"
exit "$status"

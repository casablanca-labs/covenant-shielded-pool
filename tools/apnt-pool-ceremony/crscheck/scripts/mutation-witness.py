#!/usr/bin/env python3
"""RESEARCH PROTOTYPE, NOT REVIEWED (ARCH-238, run R-393; the release gate's
mutations ENG-441, run R-399; the mask origin, report binding and code
pins ENG-447, run R-415).

Mutation witness for crscheck and its release gate: copies the ceremony
module to a scratch directory, disables or corrupts one check at a time, and
requires the tests to fail for every mutation (and to pass unmutated). A
mutation in crscheck/ runs `go test ./crscheck/...`; one in release/ or cmd/
runs the release and command packages' tests. A build failure is not a
catch. Toy ceremonies and toy proves only; run it under with-prover-lock.sh.

usage: mutation-witness.py SCRATCH-DIR
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = os.path.abspath(os.path.join(HERE, "..", ".."))

# (name, file, old, new): each must occur exactly once.
MUTATIONS = [
    ("z-order-not-bit-reversed", "check.go",
     "k := int(bitRev(uint64(i), logN))", "k := i + 0*logN"),
    ("ifft-output-left-bit-reversed", "check.go",
     "\t\tfft.BitReverse(v)\n", "\n"),
    ("a-query-always-passes", "check.go",
     "Pass: ks.aAll.Equal(&p.sA)", "Pass: true"),
    ("b1-query-always-passes", "check.go",
     "Pass: ks.b1All.Equal(&p.sB)", "Pass: true"),
    ("b2-query-always-passes", "check.go",
     "Name: CheckBQueryG2, ZK: true, Pass: pairingOne(", "Name: CheckBQueryG2, ZK: true, Pass: true || pairingOne("),
    ("k-query-always-passes", "check.go",
     "Name: CheckKQuery, ZK: true, Pass: pairingOne(", "Name: CheckKQuery, ZK: true, Pass: true || pairingOne("),
    ("z-query-always-passes", "check.go",
     "Name: CheckZQuery, ZK: true, Pass: pairingOne(", "Name: CheckZQuery, ZK: true, Pass: true || pairingOne("),
    ("basis-always-passes", "check.go",
     "Name: CheckCommitBase, ZK: true, Detail: tag, Pass: pairingOne(", "Name: CheckCommitBase, ZK: true, Detail: tag, Pass: true || pairingOne("),
    ("sigma-always-passes", "check.go",
     "Name: CheckCommitSig, ZK: true, Detail: tag, Pass: pairingOne(", "Name: CheckCommitSig, ZK: true, Detail: tag, Pass: true || pairingOne("),
    ("mask-zero-ignored", "check.go",
     "if ck.Basis[m].IsInfinity() {", "if false && ck.Basis[m].IsInfinity() {"),
    ("mask-detection-off", "layout.go",
     "l.masks[k] = append(l.masks[k], p)", "_ = p"),
    ("delta-zero-ignored", "check.go",
     '"[δ]₁": pk.G1.Delta.IsInfinity(), "[δ]₂": pk.G2.Delta.IsInfinity(),', '"[δ]₁": false, "[δ]₂": false,'),
    ("beta-g1-g2-always-passes", "check.go",
     "Name: CheckBeta, ZK: true, Pass: pairingOne(", "Name: CheckBeta, ZK: true, Pass: true || pairingOne("),
    ("domain-always-passes", "check.go",
     "if bad := checkDomain(&pk.Domain, p.n); bad != \"\" {", "if bad := checkDomain(&pk.Domain, p.n); false && bad != \"\" {"),
    ("tau-in-domain-ignored", "check.go",
     "Pass: !srs.TauG1[n].Equal(&g1)}", "Pass: true}"),
    ("srs-powers-geometric-ignored", "check.go",
     "\treturn fail(\"the [τᵏ]₁ are not a geometric sequence with ratio τ\")\n", "\t_ = 0\n"),
    ("ptau-pin-ignored", "srs.go",
     'if wantSHA256 == "" || first != wantSHA256 {', "if false {"),
    ("committed-class-to-vk", "layout.go",
     "\t\t\tdefault:\n\t\t\t\tdst = &s.wComm[l.commitOf[j]][i]", "\t\t\tdefault:\n\t\t\t\tdst = &s.wVK[i]"),

    # ENG-441: the ancillary negative controls.
    ("vk-k-control-noop", "controls.go",
     "return addG1(&vk.G1.K[vi])", "return func() {}"),
    ("pk-alpha-control-noop", "controls.go",
     "func() { return addG1(&pk.G1.Alpha) },", "func() { return func() {} },"),

    # ENG-441: the release gate, one refusal at a time.
    ("release-ancillary-ignored", "release/release.go",
     "if len(failedOther) > 0 {", "if false && len(failedOther) > 0 {"),
    ("release-malformed-ignored", "release/release.go",
     "if len(failedZK) > 0 || clean.Verdict != crscheck.VerdictWellFormed {", "if false {"),
    ("release-incomplete-ignored", "release/release.go",
     "if len(missing) > 0 {", "if false && len(missing) > 0 {"),
    ("release-control-not-fired-ignored", "release/release.go",
     "if len(notFired) > 0 {", "if false && len(notFired) > 0 {"),
    ("release-untargeted-ignored", "release/release.go",
     "if len(untargeted) > 0 {", "if false && len(untargeted) > 0 {"),
    ("release-restored-ignored", "release/release.go",
     "if restored == nil || restored.Verdict != crscheck.VerdictWellFormed || len(restored.Failed) > 0 {", "if false {"),
    ("release-controls-not-run", "release/release.go",
     "controls, err := plan.Controls(pk)", "controls, err := []crscheck.Control(nil), error(nil)"),
    ("release-ceremony-verdict-ignored", "release/release.go",
     "if !rep.Authoritative() {", "if false {"),
    ("release-report-digest-ignored", "release/release.go",
     "if rec.SHA256 != rec.Expected {", "if false {"),
    ("release-report-content-ignored", "release/release.go",
     "if d := fieldDiff(rep, want); len(d) > 0 {", "if d := fieldDiff(rep, want); false && len(d) > 0 {"),
    ("release-key-metadata-ignored", "release/release.go",
     "if want := transcript.MetadataFor(t); m != want {", "if want := transcript.MetadataFor(t); false && m != want {"),
    ("release-status-ignored", "release/release.go",
     "if t.Status != transcript.StatusSealed || t.Keys == nil || t.Beacon == nil {", "if t.Keys == nil || t.Beacon == nil {"),
    ("release-labels-ignored", "release/release.go",
     "if err := t.CheckLabels(); err != nil {", "if err := t.CheckLabels(); false && err != nil {"),
    ("release-curve-ignored", "release/release.go",
     'if t.Tool.Curve != "bn254" || t.Tool.Backend != "groth16" {', "if false {"),
    ("release-encoding-ignored", "release/release.go",
     "if t.Keys.ProvingKey.Encoding != transcript.ProvingKeyEncoding || t.Keys.VerifyingKey.Encoding != transcript.VerifyingKeyEncoding {", "if false {"),
    ("release-gnark-version-ignored", "release/release.go",
     "if t.Tool.Gnark != crscheck.GnarkVersion || t.Tool.GnarkCrypto != crscheck.GnarkCryptoVersion {", "if false {"),
    ("release-record-r1cs-ignored", "release/release.go",
     "if in.R1CSSHA256 != t.Circuit.R1CSSHA256 {", "if false {"),
    ("release-record-ptau-ignored", "release/release.go",
     'if t.Phase1.Pin.Algorithm != "sha256" || in.PtauSHA256 != t.Phase1.Pin.Digest {', "if false {"),
    ("release-record-vk-ignored", "release/release.go",
     "if in.VerifyingKeySHA256 != t.Keys.VerifyingKey.SHA256 {", "if false {"),
    ("release-record-pk-ignored", "release/release.go",
     "if in.ProvingKeySHA256 != t.Keys.ProvingKey.SHA256 {", "if false {"),
    ("release-file-digest-ignored", "release/release.go",
     "if first != want {", "if false {"),
    ("release-second-pass-ignored", "release/release.go",
     "if second := hex.EncodeToString(h.Sum(nil)); second != first {", "if second := hex.EncodeToString(h.Sum(nil)); false && second != first {"),
    ("release-decoder-count-ignored", "release/release.go",
     "if _, err := br.ReadByte(); err != io.EOF || used != n {", "if _, err := br.ReadByte(); err != io.EOF || used < 0 {"),
    ("release-trailing-read-ignored", "release/release.go",
     "if _, err := br.ReadByte(); err != io.EOF || used != n {", "if _, _ = br.ReadByte(); used != n {"),
    ("release-build-check-ignored", "release/release.go",
     "if st.Checker, err = checkerOf(bi, ok); err != nil {", "if st.Checker, err = checkerOf(bi, ok); false && err != nil {"),
    ("release-statement-digest-ignored", "release/release.go",
     "if d != r.StatementSHA256 {", "if false && d != r.StatementSHA256 {"),
    ("release-refused-exits-zero", "release/release.go",
     "return ExitOf(r.Statement.Refusals[0].Code)", "return 0"),
    ("build-main-module-ignored", "release/build.go",
     "if bi.Main.Path != MainModule {", "if false {"),
    ("build-replace-ignored", "release/build.go",
     "case rec.Replace != nil:", "case false:"),
    ("build-version-ignored", "release/build.go",
     "case rec.Version != w.version:", "case false:"),
    ("build-revision-ignored", "release/build.go",
     "if !vcsRevision.MatchString(c.VCSRevision) {", "if false {"),
    ("build-modified-ignored", "release/build.go",
     'if c.VCSModified != "false" {', "if false {"),
    ("cli-exits-zero", "cmd/apnt-pool-crscheck/main.go",
     "return rep.ExitStatus()", "return 0"),
    ("cli-usage-unchecked", "cmd/apnt-pool-crscheck/main.go",
     "if err := in.Validate(); err != nil {", "if err := in.Validate(); false && err != nil {"),

    # ENG-447: the masks' origin and the schedule (origin.go), one condition
    # at a time.
    ("origin-level-count-ignored", "origin.go",
     "if len(r.Levels) != len(s.levels) {", "if false {"),
    ("origin-level-equality-ignored", "origin.go",
     "if !slices.Equal(r.Levels[k], s.levels[k]) {", "if !slices.Equal(r.Levels[k], r.Levels[k]) {"),
    ("origin-double-set-ignored", "origin.go",
     "case t.level[i] != constraint.LevelUnset:", "case false:"),
    ("origin-lookup-cache-reused", "origin.go",
     "out[i] = &constraint.BlueprintLookupHint[constraint.U64]{EntriesCalldata: b.EntriesCalldata}", "out[i] = b"),
    ("origin-unknown-blueprint-accepted", "origin.go",
     'return nil, fmt.Errorf("blueprint %d has type %T, which the schedule replay does not know", i, b)', "out[i] = b"),
    ("origin-input-wire-accepted", "origin.go",
     'return fmt.Sprintf("wire %d is an input, not the output of an instruction", w)', 'return ""'),
    ("origin-not-a-hint-accepted", "origin.go",
     'return fmt.Sprintf("wire %d is set by instruction %d, a %T, not a hint", w, set, r.Blueprints[pi.BlueprintID])', 'return ""'),
    ("origin-randomize-id-ignored", "origin.go",
     "case h.HintID != RandomizeHintID:", "case false:"),
    ("origin-inputs-ignored", "origin.go",
     "case len(h.Inputs) != 0:", "case false:"),
    ("origin-outputs-ignored", "origin.go",
     "case h.OutputRange.Start != w || h.OutputRange.End != w+1:", "case false:"),
    ("origin-order-ignored", "origin.go",
     "if o != set && s.level[o] <= s.level[set] {", "if false {"),
    ("origin-name-record-ignored", "origin.go",
     "if !recorded || record != RandomizeHintName {", "if false {"),
    ("origin-untrusted-schedule-used", "origin.go",
     'case s.problem != "":', "case false:"),
    ("origin-no-mask-accepted", "origin.go",
     "case len(masks[k]) == 0:", "case false:"),
    ("origin-not-in-prepare", "check.go",
     "\tp.results = append(p.results, origin...)\n", "\t_ = origin\n"),
    ("pick-returns-avoided-index", "controls.go",
     "\t\ti = (i + 1) % n\n\t}\n\treturn -1\n", "\t\ti = (i + 1) % n\n\t}\n\treturn (n * 3) / 7\n"),
    ("controls-basis-guard-ignored", "controls.go",
     "p.Masks[0]); ci >= 0 {", "p.Masks[0]); true {"),

    # ENG-447: the verifier output's transcript digest and build (REV-198 H2).
    ("release-report-unbound-ignored", "release/release.go",
     'rep.TranscriptSHA256 == "" || rep.TranscriptSHA256 != parsed {', 'rep.TranscriptSHA256 == "" {'),
    ("release-verifier-build-ignored", "release/release.go",
     'if why := unverifiedBuild(rep.VerifierBuild); why != "" {', 'if why := unverifiedBuild(rep.VerifierBuild); false && why != "" {'),
    ("release-build-status-ignored", "release/release.go",
     'if b.Status != verifier.BuildVerified || b.Reason != "" {', "if false {"),
    ("release-build-module-ignored", "release/release.go",
     "if b.Module != MainModule {", "if false {"),
    ("release-build-revision-ignored", "release/release.go",
     "if !vcsRevision.MatchString(b.VCSRevision) {", "if false {"),
    ("release-build-modified-ignored", "release/release.go",
     'if b.VCSModified != "false" {', "if false {"),
    ("release-build-gnark-ignored", "release/release.go",
     "if b.Gnark != crscheck.GnarkVersion || b.GnarkCrypto != crscheck.GnarkCryptoVersion {", "if false {"),
    ("release-new-fields-diffed", "release/release.go",
     "want.Verdict, want.Anchors, want.TranscriptSHA256, want.VerifierBuild = rep.Verdict, rep.Anchors, rep.TranscriptSHA256, rep.VerifierBuild",
     "want.Verdict, want.Anchors = rep.Verdict, rep.Anchors"),

    # REV-198 H3: the reviewer's two code-table mutations.
    ("code-r1cs-renamed", "release/codes.go",
     'CodeR1CSDigest Code = "R1CS_DIGEST_MISMATCH"', 'CodeR1CSDigest Code = "R1CS_DIGEST_CHANGED"'),
    ("code-r1cs-exit-moved", "release/codes.go",
     "{CodeR1CSDigest, 17},", "{CodeR1CSDigest, 26},"),
]


def packages(fname):
    if fname.startswith("release/") or fname.startswith("cmd/"):
        return ["./crscheck/release/", "./crscheck/cmd/..."]
    return ["./crscheck/..."]


def run_tests(root, pkgs=("./crscheck/...",)):
    env = dict(os.environ, GOMAXPROCS=os.environ.get("GOMAXPROCS", "4"), GOFLAGS="-count=1")
    # -timeout: a mutation that makes a test hang fails its package without
    # a named failing test, so it counts as NOT CAUGHT rather than stalling.
    p = subprocess.run(["go", "test", "-timeout", "300s", *pkgs], cwd=root, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
    return p.returncode, p.stdout


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    scratch = os.path.abspath(sys.argv[1])
    root = os.path.join(scratch, "apnt-pool-ceremony")
    if os.path.exists(root):
        shutil.rmtree(root)
    shutil.copytree(MODULE, root, ignore=shutil.ignore_patterns("bin", ".work"))

    code, out = run_tests(root)
    print(f"unmutated: exit {code}")
    if code != 0:
        print(out)
        return 1
    bad = 0
    for name, fname, old, new in MUTATIONS:
        path = os.path.join(root, "crscheck", fname)
        src = open(path, encoding="utf-8").read()
        if src.count(old) != 1:
            print(f"{name}: pattern occurs {src.count(old)} times, want 1")
            bad += 1
            continue
        open(path, "w", encoding="utf-8").write(src.replace(old, new))
        try:
            code, out = run_tests(root, packages(fname))
        finally:
            open(path, "w", encoding="utf-8").write(src)
        failing = sorted({l.split()[2] for l in out.splitlines() if l.startswith("--- FAIL:")})
        # A build failure is not a catch: the tests must run and fail.
        verdict = "caught" if code != 0 and failing else "NOT CAUGHT"
        if verdict != "caught":
            bad += 1
        print(f"{name}: exit {code}, {verdict}; failing tests: {', '.join(failing) or '(build or none)'}")
    print(f"{len(MUTATIONS) - bad} of {len(MUTATIONS)} mutations caught")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

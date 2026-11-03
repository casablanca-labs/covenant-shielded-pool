#!/usr/bin/env python3
"""Mutation witnesses for the ceremony tooling's checks.

Each mutation disables one check in a scratch copy of the module (the working
tree is never touched) and runs the tests that should notice. A mutation is
KILLED when those tests fail. The unmutated copy must pass the same tests
first, so a kill is never a pre-existing failure. Exit status 0 only if every
mutation is killed.

The copy holds this module only, so transcript's TestToolRecordMatchesGoMod,
which reads ../apnt-pool-action-circuit/go.mod, fails in it (REV-200's
trap). No mutation targets that test, and each mutation's tests must pass
unmutated in the same copy first, so an environment failure shows as
BASELINE-FAILED, never as a kill.

Deliberately absent: disabling the contribution shape guard. Without it the
negative test hands gnark's decoder a length prefix near 2^31 and the decoder
allocates from it -- the resource hazard the guard exists for, and not
something to run on a shared machine.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (id, file, exact original text, replacement, package, test regexp). The
# original and replacement may instead be tuples of equal length, for a revert
# that must touch several places in the file; each original must occur once.
MUTATIONS = [
    ("M1-phase1-pin", "ptau/pin.go",
     "\tcase AlgSHA256:\n\t\treturn p.Digest == sha\n",
     "\tcase AlgSHA256:\n\t\treturn true || p.Digest == sha\n",
     "./ptau/", "^TestPhase1HashMismatchRefused$"),
    ("M2-phase1-same-ratio", "ptau/validate.go",
     "if err := cryptompc.SameRatioMany(c.G1.Tau, c.G2.Tau, c.G1.AlphaTau, c.G1.BetaTau); err != nil {",
     "if err := cryptompc.SameRatioMany(c.G1.Tau, c.G2.Tau, c.G1.AlphaTau, c.G1.BetaTau); false && err != nil {",
     "./ptau/", "^TestImportRefusesBrokenPowersOfTau$"),
    ("M3-coordinator-verify", "coordinator/coordinator.go",
     "if err := c.current.Verify(next); err != nil {",
     "if err := error(nil); err != nil {",
     "./coordinator/", "^TestCoordinatorRefusesTamperedContribution$"),
    ("M4-coordinator-inner-chain", "coordinator/coordinator.go",
     "if !bytes.Equal(next.Challenge, prevDigest) {",
     "if false && !bytes.Equal(next.Challenge, prevDigest) {",
     "./coordinator/", "^TestCoordinatorRefusesSkippedStep$"),
    ("M5-verifier-record-chain", "verifier/verifier.go",
     "if rec.Challenge != prevSHA {",
     "if false && rec.Challenge != prevSHA {",
     "./verifier/", "^TestRefusesEditedChallengeRecord$"),
    ("M6-verifier-inner-chain", "verifier/verifier.go",
     "if !bytes.Equal(next.Challenge, prevRaw) {",
     "if false && !bytes.Equal(next.Challenge, prevRaw) {",
     "./verifier/", "^(TestRefusesSkippedStep|TestSimulatedNeverReportedMultiParty)$"),
    ("M7-verifier-sealed-keys", "verifier/verifier.go",
     "if pkSHA != t.Keys.ProvingKey.SHA256 || vkSHA != t.Keys.VerifyingKey.SHA256 {",
     "if false {",
     "./verifier/", "^TestRefusesWrongBeacon$"),
    ("M8-verifier-r1cs-digest", "verifier/verifier.go",
     "if r1csSHA != t.Circuit.R1CSSHA256 {",
     "if false && r1csSHA != t.Circuit.R1CSSHA256 {",
     "./verifier/", "^TestRefusesDifferentR1CS$"),
    ("M9-root-binds-provenance", "transcript/transcript.go",
     "for _, s := range []string{Format, ceremonyID, string(p)} {",
     "for _, s := range []string{Format, ceremonyID} {",
     "./verifier/", "^(TestSimulatedNeverReportedMultiParty|TestFullyConsistentRelabelRefused)$"),
    # The same mutation against the single-shot relabel alone: without the
    # root binding, nothing else stops a fully consistent relabel.
    ("M9b-root-binds-provenance-full-relabel", "transcript/transcript.go",
     "for _, s := range []string{Format, ceremonyID, string(p)} {",
     "for _, s := range []string{Format, ceremonyID} {",
     "./verifier/", "^TestFullyConsistentRelabelRefused$"),
    ("M10-no-automated-in-multiparty", "transcript/provenance.go",
     "\t\tif p == PermissionlessMultiParty {\n\t\t\treturn failure.New(failure.ProvenanceConflict, \"an automated",
     "\t\tif false {\n\t\t\treturn failure.New(failure.ProvenanceConflict, \"an automated",
     "./coordinator/", "^TestMultiPartyCeremonyRefusesAutomatedContributions$"),
    # REV-148 fixes (ENG-333/334/335): each reverts one fix exactly and
    # requires its negative test to fail.
    ("M11-probe-version", "ptau/probe.go",
     "\tif err := checkVersion(rep.Version); err != nil {\n\t\treturn rep, err\n\t}\n",
     "",
     "./ptau/", "^TestProbeRefusesUnsupportedVersion$"),
    ("M11b-probe-version-cli", "ptau/probe.go",
     "\tif err := checkVersion(rep.Version); err != nil {\n\t\treturn rep, err\n\t}\n",
     "",
     "./cmd/apnt-pool-ceremony/", "^TestPhase1ProbeRefusesUnsupportedVersion$"),
    ("M12-valid-needs-anchors", "verifier/verifier.go",
     "\tverdict := VerdictUnanchored\n",
     "\tverdict := VerdictValid\n",
     "./verifier/", "^TestValidRequiresBothAnchors$"),
    ("M12b-valid-needs-anchors-cli", "verifier/verifier.go",
     "\tverdict := VerdictUnanchored\n",
     "\tverdict := VerdictValid\n",
     "./cmd/apnt-pool-ceremony-verify/", "^TestExitStatusRequiresBothAnchors$"),
    ("M12c-unanchored-exit-status", "cmd/apnt-pool-ceremony-verify/main.go",
     "\t\texit = 3\n",
     "\t\texit = 0\n",
     "./cmd/apnt-pool-ceremony-verify/", "^TestExitStatusRequiresBothAnchors$"),
    ("M13-key-metadata-trailing", "transcript/transcript.go",
     "\tvar m KeyMetadata\n\tif err := decodeStrict(b, &m, failure.KeyMetadataMalformed, \"key metadata\"); err != nil {\n\t\treturn nil, err\n\t}\n",
     "\tdec := json.NewDecoder(bytes.NewReader(b))\n\tdec.DisallowUnknownFields()\n\tvar m KeyMetadata\n\tif err := dec.Decode(&m); err != nil {\n\t\treturn nil, failure.Wrap(failure.KeyMetadataMalformed, err, \"decoding key metadata\")\n\t}\n",
     "./transcript/", "^TestLoadKeyMetadataRejectsTrailingData$"),
    ("M13b-key-metadata-trailing-verifier", "transcript/transcript.go",
     "\tvar m KeyMetadata\n\tif err := decodeStrict(b, &m, failure.KeyMetadataMalformed, \"key metadata\"); err != nil {\n\t\treturn nil, err\n\t}\n",
     "\tdec := json.NewDecoder(bytes.NewReader(b))\n\tdec.DisallowUnknownFields()\n\tvar m KeyMetadata\n\tif err := dec.Decode(&m); err != nil {\n\t\treturn nil, failure.Wrap(failure.KeyMetadataMalformed, err, \"decoding key metadata\")\n\t}\n",
     "./verifier/", "^TestRefusesTamperedKeysAndMetadata$"),
    # The transcript's earlier check, json.Decoder.More, misses a stray "}".
    # ENG-443 moved this code into LoadDigest (three results); same mutation.
    ("M14-transcript-trailing-more", "transcript/transcript.go",
     "\tvar t Transcript\n\tif err := decodeStrict(b, &t, failure.TranscriptFormat, \"transcript\"); err != nil {\n\t\treturn nil, \"\", err\n\t}\n",
     "\tdec := json.NewDecoder(bytes.NewReader(b))\n\tdec.DisallowUnknownFields()\n\tvar t Transcript\n\tif err := dec.Decode(&t); err != nil {\n\t\treturn nil, \"\", failure.Wrap(failure.TranscriptFormat, err, \"decoding transcript\")\n\t}\n\tif dec.More() {\n\t\treturn nil, \"\", failure.New(failure.TranscriptFormat, \"trailing data after the transcript\")\n\t}\n",
     "./transcript/", "^TestLoadTranscriptRejectsTrailingData$"),
    ("M15-message-header-trailing", "transcript/state.go",
     "\tif err := decodeStrict(rest[:n], &h, failure.MessageMalformed, \"message header\"); err != nil {\n\t\treturn h, nil, err\n\t}\n",
     "\tdec := json.NewDecoder(bytes.NewReader(rest[:n]))\n\tdec.DisallowUnknownFields()\n\tif err := dec.Decode(&h); err != nil {\n\t\treturn h, nil, failure.Wrap(failure.MessageMalformed, err, \"decoding message header\")\n\t}\n",
     "./transcript/", "^TestMessageHeaderRejectsTrailingData$"),
    # REV-152 fixes (ENG-352/353): each reverts one fix exactly.
    ("M16-probe-section-order", "ptau/probe.go",
     ("\tpos := int64(12)\n\tseen := map[uint32]bool{}\n",
      "\t\tif err := checkSectionEntry(typ, seen); err != nil {\n\t\t\treturn rep, err\n\t\t}\n"),
     ("\tpos := int64(12)\n",
      "\t\tif _, dup := offsets[typ]; dup && typ <= secBetaG2 {\n\t\t\treturn nil, failure.New(failure.Phase1Format, \"section %d appears twice\", typ)\n\t\t}\n"),
     "./ptau/", "^TestProbeRefusesSectionBeforeHeader$"),
    ("M16b-probe-section-order-cli", "ptau/probe.go",
     ("\tpos := int64(12)\n\tseen := map[uint32]bool{}\n",
      "\t\tif err := checkSectionEntry(typ, seen); err != nil {\n\t\t\treturn rep, err\n\t\t}\n"),
     ("\tpos := int64(12)\n",
      "\t\tif _, dup := offsets[typ]; dup && typ <= secBetaG2 {\n\t\t\treturn nil, failure.New(failure.Phase1Format, \"section %d appears twice\", typ)\n\t\t}\n"),
     "./cmd/apnt-pool-ceremony/", "^TestPhase1ProbeRefusesUnsupportedVersion$"),
    ("M17-unanchored-output-guard", "cmd/apnt-pool-ceremony-verify/main.go",
     "\treturn bytes.ReplaceAll(b, []byte(\"VALID\"), []byte(`VAL" + chr(92) + "u0049D`))\n",
     "\treturn b\n",
     "./cmd/apnt-pool-ceremony-verify/", "^TestUnanchoredOutputFreeOfValidUnderAdversarialNames$"),
    # REV-154 fix (ENG-357): the size limit back after the whole-file read.
    ("M18-real-file-read-after-limit", "ptau/ptau_test.go",
     "\tif size > maxWholeRead {\n\t\tt.Logf(\"reorder negative skipped: %d bytes exceeds the %d-byte whole-read limit\", size, maxWholeRead)\n\t\treturn false\n\t}\n\twhole, err := read()\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n",
     "\twhole, err := read()\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif int64(len(whole)) > maxWholeRead {\n\t\treturn false\n\t}\n",
     "./ptau/", "^TestReorderNegativeSizeGuardPrecedesRead$"),
    ("M19-verifier-tool-record", "verifier/verifier.go",
     "if t.Tool != transcript.CurrentTool {",
     "if false && t.Tool != transcript.CurrentTool {",
     "./verifier/", "^TestRefusesOtherGnarkToolRecord$"),
    # ENG-331 phased re-run: each reverts one check of the coordinator's work
    # files or the seal phase and requires its negative test to fail.
    ("M20-work-file-digest", "coordinator/work.go",
     "\tif int64(len(b)) != ref.Length || transcript.Digest(b) != ref.SHA256 {",
     "\tif false {",
     "./coordinator/", "^TestOpenRefusesDamagedWork$"),
    ("M21-work-record-binding", "coordinator/work.go",
     "\treturn w.Format == WorkFormat &&",
     "\treturn true || w.Format == WorkFormat &&",
     "./coordinator/", "^TestOpenRefusesDamagedWork$"),
    ("M22-evaluations-digest", "coordinator/work.go",
     "\t\tif h.n != ref.Length || hex.EncodeToString(h.w.(hash.Hash).Sum(nil)) != ref.SHA256 {",
     "\t\tif false && (h.n != ref.Length || hex.EncodeToString(h.w.(hash.Hash).Sum(nil)) != ref.SHA256) {",
     "./coordinator/", "^TestOpenRefusesDamagedWork$"),
    ("M23-open-for-seal-phase1", "coordinator/work.go",
     "\t\tif sha != t.Phase1.CommonsSHA256 || uint64(len(cfg.Commons.G2.Tau)) != t.Phase1.DomainSize {",
     "\t\tif false && (sha != t.Phase1.CommonsSHA256 || uint64(len(cfg.Commons.G2.Tau)) != t.Phase1.DomainSize) {",
     "./coordinator/", "^TestOpenForSealRefusesOtherPhase1$"),
    ("M24-seal-phase-pin", "rerun/rerun.go",
     "\tif o.PtauPin != t.Phase1.Pin {",
     "\tif false {",
     "./rerun/", "^TestSealRefusesOtherPinAndCount$"),
    ("M25-seal-phase-count", "rerun/rerun.go",
     "o.Contributions > 0 && n != o.Contributions {",
     "false && n != o.Contributions {",
     "./rerun/", "^TestSealRefusesOtherPinAndCount$"),
    # SealCommons is shared by the coordinator and the verifier, so a defect
    # in it is common to both and the verifier cannot see it; only the
    # comparison with gnark's seal on the full parameters can.
    ("M26-seal-commons-keeps-alpha", "transcript/state.go",
     "\ts.G1.AlphaTau = c.G1.AlphaTau\n",
     "\ts.G1.AlphaTau = make([]curve.G1Affine, len(c.G1.AlphaTau))\n",
     "./transcript/", "^TestSealCommonsSealsTheSameKeys$"),
    # ENG-440 (ARCH-238): each disables one new check and requires its
    # negative control to fail, at the import, the verifier and the recheck.
    ("M27-phase1-tau-in-domain", "ptau/validate.go",
     "if c.G1.Tau[n].Equal(&c.G1.Tau[0]) {",
     "if false && c.G1.Tau[n].Equal(&c.G1.Tau[0]) {",
     "./ptau/", "^TestImportRefusesTauInDomain$"),
    ("M27b-phase1-tau-in-domain-verifier", "ptau/validate.go",
     "if c.G1.Tau[n].Equal(&c.G1.Tau[0]) {",
     "if false && c.G1.Tau[n].Equal(&c.G1.Tau[0]) {",
     "./verifier/", "^TestRefusesDegeneratePhase1$"),
    ("M27c-phase1-tau-in-domain-recheck", "ptau/validate.go",
     "if c.G1.Tau[n].Equal(&c.G1.Tau[0]) {",
     "if false && c.G1.Tau[n].Equal(&c.G1.Tau[0]) {",
     "./cmd/apnt-pool-ceremony-recheck/", "^TestRecheckRefusesADegeneratePhase1$"),
    ("M28-phase1-beta-minus-one", "ptau/validate.go",
     "if c.G1.BetaTau[0].Equal(&negG1) {",
     "if false && c.G1.BetaTau[0].Equal(&negG1) {",
     "./ptau/", "^TestImportRefusesBetaMinusOne$"),
    ("M28b-phase1-beta-minus-one-verifier", "ptau/validate.go",
     "if c.G1.BetaTau[0].Equal(&negG1) {",
     "if false && c.G1.BetaTau[0].Equal(&negG1) {",
     "./verifier/", "^TestRefusesDegeneratePhase1$"),
    ("M28c-phase1-beta-minus-one-recheck", "ptau/validate.go",
     "if c.G1.BetaTau[0].Equal(&negG1) {",
     "if false && c.G1.BetaTau[0].Equal(&negG1) {",
     "./cmd/apnt-pool-ceremony-recheck/", "^TestRecheckRefusesADegeneratePhase1$"),
    ("M29-validate-calls-non-degenerate", "ptau/validate.go",
     "\treturn CheckNonDegenerate(c)\n",
     "\treturn nil\n",
     "./ptau/", "^(TestImportRefusesTauInDomain|TestImportRefusesBetaMinusOne)$"),
    ("M30-verifier-mask-check", "verifier/verifier.go",
     "if err := masks.Check(pk); err != nil {",
     "if err := error(nil); masks == nil && err != nil {",
     "./verifier/", "^TestRefusesZeroMaskBasisAfterSealing$"),
    ("M31-mask-missing", "transcript/masks.go",
     "if len(m.Positions[k]) == 0 {",
     "if false && len(m.Positions[k]) == 0 {",
     "./verifier/", "^TestRefusesCommitmentWithoutMask$"),
    ("M31b-mask-missing-unit", "transcript/masks.go",
     "if len(m.Positions[k]) == 0 {",
     "if false && len(m.Positions[k]) == 0 {",
     "./transcript/", "^TestLocateCommitmentMasksRefusesAnUnmaskedCommitment$"),
    ("M32-mask-zero", "transcript/masks.go",
     "if ck.Basis[p].IsInfinity() {",
     "if false && ck.Basis[p].IsInfinity() {",
     "./transcript/", "^TestCheckRefusesAZeroMaskBasisElement$"),
    ("M32b-mask-zero-recheck", "transcript/masks.go",
     "if ck.Basis[p].IsInfinity() {",
     "if false && ck.Basis[p].IsInfinity() {",
     "./cmd/apnt-pool-ceremony-recheck/", "^TestRecheckRefusesAZeroMaskBasisElement$"),
    ("M33-mask-position", "transcript/masks.go",
     "\t\tp, _ := slices.BinarySearch(committed[k], j)\n",
     "\t\tp, _ := slices.BinarySearch(committed[k], j)\n\t\tp = 0\n",
     "./transcript/", "^TestLocateCommitmentMasksOfTestCircuits$"),
    ("M34-recheck-mask-check", "cmd/apnt-pool-ceremony-recheck/main.go",
     "if err := masks.Check(pk); err != nil {",
     "if err := error(nil); pk == nil && err != nil {",
     "./cmd/apnt-pool-ceremony-recheck/", "^TestRecheckRefusesAZeroMaskBasisElement$"),
    # The action-shaped test circuit's mask constraint: without it the
    # verifier refuses the phased measurement ceremony (COMMITMENT_MASK_MISSING).
    ("M35-shaped-mask-constraint", "testcircuits/shaped.go",
     "O: constraint.LinearExpression{{CID: cidOne, VID: uint32(mask)}},",
     "O: constraint.LinearExpression{{CID: cidTwo, VID: uint32(mask)}},",
     "./rerun/", "^TestPhasesRunAsSeparateSteps$"),
    # IMPL-28 (REV-197): mask provenance and the circuit anchor.
    ("M36-mask-provenance-refusal", "transcript/masks.go",
     "if w := committed[k][p]; why[w] != \"\" {",
     "if w := committed[k][p]; false && why[w] != \"\" {",
     "./transcript/", "^TestRev197NonrandomMaskLikeWireIsNotAMask$"),
    ("M36b-mask-provenance-refusal-verifier", "transcript/masks.go",
     "if w := committed[k][p]; why[w] != \"\" {",
     "if w := committed[k][p]; false && why[w] != \"\" {",
     "./verifier/", "^TestRev197NonrandomMaskLikeWireIsRefused$"),
    ("M36c-mask-provenance-refusal-recheck", "transcript/masks.go",
     "if w := committed[k][p]; why[w] != \"\" {",
     "if w := committed[k][p]; false && why[w] != \"\" {",
     "./cmd/apnt-pool-ceremony-recheck/", "^TestRecheckRefusesUnanchoredOrUnmaskedInputs$"),
    ("M37-randomize-call-shape", "transcript/masks.go",
     "if hm.HintID == RandomizeHintID && len(hm.Inputs) == 0 && hm.OutputRange.End == hm.OutputRange.Start+1 {",
     "if true {",
     "./transcript/", "^TestLocateCommitmentMasksRequiresRandomizeProvenance$"),
    ("M38-single-setter", "transcript/masks.go",
     "\t\tcase setBy[w] > 1:\n",
     "\t\tcase false:\n",
     "./transcript/", "^TestLocateCommitmentMasksRequiresRandomizeProvenance$"),
    # IMPL-31 rewrote the name check (the record is now also required).
    ("M39-hint-name-record", "transcript/masks.go",
     "if (recorded || len(randomizeOf) > 0) && name != RandomizeHintName {",
     "if false && (recorded || len(randomizeOf) > 0) && name != RandomizeHintName {",
     "./transcript/", "^TestLocateCommitmentMasksRequiresRandomizeProvenance$"),
    ("M40-randomize-id-pin", "transcript/masks.go",
     "RandomizeHintID   solver.HintID = 0x69c66a53",
     "RandomizeHintID   solver.HintID = 0x69c66a54",
     "./transcript/", "^TestRandomizeHintIDIsPinned$"),
    ("M41-verifier-r1cs-anchor", "verifier/verifier.go",
     "if in.ExpectedR1CSSHA256 != \"\" && in.ExpectedR1CSSHA256 != t.Circuit.R1CSSHA256 {",
     "if false {",
     "./verifier/", "^TestExpectedR1CSDigestIsEnforced$"),
    ("M41b-verifier-r1cs-anchor-cli", "verifier/verifier.go",
     "if in.ExpectedR1CSSHA256 != \"\" && in.ExpectedR1CSSHA256 != t.Circuit.R1CSSHA256 {",
     "if false {",
     "./cmd/apnt-pool-ceremony-verify/", "^TestExpectR1CSFlag$"),
    ("M42-verify-cli-r1cs-flag", "cmd/apnt-pool-ceremony-verify/main.go",
     "ExpectedR1CSSHA256: *expectR1CS}",
     "ExpectedR1CSSHA256: (*expectR1CS)[:0]}",
     "./cmd/apnt-pool-ceremony-verify/", "^TestExpectR1CSFlag$"),
    ("M43-recheck-r1cs-anchor", "cmd/apnt-pool-ceremony-recheck/main.go",
     "if expR1CS != t.Circuit.R1CSSHA256 {",
     "if false {",
     "./cmd/apnt-pool-ceremony-recheck/", "^TestRecheckRefusesUnanchoredOrUnmaskedInputs$"),
    ("M44-shaped-randomize-hint", "testcircuits/shaped.go",
     "r.AddSolverHint(randomize, transcript.RandomizeHintID, nil, 1)",
     "r.AddSolverHint(randomize, transcript.RandomizeHintID+1, nil, 1)",
     "./rerun/", "^TestPhasesRunAsSeparateSteps$"),
    # REV-197's own two mutations, kept.
    ("M45-shared-committed-wire", "transcript/masks.go",
     "if j < nbPublic || j >= nbWires || isCommitmentWire[j] || commitOf[j] != -1 {",
     "if j < nbPublic || j >= nbWires || isCommitmentWire[j] {",
     "./transcript/", "^TestRev197RejectsCrossCommitmentWire$"),
    ("M46-every-commitment-checked", "transcript/masks.go",
     "for k, ck := range key.CommitmentKeys {",
     "for k, ck := range key.CommitmentKeys[:1] {",
     "./transcript/", "^TestRev197RejectsSecondZeroMask$"),
    # ENG-443 (REV-198): the report names the transcript bytes and the build.
    ("M47-transcript-digest-bytes", "transcript/transcript.go",
     "\treturn &t, Digest(b), nil\n",
     "\treturn &t, Digest(nil), nil\n",
     "./verifier/", "^TestReportNamesTheExactTranscript$"),
    ("M47b-transcript-digest-bytes-cli", "transcript/transcript.go",
     "\treturn &t, Digest(b), nil\n",
     "\treturn &t, Digest(nil), nil\n",
     "./cmd/apnt-pool-ceremony-verify/", "^TestReportNamesTranscriptAndBuild$"),
    ("M48-report-transcript-field", "verifier/verifier.go",
     "TranscriptSHA256:    transcriptSHA,",
     "TranscriptSHA256:    transcriptSHA[:0],",
     "./verifier/", "^TestReportNamesTheExactTranscript$"),
    ("M49-report-build-field", "verifier/verifier.go",
     "VerifierBuild:       ThisBuild(),",
     "VerifierBuild:       Build{},",
     "./cmd/apnt-pool-ceremony-verify/", "^TestReportNamesTranscriptAndBuild$"),
    ("M50-build-revision", "verifier/build.go",
     "if !vcsRevision.MatchString(b.VCSRevision) {",
     "if false && !vcsRevision.MatchString(b.VCSRevision) {",
     "./verifier/", "^TestBuildOfIsUnverifiedWithoutEveryRecord$"),
    ("M51-build-modified", "verifier/build.go",
     "if b.VCSModified != \"false\" {",
     "if false && b.VCSModified != \"false\" {",
     "./verifier/", "^TestBuildOfIsUnverifiedWithoutEveryRecord$"),
    ("M52-build-replaced", "verifier/build.go",
     "\t\tcase rec.Replace != nil:\n",
     "\t\tcase false:\n",
     "./verifier/", "^TestBuildOfIsUnverifiedWithoutEveryRecord$"),
    ("M53-build-version", "verifier/build.go",
     "\t\tcase rec.Version != w.version:\n",
     "\t\tcase false:\n",
     "./verifier/", "^TestBuildOfIsUnverifiedWithoutEveryRecord$"),
    ("M54-build-main-module", "verifier/build.go",
     "if bi.Main.Path != Module {",
     "if false && bi.Main.Path != Module {",
     "./verifier/", "^TestBuildOfIsUnverifiedWithoutEveryRecord$"),
    ("M55-build-duplicate-dep", "verifier/build.go",
     "\t\t\t\tif rec != nil {\n",
     "\t\t\t\tif false && rec != nil {\n",
     "./verifier/", "^TestBuildOfIsUnverifiedWithoutEveryRecord$"),
    ("M56-build-no-info", "verifier/build.go",
     "if !ok || bi == nil {",
     "if bi == nil {",
     "./verifier/", "^TestBuildOfIsUnverifiedWithoutEveryRecord$"),
    # IMPL-31 (REV-200): each condition of the call-shape test on its own
    # (M57 and M59 are REV-200's mutR1 and mutR2), the name record, and the
    # schedule.
    ("M57-call-shape-id", "transcript/masks.go",
     "if hm.HintID == RandomizeHintID && len(hm.Inputs) == 0 && hm.OutputRange.End == hm.OutputRange.Start+1 {",
     "if len(hm.Inputs) == 0 && hm.OutputRange.End == hm.OutputRange.Start+1 {",
     "./transcript/", "^TestRev200NoInputForeignHintRefused$"),
    ("M58-call-shape-no-input", "transcript/masks.go",
     "if hm.HintID == RandomizeHintID && len(hm.Inputs) == 0 && hm.OutputRange.End == hm.OutputRange.Start+1 {",
     "if hm.HintID == RandomizeHintID && hm.OutputRange.End == hm.OutputRange.Start+1 {",
     "./transcript/", "^TestLocateCommitmentMasksRequiresRandomizeProvenance$"),
    ("M59-call-shape-one-output", "transcript/masks.go",
     "if hm.HintID == RandomizeHintID && len(hm.Inputs) == 0 && hm.OutputRange.End == hm.OutputRange.Start+1 {",
     "if hm.HintID == RandomizeHintID && len(hm.Inputs) == 0 {",
     "./transcript/", "^TestRev200TwoOutputRandomizeRefused$"),
    ("M60-name-record-required", "transcript/masks.go",
     "if (recorded || len(randomizeOf) > 0) && name != RandomizeHintName {",
     "if recorded && name != RandomizeHintName {",
     "./transcript/", "^TestRev200MissingNameRecordRefused$"),
    ("M61-schedule-checked", "transcript/masks.go",
     "if err := checkSchedule(r1cs, randomizeOf); err != nil {",
     "if err := error(nil); err != nil {",
     "./verifier/", "^TestRev200RandomizeOutsideLevelsIsRefused$"),
    ("M61b-schedule-checked-setter-first", "transcript/masks.go",
     "if err := checkSchedule(r1cs, randomizeOf); err != nil {",
     "if err := error(nil); err != nil {",
     "./verifier/", "^TestRev200SetterScheduledFirstIsRefused$"),
    ("M62-schedule-level-contents", "transcript/schedule.go",
     "if !slices.Equal(levels[l], r.Levels[l]) {",
     "if false && !slices.Equal(levels[l], r.Levels[l]) {",
     "./transcript/", "^TestScheduleRefusesEditedLevels$"),
    ("M63-schedule-level-count", "transcript/schedule.go",
     "if len(levels) != len(r.Levels) {",
     "if false && len(levels) != len(r.Levels) {",
     "./transcript/", "^TestScheduleRefusesEditedLevels$"),
    ("M64-mask-first", "transcript/schedule.go",
     "if i != h && at[i] <= at[h] {",
     "if false && i != h && at[i] <= at[h] {",
     "./transcript/", "^TestScheduleRefusesAMaskReadBeforeItIsRandomized$"),
    ("M65-replay-single-setter", "transcript/schedule.go",
     "if t.levels[w-t.offset] != constraint.LevelUnset {",
     "if false && t.levels[w-t.offset] != constraint.LevelUnset {",
     "./transcript/", "^TestScheduleRefusesASecondSetter$"),
    ("M66-replay-fresh-blueprints", "transcript/schedule.go",
     "bps[i] = freshBlueprint(b)",
     "bps[i] = b",
     "./transcript/", "^TestScheduleOfALookupCircuit$"),
    ("M67-replay-refuses-sparse-blueprints", "transcript/schedule.go",
     "if _, sparse := b.(constraint.BlueprintSparseR1C); sparse {",
     "if _, sparse := b.(constraint.BlueprintSparseR1C); false && sparse {",
     "./transcript/", "^TestRev205SparseMulSecondSetterRefused$"),
]


def go_test(cwd, pkg, tests):
    env = dict(os.environ, GOPROXY="off", GOFLAGS="-mod=mod", GOMAXPROCS=os.environ.get("GOMAXPROCS", "4"))
    return subprocess.run(["go", "test", "-count=1", "-run", tests, pkg], cwd=cwd, env=env,
                          capture_output=True, text=True)


def main():
    scratch = tempfile.mkdtemp(prefix="apnt-pool-ceremony-mutation.")
    survived = 0
    try:
        for mid, path, old, new, pkg, tests in MUTATIONS:
            copy = os.path.join(scratch, "m")
            shutil.rmtree(copy, ignore_errors=True)
            shutil.copytree(HERE, copy, ignore=shutil.ignore_patterns("scripts"))
            base = go_test(copy, pkg, tests)
            if base.returncode != 0:
                print(f"BASELINE-FAILED {mid}: unmutated tests fail\n{base.stdout}{base.stderr}")
                return 2
            target = os.path.join(copy, path)
            src = open(target).read()
            olds, news = (old, new) if isinstance(old, tuple) else ((old,), (new,))
            for o, r in zip(olds, news, strict=True):
                n = src.count(o)
                if n != 1:
                    print(f"MUTATION-NOT-APPLIED {mid}: original text found {n} times in {path}")
                    return 2
                src = src.replace(o, r)
            open(target, "w").write(src)
            res = go_test(copy, pkg, tests)
            out = res.stdout + res.stderr
            if "[build failed]" in out or "[setup failed]" in out:
                print(f"INVALID {mid}: the mutated copy does not build, which witnesses nothing\n{out}")
                return 2
            if res.returncode == 0:
                survived += 1
                print(f"SURVIVED {mid} ({pkg} {tests})")
            else:
                m = re.search(r"^\s*(\S+_test\.go:\d+: .*)$", out, re.M) or re.search(r"^(# .*|.*error.*)$", out, re.M)
                why = m.group(1)[:220] if m else out.strip().splitlines()[-1]
                print(f"KILLED   {mid} ({pkg} {tests}): {why}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    print(f"survived: {survived} of {len(MUTATIONS)}")
    return 0 if survived == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

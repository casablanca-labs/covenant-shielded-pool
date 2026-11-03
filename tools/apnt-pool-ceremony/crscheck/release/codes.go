package release

// Code is a stable refusal code of the release gate. Tests assert codes, not
// messages, so a check that stops firing changes the code a negative test
// observes.
type Code string

const (
	// The gate's own build is not identified (build.go).
	CodeCheckerBuild Code = "CHECKER_BUILD_UNVERIFIED"
	// The transcript is unreadable, not sealed, mislabelled, or for another
	// curve, backend or key encoding.
	CodeTranscript Code = "TRANSCRIPT_INVALID"
	// keys.meta.json is unreadable or is not exactly what the transcript
	// implies (transcript.MetadataFor).
	CodeKeyMetadata Code = "KEY_METADATA_MISMATCH"
	// The ceremony verifier's output does not hash to the digest the
	// operator named, so nothing in it is trusted.
	CodeReportDigest Code = "CEREMONY_REPORT_DIGEST_MISMATCH"
	// The verifier's output is not an authoritative verdict: not VALID, an
	// anchor missing, or not a verifier report at all (a REFUSED output).
	CodeCeremonyNotValid Code = "CEREMONY_NOT_VALID"
	// The verifier's output describes another transcript.
	CodeReportMismatch Code = "CEREMONY_REPORT_MISMATCH"
	// The transcript's gnark is not the one crscheck was written against.
	CodeGnarkVersion Code = "GNARK_VERSION_MISMATCH"
	// An out-of-band digest differs from the transcript's, or the file read
	// does not hash to it.
	CodeR1CSDigest Code = "R1CS_DIGEST_MISMATCH"
	CodePtauPin    Code = "PTAU_PIN_MISMATCH"
	CodeVKDigest   Code = "VK_DIGEST_MISMATCH"
	CodePKDigest   Code = "PK_DIGEST_MISMATCH"
	// An input could not be read or decoded (gnark's checked decoders
	// refuse a point off the curve or outside the subgroup), or the inputs
	// are incomplete.
	CodeUnreadable Code = "INPUT_UNREADABLE"
	// A zero-knowledge check failed: crscheck's privacy-only verdict is
	// MALFORMED.
	CodeMalformed Code = "CRS_MALFORMED"
	// A check the gate requires is missing from the checker's results.
	CodeIncomplete Code = "CHECK_INCOMPLETE"
	// A check that does not decide the privacy verdict failed: VK_K,
	// VK_MATCHES_PK, PHASE1_ALPHA_BETA (REV-195 H3).
	CodeAncillary Code = "ANCILLARY_CHECK_FAILED"
	// A negative control did not fire, a required control is absent, or the
	// restored key does not pass every check again.
	CodeControl Code = "NEGATIVE_CONTROL_NOT_FIRED"
	// The verifier's output does not name, by transcriptSha256, exactly the
	// transcript bytes the gate parsed, or names none (an output from before
	// ENG-443, such as 5.1c's archived one). REV-198 H2.
	CodeReportUnbound Code = "CEREMONY_REPORT_UNBOUND"
	// The verifier's output does not record a clean, stamped build of this
	// module: status verified, this module, a clean VCS revision, the gnark
	// versions crscheck is written against. The record is the verifier
	// binary's self-report, not authenticated, and its revision is not
	// compared with a reviewed commit. REV-198 H2, REV-206 W1.
	CodeVerifierUnverified Code = "CEREMONY_VERIFIER_UNVERIFIED"
)

// Codes lists every refusal code in its canonical order with its exit
// status. A refused run lists all its refusals in this order and exits with
// the first one's status. Status 0 is RELEASE-OK only; 1 means the report
// could not be written; 2 is a usage error; 75 is the prover-lock wrapper's
// refusal, which runs nothing.
var Codes = []struct {
	Code Code
	Exit int
}{
	{CodeCheckerBuild, 10},
	{CodeTranscript, 11},
	{CodeKeyMetadata, 12},
	{CodeReportDigest, 13},
	{CodeCeremonyNotValid, 14},
	{CodeReportMismatch, 15},
	{CodeGnarkVersion, 16},
	{CodeR1CSDigest, 17},
	{CodePtauPin, 18},
	{CodeVKDigest, 19},
	{CodePKDigest, 20},
	{CodeUnreadable, 21},
	{CodeMalformed, 22},
	{CodeIncomplete, 23},
	{CodeAncillary, 24},
	{CodeControl, 25},
	// Appended by ENG-447, after the existing codes, so that no existing
	// code's status changes.
	{CodeReportUnbound, 26},
	{CodeVerifierUnverified, 27},
}

// rank is a code's position in Codes; an unknown code sorts last.
func rank(c Code) int {
	for i, e := range Codes {
		if e.Code == c {
			return i
		}
	}
	return len(Codes)
}

// ExitOf is a code's exit status; 1 for an unknown code.
func ExitOf(c Code) int {
	for _, e := range Codes {
		if e.Code == c {
			return e.Exit
		}
	}
	return 1
}

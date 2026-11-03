// Command apnt-pool-crscheck is the once-per-ceremony CRS release gate
// (ENG-441, run R-399; reviewed by REV-206); package release holds the rules.
// It checks a sealed ceremony's proving key and verifying key against their
// R1CS and pinned phase-1 file for CRS well-formedness (package crscheck),
// requires the ceremony verifier's archived VALID output, the transcript,
// the key metadata and the operator's out-of-band digests to name exactly
// those files, runs the negative controls, and writes the release report and
// its SHA-256 (REPORT.sha256).
//
// Exit status: 0 only for RELEASE-OK; 2 on a usage error; 1 if the report
// could not be written; otherwise the status of the first refusal code
// (release.Codes, 10-27). crscheck's privacy-only verdict, WELL-FORMED or
// MALFORMED, is a field of the report and never decides the exit status.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/crscheck/release"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apnt-pool-crscheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var in release.Inputs
	fs.StringVar(&in.ProvingKey, "pk", "", "the sealed proving key (gnark WriteRawTo)")
	fs.StringVar(&in.VerifyingKey, "vk", "", "the sealed verifying key")
	fs.StringVar(&in.R1CS, "r1cs", "", "the circuit's R1CS")
	fs.StringVar(&in.Ptau, "ptau", "", "the phase-1 .ptau file")
	fs.StringVar(&in.Transcript, "transcript", "", "the ceremony's transcript.json")
	fs.StringVar(&in.KeyMetadata, "keys-meta", "", "the ceremony's keys.meta.json")
	fs.StringVar(&in.CeremonyReport, "ceremony-report", "", "the ceremony verifier's archived --json output (VALID, both anchors)")
	fs.StringVar(&in.ProvingKeySHA256, "pk-sha256", "", "out-of-band SHA-256 of the proving key (required)")
	fs.StringVar(&in.VerifyingKeySHA256, "vk-sha256", "", "out-of-band SHA-256 of the verifying key (required)")
	fs.StringVar(&in.R1CSSHA256, "r1cs-sha256", "", "out-of-band SHA-256 of the R1CS (required)")
	fs.StringVar(&in.PtauSHA256, "ptau-sha256", "", "out-of-band SHA-256 pin of the .ptau file (required)")
	fs.StringVar(&in.CeremonyReportSHA256, "ceremony-report-sha256", "", "out-of-band SHA-256 of the verifier output (required)")
	out := fs.String("out", "", "write the release report here, and its SHA-256 to OUT.sha256")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *out == "" {
		fmt.Fprintln(stderr, "apnt-pool-crscheck: every flag is required; see -h")
		return 2
	}
	if err := in.Validate(); err != nil {
		fmt.Fprintln(stderr, "apnt-pool-crscheck:", err)
		return 2
	}
	if _, err := os.Lstat(*out); err == nil {
		fmt.Fprintf(stderr, "apnt-pool-crscheck: %s exists; the gate never overwrites a report\n", *out)
		return 2
	}
	in.Log = stderr
	rep := release.Run(in)
	sum, err := rep.Write(*out)
	if err != nil {
		fmt.Fprintln(stderr, "apnt-pool-crscheck: writing the report:", err)
		return 1
	}
	fmt.Fprintf(stdout, "verdict %s; refusals %v; privacy-only verdict %q (informational); report %s sha256 %s; statement sha256 %s\n",
		rep.Statement.Verdict, rep.Codes(), rep.Statement.PrivacyOnlyVerdict, *out, sum, rep.StatementSHA256)
	return rep.ExitStatus()
}

// Command apnt-pool-ceremony-verify re-verifies a sealed ceremony transcript
// from phase 1 to the sealed keys and reports its provenance. It imports
// neither the coordinator nor the contributor, but shares the ptau importer
// and the transcript derivations with them.
//
// VALID requires both out-of-band anchors, --expect-phase1-pin and
// --expect-beacon. Without either, a transcript that passes every other check
// is reported CONSISTENT-UNANCHORED: consistent with the pin and beacon it
// names itself, which is not an authoritative verdict.
//
// Exit status: 0 VALID, 1 refused (the stable failure code is printed), 2
// usage error, 3 CONSISTENT-UNANCHORED.
//
// Only exit status 0 means VALID. The complete output of an exit-3 run, text
// or JSON, stdout and stderr, never contains the substring VALID, whatever
// names the transcript carries: see unanchoredGuard. Exit-1 output can
// contain it, in stable codes such as BEACON_INVALID and in refusal details
// that quote the transcript; callers must decide on the exit status or the
// JSON verdict field, never on a text search.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// unanchoredGuard makes an exit-3 output free of the substring VALID. The
// transcript's freeform fields (ceremony id, circuit label, contributor ids,
// beacon source) are chosen by whoever made it and are bound into the root,
// so they cannot be refused; any of them can read "VALID". Every occurrence
// in the finished output is written as VAL\u0049D. In JSON that is a string
// escape, so a decoder reads back exactly the transcript's value; in text it
// is visible and unambiguous. It rewrites the whole output rather than a list
// of fields, so a field added later cannot reopen the gap. The verdict tokens
// and fixed text of an exit-3 run contain no VALID of their own.
func unanchoredGuard(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("VALID"), []byte(`VAL\u0049D`))
}

// run is the command, returning its exit status. It buffers the output so the
// exit-3 guard applies to all of it.
func run(args []string, stdout, stderr io.Writer) int {
	var out, errOut bytes.Buffer
	code := execute(args, &out, &errOut)
	if code == 3 {
		stdout.Write(unanchoredGuard(out.Bytes()))
		stderr.Write(unanchoredGuard(errOut.Bytes()))
		return code
	}
	stdout.Write(out.Bytes())
	stderr.Write(errOut.Bytes())
	return code
}

func execute(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apnt-pool-ceremony-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tr := fs.String("transcript", "", "transcript.json of a sealed ceremony")
	ptauPath := fs.String("ptau", "", "the phase-1 .ptau file the transcript pins")
	r1cs := fs.String("r1cs", "", "the R1CS the transcript is for")
	expectPin := fs.String("expect-phase1-pin", "", "phase-1 pin you trust out of band (required for VALID)")
	expectBeacon := fs.String("expect-beacon", "", "beacon hex you trust out of band (required for VALID)")
	expectR1CS := fs.String("expect-r1cs-sha256", "", "the circuit's R1CS SHA-256 from the proof-system record; refuses a transcript for another circuit")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	// ContinueOnError keeps flag errors inside the buffered output; the exit
	// statuses are flag.ExitOnError's: 0 for -h, 2 for a bad flag.
	if err := fs.Parse(args); err == flag.ErrHelp {
		return 0
	} else if err != nil {
		return 2
	}
	if *tr == "" || *ptauPath == "" || *r1cs == "" {
		fmt.Fprintln(stderr, "usage: apnt-pool-ceremony-verify --transcript F --ptau F --r1cs F [--expect-phase1-pin P] [--expect-beacon HEX] [--expect-r1cs-sha256 HEX] [--json]\n  VALID needs both --expect-phase1-pin and --expect-beacon; without them the verdict is CONSISTENT-UNANCHORED (exit 3)\n  without --expect-r1cs-sha256 the circuit is whatever the transcript names")
		return 2
	}
	in := verifier.Inputs{TranscriptPath: *tr, PtauPath: *ptauPath, R1CSPath: *r1cs, ExpectedBeacon: *expectBeacon, ExpectedR1CSSHA256: *expectR1CS}
	if *expectPin != "" {
		p, err := ptau.ParsePin(*expectPin)
		if err != nil {
			fmt.Fprintf(stderr, "REFUSED %s\n", err)
			return 1
		}
		in.ExpectedPhase1Pin = &p
	}
	rep, err := verifier.Verify(in)
	if err != nil {
		if *asJSON {
			json.NewEncoder(stdout).Encode(map[string]string{"verdict": "REFUSED", "code": string(failure.CodeOf(err)), "detail": err.Error()})
		}
		fmt.Fprintf(stderr, "REFUSED %s\n", err)
		return 1
	}
	exit := 0
	if !rep.Authoritative() {
		exit = 3
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(rep)
		return exit
	}
	fmt.Fprintf(stdout, "%s ceremony %s\n", rep.Verdict, rep.CeremonyID)
	if !rep.Authoritative() {
		var missing []string
		if !rep.Anchors.Phase1Pin {
			missing = append(missing, "--expect-phase1-pin")
		}
		if !rep.Anchors.Beacon {
			missing = append(missing, "--expect-beacon")
		}
		fmt.Fprintf(stdout, "anchors:        MISSING %s\n", strings.Join(missing, ", "))
		fmt.Fprintf(stdout, "authoritative:  NO - checked only against the phase-1 pin and beacon the transcript names itself\n")
	}
	fmt.Fprintf(stdout, "provenance:     %s\n", rep.Provenance)
	if rep.Provenance == transcript.SimulatedSingleParty {
		fmt.Fprintf(stdout, "zero-value:     ONLY - these keys must never guard value\n")
	}
	fmt.Fprintf(stdout, "notice:         %s\n", rep.Notice)
	fmt.Fprintf(stdout, "circuit:        %s, %d constraints, r1cs sha256 %s\n", rep.CircuitLabel, rep.NbConstraints, rep.R1CSSHA256)
	if rep.Anchors.R1CS {
		fmt.Fprintf(stdout, "circuit anchor: r1cs sha256 equals --expect-r1cs-sha256\n")
	} else {
		fmt.Fprintf(stdout, "circuit anchor: NONE - the r1cs is checked only against the transcript's own record (pass --expect-r1cs-sha256)\n")
	}
	fmt.Fprintf(stdout, "phase 1:        pin %s, domain %d\n", rep.Phase1Pin, rep.DomainSize)
	for _, c := range rep.Contributions {
		fmt.Fprintf(stdout, "contribution %d: %s (%s) state sha256 %s\n", c.Index, c.Contributor.ID, c.Contributor.Kind, c.StateSHA256)
	}
	fmt.Fprintf(stdout, "beacon:         %s (%s)\n", rep.Beacon.Value, rep.Beacon.Source)
	fmt.Fprintf(stdout, "proving key:    sha256 %s\n", rep.ProvingKeySHA256)
	fmt.Fprintf(stdout, "verifying key:  sha256 %s\n", rep.VerifyingKeySHA256)
	fmt.Fprintf(stdout, "transcript:     sha256 %s\n", rep.TranscriptSHA256)
	b := rep.VerifierBuild
	fmt.Fprintf(stdout, "verifier build: %s: module %s, vcs.revision %q, vcs.modified %q, gnark %s, gnark-crypto %s\n", b.Status, b.Module, b.VCSRevision, b.VCSModified, b.Gnark, b.GnarkCrypto)
	if b.Reason != "" {
		fmt.Fprintf(stdout, "                %s\n", b.Reason)
	}
	return exit
}

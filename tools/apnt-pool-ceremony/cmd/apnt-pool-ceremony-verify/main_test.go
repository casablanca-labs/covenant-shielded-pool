package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/contributor"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/coordinator"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/rerun"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// The command exits 0 and prints VALID only with both anchors. Without either
// it exits 3 and nothing it prints contains "VALID", so a caller testing the
// exit status or grepping for VALID cannot mistake it.
func TestExitStatusRequiresBothAnchors(t *testing.T) {
	root := t.TempDir()
	r1csPath, r := fixture.R1CS(t, root, "cubic", 5)
	ptauPath, pin := fixture.Ptau(t, root, fixture.Power(r))
	out := filepath.Join(root, "ceremony")
	if _, err := rerun.Run(rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
		R1CSPath: r1csPath, CircuitLabel: "cubic",
		OutDir: out, CeremonyID: "cli-anchors", Contributions: 2,
		Beacon: fixture.Beacon,
	}); err != nil {
		t.Fatal(err)
	}
	baseArgs := []string{"--transcript", filepath.Join(out, transcript.TranscriptFile), "--ptau", ptauPath, "--r1cs", r1csPath}
	pinArgs := []string{"--expect-phase1-pin", pin.String()}
	beaconArgs := []string{"--expect-beacon", fixture.Beacon.Value}
	for _, c := range []struct {
		name  string
		extra [][]string
		exit  int
	}{
		{"both anchors", [][]string{pinArgs, beaconArgs}, 0},
		{"phase-1 pin only", [][]string{pinArgs}, 3},
		{"beacon only", [][]string{beaconArgs}, 3},
		{"no anchor", nil, 3},
	} {
		for _, asJSON := range []bool{false, true} {
			args := append([]string(nil), baseArgs...)
			for _, e := range c.extra {
				args = append(args, e...)
			}
			if asJSON {
				args = append(args, "--json")
			}
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if code != c.exit {
				t.Fatalf("%s json=%v: exit %d, want %d\n%s%s", c.name, asJSON, code, c.exit, stdout.String(), stderr.String())
			}
			verdict := strings.Fields(stdout.String())[0]
			if asJSON {
				var rep struct{ Verdict string }
				if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
					t.Fatal(err)
				}
				verdict = rep.Verdict
			}
			if c.exit == 0 {
				if verdict != "VALID" {
					t.Fatalf("%s json=%v: verdict %q", c.name, asJSON, verdict)
				}
				continue
			}
			if verdict != "CONSISTENT-UNANCHORED" || strings.Contains(stdout.String()+stderr.String(), "VALID") {
				t.Fatalf("%s json=%v: output mentions VALID or wrong verdict %q:\n%s", c.name, asJSON, verdict, stdout.String())
			}
		}
	}
}

// escapedValid is how the exit-3 guard writes VALID: a JSON unicode escape
// of the I. Built from the backslash's code point to keep the escape literal.
var escapedValid = "VAL" + string(rune(92)) + "u0049D"

// adversarialCeremony seals a simulated ceremony whose every freeform field
// reads VALID: ceremony id, circuit label, contributor id and beacon source.
func adversarialCeremony(t *testing.T) (transcriptPath, ptauPath, r1csPath string, pin ptau.Pin) {
	t.Helper()
	root := t.TempDir()
	r1csPath, r := fixture.R1CS(t, root, "cubic", 5)
	ptauPath, pin = fixture.Ptau(t, root, fixture.Power(r))
	commons, info, err := ptau.ImportFile(ptauPath, pin, transcript.DomainSize(r))
	if err != nil {
		t.Fatal(err)
	}
	_, digest, _ := transcript.ReadR1CS(r1csPath)
	out := filepath.Join(root, "ceremony")
	co, err := coordinator.New(coordinator.Config{
		Dir: out, CeremonyID: "VALID", Provenance: transcript.SimulatedSingleParty,
		Phase1: transcript.Phase1{Source: "VALID", File: filepath.Base(ptauPath), FileSize: info.FileSize,
			Pin: pin, Power: info.Power, CommonsSHA256: info.CommonsSHA256},
		Commons: commons, R1CS: r, R1CSSHA256: digest, CircuitLabel: "VALID",
	})
	if err != nil {
		t.Fatal(err)
	}
	if accepted, _, err := co.RunQueue([]coordinator.Contributor{contributor.NewAutomated("VALID"), contributor.NewAutomated("xVALIDx")}); err != nil || len(accepted) != 2 {
		t.Fatalf("contributions: %d %v", len(accepted), err)
	}
	if _, err := co.Seal(transcript.Beacon{Value: fixture.Beacon.Value, Source: "VALID"}); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(out, transcript.TranscriptFile), ptauPath, r1csPath, pin
}

// With attacker-chosen names that read VALID, an unanchored run's complete
// output, text and JSON, still contains no VALID, and the JSON decodes back
// to the transcript's exact values. Control: the same transcript with both
// anchors exits 0 and prints the names unchanged.
func TestUnanchoredOutputFreeOfValidUnderAdversarialNames(t *testing.T) {
	tr, ptauPath, r1csPath, pin := adversarialCeremony(t)
	base := []string{"--transcript", tr, "--ptau", ptauPath, "--r1cs", r1csPath}
	anchors := []string{"--expect-phase1-pin", pin.String(), "--expect-beacon", fixture.Beacon.Value}

	for _, c := range []struct {
		name  string
		extra []string
	}{
		{"no anchor", nil},
		{"phase-1 pin only", anchors[:2]},
		{"beacon only", anchors[2:]},
	} {
		for _, asJSON := range []bool{false, true} {
			args := append(append([]string(nil), base...), c.extra...)
			if asJSON {
				args = append(args, "--json")
			}
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 3 {
				t.Fatalf("%s json=%v: exit %d\n%s%s", c.name, asJSON, code, stdout.String(), stderr.String())
			}
			if all := stdout.String() + stderr.String(); strings.Contains(all, "VALID") {
				t.Fatalf("%s json=%v: output contains VALID:\n%s", c.name, asJSON, all)
			}
			if !asJSON {
				if !strings.HasPrefix(stdout.String(), "CONSISTENT-UNANCHORED ceremony "+escapedValid) {
					t.Fatalf("%s: text output %q", c.name, stdout.String())
				}
				continue
			}
			var rep struct {
				Verdict       string
				CeremonyID    string
				CircuitLabel  string
				Contributions []struct{ Contributor struct{ ID string } }
				Beacon        struct{ Source string }
			}
			if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
				t.Fatalf("%s: guarded JSON does not decode: %v", c.name, err)
			}
			if rep.Verdict != "CONSISTENT-UNANCHORED" || rep.CeremonyID != "VALID" || rep.CircuitLabel != "VALID" ||
				len(rep.Contributions) != 2 || rep.Contributions[0].Contributor.ID != "VALID" ||
				rep.Contributions[1].Contributor.ID != "xVALIDx" || rep.Beacon.Source != "VALID" {
				t.Fatalf("%s: decoded values changed: %+v", c.name, rep)
			}
		}
	}

	// Control: anchored, the same names print as they are.
	for _, asJSON := range []bool{false, true} {
		args := append(append([]string(nil), base...), anchors...)
		if asJSON {
			args = append(args, "--json")
		}
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("anchored json=%v: exit %d\n%s", asJSON, code, stderr.String())
		}
		if strings.Contains(stdout.String(), escapedValid) || strings.Count(stdout.String(), "VALID") < 5 {
			t.Fatalf("anchored json=%v: output %s", asJSON, stdout.String())
		}
	}
}

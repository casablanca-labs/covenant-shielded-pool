package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/crscheck/release"
)

func args(dir string, extra ...string) []string {
	d := strings.Repeat("ab", 32)
	a := []string{
		"--pk", filepath.Join(dir, "proving.key"), "--vk", filepath.Join(dir, "verifying.key"), "--r1cs", filepath.Join(dir, "c.r1cs"),
		"--ptau", filepath.Join(dir, "p.ptau"), "--transcript", filepath.Join(dir, "transcript.json"),
		"--keys-meta", filepath.Join(dir, "keys.meta.json"), "--ceremony-report", filepath.Join(dir, "verify.stdout"),
		"--pk-sha256", d, "--vk-sha256", d, "--r1cs-sha256", d, "--ptau-sha256", d, "--ceremony-report-sha256", d,
	}
	return append(a, extra...)
}

// Every input is required; a missing or malformed digest, a stray argument
// or an existing report is a usage error, and nothing is written.
func TestUsageErrors(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.json")
	existing := filepath.Join(dir, "existing.json")
	os.WriteFile(existing, []byte("{}"), 0o644)
	for _, c := range []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"no --out", args(dir)},
		{"a digest missing", append(args(dir, "--out", out), "--pk-sha256", "")},
		{"an uppercase digest", append(args(dir, "--out", out), "--vk-sha256", strings.Repeat("AB", 32))},
		{"a stray argument", append(args(dir, "--out", out), "extra")},
		{"the report exists", args(dir, "--out", existing)},
		{"an unknown flag", append(args(dir, "--out", out), "--controls")},
	} {
		var so, se bytes.Buffer
		if got := run(c.args, &so, &se); got != 2 {
			t.Errorf("%s: exit %d, want 2 (%s)", c.name, got, se.String())
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("%s: a report was written", c.name)
		}
	}
}

// A go test binary records no dependencies and no VCS revision, so the real
// build-identity check refuses it: exit status CHECKER_BUILD_UNVERIFIED, and
// the refusal is written as a report with its SHA-256.
func TestGoTestBinaryIsRefused(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.json")
	var so, se bytes.Buffer
	got := run(args(dir, "--out", out), &so, &se)
	if want := 10; got != want { // CHECKER_BUILD_UNVERIFIED, pinned literally
		t.Fatalf("exit %d, want %d; %s %s", got, want, so.String(), se.String())
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := release.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Statement.Verdict != release.VerdictRefused || rep.Codes()[0] != release.CodeCheckerBuild {
		t.Fatalf("verdict %s, codes %v", rep.Statement.Verdict, rep.Codes())
	}
	side, err := os.ReadFile(out + ".sha256")
	if err != nil || !strings.HasSuffix(string(side), "  report.json\n") {
		t.Fatalf("sidecar %q %v", side, err)
	}
	if !strings.Contains(so.String(), "verdict RELEASE-REFUSED") {
		t.Fatalf("stdout %q", so.String())
	}
}

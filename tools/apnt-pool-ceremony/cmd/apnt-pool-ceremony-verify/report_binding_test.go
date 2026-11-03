package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/rerun"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// ENG-443: --json and the text report name the transcript's SHA-256 and the
// verifier's build. A go test binary records no VCS revision, so its build is
// "unverified" with a reason; scripts/test-verifier-build-identity.sh covers
// real worktree and clean-clone builds.
func TestReportNamesTranscriptAndBuild(t *testing.T) {
	root := t.TempDir()
	r1csPath, r := fixture.R1CS(t, root, "cubic", 5)
	ptauPath, pin := fixture.Ptau(t, root, fixture.Power(r))
	out := filepath.Join(root, "ceremony")
	if _, err := rerun.Run(rerun.Options{
		PtauPath: ptauPath, PtauPin: pin, PtauSource: "toy fixture (INSECURE)",
		R1CSPath: r1csPath, CircuitLabel: "cubic", OutDir: out, CeremonyID: "cli-binding",
		Contributions: 1, Beacon: fixture.Beacon,
	}); err != nil {
		t.Fatal(err)
	}
	tpath := filepath.Join(out, transcript.TranscriptFile)
	b, err := os.ReadFile(tpath)
	if err != nil {
		t.Fatal(err)
	}
	digest := transcript.Digest(b)
	args := []string{"--transcript", tpath, "--ptau", ptauPath, "--r1cs", r1csPath,
		"--expect-phase1-pin", pin.String(), "--expect-beacon", fixture.Beacon.Value}

	var o, e bytes.Buffer
	if code := run(append(args, "--json"), &o, &e); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, o.String(), e.String())
	}
	var rep struct {
		TranscriptSHA256 *string `json:"transcriptSha256"`
		VerifierBuild    *struct {
			Status, Reason, Module, VCSRevision string
		} `json:"verifierBuild"`
	}
	if err := json.Unmarshal(o.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.TranscriptSHA256 == nil || *rep.TranscriptSHA256 != digest {
		t.Fatalf("transcriptSha256 %v, the file hashes to %s", rep.TranscriptSHA256, digest)
	}
	if rep.VerifierBuild == nil || rep.VerifierBuild.Status != "unverified" || rep.VerifierBuild.Reason == "" || rep.VerifierBuild.VCSRevision != "" {
		t.Fatalf("verifierBuild %+v", rep.VerifierBuild)
	}

	o.Reset()
	e.Reset()
	if code := run(args, &o, &e); code != 0 {
		t.Fatalf("text: exit %d", code)
	}
	for _, want := range []string{"transcript:     sha256 " + digest, "verifier build: unverified"} {
		if !strings.Contains(o.String(), want) {
			t.Fatalf("text report lacks %q:\n%s", want, o.String())
		}
	}
}

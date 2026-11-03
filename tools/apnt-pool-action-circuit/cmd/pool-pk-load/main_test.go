package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark/logger"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/devprove"
)

// The command end to end on the small test circuit (not the pool action
// circuit): every command, the refusals, and a prove from the image.

type files struct {
	bin, dir               string
	raw, vk, r1cs          string
	rawPin, vkPin, r1csPin [2]string
}

func pinOf(t *testing.T, path string) [2]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		protectedFatal(t, err)
	}
	d := sha256.Sum256(b)
	return [2]string{fmt.Sprint(len(b)), hex.EncodeToString(d[:])}
}

func write(t *testing.T, path string, w func(io.Writer) error) {
	t.Helper()
	var b bytes.Buffer
	if err := w(&b); err != nil {
		protectedFatal(t, err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		protectedFatal(t, err)
	}
}

func newFiles(t *testing.T) *files {
	t.Helper()
	dir := t.TempDir()
	f := &files{dir: dir, bin: filepath.Join(dir, "pool-pk-load")}
	build := exec.Command("go", "build", "-o", f.bin, ".")
	build.Env = append(os.Environ(), "GOFLAGS=-mod=readonly", "GOPROXY=off")
	if out, err := build.CombinedOutput(); err != nil {
		protectedFatal(t, "build: %v\n%s", err, out)
	}
	target := devprove.SmallTarget(devprove.SmallRounds)
	ccs, err := target.Compile()
	if err != nil {
		protectedFatal(t, err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		protectedFatal(t, err)
	}
	f.raw, f.vk, f.r1cs = filepath.Join(dir, "raw.key"), filepath.Join(dir, "vk.bin"), filepath.Join(dir, "circuit.r1cs")
	write(t, f.raw, func(w io.Writer) error { _, err := pk.(*groth16bn254.ProvingKey).WriteRawTo(w); return err })
	write(t, f.vk, func(w io.Writer) error { _, err := vk.WriteTo(w); return err })
	write(t, f.r1cs, func(w io.Writer) error { _, err := ccs.WriteTo(w); return err })
	f.rawPin, f.vkPin, f.r1csPin = pinOf(t, f.raw), pinOf(t, f.vk), pinOf(t, f.r1cs)
	return f
}

var runs int

// run runs the command and decodes its result; it returns the exit error.
func (f *files) run(t *testing.T, args ...string) (*Result, error) {
	t.Helper()
	runs++
	out := filepath.Join(f.dir, fmt.Sprintf("result-%d.json", runs))
	cmd := exec.Command(f.bin, append(args, out)...)
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var r Result
	raw, rerr := os.ReadFile(out)
	if rerr != nil {
		protectedFatal(t, "%v: no result (%v); stderr %s", args, err, stderr.String())
	}
	if jerr := json.Unmarshal(raw, &r); jerr != nil {
		protectedFatal(t, jerr)
	}
	return &r, err
}

func pinArgs(p [2]string) []string { return []string{"--pin-bytes", p[0], "--pin-sha256", p[1]} }

func TestCommand(t *testing.T) {
	defer protectedPanic(t)
	f := newFiles(t)

	r, err := f.run(t, "sha256", "--key", f.raw)
	if err != nil || r.SHA256 != f.rawPin[1] {
		protectedFatal(t, "sha256: %v %s", err, r.SHA256)
	}
	if runtime.GOOS == "darwin" {
		// Eviction is observable: the file is resident after a read and not
		// after evict (the negative control of every cold-cache figure).
		os.ReadFile(f.raw)
		if r, err = f.run(t, "evict", "--key", f.raw); err != nil || r.Residency.ResidentPages == 0 || r.After.ResidentPages != 0 {
			protectedFatal(t, "evict: %v, residency before %+v after %+v", err, r.Residency, r.After)
		}
	}

	derived := map[string]string{}
	for _, format := range []string{"image", "dump"} {
		out := filepath.Join(f.dir, "derived."+format)
		r, err := f.run(t, append(append([]string{"derive", "--format", format, "--key", f.raw}, pinArgs(f.rawPin)...), "--out", out)...)
		if err != nil {
			protectedFatal(t, "derive %s: %v %s", format, err, r.Error)
		}
		if got := pinOf(t, out); got[1] != r.Derive.OutPin.SHA256 {
			protectedFatal(t, "derive %s: result pin %+v, file %v", format, r.Derive.OutPin, got)
		}
		derived[format] = out
	}
	image, imagePin := derived["image"], pinOf(t, derived["image"])
	dumpPin := pinOf(t, derived["dump"])

	for _, c := range []struct {
		cse, key string
		pin      [2]string
	}{
		{"readfrom", f.raw, f.rawPin}, {"unsafe", f.raw, f.rawPin}, {"readdump", derived["dump"], dumpPin},
		{"verified-raw", f.raw, f.rawPin}, {"verified-dump", derived["dump"], dumpPin}, {"verified-image", image, imagePin},
	} {
		r, err := f.run(t, append([]string{"load", "--case", c.cse, "--key", c.key}, pinArgs(c.pin)...)...)
		if err != nil || r.Shape == nil || r.Shape.G1A == 0 || len(r.Shape.Commitments) == 0 {
			protectedFatal(t, "load %s: %v %s %+v", c.cse, err, r.Error, r.Shape)
		}
	}

	// Round trip: the image-loaded key re-encodes to the raw key; a raw pin
	// for anything else is refused.
	rt := append([]string{"roundtrip", "--format", "image", "--key", image}, pinArgs(imagePin)...)
	if r, err := f.run(t, append(rt, "--raw-bytes", f.rawPin[0], "--raw-sha256", f.rawPin[1])...); err != nil || !r.RoundTrip.Matches {
		protectedFatal(t, "roundtrip: %v %s", err, r.Error)
	}
	if r, err := f.run(t, append(rt, "--raw-bytes", f.rawPin[0], "--raw-sha256", f.vkPin[1])...); err == nil || r.RoundTrip == nil || r.RoundTrip.Matches {
		protectedFatal(t, "roundtrip against another digest was not refused")
	}

	prove := func(key string, pin [2]string) (*Result, error) {
		args := append([]string{"prove", "--target", "small", "--format", "image", "--key", key}, pinArgs(pin)...)
		args = append(args, "--r1cs", f.r1cs, "--r1cs-bytes", f.r1csPin[0], "--r1cs-sha256", f.r1csPin[1],
			"--vk", f.vk, "--vk-bytes", f.vkPin[0], "--vk-sha256", f.vkPin[1])
		return f.run(t, args...)
	}
	r, err = prove(image, imagePin)
	if err != nil || !r.Prove.Verified || !r.Prove.FlippedRefused || !strings.Contains(r.Target, "NOT the pool action circuit") {
		protectedFatal(t, "prove: %v %s %+v", err, r.Error, r.Prove)
	}

	// One flipped image byte: refused at the digest, before any decode or prove.
	b, _ := os.ReadFile(image)
	b[len(b)/2] ^= 1
	flipped := filepath.Join(f.dir, "flipped.image")
	os.WriteFile(flipped, b, 0o600)
	r, err = prove(flipped, imagePin)
	if err == nil || r.ErrorStage != "digest" || r.Decode != nil {
		protectedFatal(t, "flipped image: %v stage %q decode %+v", err, r.ErrorStage, r.Decode)
	}
	for _, p := range r.Phases {
		if p.Name == "prove" || p.Name == "witness" {
			protectedFatal(t, "flipped image reached the %s phase", p.Name)
		}
	}
	// Truncated: refused from the size, with nothing read.
	truncated := filepath.Join(f.dir, "truncated.image")
	os.WriteFile(truncated, b[:len(b)-1], 0o600)
	if r, err = f.run(t, append([]string{"load", "--case", "verified-image", "--key", truncated}, pinArgs(imagePin)...)...); err == nil || r.ErrorStage != "size" || r.Read != nil {
		protectedFatal(t, "truncated image: %v stage %q", err, r.ErrorStage)
	}
	// Another key's digest (the raw key's, for the image).
	if r, err = f.run(t, append([]string{"load", "--case", "verified-image", "--key", image}, "--pin-bytes", imagePin[0], "--pin-sha256", f.rawPin[1])...); err == nil || r.ErrorStage != "digest" {
		protectedFatal(t, "another key's digest: %v stage %q", err, r.ErrorStage)
	}
}

func TestResultPaths(t *testing.T) {
	defer protectedPanic(t)
	f := &files{dir: t.TempDir()}
	f.bin = filepath.Join(f.dir, "pool-pk-load")
	build := exec.Command("go", "build", "-o", f.bin, ".")
	build.Env = append(os.Environ(), "GOFLAGS=-mod=readonly", "GOPROXY=off")
	if out, err := build.CombinedOutput(); err != nil {
		protectedFatal(t, "build: %v\n%s", err, out)
	}
	wd, _ := os.Getwd()
	for name, out := range map[string]string{
		"inside the repository": filepath.Join(wd, "result.json"),
		"existing":              f.bin,
	} {
		cmd := exec.Command(f.bin, "residency", "--key", f.bin, out)
		if err := cmd.Run(); err == nil {
			protectedFatal(t, "%s: the command wrote %s", name, out)
		}
	}
	if _, err := os.Lstat(filepath.Join(wd, "result.json")); err == nil {
		protectedFatal(t, "a result was written inside the repository")
	}
}

// Only fixed rules reach testing.T. Arguments still evaluate at the original
// assertion site; no String/Error method or formatter is invoked here.
func protectedFatal(t testing.TB, _ ...any) { t.Helper(); t.Fatal("pool-test-fatal") }
func protectedError(t testing.TB, _ ...any) { t.Helper(); t.Error("pool-test-error") }
func protectedLog(t testing.TB, _ ...any)   { t.Helper(); t.Log("pool-test-log") }
func protectedSkip(t testing.TB, _ ...any)  { t.Helper(); t.Skip("pool-test-source-skip") }
func protectedPanic(t testing.TB) {
	if recover() != nil {
		t.Helper()
		t.Fatal("pool-test-panic")
	}
}

// Suppress dependency diagnostic bodies before a test can enter the solver.
func init() { logger.Disable() }

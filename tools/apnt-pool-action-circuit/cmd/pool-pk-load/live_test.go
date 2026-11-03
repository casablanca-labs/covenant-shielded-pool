package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/devprove"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/pkload"
)

func requestFile(t *testing.T) string {
	t.Helper()
	c, err := poolaction.LoadCorpus("../../../../packages/protocol-runtime/test-vectors/apnt-pool-v1-action-circuit-vectors.json")
	if err != nil {
		protectedFatal(t, "fixture read failed")
	}
	found := false
	for _, e := range c.Entries {
		if e.Name == "dummy-dummy-deposit" {
			e.Name = "wallet-self-deposit"
			e.Note = "private-canary"
			c.Entries = []poolaction.CorpusEntry{e}
			found = true
			break
		}
	}
	if !found {
		protectedFatal(t, "deposit fixture absent")
	}
	b, _ := json.Marshal(c)
	p := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(p, b, 0600); err != nil {
		protectedFatal(t, "fixture write failed")
	}
	return p
}

// A copied harness cannot use caller SELF/HERE variables to acquire a plan.
// The earlier generation-2 entry refusal replaces the v1 plan-parser controls;
// admitted plan/resource controls remain in the final driver, not this copy.
func TestLiveHarnessCopiedEntryRefusesBeforePlan(t *testing.T) {
	t.Skip("requires private runner bridge and installation source; not shipped")
	defer protectedPanic(t)
	root := t.TempDir()
	if err := exec.Command("git", "init", "-b", "main", root).Run(); err != nil {
		protectedFatal(t, "scratch checkout init")
	}
	if err := os.Rename(filepath.Join(root, ".git"), filepath.Join(root, "git-meta")); err != nil {
		protectedFatal(t, "scratch checkout metadata")
	}
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: git-meta\n"), 0600); err != nil {
		protectedFatal(t, "scratch worktree marker")
	}
	script, err := os.ReadFile("../../scripts/measure-pk-load.sh")
	if err != nil {
		protectedFatal(t, "read committed harness")
	}
	dir := t.TempDir()
	copy := filepath.Join(dir, "harness.sh")
	if err := os.WriteFile(copy, script, 0600); err != nil {
		protectedFatal(t, "copy harness")
	}
	fifo := filepath.Join(dir, "plan.pipe")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		protectedFatal(t, "create unopened plan")
	}
	for _, plan := range []string{filepath.Join(dir, "absent-plan"), fifo} {
		out := filepath.Join(t.TempDir(), "out")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, "/bin/bash", copy, out, plan, "4")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "MEASURE_PK_LOAD_SELF="+copy, "MEASURE_PK_LOAD_HERE="+root, "PRIVATE_RUNNER_GENERATION=1")
		console, err := cmd.CombinedOutput()
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || len(console) != 0 {
			protectedFatal(t, "copied generation-2 harness lost silent exit-1 boundary or opened plan")
		}
		if _, err := os.Lstat(out); !os.IsNotExist(err) {
			protectedFatal(t, "refused copied harness created output")
		}
		if _, err := os.Lstat(copy); err != nil {
			protectedFatal(t, "unadmitted caller copy was removed")
		}
	}
}

// MIG01 R3 disposition: the pin-declaration unit uses the existing public
// corpus target. A raw private locator no longer supplies a positive reader.
func TestMIG01R3PinDeclarationsBeforePrivateAcquisition(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	target := devprove.ActionTarget("../../../../packages/protocol-runtime/test-vectors/apnt-pool-v1-action-circuit-vectors.json")
	pins := pkload.ChipnetZeroValueRevision3
	type config struct {
		f            pkload.Format
		pk, r1cs, vk pkload.Pin
		profile      string
	}
	good := config{pkload.FormatImage, pins.Image, pins.R1CS, pins.VerifyingKey, poolaction.ChipnetZeroValueRevision3ProfileID}
	admit := func(c config) error {
		w, a, err := admitRequest(target, c.f, c.pk, c.r1cs, c.vk, c.profile)
		if err == nil && (w == nil || a == nil || a.Source.Kind != "committed-corpus" || a.KeyFilesLoaded || a.ProfileID != good.profile || a.Parameters != pins.Label) {
			protectedFatal(t, "admission receipt incomplete")
		}
		return err
	}
	for _, field := range []string{"pk-size", "pk-digest", "r1cs-size", "r1cs-digest", "vk-size", "vk-digest", "profile", "missing-profile", "format", "raw-with-image-pin"} {
		t.Run(field, func(t *testing.T) {
			defer protectedPanic(t)
			bad := good
			switch field {
			case "pk-size":
				bad.pk.Bytes--
			case "pk-digest":
				bad.pk.SHA256 = strings.Repeat("0", 64)
			case "r1cs-size":
				bad.r1cs.Bytes--
			case "r1cs-digest":
				bad.r1cs.SHA256 = strings.Repeat("0", 64)
			case "vk-size":
				bad.vk.Bytes--
			case "vk-digest":
				bad.vk.SHA256 = strings.Repeat("0", 64)
			case "profile":
				bad.profile = strings.Repeat("0", 64)
			case "missing-profile":
				bad.profile = ""
			case "format":
				bad.f = pkload.FormatDump
			case "raw-with-image-pin":
				bad.f = pkload.FormatRaw
			}
			if admit(bad) != errLivePin {
				protectedFatal(t, "pin mismatch accepted")
			}
			if admit(good) != nil {
				protectedFatal(t, "restored pins refused")
			}
		})
	}
	good.f, good.pk = pkload.FormatRaw, pins.RawKey
	if admit(good) != nil {
		protectedFatal(t, "raw pin positive refused")
	}
}

// Production dispatch retains exact prerequisite and no-write controls in
// process, and the freshly built ordinary CLI must enforce the same boundary.
func TestMIG01ProductionRawDispatchBeforeKeys(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	f, flags, _ := reviewCLI(t)
	args := append(append([]string{"pool-pk-load", "admit-request"}, flags...), filepath.Join(t.TempDir(), "result.json"))
	prior := os.Args
	defer func() { os.Args = prior }()
	t.Chdir(t.TempDir()) // Independently reaches the exact checkout prerequisite.
	for _, command := range []string{"admit-request", "check-live", "prove"} {
		t.Run(command, func(t *testing.T) {
			defer protectedPanic(t)
			selected := append([]string(nil), args...)
			selected[1] = command
			os.Args = selected
			var terminal bytes.Buffer
			writes := 0
			result := runV2(selected, runDeps{stderr: &terminal, resultWriter: func(string, []byte) error { writes++; return nil }})
			if result.status != 1 || result.refusal != nil || result.prerequisite == nil || result.prerequisite.Error() != "live-request-main-checkout-required" || writes != 0 || terminal.Len() != 0 {
				protectedFatal(t, "production dispatch lost exact prerequisite or reached output/key work")
			}
			cmd := exec.Command(f.bin, selected[1:]...)
			console, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 || len(console) != 0 {
				protectedFatal(t, "production CLI lost silent prerequisite refusal")
			}
			if _, err := os.Lstat(selected[len(selected)-1]); !os.IsNotExist(err) {
				protectedFatal(t, "refused dispatch wrote a result")
			}
		})
	}
}

func TestMIG01ProductionPinAndOptionsBeforeAcquisition(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	_, flags, path := reviewCLI(t)
	for _, tc := range []struct{ name, flag, value, want string }{
		{"pin", "--pin-sha256", strings.Repeat("0", 64), "live-request-pin-mismatch"},
		{"conflict", "--corpus", path, "live-request-options"},
		{"target", "--target", "small", "live-request-options"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer protectedPanic(t)
			args := append(append([]string{"pool-pk-load", "admit-request"}, flags...), tc.flag, tc.value, filepath.Join(t.TempDir(), "result.json"))
			prior := os.Args
			os.Args = args
			defer func() { os.Args = prior }()
			var terminal bytes.Buffer
			writes := 0
			var receipt Result
			result := runV2(args, runDeps{stderr: &terminal, resultWriter: func(_ string, body []byte) error { writes++; return json.Unmarshal(body, &receipt) }})
			if result.status != 1 || result.prerequisite != nil || result.refusal != nil || writes != 1 || receipt.Error != tc.want || receipt.Admission != nil || receipt.Read != nil || receipt.Decode != nil || receipt.Prove != nil {
				protectedFatal(t, "exact pin/options refusal did not precede private acquisition and keys")
			}
			body, _ := json.Marshal(receipt)
			if bytes.Contains(append(body, terminal.Bytes()...), []byte(path)) {
				protectedFatal(t, "private path escaped")
			}
		})
	}
}

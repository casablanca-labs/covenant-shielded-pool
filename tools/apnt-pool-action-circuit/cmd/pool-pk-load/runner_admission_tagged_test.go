//go:build private_runner_admission_test

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/devprove"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/internal/runneradmission"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/pkload"
)

// PH11-X: actual run dispatch, only the shared prerequisite substituted.
// Ownership, installed bridge checks, decoder, serializer and writer stay real.
// An unregistered source in this lane reaches the quiet ownership return;
// this is separate from the genuine-issuer production runtime pair.
func TestMIG01R3TaggedRealDispatchOwnershipTuple(t *testing.T) {
	t.Skip("requires private runner bridge and installation source; not shipped")
	defer protectedPanic(t)
	var prerequisites int
	runneradmission.SetTestPrerequisite(t.Cleanup, func() error { prerequisites++; return nil })
	pins := pkload.ChipnetZeroValueRevision3
	for _, command := range []string{"admit-request", "check-live", "prove"} {
		t.Run(command, func(t *testing.T) {
			defer protectedPanic(t)
			request := filepath.Join(t.TempDir(), "absent-private-source.json")
			args := []string{"pool-pk-load", command, "--request", request, "--format", "image", "--profile-id", poolaction.ChipnetZeroValueRevision3ProfileID}
			for _, pin := range []struct {
				name  string
				value pkload.Pin
			}{{"pin", pins.Image}, {"r1cs", pins.R1CS}, {"vk", pins.VerifyingKey}} {
				args = append(args, "--"+pin.name+"-bytes", strconv.FormatInt(pin.value.Bytes, 10), "--"+pin.name+"-sha256", pin.value.SHA256)
			}
			args = append(args, filepath.Join(t.TempDir(), "native-result.json"))
			prior := os.Args
			os.Args = args
			defer func() { os.Args = prior }()
			var terminal bytes.Buffer
			writes := 0
			before := prerequisites
			result := runV2(args, runDeps{stderr: &terminal, resultWriter: func(string, []byte) error { writes++; return nil }})
			want := runneradmission.Refusal{Code: "wallet-command-component-refused", Retry: "none", Cause: "pool-wallet-payment-host-authority-required"}
			if prerequisites-before != 1 || result.status != 1 || result.prerequisite != nil || result.refusal == nil || *result.refusal != want {
				protectedFatal(t, "real dispatch did not reach the exact ownership tuple")
			}
			if writes != 0 || terminal.Len() != 0 {
				protectedFatal(t, "ownership refusal reached serialization or terminal output")
			}
			if _, err := os.Lstat(args[len(args)-1]); !os.IsNotExist(err) {
				protectedFatal(t, "ownership refusal created a native result")
			}
		})
	}
}

func TestMIG01R3RegisteredLibraryObservation(t *testing.T) {
	defer protectedPanic(t)
	raw := os.Getenv("MIG01_TEST_RUN_ARGUMENTS")
	if raw == "" {
		protectedSkip(t, "requires the genuine outside synthetic issuer")
	}
	var args []string
	if json.Unmarshal([]byte(raw), &args) != nil || len(args) < 5 || args[2] != "--request" {
		protectedFatal(t, "closed library test invocation required")
	}
	want := os.Getenv("MIG01_TEST_EXPECT")
	if want != "success" && want != "ownership" {
		protectedFatal(t, "unknown library test expectation")
	}
	prerequisites := 0
	runneradmission.SetTestPrerequisite(t.Cleanup, func() error { prerequisites++; return nil })
	prior := os.Args
	os.Args = args
	defer func() { os.Args = prior }()
	a, source, err := devprove.InactiveLiveActionTargetV2(args[3]).Assignment()
	if prerequisites != 1 {
		protectedFatal(t, "direct library did not use the shared prerequisite")
	}
	if want == "success" {
		if err != nil || a == nil || source == nil || source.Kind != "live-request" {
			protectedFatal(t, "genuine direct library acquisition failed")
		}
	} else {
		var refusal *runneradmission.Refusal
		expected := runneradmission.Refusal{Code: "wallet-command-component-refused", Retry: "none", Cause: "pool-wallet-payment-host-authority-required"}
		if !errors.As(err, &refusal) || *refusal != expected || a != nil || source != nil {
			protectedFatal(t, "direct library exact ownership/no-assignment boundary")
		}
	}
}

// Only the outside synthetic issuer fixture supplies this input. The ordinary
// artifact contains neither this test nor the prerequisite setter. No decoder,
// route, membership, registry, writer or resource check is substituted.
func TestMIG01R3RegisteredDispatchObservation(t *testing.T) {
	defer protectedPanic(t)
	raw := os.Getenv("MIG01_TEST_RUN_ARGUMENTS")
	if raw == "" {
		protectedSkip(t, "requires the genuine outside synthetic issuer")
	}
	var args []string
	if json.Unmarshal([]byte(raw), &args) != nil || len(args) < 3 || (args[1] != "admit-request" && args[1] != "check-live") {
		protectedFatal(t, "closed no-proof test invocation required")
	}
	want := os.Getenv("MIG01_TEST_EXPECT")
	if want != "success" && want != "ownership" && want != "binding" {
		protectedFatal(t, "unknown test expectation")
	}
	prerequisites := 0
	runneradmission.SetTestPrerequisite(t.Cleanup, func() error { prerequisites++; return nil })
	prior := os.Args
	os.Args = args
	defer func() { os.Args = prior }()
	var terminal bytes.Buffer
	writes := 0
	var receipt Result
	result := runV2(args, runDeps{stderr: &terminal, resultWriter: func(_ string, body []byte) error {
		writes++
		return json.Unmarshal(body, &receipt)
	}})
	// Assignment checks the shared prerequisite once. A successful W then
	// rechecks it in checkLiveV2 before monitoring without a proving floor.
	// Refused acquisition must never reach that second check.
	wantPrerequisites := 1
	if want == "success" && args[1] == "check-live" {
		wantPrerequisites = 2
	}
	if prerequisites != wantPrerequisites || terminal.Len() != 0 {
		protectedFatal(t, "dispatch prerequisite or console boundary")
	}
	if want == "success" {
		if result.status != 0 || result.prerequisite != nil || result.refusal != nil || writes != 1 || receipt.Admission == nil || receipt.Prove != nil || receipt.Read != nil {
			protectedFatal(t, "genuine dispatch did not reach assignment-only control")
		}
	} else {
		cause := "pool-wallet-payment-host-authority-required"
		if want == "binding" {
			cause = "pool-wallet-payment-binding"
		}
		expected := runneradmission.Refusal{Code: "wallet-command-component-refused", Retry: "none", Cause: cause}
		if result.status != 1 || result.prerequisite != nil || result.refusal == nil || *result.refusal != expected || writes != 0 {
			protectedFatal(t, "exact registered dispatch refusal or no-write boundary")
		}
	}
	if _, err := os.Lstat(args[len(args)-1]); !os.IsNotExist(err) {
		protectedFatal(t, "test observer wrote a native result")
	}
}

func TestMIG01CheckLiveRejectsProve(t *testing.T) {
	defer protectedPanic(t)
	calls := 0
	runneradmission.SetTestPrerequisite(t.Cleanup, func() error { calls++; return nil })
	for _, command := range []string{"prove", "load", "admit-request", ""} {
		if err := checkLiveV2(command); err == nil || err.Error() != "live-request-options" || calls != 0 {
			protectedFatal(t, "non-check operation entered floor-free work or prerequisites")
		}
	}
}

func TestMIG01TaggedPrerequisiteCodes(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	_, flags, _ := reviewCLI(t)
	for _, code := range []string{"live-request-main-checkout-required", "live-request-harness-required", "live-request-prover-lock-required"} {
		t.Run(code, func(t *testing.T) {
			defer protectedPanic(t)
			calls := 0
			runneradmission.SetTestPrerequisite(t.Cleanup, func() error { calls++; return errors.New(code) })
			args := append(append([]string{"pool-pk-load", "admit-request"}, flags...), filepath.Join(t.TempDir(), "result.json"))
			prior := os.Args
			os.Args = args
			defer func() { os.Args = prior }()
			var terminal bytes.Buffer
			writes := 0
			result := runV2(args, runDeps{stderr: &terminal, resultWriter: func(string, []byte) error { writes++; return nil }})
			if result.status != 1 || result.refusal != nil || result.prerequisite == nil || result.prerequisite.Error() != code || calls != 1 || writes != 0 || terminal.Len() != 0 {
				protectedFatal(t, "exact prerequisite return lost its quiet no-write boundary")
			}
		})
	}
}

func TestMIG01TaggedWorkUsesOwningPrerequisite(t *testing.T) {
	defer protectedPanic(t)
	calls, work := 0, 0
	runneradmission.SetTestPrerequisite(t.Cleanup, func() error { calls++; return errors.New("live-request-harness-required") })
	err := (liveV2{}).guard(func() error { work++; return nil })
	if calls != 1 || work != 0 || err == nil || err.Error() != "live-request-harness-required" {
		protectedFatal(t, "v2 work skipped owning prerequisite or reached work")
	}
}

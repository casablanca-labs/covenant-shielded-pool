package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/devprove"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/pkload"
)

func reviewCLI(t *testing.T) (*files, []string, string) {
	t.Helper()
	f := &files{dir: t.TempDir()}
	f.bin = filepath.Join(f.dir, "pool-pk-load")
	build := exec.Command("go", "build", "-o", f.bin, ".")
	build.Env = append(os.Environ(), "GOFLAGS=", "GOENV=off")
	if b, err := build.CombinedOutput(); err != nil {
		protectedFatal(t, "build failed: %s", b)
	}
	path := requestFile(t)
	markerPath := filepath.Join(filepath.Dir(path), "SYNTHETIC_PRIVATE_PATH_MARKER.json")
	if err := os.Rename(path, markerPath); err != nil {
		protectedFatal(t, "rename fixture")
	}
	p := pkload.ChipnetZeroValueRevision3
	args := []string{"--request", markerPath, "--format", "image", "--profile-id", poolaction.ChipnetZeroValueRevision3ProfileID}
	for _, x := range []struct {
		flag string
		pin  pkload.Pin
	}{{"pin", p.Image}, {"r1cs", p.R1CS}, {"vk", p.VerifyingKey}} {
		args = append(args, "--"+x.flag+"-bytes", strconv.FormatInt(x.pin.Bytes, 10), "--"+x.flag+"-sha256", x.pin.SHA256)
	}
	args = append(args, "--key", filepath.Join(f.dir, "absent-pk"), "--r1cs", filepath.Join(f.dir, "absent-r1cs"), "--vk", filepath.Join(f.dir, "absent-vk"))
	return f, args, markerPath
}

// The production raw CLI controls below stop at runner admission. Registered
// replacement and snapshot controls belong to the owning bridge suites.

func TestLiveReviewResourceControls(t *testing.T) {
	defer protectedPanic(t)
	if liveFloor != 17<<30 {
		protectedFatal(t, "child admission floor must be exactly 17 GiB")
	}
	good := liveResources{liveFloor, 50 << 30, 1 << 30} // large existing swap is allowed
	for _, tc := range []struct {
		name        string
		first, next liveResources
		readErr     bool
		want        string
	}{
		{"16-gib", liveResources{16 << 30, 0, 0}, good, false, "live-request-memory-floor"},
		{"floor", liveResources{liveFloor - 1, 0, 0}, good, false, "live-request-memory-floor"},
		{"rss", good, liveResources{liveFloor, 50 << 30, liveRSSTrip + 1}, false, "live-request-rss-trip"},
		{"swap", good, liveResources{liveFloor, (50 << 30) + liveSwapTrip + 1, 0}, false, "live-request-swap-trip"},
		{"unavailable", good, good, true, "live-request-monitor-unavailable"},
		{"negative", good, liveResources{liveFloor, -1, 0}, false, "live-request-monitor-unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer protectedPanic(t)
			ticks := make(chan time.Time)
			fired := make(chan error, 1)
			n := 0
			read := func() (liveResources, error) {
				n++
				if n == 1 {
					return tc.first, nil
				}
				if tc.readErr {
					return liveResources{}, errors.New(tc.want)
				}
				return tc.next, nil
			}
			stop, err := startLiveMonitor("prove", read, ticks, func(err error) { fired <- err })
			if tc.name == "floor" || tc.name == "16-gib" {
				if err == nil || err.Error() != tc.want {
					protectedFatal(t, "floor did not fire")
				}
				return
			}
			if err != nil {
				protectedFatal(t, "positive baseline refused")
			}
			ticks <- time.Now()
			select {
			case got := <-fired:
				if got.Error() != tc.want {
					protectedFatal(t, "wrong trip")
				}
			case <-time.After(3 * time.Second):
				protectedFatal(t, "monitor did not trip")
			}
			stop()
		})
	}
	ticks := make(chan time.Time)
	sampled := make(chan struct{}, 1)
	n := 0
	stop, err := startLiveMonitor("prove", func() (liveResources, error) {
		n++
		if n > 1 {
			sampled <- struct{}{}
		}
		return good, nil
	}, ticks, func(error) { protectedError(t, "positive monitor tripped") })
	if err != nil {
		protectedFatal(t, "positive monitor refused")
	}
	ticks <- time.Now()
	<-sampled
	stop()
	// 8 GiB free + 6 GiB inactive + 3 GiB speculative. Purgeable never counts.
	raw := "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 524288.\nPages inactive: 393216.\nPages speculative: 196608.\nPages purgeable: 1310720.\n"
	if got, err := parseAvailable(raw); err != nil || got != 17<<30 {
		protectedFatal(t, "vm_stat positive parser")
	}
	for _, bad := range []string{"", strings.ReplaceAll(raw, "16384", "bad"), strings.ReplaceAll(raw, "Pages speculative:", "missing:")} {
		if _, err := parseAvailable(bad); err == nil {
			protectedFatal(t, "vm_stat malformed accepted")
		}
	}
}

func TestLiveReviewNoProofAdmission(t *testing.T) {
	defer protectedPanic(t)
	for _, command := range []string{"check-live", "prove", "load", "", "CHECK-LIVE"} {
		t.Run(command, func(t *testing.T) {
			defer protectedPanic(t)
			reads, trips := 0, 0
			stop, err := startLiveMonitor(command, func() (liveResources, error) {
				reads++
				return liveResources{1 << 30, 0, 0}, nil
			}, make(chan time.Time), func(error) { trips++ })
			want, wantReads := "live-request-options", 0
			switch command {
			case "check-live":
				want, wantReads = "", 1
			case "prove":
				want, wantReads = "live-request-memory-floor", 1
			}
			if stop != nil {
				stop()
			}
			got := ""
			if err != nil {
				got = err.Error()
			}
			if got != want || reads != wantReads || trips != 0 || (stop != nil) != (want == "") {
				protectedFatal(t, "exact mode admission or no-monitor boundary")
			}
		})
	}
}

// Compile the actual proving guard, begin function and monitor together. Only
// inventory and resource reads are synthetic; no production injection is added.
// Embedding binds the unit to the source compiled by Go, including Go overlays.
//
//go:embed live_harness.go
var reviewLiveHarnessSource string

func TestLiveReviewProvingGuardFloor(t *testing.T) {
	defer protectedPanic(t)
	source := reviewLiveHarnessSource
	unit := func(start, end string) string {
		t.Helper()
		if strings.Count(source, start) != 1 || strings.Count(source, end) != 1 {
			protectedFatal(t, "guard extraction boundary changed")
		}
		return start + strings.Split(strings.Split(source, start)[1], end)[0]
	}
	text := "package main\nimport(\"errors\";\"fmt\";\"os\";\"time\")\n" +
		unit("type liveResources struct", "func readLiveResources()") +
		unit("func liveResourceFailure(", "// Production live work") +
		unit("func guardLiveResources(", "// No arbitrary work") +
		"func beginLiveResources(" + strings.Split(source, "func beginLiveResources(")[1] + `
var available int64
var scans, reads int
func liveQuietMachine(string) error { scans++; return nil }
func readLiveResources() (liveResources,error) { reads++; return liveResources{available,0,0},nil }
`
	regression := `package main
import "testing"
func TestProvingFloor(t *testing.T) {
 for _, n := range []int64{16<<30,17<<30} {
  available=n;scans=0;reads=0;work:=0
  err:=guardLiveResources(func()error{work++;return nil},"synthetic-inventory")
  code:="";if err!=nil {code=err.Error()}
  want:="";wantWork:=1
  if n==16<<30 {want="live-request-memory-floor";wantWork=0}
  if code!=want || work!=wantWork || scans!=1 || reads!=1 {
   t.Fatal("proving floor/work boundary")
  }
 }
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "unit.go")
	if err := os.WriteFile(filepath.Join(dir, "unit_test.go"), []byte(regression), 0600); err != nil {
		protectedFatal(t, err)
	}
	before := `beginLiveResources(reader, "prove")`
	phase := 0
	for _, mutant := range []bool{false, true, false} {
		candidate := text
		if mutant {
			if strings.Count(text, before) != 1 {
				protectedFatal(t, "proving call boundary changed")
			}
			candidate = strings.Replace(text, before, `beginLiveResources(reader, "check-live")`, 1)
		}
		if err := os.WriteFile(path, []byte(candidate), 0600); err != nil {
			protectedFatal(t, err)
		}
		cmd := exec.Command("go", "test", "-json", "-timeout=0", "-p=1", "-parallel=1", "unit.go", "unit_test.go", "-run", "^TestProvingFloor$", "-count=1")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOFLAGS=", "GOENV=off", "GOPROXY=off")
		output, err := cmd.CombinedOutput()
		if mutant {
			if err == nil || !bytes.Contains(output, []byte("proving floor/work boundary")) {
				protectedFatal(t, "G4 did not fail at the proving floor oracle")
			}
		} else if err != nil {
			protectedFatal(t, "proving floor control failed: %s", output)
		}
		recordProvingFloorPhase(t, phase, output, err)
		phase++
	}
}

func TestLiveReviewNoProofKeepsMonitoring(t *testing.T) {
	defer protectedPanic(t)
	for _, code := range []string{"live-request-monitor-unavailable", "live-request-swap-trip", "live-request-rss-trip"} {
		t.Run(code, func(t *testing.T) {
			defer protectedPanic(t)
			ticks := make(chan time.Time)
			fired := make(chan error, 1)
			reads := 0
			stop, err := startLiveMonitor("check-live", func() (liveResources, error) {
				reads++
				s := liveResources{1 << 30, 0, 0}
				if reads > 1 {
					switch code {
					case "live-request-monitor-unavailable":
						s.available = -1
					case "live-request-swap-trip":
						s.swap = liveSwapTrip + 1
					case "live-request-rss-trip":
						s.rss = liveRSSTrip + 1
					}
				}
				return s, nil
			}, ticks, func(err error) { fired <- err })
			if err != nil {
				protectedFatal(t, "low-memory no-proof baseline refused")
			}
			defer stop()
			ticks <- time.Now()
			select {
			case got := <-fired:
				if got.Error() != code {
					protectedFatal(t, "wrong no-proof monitor trip")
				}
			case <-time.After(3 * time.Second):
				protectedFatal(t, "no-proof monitor did not trip")
			}
		})
	}
}

// Production raw CLI privacy, alias and prerequisite controls.
func TestMIG01R3RawReviewCLIPrivacyAliasesAndReplacement(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	_, args, path := reviewCLI(t)
	t.Chdir(t.TempDir()) // Deterministic ordinary-build prerequisite.
	raw, _ := os.ReadFile(path)
	marker := []byte("SYNTHETIC_PRIVATE_PATH_MARKER")
	leaked := func(b []byte) bool { return bytes.Contains(b, marker) || bytes.Contains(b, []byte("private-canary")) }
	if !leaked(append([]byte("receipt: "), marker...)) {
		protectedFatal(t, "path detector firing control failed")
	}
	call := func(command string, extra []string, wantExit int, wantError string) Result {
		t.Helper()
		out := filepath.Join(t.TempDir(), "result.json")
		argv := append(append(append([]string{command}, args...), extra...), out)
		native := append([]string{"pool-pk-load"}, argv...)
		prior := os.Args
		os.Args = native
		defer func() { os.Args = prior }()
		var terminal bytes.Buffer
		writes := 0
		result := runV2(native, runDeps{stderr: &terminal, resultWriter: func(path string, body []byte) error { writes++; return writeNew(path, body) }})
		console, exit := terminal.Bytes(), result.status
		if wantError == "@harness" && (result.prerequisite == nil || result.prerequisite.Error() != "live-request-main-checkout-required" || result.refusal != nil || writes != 0) {
			protectedFatal(t, "raw v2 prerequisite code/no-write boundary")
		}
		b, _ := os.ReadFile(out)
		if leaked(append(b, console...)) {
			protectedFatal(t, "private path or text escaped")
		}
		if exit != wantExit {
			protectedFatal(t, "exit %d, want %d", exit, wantExit)
		}
		var r Result
		if len(b) > 0 && json.Unmarshal(b, &r) != nil {
			protectedFatal(t, "invalid receipt")
		}
		if wantError == "@harness" {
			if len(b) != 0 || len(console) != 0 {
				protectedFatal(t, "raw prerequisite refusal serialized or printed")
			}
		} else if r.Error != wantError {
			protectedFatal(t, "unexpected named refusal: %s", r.Error)
		}
		if r.Key != "" || len(r.Args) != 0 || r.Read != nil || r.Decode != nil || r.Prove != nil {
			protectedFatal(t, "receipt exposed path or reached key work")
		}
		for _, phase := range r.Phases {
			if phase.Name != "admit-request" {
				protectedFatal(t, "reached key work")
			}
		}
		protectedLog(t, "exit=%d error=%s keyWork=false pathDetector=false", exit, wantError)
		return r
	}
	// Raw callers, including a valid decoder fixture, reach the real harness
	// prerequisite before private acquisition. Registered positives and source
	// replacement use the separate exact-code controls.
	call("admit-request", nil, 1, "@harness")
	link := filepath.Join(t.TempDir(), "SYNTHETIC_PRIVATE_PATH_MARKER-link")
	hard := filepath.Join(t.TempDir(), "SYNTHETIC_PRIVATE_PATH_MARKER-hard")
	if os.Symlink(path, link) != nil || os.Link(path, hard) != nil {
		protectedFatal(t, "alias fixture")
	}
	for _, alias := range []string{path, link, hard, filepath.Dir(path) + "/./" + filepath.Base(path)} {
		for _, flag := range []string{"--key", "--r1cs", "--vk"} {
			call("admit-request", []string{flag, alias}, 1, "live-request-options")
		}
	}
	call("admit-request", []string{"--request", link}, 1, "@harness")
	call("admit-request", []string{"--pin-bytes", string(marker)}, 2, "")
	call("admit-request", []string{"--request=" + path, "--key=" + path}, 1, "live-request-options")
	call("admit-request", []string{"--request", ""}, 1, "live-request-options")
	call("admit-request", []string{path}, 2, "") // extra positional input must not be echoed
	// Malformed bytes and aliases do not turn an ordinary caller into a
	// registered owner. Cache modes retain the earlier harness refusal.
	call("admit-request", nil, 1, "@harness")
	for _, mode := range []string{"warm", "cold", "asis"} {
		if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
			protectedFatal(t, "write replacement")
		}
		call("prove", []string{"--live-cache", mode}, 1, "@harness")
		os.Remove(path)
		if os.Symlink(hard, path) != nil {
			protectedFatal(t, "replace by symlink")
		}
		call("prove", []string{"--live-cache", mode}, 1, "@harness")
		os.Remove(path)
		if os.WriteFile(path, raw, 0600) != nil {
			protectedFatal(t, "restore")
		}
		call("admit-request", nil, 1, "@harness")
	}
	// Loader errors are independently value-free, even if aliasing happens later.
	if leaked([]byte(redactLiveError(fmt.Errorf("open %s: absent", path)).Error())) {
		protectedFatal(t, "loader error leaked")
	}
	if redactLiveError(devprove.ErrRequestMalformed) != devprove.ErrRequestMalformed {
		protectedFatal(t, "named error lost")
	}
}

// Only fixed rules reach testing.T.
// Record only actual generated-unit harness facts. The original extraction,
// single prove-to-check-live mutation and its exact oracle remain above.
func recordProvingFloorPhase(t *testing.T, phase int, output []byte, childError error) {
	t.Helper()
	exit := 0
	if childError != nil {
		failure, ok := childError.(*exec.ExitError)
		if !ok {
			protectedFatal(t, "nested launch failed")
		}
		exit = failure.ExitCode()
	}
	if phase < 0 || phase > 2 || exit != []int{0, 1, 0}[phase] {
		protectedFatal(t, "nested exit mismatch")
	}
	runs, terminals, packageTerminals := 0, 0, 0
	state, oracle := "", false
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		var event struct{ Action, Test, Package, Output string }
		if json.Unmarshal([]byte(line), &event) != nil || event.Package != "command-line-arguments" {
			protectedFatal(t, "nested event malformed")
		}
		if event.Test != "" && event.Test != "TestProvingFloor" {
			protectedFatal(t, "nested unexpected test")
		}
		if event.Test == "TestProvingFloor" {
			switch event.Action {
			case "run":
				runs++
			case "pass", "fail", "skip":
				terminals++
				state = event.Action
			case "output":
				oracle = oracle || strings.Contains(event.Output, "proving floor/work boundary")
			}
		} else if event.Action == "pass" || event.Action == "fail" || event.Action == "skip" {
			packageTerminals++
			if event.Action != []string{"pass", "fail", "pass"}[phase] {
				protectedFatal(t, "nested package state mismatch")
			}
		}
	}
	if runs != 1 || terminals != 1 || packageTerminals != 1 || state != []string{"pass", "fail", "pass"}[phase] || oracle != (phase == 1) {
		protectedFatal(t, "nested state mismatch")
	}
	receipt := struct {
		Phase         string `json:"phase"`
		Name          string `json:"name"`
		State         string `json:"state"`
		ExitCode      int    `json:"exitCode"`
		RunCount      int    `json:"runCount"`
		TerminalCount int    `json:"terminalCount"`
		OutputBytes   int    `json:"outputBytes"`
		OutputSha256  string `json:"outputSha256"`
		Oracle        bool   `json:"oracle"`
	}{[]string{"original", "mutant", "restored"}[phase], "TestProvingFloor", state, exit, runs, terminals, len(output), fmt.Sprintf("%x", sha256.Sum256(output)), oracle}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		protectedFatal(t, "nested metadata encoding")
	}
	t.Log("POOL_NATIVE_NESTED " + string(encoded))
}

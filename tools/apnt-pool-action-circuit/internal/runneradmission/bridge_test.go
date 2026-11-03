package runneradmission

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func testNodePath(t *testing.T) string {
	t.Helper()
	account, err := user.Current()
	if err != nil {
		t.Fatal("native account unavailable")
	}
	return filepath.Join(account.HomeDir, ".nvm/versions/node/v22.22.3/bin/node")
}

func TestMIG01R3PrivateLocalFrameExactKeys(t *testing.T) {
	if value, ok := decodeBridgeMetadata([]byte(`{"bytes":3,"error":null}`), 3); !ok || value != nil {
		t.Fatal("valid snapshot metadata refused")
	}
	closed := `{"bytes":0,"error":{"cause":"pool-wallet-store-busy","code":"wallet-command-component-refused","retry":"none"}}`
	if value, ok := decodeBridgeMetadata([]byte(closed), 0); !ok || value == nil || value.Cause != "pool-wallet-store-busy" {
		t.Fatal("valid closed error refused")
	}
	for name, raw := range map[string]string{
		"duplicate": `{"bytes":3,"bytes":3,"error":null}`, "unknown": `{"bytes":3,"error":null,"extra":0}`,
		"missing": `{"bytes":3}`, "case": `{"Bytes":3,"error":null}`, "null-count": `{"bytes":null,"error":null}`,
		"fraction": `{"bytes":3.0,"error":null}`, "count-type": `{"bytes":"3","error":null}`, "trailing": `{"bytes":3,"error":null}{}`,
		"count-mismatch": `{"bytes":4,"error":null}`, "zero-snapshot": `{"bytes":0,"error":null}`,
		"error-duplicate": `{"bytes":0,"error":{"cause":"pool-wallet-store-busy","cause":"pool-wallet-store-busy","code":"wallet-command-component-refused","retry":"none"}}`,
		"error-missing":   `{"bytes":0,"error":{"cause":"pool-wallet-store-busy","code":"wallet-command-component-refused"}}`,
		"error-case":      `{"bytes":0,"error":{"cause":"pool-wallet-store-busy","Code":"wallet-command-component-refused","retry":"none"}}`,
		"free-text":       `{"bytes":0,"error":{"cause":"arbitrary","code":"wallet-command-component-refused","retry":"none"}}`,
		"retry":           `{"bytes":0,"error":{"cause":"pool-wallet-store-busy","code":"wallet-command-component-refused","retry":"after-sync"}}`,
		"error-payload":   `{"bytes":3,"error":{"cause":"pool-wallet-store-busy","code":"wallet-command-component-refused","retry":"none"}}`,
		"whitespace":      `{ "bytes":3,"error":null}`,
		"negative-count":  `{"bytes":-1,"error":null}`, "array": `[]`, "error-type": `{"bytes":0,"error":false}`,
		"code-type":  `{"bytes":0,"error":{"cause":"pool-wallet-store-busy","code":7,"retry":"none"}}`,
		"wrong-code": `{"bytes":0,"error":{"cause":"pool-wallet-store-busy","code":"other","retry":"none"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			payload := 3
			if strings.HasPrefix(raw, `{"bytes":0,`) {
				payload = 0
			}
			if _, ok := decodeBridgeMetadata([]byte(raw), payload); ok {
				t.Fatal("invalid local frame accepted")
			}
		})
	}
}

func TestMIG01ExactObject(t *testing.T) {
	if _, ok := exactObject([]byte(`{"bytes":3,"error":null}`), "bytes", "error"); !ok {
		t.Fatal("valid object refused")
	}
	for _, raw := range []string{`[]`, `{`, `{"bytes":3,"bytes":3,"error":null}`, `{"bytes":3,"error":null,"extra":0}`, `{"bytes":3}`, `{"Bytes":3,"error":null}`, `{"bytes":3,"error":null}{}`, `{"bytes":3,"error":`} {
		if _, ok := exactObject([]byte(raw), "bytes", "error"); ok {
			t.Fatal("invalid object admitted")
		}
	}
}

func TestMIG01InstallationSource(t *testing.T) {
	root := t.TempDir()
	fixtureGit(t, root, "init", "-b", "main")
	paths := []string{bridgeEntry, "tools/pool-action-modules/lib/private-runner-installation.mjs", "tools/pool-action-modules/private-runner-installation.py"}
	nodeLiteral, _ := json.Marshal(testNodePath(t))
	verifier := "import sys\nprint(" + string(nodeLiteral) + ")\n"
	// The synthetic verifier isolates Go's committed-source guard. It does not
	// certify an installation graph; RN owns the real Python verifier controls.
	for _, path := range paths {
		text := "# synthetic fixture\n"
		if strings.HasSuffix(path, ".py") {
			text = verifier
		}
		if os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0700) != nil || os.WriteFile(filepath.Join(root, path), []byte(text), 0600) != nil {
			t.Fatal("fixture unavailable")
		}
	}
	fixtureGit(t, root, "add", ".")
	fixtureGit(t, root, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-m", "synthetic fixture")
	if selected, err := verifyBridgeInstallation(root); err != nil || selected != testNodePath(t) {
		t.Fatal("source control refused")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			file := filepath.Join(root, path)
			original, err := os.ReadFile(file)
			if err != nil {
				t.Fatal("fixture unavailable")
			}
			if os.WriteFile(file, []byte("# synthetic poison\n"), 0600) != nil {
				t.Fatal("fixture unavailable")
			}
			_, err = verifyBridgeInstallation(root)
			assertOwnership(t, err)
			if os.WriteFile(file, original, 0600) != nil {
				t.Fatal("fixture unavailable")
			}
		})
	}
	_, err := verifyBridgeInstallation("")
	assertOwnership(t, err)
	_, err = verifyBridgeInstallation("relative")
	assertOwnership(t, err)
}

// Installed selection is a single closed path, never caller text or an argv tail.
func TestMIG01InstallationSelectionOutput(t *testing.T) {
	for _, output := range []string{"relative\n", "/bin/false\n", "/synthetic/path --option\n", "/synthetic/path\nextra\n", ""} {
		t.Run(strconv.Itoa(len(output)), func(t *testing.T) {
			root := t.TempDir()
			fixtureGit(t, root, "init", "-b", "main")
			literal, _ := json.Marshal(output)
			for _, relative := range []string{bridgeEntry, "tools/pool-action-modules/lib/private-runner-installation.mjs", "tools/pool-action-modules/private-runner-installation.py"} {
				source := "# synthetic fixture\n"
				if strings.HasSuffix(relative, ".py") {
					source = "import sys\nsys.stdout.write(" + string(literal) + ")\n"
				}
				file := filepath.Join(root, relative)
				if os.MkdirAll(filepath.Dir(file), 0700) != nil || os.WriteFile(file, []byte(source), 0600) != nil {
					t.Fatal("fixture unavailable")
				}
			}
			fixtureGit(t, root, "add", ".")
			fixtureGit(t, root, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-m", "synthetic fixture")
			_, err := verifyBridgeInstallation(root)
			assertOwnership(t, err)
		})
	}
}

// All fixtures are synthetic; assertions never print a request or snapshot.
func assertOwnership(t *testing.T, err error) {
	t.Helper()
	// Keep this independent of the constructor being checked. A mutation of
	// OwnershipRefusal must not change both the observed and expected tuple.
	want := Refusal{Code: "wallet-command-component-refused", Retry: "none", Cause: "pool-wallet-payment-host-authority-required"}
	if got, ok := err.(*Refusal); !ok || got == nil || *got != want || err.Error() != "private-runner-refused" {
		t.Fatal("ownership refusal mismatch")
	}
}

// Local construction and authenticated remote refusal propagation are
// separate obligations. The expiry observers cover the latter through runV2.
func TestMIG01R3PrivateOwnershipTuple(t *testing.T) {
	t.Run("constructor", func(t *testing.T) { assertOwnership(t, OwnershipRefusal()) })
	t.Run("invocation", func(t *testing.T) {
		prior := os.Args
		os.Args = []string{"pool-pk-load"}
		defer func() { os.Args = prior }()
		value, err := fixedInvocation("relative")
		if value != nil {
			t.Fatal("invalid invocation produced authority")
		}
		assertOwnership(t, err)
	})
}

func TestMIG01LocalFrameBounds(t *testing.T) {
	frame := func(metadata string, payload []byte) []byte {
		raw := make([]byte, 8)
		binary.BigEndian.PutUint32(raw[:4], uint32(len(metadata)))
		binary.BigEndian.PutUint32(raw[4:], uint32(len(payload)))
		return append(append(raw, metadata...), payload...)
	}
	valid := frame(`{"bytes":3,"error":null}`, []byte{1, 2, 3})
	if got, err := decodeBridgeFrame(valid); err != nil || !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatal("valid frame refused")
	}
	refused := frame(`{"bytes":0,"error":{"cause":"pool-wallet-store-busy","code":"wallet-command-component-refused","retry":"none"}}`, nil)
	if got, err := decodeBridgeFrame(refused); got != nil || err == nil || *err.(*Refusal) != (Refusal{"wallet-command-component-refused", "none", "pool-wallet-store-busy"}) {
		t.Fatal("closed refusal mismatch")
	}
	for _, name := range []string{"short", "zero-metadata", "metadata-bound", "payload-bound", "truncated", "trailing", "invalid-metadata"} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), valid...)
			switch name {
			case "short":
				raw = raw[:7]
			case "zero-metadata":
				binary.BigEndian.PutUint32(raw[:4], 0)
			case "metadata-bound":
				binary.BigEndian.PutUint32(raw[:4], (64<<10)+1)
			case "payload-bound":
				binary.BigEndian.PutUint32(raw[4:8], (1<<20)+1)
			case "truncated":
				raw = raw[:len(raw)-1]
			case "trailing":
				raw = append(raw, 0)
			case "invalid-metadata":
				raw = frame(`{"bytes":4,"error":null}`, []byte{1, 2, 3})
			}
			got, err := decodeBridgeFrame(raw)
			assertOwnership(t, err)
			if got != nil {
				t.Fatal("refusal returned payload")
			}
		})
	}
}
func TestMIG01FixedInvocation(t *testing.T) {
	old := os.Args
	t.Cleanup(func() { os.Args = old })
	source := "/private/tmp/synthetic-request.json"
	args := []string{"native", "admit-request", "--request", source, "--format", "live-p2-v1", "--profile-id", "synthetic-profile", "--pin-bytes", "11", "--pin-sha256", "0123456789abcdef", "--r1cs-bytes", "22", "--r1cs-sha256", "fedcba9876543210", "--vk-bytes", "33", "--vk-sha256", "1234567890abcdef", "--live-cache", "cold", "synthetic-target"}
	want := []string{source, "admit-request", "live-p2-v1", "synthetic-profile", "11", "0123456789abcdef", "22", "fedcba9876543210", "33", "1234567890abcdef", "synthetic-target", "cold"}
	for _, command := range []string{"admit-request", "prove", "check-live"} {
		t.Run(command, func(t *testing.T) {
			os.Args = append([]string(nil), args...)
			os.Args[1] = command
			want[1] = command
			got, err := fixedInvocation(source)
			phase := "W"
			if command == "admit-request" {
				phase = "A"
			}
			if err != nil || len(got) != 3 || got["phase"] != phase || got["source"] != source || !reflect.DeepEqual(got["arguments"], want) {
				t.Fatal("invocation tuple mismatch")
			}
		})
	}
	for _, name := range []string{"short", "dispatch", "flag", "position-count", "source-binding", "relative", "unclean", "whitespace"} {
		t.Run(name, func(t *testing.T) {
			os.Args = append([]string(nil), args...)
			input := source
			switch name {
			case "short":
				os.Args = os.Args[:2]
			case "dispatch":
				os.Args[1] = "other"
			case "flag":
				os.Args[2] = "--unknown"
			case "position-count":
				os.Args = append(os.Args, "extra")
			case "source-binding":
				input += ".other"
			case "relative":
				input = "synthetic-request.json"
				os.Args[3] = input
			case "unclean":
				input = "/private/tmp/../tmp/synthetic-request.json"
				os.Args[3] = input
			case "whitespace":
				input = "/private/tmp/synthetic request.json"
				os.Args[3] = input
			}
			got, err := fixedInvocation(input)
			assertOwnership(t, err)
			if got != nil {
				t.Fatal("refusal returned invocation")
			}
		})
	}
}
func fixtureGit(t *testing.T, root string, args ...string) {
	t.Helper()
	if _, err := repositoryGit(root, args...); err != nil {
		t.Fatal("synthetic git fixture failed")
	}
}
func TestMIG01HarnessParent(t *testing.T) {
	if os.Getenv("MIG01_HARNESS_PARENT") != "1" {
		return
	}
	got := harnessAncestor(os.Getppid(), os.Getenv("MIG01_HARNESS_ROOT"))
	want := os.Getenv("MIG01_HARNESS_VALID") == "true"
	if got != want {
		os.Exit(2)
	}
	os.Setenv("POOL_PK_LOAD_HARNESS_PID", strconv.Itoa(os.Getppid()))
	if err := Require(os.Getenv("MIG01_HARNESS_ROOT")); err == nil || err.Error() != "live-request-harness-required" {
		os.Exit(2)
	}
	os.Exit(0)
}
func TestMIG01HarnessAncestryAndCheckout(t *testing.T) {
	root := t.TempDir()
	fixtureGit(t, root, "init", "-b", "main")
	if os.WriteFile(filepath.Join(root, ".gitignore"), []byte("tools/pool-action-modules/dist/\npoison.sh\nlink.sh\n"), 0600) != nil {
		t.Fatal("fixture unavailable")
	}
	script := filepath.Join(root, "tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh")
	if os.MkdirAll(filepath.Dir(script), 0700) != nil || os.WriteFile(script, []byte("#!/bin/bash\n\"$1\" -test.run=^TestMIG01HarnessParent$\nstatus=$?\nexit $status\n"), 0600) != nil {
		t.Fatal("fixture unavailable")
	}
	fixtureGit(t, root, "add", ".")
	fixtureGit(t, root, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "-m", "synthetic fixture")
	if CheckCheckout(root) != nil {
		t.Fatal("clean main refused")
	}
	fixtureGit(t, root, "checkout", "-b", "synthetic")
	if err := CheckCheckout(root); err == nil || err.Error() != "main branch required" {
		t.Fatal("branch guard mismatch")
	}
	fixtureGit(t, root, "checkout", "main")
	reader := filepath.Join(root, "tools/pool-action-modules/dist/private-runner-process")
	if os.MkdirAll(filepath.Dir(reader), 0700) != nil {
		t.Fatal("fixture unavailable")
	}
	checkout, err := repositoryGit(".", "rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatal("checkout unavailable")
	}
	// Compile RN's actual kernel reader; its captured arguments stay in memory.
	build := exec.Command("/usr/bin/clang", "-O2", "-Wall", "-Wextra", "-Werror", filepath.Join(strings.TrimSpace(string(checkout)), "tools/pool-action-modules/private-runner-process.c"), "-lproc", "-o", reader)
	if build.Run() != nil {
		t.Fatal("native reader fixture build failed")
	}
	if os.WriteFile(filepath.Join(root, "dirty"), nil, 0600) != nil {
		t.Fatal("fixture unavailable")
	}
	if err := CheckCheckout(root); err == nil || err.Error() != "clean checkout required" {
		t.Fatal("dirty guard mismatch")
	}
	if os.Remove(filepath.Join(root, "dirty")) != nil {
		t.Fatal("fixture unavailable")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	for _, name := range []string{"valid", "script-poison", "symlink", "ancestor-poison"} {
		t.Run(name, func(t *testing.T) {
			entry := script
			valid := name == "valid"
			if name == "script-poison" {
				entry = filepath.Join(root, "poison.sh")
				raw, _ := os.ReadFile(script)
				if os.WriteFile(entry, append(raw, []byte("# synthetic poison\n")...), 0600) != nil {
					t.Fatal("fixture unavailable")
				}
			}
			if name == "symlink" {
				entry = filepath.Join(root, "link.sh")
				if os.Symlink(script, entry) != nil {
					t.Fatal("fixture unavailable")
				}
			}
			command := exec.Command("/bin/bash", entry, binary)
			if name == "ancestor-poison" {
				command = exec.Command(binary, "-test.run=^TestMIG01HarnessParent$")
			}
			command.Dir = root
			command.Env = append(os.Environ(), "HOME="+filepath.Join(root, "synthetic-home"), "MIG01_HARNESS_PARENT=1", "MIG01_HARNESS_ROOT="+root, "MIG01_HARNESS_VALID="+strconv.FormatBool(valid))
			if command.Run() != nil {
				t.Fatal("ancestry guard mismatch")
			}
		})
	}
	// A release clone runs on standalone main; development usually runs in a
	// linked worktree. Both must refuse ordinary execution, at their own guard.
	checkoutRoot := strings.TrimSpace(string(checkout))
	metadata, metadataErr := os.Lstat(filepath.Join(checkoutRoot, ".git"))
	branch, branchErr := repositoryGit(checkoutRoot, "branch", "--show-current")
	status, statusErr := repositoryGit(checkoutRoot, "status", "--porcelain")
	wantRefusal := "live-request-main-checkout-required"
	if metadataErr == nil && metadata.IsDir() && branchErr == nil && strings.TrimSpace(string(branch)) == "main" && statusErr == nil && len(status) == 0 {
		t.Setenv("POOL_PK_LOAD_HARNESS_PID", "")
		wantRefusal = "live-request-harness-required"
	}
	if err := Require(checkoutRoot); err == nil || err.Error() != wantRefusal {
		t.Fatal("ordinary prerequisite refusal mismatch")
	}
	if err := CheckCheckout(t.TempDir()); err == nil || err.Error() != "main checkout required" {
		t.Fatal("missing checkout admitted")
	}
}
func TestMIG01InheritedLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	defer file.Close()
	fd := int(file.Fd())
	if InheritedLockHeld(fd, path) {
		t.Fatal("unlocked descriptor admitted")
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		t.Fatal("lock unavailable")
	}
	if !InheritedLockHeld(fd, path) {
		t.Fatal("held descriptor refused")
	}
	if InheritedLockHeld(fd, path+".missing") || InheritedLockHeld(-1, path) {
		t.Fatal("wrong descriptor admitted")
	}
	other, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	defer other.Close()
	if InheritedLockHeld(int(other.Fd()), path) {
		t.Fatal("another description admitted")
	}
}

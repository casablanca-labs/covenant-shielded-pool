package runneradmission

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const nodeVersion = "v22.22.3"
const bridgeEntry = "tools/pool-action-modules/private-runner-bridge.mjs"

// Immutable command selection is derived from the actual native dispatch,
// not a reusable caller-issued admission object or an environment phase flag.
func fixedInvocation(source string) (map[string]any, error) {
	args := os.Args
	if len(args) < 3 || (args[1] != "admit-request" && args[1] != "prove" && args[1] != "check-live") {
		return nil, OwnershipRefusal()
	}
	fs := flag.NewFlagSet("private-runner", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	request := fs.String("request", "", "")
	format := fs.String("format", "", "")
	profile := fs.String("profile-id", "", "")
	pkBytes := fs.Int64("pin-bytes", 0, "")
	pkSHA := fs.String("pin-sha256", "", "")
	r1csBytes := fs.Int64("r1cs-bytes", 0, "")
	r1csSHA := fs.String("r1cs-sha256", "", "")
	vkBytes := fs.Int64("vk-bytes", 0, "")
	vkSHA := fs.String("vk-sha256", "", "")
	cache := fs.String("live-cache", "asis", "")
	for _, name := range []string{"key", "r1cs", "vk", "target", "corpus"} {
		fs.String(name, "", "")
	}
	if fs.Parse(args[2:]) != nil || fs.NArg() != 1 || *request != source || !filepath.IsAbs(source) || filepath.Clean(source) != source ||
		strings.ContainsAny(source, " \t\r\n\x00") {
		return nil, OwnershipRefusal()
	}
	phase := "W"
	if args[1] == "admit-request" {
		phase = "A"
	}
	tuple := []string{source, args[1], *format, *profile, strconv.FormatInt(*pkBytes, 10), *pkSHA,
		strconv.FormatInt(*r1csBytes, 10), *r1csSHA, strconv.FormatInt(*vkBytes, 10), *vkSHA, fs.Arg(0), *cache}
	return map[string]any{"phase": phase, "source": source, "arguments": tuple}, nil
}

func fixedEnvironment() []string {
	return []string{"PATH=/usr/bin:/bin", "LANG=C", "TMPDIR=/private/tmp"}
}

// Keep the actual exec descriptor contract in one package-private constructor.
// Admission and installation checks still precede its production use.
func fixedBridgeCommand(root, nodePath string, child, null *os.File) *exec.Cmd {
	command := exec.Command(nodePath, filepath.Join(root, bridgeEntry))
	command.Dir = root
	command.Env = fixedEnvironment()
	command.Stdin, command.Stdout, command.Stderr = null, null, null
	command.ExtraFiles = []*os.File{child} // FD3 only; 8/9 are closed at exec.
	return command
}

// ForkExec preserves unrelated descriptors lacking FD_CLOEXEC; ExtraFiles is
// not a close-all allowlist. Keep the parent's handles (and its FD9 lock) open,
// but make every non-stdio descriptor close at exec. ExtraFiles explicitly
// duplicates the private transport to FD3 with close-on-exec cleared there.
func closeBridgeInheritance() error {
	// Enumerate existing handles rather than a soft-limit range: a caller can
	// lower that limit after opening FD8/9, and an unlimited range cannot bound
	// this admission. /dev/fd supplies descriptor names, never file contents.
	directory, openErr := os.Open("/dev/fd")
	if openErr != nil {
		return OwnershipRefusal()
	}
	descriptors, readErr := directory.Readdirnames(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return OwnershipRefusal()
	}
	for _, descriptor := range descriptors {
		number, parseErr := strconv.Atoi(descriptor)
		if parseErr != nil || number < 0 {
			return OwnershipRefusal()
		}
		if number < 3 {
			continue
		}
		fd := uintptr(number)
		flags, _, err := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
		if err == syscall.EBADF {
			continue
		}
		if err != 0 {
			return OwnershipRefusal()
		}
		if flags&syscall.FD_CLOEXEC == 0 {
			if _, _, err = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, flags|syscall.FD_CLOEXEC); err != 0 {
				return OwnershipRefusal()
			}
		}
	}
	return nil
}

// Installation and admission helpers have only stdio, with no private FD3
// transport. Apply the same inheritance allowlist at every helper exec,
// including helpers that run before the bridge, without closing parent handles.
func helperOutput(command *exec.Cmd) ([]byte, error) {
	command.ExtraFiles = nil
	if err := closeBridgeInheritance(); err != nil {
		return nil, err
	}
	return command.Output()
}

func helperRun(command *exec.Cmd) error {
	command.ExtraFiles = nil
	if err := closeBridgeInheritance(); err != nil {
		return err
	}
	return command.Run()
}

// Verify the package-owned entry against the fixed source checkout before
// executing it. The installation verifier also binds the rebuilt dependency
// graph; absence of its completed record is a quiet closed refusal.
func verifyBridgeInstallation(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", OwnershipRefusal()
	}
	for _, path := range []string{bridgeEntry, "tools/pool-action-modules/lib/private-runner-installation.mjs", "tools/pool-action-modules/private-runner-installation.py"} {
		committed, err := repositoryGit(root, "show", "HEAD:"+path)
		actual, readErr := os.ReadFile(filepath.Join(root, path))
		if err != nil || readErr != nil || !bytes.Equal(actual, committed) {
			return "", OwnershipRefusal()
		}
	}
	check := exec.Command("/usr/bin/python3", filepath.Join(root, "tools/pool-action-modules/private-runner-installation.py"), "--node-path", root)
	check.Dir = root
	check.Env = fixedEnvironment()
	selected, err := helperOutput(check)
	if err != nil {
		return "", OwnershipRefusal()
	}
	// The committed verifier emits only after validating the complete installed
	// graph and exact pinned account-relative executable. No caller path selector.
	nodePath := strings.TrimSuffix(string(selected), "\n")
	if string(selected) != nodePath+"\n" || !filepath.IsAbs(nodePath) || filepath.Clean(nodePath) != nodePath || strings.ContainsAny(nodePath, " \t\r\n\x00") {
		return "", OwnershipRefusal()
	}
	version := exec.Command(nodePath, "--version")
	version.Env = fixedEnvironment()
	output, err := helperOutput(version)
	if err != nil || string(output) != nodeVersion+"\n" {
		return "", OwnershipRefusal()
	}
	return nodePath, nil
}

func AcquireSnapshot(root, source string) ([]byte, error) {
	invocation, err := fixedInvocation(source)
	if err != nil {
		return nil, err
	}
	nodePath, err := verifyBridgeInstallation(root)
	if err != nil {
		return nil, err
	}
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, OwnershipRefusal()
	}
	syscall.CloseOnExec(pair[0])
	syscall.CloseOnExec(pair[1])
	parent := os.NewFile(uintptr(pair[0]), "private-runner-parent")
	child := os.NewFile(uintptr(pair[1]), "private-runner-child")
	defer parent.Close()
	defer child.Close()
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nil, OwnershipRefusal()
	}
	defer null.Close()
	command := fixedBridgeCommand(root, nodePath, child, null)
	if closeBridgeInheritance() != nil {
		return nil, OwnershipRefusal()
	}
	if command.Start() != nil {
		return nil, OwnershipRefusal()
	}
	child.Close()
	// The fixed bridge receives a single bounded private request. No private
	// tuple is placed in an argument, environment, stdout or stderr.
	request, _ := json.Marshal(invocation)
	if _, err = parent.Write(append(request, '\n')); err != nil {
		command.Process.Kill()
		command.Wait()
		return nil, OwnershipRefusal()
	}
	if syscall.Shutdown(pair[0], syscall.SHUT_WR) != nil {
		command.Process.Kill()
		command.Wait()
		return nil, OwnershipRefusal()
	}
	watchdog := time.AfterFunc(35000*time.Millisecond, func() { command.Process.Kill(); parent.Close() })
	defer watchdog.Stop()
	raw, err := io.ReadAll(io.LimitReader(parent, (1<<20)+(64<<10)+9))
	waitErr := command.Wait()
	if err != nil || waitErr != nil || len(raw) < 8 {
		return nil, OwnershipRefusal()
	}
	return decodeBridgeFrame(raw)
}

func decodeBridgeFrame(raw []byte) ([]byte, error) {
	if len(raw) < 8 {
		return nil, OwnershipRefusal()
	}
	metadataLength, payloadLength := int(binary.BigEndian.Uint32(raw[:4])), int(binary.BigEndian.Uint32(raw[4:8]))
	if metadataLength <= 0 || metadataLength > 64<<10 || payloadLength < 0 || payloadLength > 1<<20 || len(raw) != 8+metadataLength+payloadLength {
		return nil, OwnershipRefusal()
	}
	if refusal, ok := decodeBridgeMetadata(raw[8:8+metadataLength], payloadLength); !ok {
		return nil, OwnershipRefusal()
	} else if refusal != nil {
		return nil, refusal
	}
	return append([]byte(nil), raw[8+metadataLength:]...), nil
}

// The fixed local frame is also closed and canonical. encoding/json's struct
// decoder alone accepts duplicate and case-folded keys; neither is authority.
func exactObject(raw []byte, keys ...string) (map[string]json.RawMessage, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	object := make(map[string]json.RawMessage, len(keys))
	for d.More() {
		token, err := d.Token()
		name, stringKey := token.(string)
		if err != nil || !stringKey {
			return nil, false
		}
		if _, duplicate := object[name]; duplicate {
			return nil, false
		}
		allowed := false
		for _, key := range keys {
			if name == key {
				allowed = true
			}
		}
		if !allowed {
			return nil, false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, false
		}
		object[name] = value
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || d.Decode(new(any)) != io.EOF || len(object) != len(keys) {
		return nil, false
	}
	return object, true
}
func decodeBridgeMetadata(raw []byte, payloadLength int) (*Refusal, bool) {
	object, ok := exactObject(raw, "bytes", "error")
	if !ok {
		return nil, false
	}
	var count int
	if bytes.Equal(object["bytes"], []byte("null")) || json.Unmarshal(object["bytes"], &count) != nil || count != payloadLength || count < 0 {
		return nil, false
	}
	var refusal *Refusal
	if !bytes.Equal(object["error"], []byte("null")) {
		closed, ok := exactObject(object["error"], "code", "retry", "cause")
		if !ok {
			return nil, false
		}
		refusal = new(Refusal)
		for key, target := range map[string]*string{"code": &refusal.Code, "retry": &refusal.Retry, "cause": &refusal.Cause} {
			if json.Unmarshal(closed[key], target) != nil {
				return nil, false
			}
		}
		if count != 0 || !validRefusal(refusal) {
			return nil, false
		}
	} else if count == 0 {
		return nil, false
	}
	var errorValue any
	if refusal != nil {
		errorValue = map[string]string{"cause": refusal.Cause, "code": refusal.Code, "retry": refusal.Retry}
	}
	canonical, err := json.Marshal(map[string]any{"bytes": count, "error": errorValue})
	return refusal, err == nil && bytes.Equal(raw, canonical)
}
func validRefusal(value *Refusal) bool {
	if value.Code != "wallet-command-component-refused" {
		return false
	}
	retries := map[string]string{"pool-wallet-payment-host-authority-required": "none", "pool-wallet-state": "none", "pool-wallet-payment-binding": "none", "pool-wallet-store-busy": "none",
		"pool-wallet-execution-offer-basis-stale": "resnapshot", "pool-wallet-execution-deadline": "reconcile", "pool-wallet-chain-stale": "after-sync", "pool-wallet-scan-required": "after-sync",
		"pool-wallet-restore-scan-pending": "after-sync", "pool-wallet-submit-reconciliation-required": "reconcile", "pool-wallet-anchor-stale": "none"}
	want, exists := retries[value.Cause]
	return exists && value.Retry == want
}

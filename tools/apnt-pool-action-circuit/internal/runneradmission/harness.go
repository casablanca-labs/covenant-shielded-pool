package runneradmission

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func repositoryGit(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("/usr/bin/git", append([]string{"-C", root}, args...)...)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GIT_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	return helperOutput(cmd)
}

// Authenticate the harness ancestor and build checkout, then independently
// enforce resources in this process. No PID, marker or descriptor attests that
// a different process performed a memory check or started a monitor.
func requireLiveHarness(sourceCheckout string) error {
	root, err := repositoryGit(".", "rev-parse", "--show-toplevel")
	if err != nil || !samePath(strings.TrimSpace(string(root)), sourceCheckout) || CheckCheckout(strings.TrimSpace(string(root))) != nil {
		return errors.New("live-request-main-checkout-required")
	}
	pid, err := strconv.Atoi(os.Getenv("POOL_PK_LOAD_HARNESS_PID"))
	if err != nil || pid <= 1 || !harnessAncestor(pid, strings.TrimSpace(string(root))) {
		return errors.New("live-request-harness-required")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("live-request-harness-required")
	}
	marker, err := os.ReadFile(filepath.Join(home, "proof-scratch", ".prover.lock"))
	if err != nil || !strings.HasPrefix(string(marker), fmt.Sprintf("pid %d\n", pid)) {
		return errors.New("live-request-harness-required")
	}
	lock := fmt.Sprintf("/private/tmp/apnt-gnark-r2-proof-%d.lock", os.Getuid())
	if !InheritedLockHeld(9, lock) {
		return errors.New("live-request-prover-lock-required")
	}
	return nil
}

func CheckCheckout(root string) error {
	st, err := os.Lstat(filepath.Join(root, ".git"))
	if err != nil || !st.IsDir() {
		return errors.New("main checkout required")
	}
	branch, err := repositoryGit(root, "branch", "--show-current")
	if err != nil || strings.TrimSpace(string(branch)) != "main" {
		return errors.New("main branch required")
	}
	dirty, err := repositoryGit(root, "status", "--porcelain")
	if err != nil || len(dirty) != 0 {
		return errors.New("clean checkout required")
	}
	return nil
}

func InheritedLockHeld(fd int, path string) bool {
	var inherited, named syscall.Stat_t
	if syscall.Fstat(fd, &inherited) != nil || syscall.Lstat(path, &named) != nil ||
		named.Mode&syscall.S_IFMT != syscall.S_IFREG || inherited.Dev != named.Dev || inherited.Ino != named.Ino {
		return false
	}
	other, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	defer other.Close()
	err = syscall.Flock(int(other.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		syscall.Flock(int(other.Fd()), syscall.LOCK_UN)
		return false // An inherited but unlocked descriptor is not admission.
	}
	if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
		return false
	}
	// Re-locking our inherited open file description succeeds without releasing
	// it; a different process's locked description would refuse this operation.
	return syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) == nil
}

func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	x, err := filepath.EvalSymlinks(a)
	if err != nil {
		return false
	}
	y, err := filepath.EvalSymlinks(b)
	return err == nil && x == y
}

// Use the kernel's parent chain, not a caller's claim of ancestry. Check the
// running bash's script copy against the committed harness in this build's
// checkout. The resource gate below remains mandatory even for this ancestor.
func harnessAncestor(want int, root string) bool {
	reader := filepath.Join(root, "tools/pool-action-modules/dist/private-runner-process")
	pid := os.Getppid()
	for n := 0; pid > 1 && n < 8; n++ {
		b, err := helperOutput(exec.Command(reader, "-p", strconv.Itoa(pid), "-o", "ppid=", "-o", "comm="))
		fields := strings.Fields(string(b))
		if err != nil || len(fields) != 2 {
			return false
		}
		if pid == want {
			if !samePath(fields[1], "/bin/bash") {
				return false
			}
			args, err := helperOutput(exec.Command(reader, "-ww", "-p", strconv.Itoa(pid), "-o", "args="))
			argv := strings.Fields(string(args))
			if err != nil || len(argv) < 2 || !samePath(argv[0], "/bin/bash") {
				return false
			}
			st, err := os.Lstat(argv[1])
			if err != nil || !st.Mode().IsRegular() {
				return false
			}
			script, err := os.ReadFile(argv[1])
			if err != nil {
				return false
			}
			committed, err := repositoryGit(root, "show", "HEAD:tools/apnt-pool-action-circuit/scripts/measure-pk-load.sh")
			return err == nil && bytes.Equal(script, committed)
		}
		pid, err = strconv.Atoi(fields[0])
		if err != nil {
			return false
		}
	}
	return false
}

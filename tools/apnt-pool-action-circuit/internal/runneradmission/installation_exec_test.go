package runneradmission

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// Each boundary receives a newly rearmed canary: a preceding Git exec must
// not make a missing Python or Node restriction pass. Device/inode checks
// detect the capability without reading or printing the canary's contents.
func TestMIG01InstallationHelperDescriptors(t *testing.T) {
	for _, inherit := range []bool{false, true} {
		t.Run(fmt.Sprintf("inheritable-%t", inherit), func(t *testing.T) {
			root := t.TempDir()
			fixtureGit(t, root, "init", "-b", "main")
			path := filepath.Join(root, "synthetic-canary")
			file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal("canary setup failed")
			}
			defer file.Close()
			const fd = 1537
			if syscall.Dup2(int(file.Fd()), fd) != nil {
				t.Fatal("descriptor setup failed")
			}
			defer syscall.Close(fd)
			syscall.CloseOnExec(fd)
			if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
				t.Fatal("canary lock setup failed")
			}
			var identity syscall.Stat_t
			if syscall.Fstat(fd, &identity) != nil {
				t.Fatal("canary identity unavailable")
			}
			nodeLiteral, _ := json.Marshal(testNodePath(t))
			python := fmt.Sprintf(`import os, sys
inherited = False
for fd in os.listdir('/dev/fd'):
 try:
  s = os.fstat(int(fd))
  inherited |= s.st_dev == %d and s.st_ino == %d
 except OSError: pass
result = '1' if inherited else '0'
if '--stdout' in sys.argv: print(result, end='')
else:
 with open('helper-result', 'w') as out: out.write(result)
`, uint64(identity.Dev), identity.Ino) + "\nif '--node-path' in sys.argv: print(" + string(nodeLiteral) + ")\n"
			verifier := filepath.Join(root, "tools/pool-action-modules/private-runner-installation.py")
			for _, relative := range []string{bridgeEntry, "tools/pool-action-modules/lib/private-runner-installation.mjs", "tools/pool-action-modules/private-runner-installation.py"} {
				name := filepath.Join(root, relative)
				text := "// synthetic installation fixture\n"
				if name == verifier {
					text = python
				}
				if os.MkdirAll(filepath.Dir(name), 0700) != nil || os.WriteFile(name, []byte(text), 0600) != nil {
					t.Fatal("installation fixture setup failed")
				}
			}
			fixtureGit(t, root, "add", ".")
			fixtureGit(t, root, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgsign=false", "commit", "-m", "synthetic fixture")
			node := fmt.Sprintf(`const fs=require('node:fs');let inherited=false;
for(const fd of fs.readdirSync('/dev/fd')){try{const s=fs.fstatSync(Number(fd));
inherited ||= String(s.dev)==='%d' && String(s.ino)==='%d';}catch{}}
process.stdout.write(inherited?'1':'0');`, uint64(identity.Dev), identity.Ino)
			executed := 0
			for _, boundary := range []string{"git", "python", "node", "installation"} {
				t.Run(boundary, func(t *testing.T) {
					executed++
					flags := uintptr(syscall.FD_CLOEXEC)
					if inherit {
						flags = 0
					}
					if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_SETFD, flags); errno != 0 {
						t.Fatal("inheritance setup failed")
					}
					var output []byte
					var err error
					switch boundary {
					case "git":
						// The Git alias runs a synthetic identity probe after the
						// actual repositoryGit exec, using its stdout only.
						output, err = repositoryGit(root, "-c", "alias.fd-probe=!exec /usr/bin/python3 '"+verifier+"' --stdout", "fd-probe")
					case "node":
						command := exec.Command(testNodePath(t), "-e", node)
						command.Env = fixedEnvironment()
						output, err = helperOutput(command)
					case "python", "installation":
						if boundary == "installation" {
							_, err = verifyBridgeInstallation(root)
						} else {
							command := exec.Command("/usr/bin/python3", verifier, root)
							command.Dir, command.Env = root, fixedEnvironment()
							err = helperRun(command)
						}
						if err == nil {
							output, err = os.ReadFile(filepath.Join(root, "helper-result"))
						}
						if os.Remove(filepath.Join(root, "helper-result")) != nil {
							t.Fatal("helper result cleanup failed")
						}
					}
					if err != nil || (string(output) != "0" && string(output) != "1") {
						t.Fatal("installation helper execution or oracle failed")
					}
					if string(output) == "1" {
						t.Fatal("installation helper inherited unrelated parent descriptor")
					}
					var after syscall.Stat_t
					if syscall.Fstat(fd, &after) != nil || after.Dev != identity.Dev || after.Ino != identity.Ino || !InheritedLockHeld(fd, path) {
						t.Fatal("helper closure changed the parent's handle or lock")
					}
				})
			}
			if executed != 4 {
				t.Fatal("helper boundary count mismatch")
			}
		})
	}
}

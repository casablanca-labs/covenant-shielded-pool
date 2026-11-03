package runneradmission

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Run the actual command constructor in a separate parent: changing descriptors
// 8/9 in the Go test runner itself could corrupt the runner's own descriptors.
func TestMIG01ExecParent(t *testing.T) {
	if os.Getenv("MIG01_EXEC_PARENT") != "1" {
		return
	}
	root := os.Getenv("MIG01_EXEC_ROOT")
	for _, fd := range []int{8, 9} {
		file, err := os.OpenFile(filepath.Join(root, "canary"), os.O_RDWR, 0600)
		if err != nil {
			os.Exit(2)
		}
		if syscall.Dup2(int(file.Fd()), fd) != nil {
			os.Exit(2)
		}
		if int(file.Fd()) != fd {
			file.Close()
		}
		// Both deliberately inheritable descriptors must still be closed by exec.
		syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, 0)
	}
	if syscall.Flock(9, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		os.Exit(2)
	}
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		os.Exit(2)
	}
	parent, child := os.NewFile(uintptr(pair[0]), "transport-parent"), os.NewFile(uintptr(pair[1]), "transport-child")
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		os.Exit(2)
	}
	command := fixedBridgeCommand(root, testNodePath(t), child, null)
	if closeBridgeInheritance() != nil {
		os.Exit(2)
	}
	if command.Start() != nil {
		os.Exit(2)
	}
	if !InheritedLockHeld(9, filepath.Join(root, "canary")) {
		os.Exit(2)
	}
	child.Close()
	var identity syscall.Stat_t
	if syscall.Fstat(8, &identity) != nil {
		os.Exit(2)
	}
	json.NewEncoder(parent).Encode(map[string]uint64{"device": uint64(identity.Dev), "inode": identity.Ino})
	syscall.Shutdown(pair[0], syscall.SHUT_WR)
	timer := time.AfterFunc(10000*time.Millisecond, func() { command.Process.Kill(); parent.Close() })
	defer timer.Stop()
	answer, readErr := io.ReadAll(parent)
	waitErr := command.Wait()
	if readErr != nil {
		os.Exit(2)
	}
	if os.Getenv("MIG01_EXEC_LOADER") == "1" {
		if waitErr == nil || len(answer) != 0 {
			os.Exit(2)
		}
		os.Exit(0)
	}
	if waitErr != nil {
		os.Exit(2)
	}
	// Only the closed metadata oracle is relayed; the probe has no private input.
	os.Stdout.Write(answer)
	os.Exit(0)
}

const execProbe = `import fs from 'node:fs';
import {spawn} from 'node:child_process';
let text='';for await(const part of fs.createReadStream('',{fd:3,autoClose:false}))text+=part;
const source=JSON.parse(text),same=s=>String(s.dev)===String(source.device)&&String(s.ino)===String(source.inode);
const n=fs.statSync('/dev/null');let inherited=false;
for(let fd=0;fd<1024;fd++){try{if(same(fs.fstatSync(fd)))inherited=true;}catch{}}
const nullStdio=[0,1,2].every(fd=>{const s=fs.fstatSync(fd);return s.dev===n.dev&&s.ino===n.ino;});
const transport=fs.fstatSync(3).isSocket();
// The orphan remains alive after this bridge exits and independently checks
// that no inherited canary descriptor survived the bridge's exec boundary.
const orphanCode="const fs=require('node:fs');const source="+JSON.stringify(source)+";let inherited=false;for(let fd=0;fd<1024;fd++){try{let s=fs.fstatSync(fd);if(String(s.dev)===String(source.device)&&String(s.ino)===String(source.inode))inherited=true;}catch{}}fs.writeFileSync('orphan-metadata.json',JSON.stringify({inherited,alive:true,pid:process.pid}));setTimeout(()=>{},5000)";
const orphan=spawn(process.execPath,['-e',orphanCode],{stdio:'ignore'});orphan.unref();
fs.writeSync(3,JSON.stringify({nullStdio,transport,inherited}));`

func TestMIG01ActualExecDescriptorsAndLoader(t *testing.T) {
	for _, variant := range []string{"descriptor-and-orphan", "early-loader", "uncaught-error", "unhandled-rejection"} {
		t.Run(variant, func(t *testing.T) {
			loader := variant != "descriptor-and-orphan"
			root := t.TempDir()
			entry := filepath.Join(root, bridgeEntry)
			os.MkdirAll(filepath.Dir(entry), 0700)
			source := execProbe
			if variant == "early-loader" {
				source = "import './synthetic-missing-module.mjs'"
			}
			if variant == "uncaught-error" {
				source = "throw new Error('synthetic-loader-canary')"
			}
			if variant == "unhandled-rejection" {
				source = "Promise.reject(new Error('synthetic-loader-canary'))"
			}
			if os.WriteFile(entry, []byte(source), 0600) != nil || os.WriteFile(filepath.Join(root, "canary"), []byte("synthetic descriptor canary"), 0600) != nil {
				t.Fatal("fixture unavailable")
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal("fixture unavailable")
			}
			command := exec.Command(binary, "-test.run=^TestMIG01ExecParent$")
			command.Env = append(os.Environ(), "MIG01_EXEC_PARENT=1", "MIG01_EXEC_ROOT="+root, "NODE_OPTIONS=--require=/synthetic/missing-loader.js")
			if loader {
				command.Env = append(command.Env, "MIG01_EXEC_LOADER=1")
			}
			var stdout, stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			if command.Run() != nil {
				t.Fatal("exec control refused")
			}
			if stderr.Len() != 0 {
				t.Fatal("terminal diagnostic escaped")
			}
			if loader {
				if stdout.Len() != 0 {
					t.Fatal("loader diagnostic escaped")
				}
				return
			}
			var result struct{ NullStdio, Transport, Inherited bool }
			if json.Unmarshal(stdout.Bytes(), &result) != nil || !result.NullStdio || !result.Transport || result.Inherited {
				t.Fatalf("exec descriptor identity mismatch: decoded=%t null=%t transport=%t inherited=%t", json.Valid(stdout.Bytes()), result.NullStdio, result.Transport, result.Inherited)
			}
			deadline := time.Now().Add(5 * time.Second)
			var orphan []byte
			for time.Now().Before(deadline) {
				orphan, err = os.ReadFile(filepath.Join(root, "orphan-metadata.json"))
				if err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			var state struct {
				Inherited, Alive bool
				Pid              int
			}
			if json.Unmarshal(orphan, &state) != nil || state.Inherited || !state.Alive {
				t.Fatal("orphan descriptor identity mismatch")
			}
			if syscall.Kill(state.Pid, 0) != nil {
				t.Fatal("orphan exited before lock oracle")
			}
			held, err := os.OpenFile(filepath.Join(root, "canary"), os.O_RDWR, 0600)
			if err != nil {
				t.Fatal("lock oracle unavailable")
			}
			defer held.Close()
			if syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
				t.Fatal("orphan retained prover lock")
			}
			syscall.Flock(int(held.Fd()), syscall.LOCK_UN)
			// Remain inside the call until the bounded synthetic orphan exits.
			time.Sleep(5100 * time.Millisecond)
		})
	}
}

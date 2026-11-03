package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/devprove"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/internal/runneradmission"
)

type liveResources struct{ available, swap, rss int64 }

const liveFloor = int64(17 << 30)
const liveSwapTrip = int64(8 << 30)
const liveRSSTrip = int64(24 << 30)

func readLiveResources() (liveResources, error) {
	b, err := exec.Command("/usr/bin/vm_stat").Output()
	if err != nil {
		return liveResources{}, errors.New("live-request-memory-unavailable")
	}
	available, err := parseAvailable(string(b))
	if err != nil {
		return liveResources{}, err
	}
	s := liveResources{available, devprove.ReadSwap().UsedBytes, devprove.MaxRSS()}
	if s.swap < 0 || s.rss < 0 {
		return s, errors.New("live-request-monitor-unavailable")
	}
	return s, nil
}

func parseAvailable(raw string) (int64, error) {
	pageMatch := regexp.MustCompile(`page size of ([0-9]+) bytes`).FindStringSubmatch(raw)
	if len(pageMatch) != 2 {
		return 0, errors.New("live-request-memory-unavailable")
	}
	page, err := strconv.ParseInt(pageMatch[1], 10, 64)
	if err != nil || page <= 0 || page > 1<<20 {
		return 0, errors.New("live-request-memory-unavailable")
	}
	var pages int64
	for _, name := range []string{"free", "inactive", "speculative"} {
		m := regexp.MustCompile(`(?m)^Pages ` + name + `: +([0-9]+)\.`).FindStringSubmatch(raw)
		if len(m) != 2 {
			return 0, errors.New("live-request-memory-unavailable")
		}
		n, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil || n < 0 || n > (1<<50)/page {
			return 0, errors.New("live-request-memory-unavailable")
		}
		pages += n
	}
	return pages * page, nil
}

var otherProverName = regexp.MustCompile(`^(pool-pk-load|pool-action-circuit|apnt-pool-action-circuit\.test|apnt-pool-ceremony.*|cargo-prove.*|sp1-prover.*|sp1_core.*|apnt-.*-(runner|prover)(-[[:alnum:]_.-]+)?|r2-run|r3-run|relation-r2-run|apnt-successor-child-circuits(\.test)?|apnt-child-circuits-cost(\.test)?)$|(^|[-_])(prove|prover)([-_]|$)`)

func liveQuietMachine(reader string) error {
	if _, err := os.Lstat("/private/tmp/bch-cloak-sp1-prover-exclusive-v1"); !os.IsNotExist(err) {
		return errors.New("live-request-other-prover")
	}
	b, err := exec.Command(reader, "-axo", "pid=,comm=").Output()
	if err != nil {
		return errors.New("live-request-process-list-unavailable")
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			return errors.New("live-request-process-list-unavailable")
		}
		if pid != os.Getpid() && otherProverName.MatchString(filepath.Base(strings.Join(f[1:], " "))) {
			return errors.New("live-request-other-prover")
		}
	}
	return nil
}

func liveResourceFailure(s liveResources, baseline int64, initial bool) error {
	switch {
	case s.available < 0 || s.swap < 0 || s.rss < 0:
		return errors.New("live-request-monitor-unavailable")
	case initial && s.available < liveFloor:
		return errors.New("live-request-memory-floor")
	case s.swap > baseline && s.swap-baseline > liveSwapTrip:
		return errors.New("live-request-swap-trip")
	case s.rss > liveRSSTrip:
		return errors.New("live-request-rss-trip")
	}
	return nil
}

// Starts with a synchronous sample; no key work is reachable until the monitor
// goroutine has started. Unreadable samples fail closed. stop waits for exit.
// Dependencies are injected by Go tests only, never by flags or environment.
// Only the actual no-key/no-proof dispatch selects check-live. There is no
// numeric floor override, and unknown operations fail before sampling.
func startLiveMonitor(command string, read func() (liveResources, error), ticks <-chan time.Time, trip func(error)) (func(), error) {
	if command != "prove" && command != "check-live" {
		return nil, errors.New("live-request-options")
	}
	first, err := read()
	if err != nil {
		return nil, err
	}
	if err := liveResourceFailure(first, first.swap, command == "prove"); err != nil {
		return nil, err
	}
	stop, done, ready := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		close(ready)
		for {
			select {
			case <-stop:
				return
			case <-ticks:
				s, err := read()
				if err == nil {
					err = liveResourceFailure(s, first.swap, false)
				}
				if err != nil {
					trip(err)
					return
				}
			}
		}
	}()
	<-ready
	return func() { close(stop); <-done }, nil
}

// Production live work uses the shared owning prerequisite.
func guardLiveWorkV2(work func() error) error {
	if err := runneradmission.Require(devprove.SourceCheckout()); err != nil {
		return err
	}
	// W's snapshot acquisition verifies the installation; Require rechecks the
	// harness and checkout. The child makes its own fresh inventory after W;
	// neither the shell's earlier quiet result nor admission replaces it.
	reader := filepath.Join(devprove.SourceCheckout(), "tools/pool-action-modules/dist/private-runner-process")
	return guardLiveResources(work, reader)
}

func guardLiveResources(work func() error, reader string) error {
	stop, err := beginLiveResources(reader, "prove")
	if err != nil {
		return err
	}
	defer stop()
	return work()
}

// No arbitrary work can be passed to the floor-free entry. A prove invocation
// cannot select it, including through the tagged no-proof observer.
func checkLiveV2(command string) error {
	if command != "check-live" {
		return errors.New("live-request-options")
	}
	if err := runneradmission.Require(devprove.SourceCheckout()); err != nil {
		return err
	}
	reader := filepath.Join(devprove.SourceCheckout(), "tools/pool-action-modules/dist/private-runner-process")
	stop, err := beginLiveResources(reader, command)
	if err != nil {
		return err
	}
	defer stop()
	return nil
}

func beginLiveResources(reader, command string) (func(), error) {
	if err := liveQuietMachine(reader); err != nil {
		return nil, err
	}
	ticker := time.NewTicker(time.Second)
	stop, err := startLiveMonitor(command, readLiveResources, ticker.C, func(err error) {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	})
	if err != nil {
		ticker.Stop()
		return nil, err
	}
	return func() { stop(); ticker.Stop() }, nil
}

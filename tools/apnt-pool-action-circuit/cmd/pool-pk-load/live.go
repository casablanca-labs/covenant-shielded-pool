package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/devprove"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/pkload"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

type RequestAdmission struct {
	Source     *devprove.Source `json:"source"`
	ProfileID  string           `json:"profileId"`
	Parameters string           `json:"parameters"`
	// Admission checks declarations; file digests are checked during load.
	KeyFilesLoaded bool `json:"keyFilesLoaded"`
}

var errLivePin = errors.New("live-request-pin-mismatch")

func admitRequest(t devprove.Target, format pkload.Format, pk, r1cs, vk pkload.Pin, profile string) (witness.Witness, *RequestAdmission, error) {
	// Never let a caller substitute arbitrary measurement pins for a live key.
	pins := pkload.ChipnetZeroValueRevision3
	want := pins.Image
	if format == pkload.FormatRaw {
		want = pins.RawKey
	}
	if (format != pkload.FormatImage && format != pkload.FormatRaw) || pk != want ||
		r1cs != pins.R1CS || vk != pins.VerifyingKey || profile != poolaction.ChipnetZeroValueRevision3ProfileID {
		return nil, nil, errLivePin
	}
	if _, err := poolaction.ChipnetZeroValueRevision3VP(); err != nil {
		return nil, nil, errLivePin
	}
	a, src, err := t.Assignment()
	if err != nil {
		return nil, nil, err
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, devprove.ErrRequestMalformed
	}
	return w, &RequestAdmission{Source: src, ProfileID: profile, Parameters: pins.Label}, nil
}

// Suppress all caller-controlled strings in live receipts, including path aliases
// passed as --key/--r1cs/--vk, parser errors, and loader/verifier errors.
func hasRequestFlag(args []string) bool {
	for _, a := range args {
		if a == "--request" || a == "-request" || strings.HasPrefix(a, "--request=") || strings.HasPrefix(a, "-request=") {
			return true
		}
	}
	return false
}
func redactLiveError(err error) error {
	if err == nil {
		return nil
	}
	switch err.Error() {
	case "live-request-options", "live-request-malformed", "live-request-unknown-entry-kind", "live-request-pin-mismatch",
		"live-request-main-checkout-required", "live-request-harness-required", "live-request-prover-lock-required",
		"live-request-memory-unavailable", "live-request-monitor-unavailable", "live-request-memory-floor", "live-request-swap-trip", "live-request-rss-trip",
		"live-request-other-prover", "live-request-process-list-unavailable":
		return err
	}
	return errors.New("live-request-work-failed")
}

func prepareLiveCache(r *Result, mode string, paths []string) error {
	if mode == "asis" {
		return nil
	}
	return r.timed("live-cache-"+mode, func() error {
		for _, path := range paths {
			if mode == "warm" {
				if _, err := hashFile(path); err != nil {
					return err
				}
			} else {
				if err := evict(path); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func requestAliases(path string, candidates ...string) bool {
	req, _ := os.Stat(path)
	absolute, _ := filepath.Abs(path)
	for _, other := range candidates {
		if other == "" {
			continue
		}
		abs, _ := filepath.Abs(other)
		if absolute == abs {
			return true
		}
		st, err := os.Stat(other)
		if err == nil && req != nil && os.SameFile(req, st) {
			return true
		}
	}
	return false
}

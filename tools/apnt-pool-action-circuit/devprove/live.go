package devprove

import (
	"encoding/binary"
	"encoding/hex"
	"errors"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/internal/runneradmission"
	"github.com/consensys/gnark/frontend"
)

// Stable, deliberately value-free errors: decoder/assignment errors may echo
// private values, scalars, names or unknown field names supplied by a caller.
var (
	ErrRequestMalformed = errors.New("live-request-malformed")
	ErrRequestKind      = errors.New("live-request-unknown-entry-kind")
)

const maxLiveRequestBytes = 1 << 20

// Live requests require runner admission before acquiring a private snapshot.
// Admission constructs an assignment, not host acceptance or proof verification.
func InactiveLiveActionTargetV2(requestPath string) Target {
	t := ActionTarget("")
	t.Assignment = func() (frontend.Circuit, *Source, error) {
		if err := runneradmission.Require(SourceCheckout()); err != nil {
			return nil, nil, err
		}
		raw, err := runneradmission.AcquireSnapshot(SourceCheckout(), requestPath)
		if err != nil {
			return nil, nil, err
		}
		return liveAssignment(raw)
	}
	return t
}

// Pure decoder/assignment unit seam. It consumes already acquired in-memory
// bytes and has no private-file or admission API. Tests of invalid corpora
// exercise this seam, not the public owning reader.
func liveAssignment(raw []byte) (frontend.Circuit, *Source, error) {
	if len(raw) > maxLiveRequestBytes {
		return nil, nil, ErrRequestMalformed
	}
	c, err := poolaction.DecodeCorpus(raw)
	if err != nil || len(c.Entries) != 1 {
		return nil, nil, ErrRequestMalformed
	}
	e := &c.Entries[0]
	if !liveEntryName(e.Name) || e.Kind != "positive" {
		return nil, nil, ErrRequestKind
	}
	if e.HostFailureCode != nil {
		return nil, nil, ErrRequestMalformed
	}
	if !liveEntryRecord(e.Name, e.Record) {
		return nil, nil, ErrRequestMalformed
	}
	a, err := e.Assignment()
	if err != nil {
		return nil, nil, ErrRequestMalformed
	}
	return a, &Source{Kind: "live-request", Description: "private wallet request; assignment only, not host acceptance or proof verification", Entry: e.Name, EntryKind: "positive"}, nil
}

// Labels constrain public action shape. They are not a substitute for solving
// the pinned relation: admission never calls Setup, Prove, or a host oracle.
func liveEntryName(name string) bool {
	switch name {
	case "wallet-payment", "wallet-inbox-deposit", "wallet-withdrawal", "wallet-self-deposit":
		return true
	default:
		return false
	}
}

func liveEntryRecord(name string, encoded *string) bool {
	if encoded == nil {
		return false
	}
	record, err := hex.DecodeString(*encoded)
	if err != nil || len(record) != poolaction.RecordBytes {
		return false
	}
	deposit := binary.LittleEndian.Uint64(record[poolaction.OffDeposit:])
	withdrawal := binary.LittleEndian.Uint64(record[poolaction.OffWithdrawal:])
	lockZero := true
	for _, b := range record[poolaction.OffWlock:] {
		lockZero = lockZero && b == 0
	}
	if (withdrawal == 0) != lockZero {
		return false
	}
	switch name {
	case "wallet-payment":
		return deposit == 0 && withdrawal == 0
	case "wallet-inbox-deposit", "wallet-self-deposit": // legacy self-deposit remains admitted until retired
		return deposit > 0 && withdrawal == 0
	case "wallet-withdrawal":
		return deposit == 0 && withdrawal > 0
	default:
		return false
	}
}

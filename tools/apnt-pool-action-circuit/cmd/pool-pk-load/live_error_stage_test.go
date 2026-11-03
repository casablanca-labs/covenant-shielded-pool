package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/pkload"
)

// Loader IO only: no circuit, assignment, setup, key decode or proof.
func TestMIG01PinnedStreamOpenStage(t *testing.T) {
	defer protectedPanic(t)
	data := []byte("synthetic stream control")
	digest := sha256.Sum256(data)
	pin := pkload.Pin{Bytes: int64(len(data)), SHA256: hex.EncodeToString(digest[:])}
	path := filepath.Join(t.TempDir(), "absent")
	decodes := 0
	decode := func(reader io.Reader) error {
		decodes++
		_, err := io.Copy(io.Discard, reader)
		return err
	}
	err := readPinnedStream(path, pin, decode)
	if !errors.Is(err, os.ErrNotExist) || pkload.StageOf(err) != pkload.StageOpen || decodes != 0 {
		protectedFatal(t, "missing stream lost open stage or reached decoder")
	}
	receipt := new(Result)
	redacted := captureResultError(receipt, err, true)
	if receipt.ErrorStage != string(pkload.StageOpen) || redacted.Error() != "live-request-work-failed" {
		protectedFatal(t, "loader message was not redacted")
	}
	receipt.Error = redacted.Error()
	body, marshalErr := json.Marshal(receipt)
	if marshalErr != nil || bytes.Contains(body, []byte(path)) {
		protectedFatal(t, "private loader path escaped receipt")
	}
	if bytes.Contains(body, []byte("synthetic path canary")) {
		protectedFatal(t, "safe receipt contains unrelated canary")
	}
	poisoned := *receipt
	poisoned.Error = "synthetic path canary"
	bad, _ := json.Marshal(poisoned)
	if !bytes.Contains(bad, []byte("synthetic path canary")) {
		protectedFatal(t, "receipt detector failed its firing control")
	}
	if captureResultError(receipt, nil, true) != nil || receipt.ErrorStage != "" {
		protectedFatal(t, "successful result retained an error stage")
	}
	if captureResultError(receipt, err, false) != err || receipt.ErrorStage != string(pkload.StageOpen) {
		protectedFatal(t, "non-live typed error lost")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		protectedFatal(t, "synthetic control creation failed")
	}
	if err := readPinnedStream(path, pin, decode); err != nil || decodes != 1 {
		protectedFatal(t, "valid stream control failed")
	}
}

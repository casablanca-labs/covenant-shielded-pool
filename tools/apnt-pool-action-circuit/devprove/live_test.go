package devprove

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"
)

func liveFixture(t *testing.T) *poolaction.Corpus {
	return liveNamedFixture(t, "wallet-self-deposit")
}

func liveNamedFixture(t *testing.T, name string) *poolaction.Corpus {
	t.Helper()
	c, err := poolaction.LoadCorpus(corpusPath)
	if err != nil {
		protectedFatal(t, "fixture read failed")
	}
	fixture := map[string]string{
		"wallet-payment":       "honest-pair-positions-1-3",
		"wallet-inbox-deposit": "dummy-dummy-deposit",
		"wallet-withdrawal":    "withdraw-all-zero-outputs",
		"wallet-self-deposit":  "dummy-dummy-deposit",
	}[name]
	for _, e := range c.Entries {
		if e.Name == fixture {
			e.Name = name
			return &poolaction.Corpus{Description: "synthetic private request", HostRelationIdentity: c.HostRelationIdentity,
				Encoding: c.Encoding, Entries: []poolaction.CorpusEntry{e}}
		}
	}
	protectedFatal(t, "missing public deposit fixture")
	return nil
}

func liveFile(t *testing.T, raw []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(p, raw, 0600); err != nil {
		protectedFatal(t, "fixture write failed")
	}
	return p
}

func liveJSON(t *testing.T, c *poolaction.Corpus) []byte {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		protectedFatal(t, "fixture encoding failed")
	}
	return b
}

func TestMIG01R3DecoderAssignmentAndProvenance(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	c := liveFixture(t)
	// Free text is untrusted and must never be copied to a receipt.
	c.Description, c.Encoding, c.Entries[0].Note = "private-canary", "private-canary", "private-canary"
	a, src, err := liveAssignment(liveJSON(t, c))
	if err != nil {
		protectedFatal(t, "live assignment refused")
	}
	ref, err := c.Entries[0].Assignment()
	if err != nil {
		protectedFatal(t, "reference assignment refused")
	}
	encode := func(a frontend.Circuit) []byte {
		w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if err != nil {
			protectedFatal(t, "witness refused")
		}
		b, err := w.MarshalBinary()
		if err != nil {
			protectedFatal(t, "witness encoding failed")
		}
		return b
	}
	if !bytes.Equal(encode(a), encode(ref)) {
		protectedFatal(t, "shared builder assignment differs")
	}
	if src.Kind != "live-request" || src.Entry != "wallet-self-deposit" || src.Corpus != "" || src.CorpusSha256 != "" || src.EntryNote != "" {
		protectedFatal(t, "untruthful live provenance")
	}
	b, _ := json.Marshal(src)
	private := []byte(c.Entries[0].Witness.Outputs[0].RecoveryKey32)
	leaks := func(b []byte) bool { return bytes.Contains(b, []byte("private-canary")) || bytes.Contains(b, private) }
	if leaks(b) || bytes.Contains(b, []byte("committed")) {
		protectedFatal(t, "private/false source text escaped")
	}
	// The detector must fire on an injected actual fixture witness field.
	poisoned := *src
	poisoned.EntryNote = string(private)
	bad, _ := json.Marshal(poisoned)
	if !leaks(bad) {
		protectedFatal(t, "private-source detector failed its firing control")
	}
	// The old corpus target still refuses the wallet name: no disguised corpus.
	if _, _, err := ActionTarget(liveFile(t, liveJSON(t, c))).Assignment(); err == nil {
		protectedFatal(t, "corpus target accepted wallet entry")
	}
}

func TestMIG01R3DecoderRequestRefusals(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	cases := []struct {
		name   string
		mutate func(*poolaction.Corpus)
		want   error
	}{
		{"unknown-name", func(c *poolaction.Corpus) { c.Entries[0].Name = "wallet-unknown" }, ErrRequestKind},
		{"corpus-name", func(c *poolaction.Corpus) { c.Entries[0].Name = ReferenceEntry }, ErrRequestKind},
		{"negative-kind", func(c *poolaction.Corpus) { c.Entries[0].Kind = "negative" }, ErrRequestKind},
		{"unknown-kind", func(c *poolaction.Corpus) { c.Entries[0].Kind = "private-canary" }, ErrRequestKind},
		{"host-failure", func(c *poolaction.Corpus) { s := "private-canary"; c.Entries[0].HostFailureCode = &s }, ErrRequestMalformed},
		{"not-representable", func(c *poolaction.Corpus) { c.Entries[0].Representable = false }, ErrRequestMalformed},
		{"missing-record", func(c *poolaction.Corpus) { c.Entries[0].Record = nil }, ErrRequestMalformed},
		{"bad-record", func(c *poolaction.Corpus) { s := "00"; c.Entries[0].Record = &s }, ErrRequestMalformed},
		{"missing-witness", func(c *poolaction.Corpus) { c.Entries[0].Witness = nil }, ErrRequestMalformed},
		{"relation", func(c *poolaction.Corpus) { c.HostRelationIdentity = "private-canary" }, ErrRequestMalformed},
		{"two-entries", func(c *poolaction.Corpus) { c.Entries = append(c.Entries, c.Entries[0]) }, ErrRequestMalformed},
		{"no-entries", func(c *poolaction.Corpus) { c.Entries = nil }, ErrRequestMalformed},
		{"bad-value", func(c *poolaction.Corpus) { c.Entries[0].Witness.Inputs[0].ValueSats = "private-canary" }, ErrRequestMalformed},
		{"bad-scalar", func(c *poolaction.Corpus) { c.Entries[0].Witness.Inputs[0].Rerandomizer = "private-canary" }, ErrRequestMalformed},
		{"bad-secret-hex", func(c *poolaction.Corpus) { c.Entries[0].Witness.Outputs[0].RecoveryKey32 = "private-canary" }, ErrRequestMalformed},
		{"bad-membership", func(c *poolaction.Corpus) { c.Entries[0].Witness.Inputs[0].Membership = &poolaction.CorpusMemberOf{} }, ErrRequestMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer protectedPanic(t)
			c := liveFixture(t)
			tc.mutate(c)
			a, src, err := liveAssignment(liveJSON(t, c))
			if err != tc.want || a != nil || src != nil {
				protectedFatal(t, "named refusal did not fire")
			}
			// Same detector and path on the unmutated control must accept.
			if _, _, err := liveAssignment(liveJSON(t, liveFixture(t))); err != nil {
				protectedFatal(t, "positive control refused")
			}
		})
	}
	raw := liveJSON(t, liveFixture(t))
	var generic map[string]any
	json.Unmarshal(raw, &generic)
	e := generic["entries"].([]any)[0].(map[string]any)
	w := e["witness"].(map[string]any)
	for _, key := range []string{"inputs", "outputs"} {
		slots := w[key].([]any)
		for _, count := range []int{0, 1, 3} {
			w[key] = append(append([]any{}, slots...), slots[0])[:count]
			b, _ := json.Marshal(generic)
			if _, _, err := liveAssignment(b); err != ErrRequestMalformed {
				protectedFatal(t, "array arity refusal did not fire")
			}
		}
		w[key] = slots
	}
	// Independently well-formed JSON crosses only the local byte-size guard.
	boundary := append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), maxLiveRequestBytes-len(raw))...)
	if _, _, err := liveAssignment(boundary); err != nil {
		protectedFatal(t, "exact byte bound refused")
	}
	if a, src, err := liveAssignment(append(boundary, ' ')); err != ErrRequestMalformed || a != nil || src != nil {
		protectedFatal(t, "byte bound did not fire")
	}
	w["private-canary"] = true
	unknown, _ := json.Marshal(generic)
	for _, b := range [][]byte{[]byte("{"), append(append([]byte{}, raw...), []byte(" {}")...), unknown, []byte(strings.Repeat(" ", maxLiveRequestBytes+1))} {
		if _, _, err := liveAssignment(b); err != ErrRequestMalformed {
			protectedFatal(t, "strict decoder refusal did not fire")
		}
	}
	// Raw path objects are covered by the shared-prerequisite control below;
	// the retired v1 reader no longer bypasses admission to inspect them.

}

// Actual frozen relation solve, no Setup or Prove. The caller's positive
// label cannot turn an incorrect private opening into a satisfying witness.
func TestMIG01R3DecoderSolve(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	logger.Disable()
	ccs, err := poolaction.Compile()
	if err != nil {
		protectedFatal(t, "compile failed")
	}
	defer poolaction.Release()
	solve := func(c *poolaction.Corpus) bool {
		a, _, err := liveAssignment(liveJSON(t, c))
		if err != nil {
			protectedFatal(t, "assignment refused before solve")
		}
		return poolaction.Solve(ccs, a.(*poolaction.ActionCircuit)) == nil
	}
	for _, name := range []string{"wallet-payment", "wallet-inbox-deposit", "wallet-withdrawal"} {
		t.Run(name, func(t *testing.T) {
			defer protectedPanic(t)
			c := liveNamedFixture(t, name)
			if !solve(c) {
				protectedFatal(t, "positive solve failed")
			}
			// A changed private amount with the original public record must fail.
			c.Entries[0].Witness.Outputs[0].ValueSats = "1"
			if solve(c) {
				protectedFatal(t, "tampered witness solved")
			}
			c = liveNamedFixture(t, name)
			// A different valid record of the same action class cannot describe
			// this witness, even when its public hash is recomputed honestly.
			if name == "wallet-payment" {
				c.Entries[0].Record = liveRecord(t, "rel2-real-dummy-dummy-output")
			} else if name == "wallet-inbox-deposit" {
				c.Entries[0].Record = liveRecord(t, "boundary-deposit-and-fee-max-money")
			} else {
				c.Entries[0].Record = liveRecord(t, "boundary-input-and-withdrawal-max-money")
			}
			if solve(c) {
				protectedFatal(t, "mismatched record solved")
			}
			if !solve(liveNamedFixture(t, name)) {
				protectedFatal(t, "restored positive solve failed")
			}
		})
	}
}

func liveRecord(t *testing.T, name string) *string {
	t.Helper()
	c, err := poolaction.LoadCorpus(corpusPath)
	if err != nil {
		protectedFatal(t, "fixture read failed")
	}
	for _, e := range c.Entries {
		if e.Name == name {
			return e.Record
		}
	}
	protectedFatal(t, "record fixture absent")
	return nil
}

func TestMIG01R3DecoderEntryShapeAndAuthorityRefusals(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	for _, name := range []string{"wallet-payment", "wallet-inbox-deposit", "wallet-withdrawal"} {
		c := liveNamedFixture(t, name)
		other := "wallet-payment"
		if name == other {
			other = "wallet-inbox-deposit"
		}
		c.Entries[0].Record = liveNamedFixture(t, other).Entries[0].Record
		if _, _, err := liveAssignment(liveJSON(t, c)); err != ErrRequestMalformed {
			protectedFatal(t, "entry amount-shape guard did not fire")
		}
	}
	c := liveNamedFixture(t, "wallet-withdrawal")
	bad := *c.Entries[0].Record
	// A nonzero withdrawal with a zero lock hash is forbidden.
	bad = bad[:2*poolaction.OffWlock] + strings.Repeat("0", 64)
	c.Entries[0].Record = &bad
	if _, _, err := liveAssignment(liveJSON(t, c)); err != ErrRequestMalformed {
		protectedFatal(t, "withdrawal lock guard did not fire")
	}
	// Unknown nested fields cannot smuggle ask/seed into a request.
	c = liveNamedFixture(t, "wallet-payment")
	var raw map[string]any
	if err := json.Unmarshal(liveJSON(t, c), &raw); err != nil {
		protectedFatal(t, "fixture decode failed")
	}
	entries := raw["entries"].([]any)
	witness := entries[0].(map[string]any)["witness"].(map[string]any)
	witness["ask"] = "SPEND_AUTHORITY_CANARY"
	poisoned, _ := json.Marshal(raw)
	if !bytes.Contains(poisoned, []byte("SPEND_AUTHORITY_CANARY")) {
		protectedFatal(t, "canary detector did not fire")
	}
	if _, _, err := liveAssignment(poisoned); err != ErrRequestMalformed {
		protectedFatal(t, "spend-authority field admitted")
	}
}

func TestMIG01R3LibraryRawOutsideRunnerRefusesBeforeSourceObjects(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	paths := []string{filepath.Join(t.TempDir(), "absent"), t.TempDir(), "/dev/null", liveFile(t, liveJSON(t, liveFixture(t)))}
	fifo := filepath.Join(t.TempDir(), "request.pipe")
	if syscall.Mkfifo(fifo, 0600) != nil {
		protectedFatal(t, "FIFO fixture unavailable")
	}
	paths = append(paths, fifo)
	t.Chdir(t.TempDir()) // Independent earlier checkout refusal on main or a lane.
	for _, path := range paths {
		assignment, source, err := InactiveLiveActionTargetV2(path).Assignment()
		if assignment != nil || source != nil || err == nil || err.Error() != "live-request-main-checkout-required" {
			protectedFatal(t, "raw worktree reader failed to refuse at the shared checkout prerequisite")
		}
	}
}

package devprove

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/rangecheck"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
)

// The gnark versions every result and manifest records: the pool action
// circuit module's, which its tests hold equal to go.mod.
const gnarkVersion, gnarkCryptoVersion = poolaction.GnarkVersion, poolaction.GnarkCryptoVersion

// ActionTargetName names the pool action circuit target.
const ActionTargetName = "apnt-pool-action-circuit (task 5.1a, gnark " + poolaction.GnarkVersion + " Groth16 BN254)"

// ReferenceEntry is the host positive the action target proves: the corpus's
// reference vector 1, two real inputs with membership paths, a deposit and a
// withdrawal, so every clause runs on real values.
const ReferenceEntry = "rel1-real-real-deposit-withdrawal"

// ActionTarget is the pool action circuit with the reference positive from
// the host's committed parity corpus at corpusPath.
func ActionTarget(corpusPath string) Target {
	return Target{
		Name:    ActionTargetName,
		Compile: func() (constraint.ConstraintSystem, error) { return poolaction.Compile() },
		Assignment: func() (frontend.Circuit, *Source, error) {
			a, src, err := actionAssignment(corpusPath, ReferenceEntry)
			if err != nil {
				return nil, nil, err
			}
			return a, src, nil
		},
		FlipIndex: 0,
		FlipNote:  "x, the one public input (low bit flipped)",
	}
}

// SourceCheckout binds provenance and live execution to the checkout which built
// this tool. A relocated or -trimpath build fails closed; the harness builds fresh.
func SourceCheckout() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok || !filepath.IsAbs(file) {
		return ""
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

// RepositoryGit ignores caller Git redirection; PATH cannot replace the tool.
func RepositoryGit(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("/usr/bin/git", append([]string{"-C", root}, args...)...)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "GIT_") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	return cmd.Output()
}

const actionCorpusFile = "packages/protocol-runtime/test-vectors/apnt-pool-v1-action-circuit-vectors.json"

var ErrCorpusSource = errors.New("action-corpus-source-not-authenticated")

// actionAssignment builds the assignment of a host positive; any other kind of
// entry is refused.
func actionAssignment(corpusPath, name string) (*poolaction.ActionCircuit, *Source, error) {
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		return nil, nil, ErrCorpusSource
	}
	// Authenticate the exact bytes we decode against the committed canonical file,
	// not its caller-selected path or an editable entry label. Never re-open it.
	if SourceCheckout() == "" {
		return nil, nil, ErrCorpusSource
	}
	committed, err := RepositoryGit(SourceCheckout(), "show", "HEAD:"+actionCorpusFile)
	if err != nil || !bytes.Equal(raw, committed) {
		return nil, nil, ErrCorpusSource
	}
	digest := sha256.Sum256(raw)
	c, err := poolaction.DecodeCorpus(raw)
	if err != nil {
		return nil, nil, err
	}
	for i := range c.Entries {
		e := &c.Entries[i]
		if e.Name != name {
			continue
		}
		if e.Kind != "positive" || e.HostFailureCode != nil {
			return nil, nil, fmt.Errorf("corpus entry %q is not a host positive (kind %q)", name, e.Kind)
		}
		a, err := e.Assignment()
		if err != nil {
			return nil, nil, err
		}
		return a, &Source{
			Description:  "host positive from the committed action-circuit parity corpus",
			Kind:         "committed-corpus",
			Corpus:       actionCorpusFile,
			CorpusSha256: hex.EncodeToString(digest[:]),
			Entry:        e.Name,
			EntryKind:    e.Kind,
			EntryNote:    e.Note,
		}, nil
	}
	return nil, nil, fmt.Errorf("corpus has no entry %q", name)
}

// SmallCircuit is a test circuit for exercising this package end to end. It is
// not the pool action circuit. Its public inputs are bytes range-checked
// through gnark's commitment-based range checker, as the action circuit's
// record bytes are, so Setup, Prove and Verify run gnark's commitment path;
// a squaring chain sets its size.
type SmallCircuit struct {
	Bytes  [8]frontend.Variable `gnark:",public"`
	Y      frontend.Variable    `gnark:",public"`
	X      frontend.Variable
	Secret [2]frontend.Variable
	Rounds int `gnark:"-"`
}

// Define: every byte (public and secret) is in [0, 255], and
// Y = X^(2^Rounds) + Σ Bytes[i]·256^i + Secret[0] + Secret[1].
func (c *SmallCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	for _, b := range c.Bytes {
		rc.Check(b, 8)
	}
	for _, s := range c.Secret {
		rc.Check(s, 8)
	}
	v := c.X
	for i := 0; i < c.Rounds; i++ {
		v = api.Mul(v, v)
	}
	acc := api.Add(v, c.Secret[0], c.Secret[1])
	for i, b := range c.Bytes {
		acc = api.Add(acc, api.Mul(b, new(big.Int).Lsh(big.NewInt(1), uint(8*i))))
	}
	api.AssertIsEqual(acc, c.Y)
	return nil
}

// SmallRounds is the small target's squaring-chain length in the tests and
// in the command's --target small.
const SmallRounds = 2000

// SmallTargetName names the small test target for a round count.
func SmallTargetName(rounds int) string {
	return fmt.Sprintf("devprove-small-test-circuit rounds=%d (NOT the pool action circuit)", rounds)
}

// SmallTarget is the small test circuit with a fixed satisfying assignment.
func SmallTarget(rounds int) Target {
	return Target{
		Name: SmallTargetName(rounds),
		Compile: func() (constraint.ConstraintSystem, error) {
			return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &SmallCircuit{Rounds: rounds})
		},
		Assignment: func() (frontend.Circuit, *Source, error) {
			return SmallAssignment(rounds, [8]byte{0x11, 0x22, 0x5a, 0x44, 0x00, 0xff, 0x01, 0x80}),
				&Source{Description: "fixed satisfying assignment of the small test circuit"}, nil
		},
		FlipIndex: 2,
		FlipNote:  "Bytes[2]",
	}
}

// SmallAssignment is the satisfying assignment with X = 3, Secret = (7, 250).
func SmallAssignment(rounds int, pub [8]byte) *SmallCircuit {
	var v, t fr.Element
	v.SetUint64(3)
	for i := 0; i < rounds; i++ {
		v.Square(&v)
	}
	t.SetUint64(7 + 250)
	v.Add(&v, &t)
	a := &SmallCircuit{X: 3, Secret: [2]frontend.Variable{7, 250}}
	for i, b := range pub {
		a.Bytes[i] = b
		var w fr.Element
		w.SetBigInt(new(big.Int).Lsh(big.NewInt(int64(b)), uint(8*i)))
		v.Add(&v, &w)
	}
	var y big.Int
	v.BigInt(&y)
	a.Y = &y
	return a
}

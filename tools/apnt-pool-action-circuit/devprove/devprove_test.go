package devprove

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/consensys/gnark/logger"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
)

// Small test circuit only: nothing here compiles, sets up or proves the pool
// action circuit.

const smallRounds = SmallRounds

const corpusPath = "../../../packages/protocol-runtime/test-vectors/apnt-pool-v1-action-circuit-vectors.json"

func r1csDigest(t *testing.T, tgt Target) string {
	t.Helper()
	ccs, err := tgt.Compile()
	if err != nil {
		protectedFatal(t, err)
	}
	if n := ccs.GetNbConstraints(); n >= 1<<16 {
		protectedFatal(t, "test circuit has %d constraints, not well under 2^16", n)
	}
	h := sha256.New()
	if _, err := ccs.WriteTo(h); err != nil {
		protectedFatal(t, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func mustSetup(t *testing.T, tgt Target, dir, digest string) *SetupResult {
	t.Helper()
	r, err := Setup(tgt, dir, digest)
	if err != nil {
		protectedFatal(t, err)
	}
	return r
}

func wantErr(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		protectedFatal(t, "expected an error containing %q, got nil", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		protectedFatal(t, "expected an error containing %q, got %v", substr, err)
	}
}

func fileSha(t *testing.T, path string) (int64, string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		protectedFatal(t, err)
	}
	d := sha256.Sum256(b)
	return int64(len(b)), hex.EncodeToString(d[:])
}

func TestEndToEnd(t *testing.T) {
	defer protectedPanic(t)
	tgt := SmallTarget(smallRounds)
	digest := r1csDigest(t, tgt)
	dir := filepath.Join(t.TempDir(), "keys")

	s := mustSetup(t, tgt, dir, digest)
	if s.Parameters != Parameters || s.R1CS.Sha256 != digest || s.Constraints >= 1<<16 {
		protectedFatal(t, "setup result: %+v", s)
	}
	label, err := os.ReadFile(filepath.Join(dir, LabelFile))
	if err != nil || string(label) != Parameters+"\n" {
		protectedFatal(t, "label: %q %v", label, err)
	}
	for _, f := range []FileDigest{s.R1CS, s.PK, s.VK} {
		n, d := fileSha(t, filepath.Join(dir, f.File))
		if n != f.Bytes || d != f.Sha256 || n == 0 {
			protectedFatal(t, "%s: file %d %s, result %d %s", f.File, n, d, f.Bytes, f.Sha256)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, R1CSFile+".partial")); !os.IsNotExist(err) {
		protectedFatal(t, "partial R1CS left behind: %v", err)
	}

	p, err := Prove(tgt, dir)
	if err != nil {
		protectedFatal(t, err)
	}
	if p.Parameters != Parameters || p.Proof.Bytes == 0 || p.Witness == nil {
		protectedFatal(t, "prove result: %+v", p)
	}
	names := []string{}
	for _, ph := range p.Phases {
		names = append(names, ph.Name)
	}
	if strings.Join(names, ",") != "load-r1cs,load-pk,witness,prove,write-proof" {
		protectedFatal(t, "prove phases %v", names)
	}
	if runtime.GOOS == "darwin" && (p.SwapBefore.UsedBytes < 0 || p.SwapAfter.UsedBytes < 0) {
		protectedFatal(t, "swap not read: %+v %+v", p.SwapBefore, p.SwapAfter)
	}
	// A second prove is refused before it loads anything.
	again, err := Prove(tgt, dir)
	wantErr(t, err, "already holds proof.bin")
	if again == nil || len(again.Phases) != 0 {
		protectedFatal(t, "a refused prove ran phases: %+v", again)
	}

	v, err := Verify(tgt, dir)
	if err != nil {
		protectedFatal(t, err)
	}
	// The flipped witness is refused by the pairing check, and the same proof
	// verifies against the unflipped witness in the same run.
	if !v.Verified || !v.FlippedRefused || !v.PublicWitnessStored {
		protectedFatal(t, "verify result: %+v", v)
	}
	if v.FlipFrom != "90" || v.FlipTo != "91" || !strings.Contains(v.FlippedError, "pairing") {
		protectedFatal(t, "flip %s -> %s refused with %q", v.FlipFrom, v.FlipTo, v.FlippedError)
	}
	if v.Parameters != Parameters {
		protectedFatal(t, "verify result not labelled")
	}
}

// A different statement under the same keys: the proof does not verify, so
// Verify's positive check can fail. Control: TestEndToEnd.
func TestVerifyRefusesAnotherStatement(t *testing.T) {
	defer protectedPanic(t)
	tgt := SmallTarget(smallRounds)
	dir := filepath.Join(t.TempDir(), "keys")
	mustSetup(t, tgt, dir, r1csDigest(t, tgt))
	if _, err := Prove(tgt, dir); err != nil {
		protectedFatal(t, err)
	}
	other := tgt
	other.Assignment = func() (frontend.Circuit, *Source, error) {
		return SmallAssignment(smallRounds, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}), &Source{Description: "another statement"}, nil
	}
	v, err := Verify(other, dir)
	wantErr(t, err, "does not verify")
	if v == nil || v.Verified || v.PublicWitnessStored {
		protectedFatal(t, "verify result: %+v", v)
	}
}

func TestSetupRefusesDigestMismatch(t *testing.T) {
	defer protectedPanic(t)
	tgt := SmallTarget(smallRounds)
	digest := r1csDigest(t, tgt)
	dir := filepath.Join(t.TempDir(), "keys")

	last := "0"
	if strings.HasSuffix(digest, "0") {
		last = "1"
	}
	wrong := digest[:63] + last
	r, err := Setup(tgt, dir, wrong)
	wantErr(t, err, "refusing Setup: R1CS SHA-256 is "+digest+", expected "+wrong)
	if r == nil || r.R1CS.Sha256 != digest {
		protectedFatal(t, "the refusal must report the observed digest: %+v", r)
	}
	for _, ph := range r.Phases {
		if ph.Name == "setup" {
			protectedFatal(t, "Setup ran after a digest mismatch")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		protectedFatal(t, "a refused Setup left %v (%v)", entries, err)
	}

	// No default.
	_, err = Setup(tgt, filepath.Join(t.TempDir(), "keys"), "")
	wantErr(t, err, "there is no default")
	_, err = Setup(tgt, filepath.Join(t.TempDir(), "keys"), strings.ToUpper(digest))
	wantErr(t, err, "64 lowercase hex")

	// Control: the same directory with the right digest.
	mustSetup(t, tgt, dir, digest)
}

func TestProveAndVerifyRefuseWithoutLabel(t *testing.T) {
	defer protectedPanic(t)
	tgt := SmallTarget(smallRounds)
	dir := filepath.Join(t.TempDir(), "keys")
	mustSetup(t, tgt, dir, r1csDigest(t, tgt))
	labelPath := filepath.Join(dir, LabelFile)

	if err := os.Remove(labelPath); err != nil {
		protectedFatal(t, err)
	}
	p, err := Prove(tgt, dir)
	wantErr(t, err, "no parameter label")
	if p == nil || p.Parameters != Parameters || len(p.Phases) != 0 {
		protectedFatal(t, "a refused prove must return its labelled result and run nothing: %+v", p)
	}
	v, err := Verify(tgt, dir)
	wantErr(t, err, "no parameter label")
	if v == nil || v.Parameters != Parameters || len(v.Phases) != 0 {
		protectedFatal(t, "a refused verify must return its labelled result and run nothing: %+v", v)
	}

	if err := os.WriteFile(labelPath, []byte("CHIPNET CEREMONY\n"), 0o600); err != nil {
		protectedFatal(t, err)
	}
	_, err = Prove(tgt, dir)
	wantErr(t, err, "not the development label")
	_, err = Verify(tgt, dir)
	wantErr(t, err, "not the development label")

	// Control: the label restored, nothing else changed.
	if err := os.WriteFile(labelPath, []byte(Parameters+"\n"), 0o600); err != nil {
		protectedFatal(t, err)
	}
	if _, err := Prove(tgt, dir); err != nil {
		protectedFatal(t, err)
	}
	if _, err := Verify(tgt, dir); err != nil {
		protectedFatal(t, err)
	}
}

func TestProveRefusesManifestMismatch(t *testing.T) {
	defer protectedPanic(t)
	tgt := SmallTarget(smallRounds)
	dir := filepath.Join(t.TempDir(), "keys")
	mustSetup(t, tgt, dir, r1csDigest(t, tgt))
	mpath := filepath.Join(dir, ManifestFile)
	pristine, err := os.ReadFile(mpath)
	if err != nil {
		protectedFatal(t, err)
	}
	var m Manifest
	if err := json.Unmarshal(pristine, &m); err != nil {
		protectedFatal(t, err)
	}
	good := m.PK.Sha256
	m.PK.Sha256 = strings.Repeat("0", 64)
	b, _ := json.Marshal(m)
	if err := os.WriteFile(mpath, b, 0o600); err != nil {
		protectedFatal(t, err)
	}
	_, err = Prove(tgt, dir)
	wantErr(t, err, "refusing pk.bin")
	wantErr(t, err, good)

	// Another target's directory.
	if err := os.WriteFile(mpath, pristine, 0o600); err != nil {
		protectedFatal(t, err)
	}
	_, err = Prove(SmallTarget(smallRounds+1), dir)
	wantErr(t, err, "set up for target")

	// Control: the pristine manifest.
	if _, err := Prove(tgt, dir); err != nil {
		protectedFatal(t, err)
	}
}

func TestSetupRefusesInsideGitWorkTree(t *testing.T) {
	defer protectedPanic(t)
	tgt := SmallTarget(smallRounds)
	digest := r1csDigest(t, tgt)
	root := t.TempDir()
	dir := filepath.Join(root, "a", "keys")
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		protectedFatal(t, err)
	}
	_, err := Setup(tgt, dir, digest)
	wantErr(t, err, "inside the git work tree")
	if _, err := os.Stat(filepath.Join(root, "a")); !os.IsNotExist(err) {
		protectedFatal(t, "a refused Setup created a directory: %v", err)
	}
	_, err = OutsideRepository(filepath.Join(root, "out.json"))
	wantErr(t, err, "inside the git work tree")

	// Control: the same path once .git is gone.
	if err := os.Remove(filepath.Join(root, ".git")); err != nil {
		protectedFatal(t, err)
	}
	mustSetup(t, tgt, dir, digest)

	// A second Setup never overwrites the first.
	_, err = Setup(tgt, dir, digest)
	wantErr(t, err, "not empty")
}

// The action target's reference witness, built without compiling the
// circuit: a host positive whose public witness is its one public input,
// x = int_be(SHA-256(A)) mod r of the record.
func TestActionTargetReferencePositive(t *testing.T) {
	t.Skip("requires protected action witnesses; not shipped")
	defer protectedPanic(t)
	tgt := ActionTarget(corpusPath)
	a, src, err := tgt.Assignment()
	if err != nil {
		protectedFatal(t, err)
	}
	if src.Entry != ReferenceEntry || src.EntryKind != "positive" {
		protectedFatal(t, "source %+v", src)
	}
	n, d := fileSha(t, corpusPath)
	if n == 0 || src.CorpusSha256 != d {
		protectedFatal(t, "corpus digest %s, file %s", src.CorpusSha256, d)
	}
	c, err := poolaction.LoadCorpus(corpusPath)
	if err != nil {
		protectedFatal(t, err)
	}
	var record []byte
	for _, e := range c.Entries {
		if e.Name == ReferenceEntry {
			record, _ = hex.DecodeString(*e.Record)
		}
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		protectedFatal(t, err)
	}
	vec := w.Vector().(fr.Vector)
	if len(vec) != 1 || len(record) != poolaction.RecordBytes {
		protectedFatal(t, "public witness %d elements, record %d bytes", len(vec), len(record))
	}
	x, err := poolaction.PublicInput(record)
	if err != nil {
		protectedFatal(t, err)
	}
	var v big.Int
	vec[0].BigInt(&v)
	if v.Cmp(x) != 0 {
		protectedFatal(t, "public element is %s, x of the record %s", v.String(), x.String())
	}
	if tgt.FlipIndex != 0 {
		protectedFatal(t, "flip index %d", tgt.FlipIndex)
	}

	// Refused: a host negative and a missing entry.
	_, _, err = actionAssignment(corpusPath, "balance-fee-plus-one")
	wantErr(t, err, "not a host positive")
	_, _, err = actionAssignment(corpusPath, "no-such-entry")
	wantErr(t, err, "no entry")
}

// Only fixed rules reach testing.T. Arguments still evaluate at the original
// assertion site; no String/Error method or formatter is invoked here.
func protectedFatal(t testing.TB, _ ...any) { t.Helper(); t.Fatal("pool-test-fatal") }
func protectedError(t testing.TB, _ ...any) { t.Helper(); t.Error("pool-test-error") }
func protectedLog(t testing.TB, _ ...any)   { t.Helper(); t.Log("pool-test-log") }
func protectedSkip(t testing.TB, _ ...any)  { t.Helper(); t.Skip("pool-test-source-skip") }
func protectedPanic(t testing.TB) {
	if recover() != nil {
		t.Helper()
		t.Fatal("pool-test-panic")
	}
}

// Suppress dependency diagnostic bodies before a test can enter the solver.
func init() { logger.Disable() }

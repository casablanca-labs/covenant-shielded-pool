// Command gnark-reference is gnark v0.16.3's own side of the pool aggregate
// program's child verifier (ENG-421, task 5.4 slice 1; registry entry 1, one
// public input x = int_be(SHA-256(A)) mod r since revision 2, ENG-437). It
// never runs a Setup. Since revision 3 (pad16, ENG-454) it takes 314-byte
// records (poolaction.RecordBytes). The committed revision-2 fixtures under
// fixtures/development-zero-value-rev2/ were written by it at revision 2, over
// 396-byte records; at revision 3 it cannot regenerate them, and they stay
// frozen as that revision's record. Three subcommands:
//
//	gnark-reference prove-batch --keys DIR --corpus FILE [--corpus FILE...] --entries A,B,... OUT-DIR RESULT.json
//	gnark-reference prove-batch --ceremony-keys DIR --r1cs FILE --corpus FILE [--corpus FILE...] --entries A,B,... OUT-DIR RESULT.json
//	gnark-reference transform   --vk FILE --proof FILE --record-hex HEX OUT-DIR
//	gnark-reference reference   --vk FILE --alt-vk FILE --alt-proof FILE --batch DIR [--action-vk FILE --action-proof FILE]
//	                            --corpus FILE [--corpus FILE...] OUT.json
//
// prove-batch proves host positives under a DEVELOPMENT ZERO-VALUE key
// directory written by tools/apnt-pool-action-circuit's devsetup (task 5.1b),
// or, with --ceremony-keys, under registry entry 1 revision 3's Chipnet keys
// (the task-5.1c ceremony directory and its R1CS; SIMULATED SINGLE-PARTY
// SETUP - ZERO-VALUE TEST ONLY; ENG-486). It loads the R1CS and proving key
// once, each checked against the manifest, or for the ceremony keys against
// the registry's pins, while it is read, with gnark's checked ReadFrom. It is
// proving: run it only through scripts/prove-dev-batch.sh, which holds the
// machine-wide prover lock and the memory gates. Every proof is verified by
// gnark before it is written, and its public witness must be x of its record.
//
// transform makes "a proof under a different vp" without a Setup: it rescales
// δ by a fixed public scalar s (δ' = s·δ in G1 and G2) and the proof's C by
// s⁻¹. (α, β, γ, s·δ) is the verifying key a setup with toxic δ·s would
// publish, and (A, B, C/s) is a proof under it; gnark must accept that pair
// and refuse each half crossed with the original.
//
// reference writes gnark's decoded points of every verifying key and proof,
// the BSB22 commitment wire gnark derives, and gnark's verdict on a fixed set
// of cases (honest, crossed, tampered, mutated, and public inputs reduced
// other ways), for the Rust core's differential test. --vk and --batch are
// a key and its batch of proofs: at revision 3, registry entry 1's recorded
// Chipnet vp and the action proofs made under its ceremony keys (ENG-486);
// revision 2's committed dump used a stand-in key of the action circuit's
// public shape. --action-vk and --action-proof, optional since revision 3, are
// a second key of the action circuit and one proof of the first batch record
// under it. The reduction cases use the first batch record whose digest is at
// least r, so the reduction runs.
//
// Every output carries its keys' label, the development label or the
// ceremony's: both kinds of key are forgeable and never guard value.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/devprove"
)

const (
	recordBytes = poolaction.RecordBytes
	proofBytes  = 196
	// deltaRescaleLabel fixes transform's scalar s = SHA-256(label) mod r.
	deltaRescaleLabel = "eng421:aggregate-slice1:delta-rescale"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "prove-batch":
		err = proveBatch(os.Args[2:])
	case "transform":
		err = transform(os.Args[2:])
	case "reference":
		err = reference(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gnark-reference:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  gnark-reference prove-batch --keys DIR --corpus FILE [--corpus FILE...] --entries A,B,... OUT-DIR RESULT.json
  gnark-reference prove-batch --ceremony-keys DIR --r1cs FILE --corpus FILE [--corpus FILE...] --entries A,B,... OUT-DIR RESULT.json
  gnark-reference transform   --vk FILE --proof FILE --record-hex HEX OUT-DIR
  gnark-reference reference   --vk FILE --alt-vk FILE --alt-proof FILE --batch DIR [--action-vk FILE --action-proof FILE]
                              --corpus FILE [--corpus FILE...] OUT.json`)
	os.Exit(2)
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// ---- shared helpers ----

func maxRSS() int64 {
	var u syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &u) != nil {
		return -1
	}
	if runtime.GOOS == "darwin" {
		return u.Maxrss
	}
	return u.Maxrss * 1024
}

// entries returns the named host positives of the corpora, each once.
func entries(corpora []string, names []string) ([]*poolaction.CorpusEntry, error) {
	byName := map[string]*poolaction.CorpusEntry{}
	for _, path := range corpora {
		c, err := poolaction.LoadCorpus(path)
		if err != nil {
			return nil, err
		}
		for i := range c.Entries {
			e := &c.Entries[i]
			if _, dup := byName[e.Name]; dup {
				return nil, fmt.Errorf("entry %q appears in two corpora", e.Name)
			}
			byName[e.Name] = e
		}
	}
	out := make([]*poolaction.CorpusEntry, 0, len(names))
	seen := map[string]bool{}
	for _, n := range names {
		e, ok := byName[n]
		switch {
		case !ok:
			return nil, fmt.Errorf("no entry %q", n)
		case seen[n]:
			return nil, fmt.Errorf("entry %q named twice", n)
		case e.Kind != "positive" || e.HostFailureCode != nil || e.Record == nil:
			return nil, fmt.Errorf("entry %q is not a host positive", n)
		}
		seen[n] = true
		out = append(out, e)
	}
	return out, nil
}

// publicWitness is gnark's public witness for a record: its one public
// input x = int_be(SHA-256(A)) mod r (registry entry 1 revision 2), from the
// action circuit module's PublicInput.
func publicWitness(record []byte) (witness.Witness, error) {
	x, err := poolaction.PublicInput(record)
	if err != nil {
		return nil, err
	}
	return publicWitnessOf(x)
}

// publicWitnessOf is the public witness with the one input set to x, which
// gnark reduces mod r (so an integer at least r names the element x mod r).
func publicWitnessOf(x *big.Int) (witness.Witness, error) {
	var b bytes.Buffer
	for _, v := range []uint32{1, 0, 1} {
		b.Write([]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	var e fr.Element
	e.SetBigInt(x)
	s := e.Bytes()
	b.Write(s[:])
	w, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	return w, w.UnmarshalBinary(b.Bytes())
}

func readVK(raw []byte) (*groth16bn254.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	n, err := vk.ReadFrom(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if n != int64(len(raw)) {
		return nil, fmt.Errorf("verifying key: read %d of %d bytes", n, len(raw))
	}
	return vk.(*groth16bn254.VerifyingKey), nil
}

func readProof(raw []byte) (*groth16bn254.Proof, error) {
	p := groth16.NewProof(ecc.BN254)
	n, err := p.ReadFrom(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if n != int64(len(raw)) {
		return nil, fmt.Errorf("proof: read %d of %d bytes", n, len(raw))
	}
	return p.(*groth16bn254.Proof), nil
}

func writeTo(w interface {
	WriteTo(io.Writer) (int64, error)
}) ([]byte, error) {
	var b bytes.Buffer
	if _, err := w.WriteTo(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// verify is gnark v0.16.3's own Verify, from bytes: decode (gnark's
// decompression and subgroup checks) and then groth16.Verify with its default
// options, which are registry entry 1's.
func verify(vkRaw, proofRaw, record []byte) (accepted bool, stage string, detail string) {
	return verifyX(vkRaw, proofRaw, record, nil)
}

// verifyX is verify with the public input x in place of the record's, when
// x is not nil.
func verifyX(vkRaw, proofRaw, record []byte, x *big.Int) (accepted bool, stage string, detail string) {
	vk, err := readVK(vkRaw)
	if err != nil {
		return false, "decode-vk", err.Error()
	}
	p, err := readProof(proofRaw)
	if err != nil {
		return false, "decode-proof", err.Error()
	}
	var w witness.Witness
	if x != nil {
		w, err = publicWitnessOf(x)
	} else {
		w, err = publicWitness(record)
	}
	if err != nil {
		return false, "witness", err.Error()
	}
	if err := groth16.Verify(p, vk, w); err != nil {
		return false, "verify", err.Error()
	}
	return true, "accepted", ""
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func newFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// keyLabel is the label for outputs made from vkRaw: the ceremony's when it
// is registry entry 1 revision 3's recorded Chipnet vp, else the development
// label. Both kinds of key are forgeable and never guard value.
func keyLabel(vkRaw []byte) string {
	if vp, err := poolaction.ChipnetZeroValueRevision3VP(); err == nil && bytes.Equal(vkRaw, vp) {
		return poolaction.ChipnetZeroValueLabel + ": the project could forge proofs under this key; never for value"
	}
	return devprove.Parameters
}

// ---- prove-batch ----

type batchProof struct {
	Entry        string  `json:"entry"`
	Record       string  `json:"record"`
	ProofFile    string  `json:"proofFile"`
	ProofSha256  string  `json:"proofSha256"`
	ProveSeconds float64 `json:"proveSeconds"`
	Verified     bool    `json:"gnarkVerified"`
	MaxRSSBytes  int64   `json:"processMaxRSSBytesAfter"`
}

type batchResult struct {
	Parameters    string              `json:"parameters"`
	Command       string              `json:"command"`
	Keys          string              `json:"keys"`
	Manifest      *devprove.Manifest  `json:"manifest"`
	Ceremony      *ceremonyKeys       `json:"ceremony,omitempty"`
	Corpora       []string            `json:"corpora"`
	LoadR1CS      float64             `json:"loadR1csSeconds"`
	LoadPK        float64             `json:"loadPkSeconds"`
	Proofs        []batchProof        `json:"proofs"`
	SwapBefore    devprove.SwapUsage  `json:"swapBefore"`
	SwapAfter     *devprove.SwapUsage `json:"swapAfter"`
	GoVersion     string              `json:"goVersion"`
	GOMAXPROCS    int                 `json:"gomaxprocs"`
	WallSeconds   float64             `json:"processWallSeconds"`
	ProcessMaxRSS int64               `json:"processMaxRSSBytes"`
	Error         string              `json:"error,omitempty"`
	Notes         []string            `json:"notes"`
}

// readChecked reads dir/want.File, checks its length and SHA-256 against the
// manifest, and decodes it with r from the checked bytes.
func readChecked(dir string, want devprove.FileDigest, r func(io.Reader) error) error {
	f, err := os.Open(filepath.Join(dir, want.File))
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	counted := &countReader{r: io.TeeReader(f, h)}
	if err := r(counted); err != nil {
		return fmt.Errorf("%s: %w", want.File, err)
	}
	// Anything after what the decoder consumed must not exist.
	if n, _ := io.Copy(io.Discard, counted); n != 0 {
		return fmt.Errorf("%s: %d trailing bytes", want.File, n)
	}
	if counted.n != want.Bytes || hex.EncodeToString(h.Sum(nil)) != want.Sha256 {
		return fmt.Errorf("%s does not match the manifest", want.File)
	}
	return nil
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ceremonyKeys is what prove-batch checked of a ceremony key directory: the
// key metadata's label and the three files, each against the registry's pin
// (tools/apnt-pool-action-circuit/registry.go).
type ceremonyKeys struct {
	Label      string              `json:"label"`
	CeremonyID string              `json:"ceremonyId"`
	R1CS       devprove.FileDigest `json:"r1cs"`
	R1CSDir    string              `json:"r1csDir"`
	PK         devprove.FileDigest `json:"provingKey"`
	VK         devprove.FileDigest `json:"verifyingKey"`
	ProfileID  string              `json:"profileId"`
}

// ceremonyMeta is the part of the ceremony's keys.meta.json prove-batch reads.
type ceremonyMeta struct {
	Provenance         string `json:"provenance"`
	ZeroValueOnly      bool   `json:"zeroValueOnly"`
	Notice             string `json:"notice"`
	CeremonyID         string `json:"ceremonyId"`
	R1CSSha256         string `json:"r1csSha256"`
	ProvingKeySha256   string `json:"provingKeySha256"`
	VerifyingKeySha256 string `json:"verifyingKeySha256"`
}

// checkCeremonyDir refuses a directory that is not registry entry 1 revision
// 3's labelled Chipnet ceremony keys: its metadata must carry the zero-value
// label and name the registry's digests, and its verifying key must be the
// recorded vp byte for byte. The R1CS and proving key are checked against the
// registry's pins while they are read.
func checkCeremonyDir(dir, r1csPath string) (*ceremonyKeys, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "keys.meta.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("refusing %s: no ceremony key metadata: %w", dir, err)
	}
	var m ceremonyMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, err
	}
	if m.Provenance != "simulated-single-party" || !m.ZeroValueOnly || !strings.HasPrefix(m.Notice, poolaction.ChipnetZeroValueLabel) {
		return nil, nil, fmt.Errorf("refusing %s: the key metadata is not labelled %q", dir, poolaction.ChipnetZeroValueLabel)
	}
	if m.CeremonyID != poolaction.ChipnetZeroValueRevision3CeremonyID || m.R1CSSha256 != poolaction.Revision3R1CSSha256 ||
		m.ProvingKeySha256 != poolaction.ChipnetZeroValueRevision3ProvingKeySha256 || m.VerifyingKeySha256 != poolaction.ChipnetZeroValueRevision3VPSha256 {
		return nil, nil, fmt.Errorf("refusing %s: ceremony %s is not registry entry 1 revision 3's recorded vp", dir, m.CeremonyID)
	}
	vp, err := poolaction.ChipnetZeroValueRevision3VP()
	if err != nil {
		return nil, nil, err
	}
	vkRaw, err := os.ReadFile(filepath.Join(dir, "verifying.key"))
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(vkRaw, vp) {
		return nil, nil, fmt.Errorf("refusing %s: verifying.key is not the registry's recorded vp", dir)
	}
	r1csAbs, err := filepath.Abs(r1csPath)
	if err != nil {
		return nil, nil, err
	}
	return &ceremonyKeys{
		Label:      poolaction.ChipnetZeroValueLabel,
		CeremonyID: m.CeremonyID,
		R1CS:       devprove.FileDigest{File: filepath.Base(r1csAbs), Bytes: poolaction.Revision3R1CSBytes, Sha256: poolaction.Revision3R1CSSha256},
		R1CSDir:    filepath.Dir(r1csAbs),
		PK:         devprove.FileDigest{File: "proving.key", Bytes: poolaction.ChipnetZeroValueRevision3ProvingKeyBytes, Sha256: poolaction.ChipnetZeroValueRevision3ProvingKeySha256},
		VK:         devprove.FileDigest{File: "verifying.key", Bytes: int64(len(vp)), Sha256: poolaction.ChipnetZeroValueRevision3VPSha256},
		ProfileID:  poolaction.ChipnetZeroValueRevision3ProfileID,
	}, vkRaw, nil
}

func proveBatch(args []string) (err error) {
	start := time.Now()
	fs := flag.NewFlagSet("prove-batch", flag.ContinueOnError)
	keys := fs.String("keys", "", "development key directory (devsetup output)")
	ceremonyDir := fs.String("ceremony-keys", "", "registry entry 1 revision 3's Chipnet ceremony key directory (proving.key, verifying.key, keys.meta.json)")
	r1csPath := fs.String("r1cs", "", "with --ceremony-keys: the revision-3 R1CS file")
	var corpora multi
	fs.Var(&corpora, "corpus", "corpus file (repeatable)")
	names := fs.String("entries", "", "comma-separated host positives to prove")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ceremony := *ceremonyDir != ""
	if fs.NArg() != 2 || (*keys == "") == !ceremony || ceremony != (*r1csPath != "") || len(corpora) == 0 || *names == "" {
		usage()
	}
	outDir, resultPath := fs.Arg(0), fs.Arg(1)
	for _, p := range []string{outDir, filepath.Dir(resultPath)} {
		if _, err := devprove.OutsideRepository(p); err != nil {
			return err
		}
	}
	if err := os.Mkdir(outDir, 0o755); err != nil {
		return fmt.Errorf("OUT-DIR must be new: %w", err)
	}
	r := &batchResult{Parameters: devprove.Parameters, Command: "prove-batch", Corpora: corpora, SwapBefore: devprove.ReadSwap(),
		GoVersion: runtime.Version(), GOMAXPROCS: runtime.GOMAXPROCS(0)}
	defer func() {
		after := devprove.ReadSwap()
		r.SwapAfter = &after
		if err != nil {
			r.Error = err.Error()
		}
		r.WallSeconds = time.Since(start).Seconds()
		r.ProcessMaxRSS = maxRSS()
		if werr := writeJSON(resultPath, r); werr != nil && err == nil {
			err = werr
		}
	}()
	r.Notes = []string{
		"development zero-value parameters: a proof under these keys is evidence of cost and of the aggregate's plumbing only, never of validity to anyone but this process",
		"every proof was verified by gnark v0.16.3 groth16.Verify before it was written, against the public witness rebuilt from the record bytes",
	}

	var abs string
	if ceremony {
		abs, err = filepath.Abs(*ceremonyDir)
	} else {
		abs, err = filepath.Abs(*keys)
	}
	if err != nil {
		return err
	}
	r.Keys = abs
	// The three files and where each is read from.
	var r1csDir string
	var r1csPin, pkPin devprove.FileDigest
	var vkRaw []byte
	if ceremony {
		c, raw, err := checkCeremonyDir(abs, *r1csPath)
		if err != nil {
			return err
		}
		r.Parameters = poolaction.ChipnetZeroValueLabel + ": the project ran every contribution and could have kept the randomness, so it can forge proofs under these keys; never for value"
		r.Ceremony = c
		r.Notes[0] = "Chipnet simulated single-party ceremony keys (registry entry 1 revision 3's recorded vp): a proof under them is evidence of cost and of the aggregate's plumbing, never of validity to anyone but this process, since the project could forge one"
		r1csDir, r1csPin, pkPin, vkRaw = c.R1CSDir, c.R1CS, c.PK, raw
	} else {
		label, err := os.ReadFile(filepath.Join(abs, devprove.LabelFile))
		if err != nil || string(label) != devprove.Parameters+"\n" {
			return fmt.Errorf("refusing %s: no development parameter label", abs)
		}
		raw, err := os.ReadFile(filepath.Join(abs, devprove.ManifestFile))
		if err != nil {
			return err
		}
		var m devprove.Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		if m.Parameters != devprove.Parameters {
			return fmt.Errorf("refusing %s: manifest is not the development label", abs)
		}
		r.Manifest = &m
		if vkRaw, err = os.ReadFile(filepath.Join(abs, m.VK.File)); err != nil {
			return err
		}
		if sum := sha256.Sum256(vkRaw); hex.EncodeToString(sum[:]) != m.VK.Sha256 {
			return fmt.Errorf("vk does not match the manifest")
		}
		r1csDir, r1csPin, pkPin = abs, m.R1CS, m.PK
	}

	want, err := entries(corpora, strings.Split(*names, ","))
	if err != nil {
		return err
	}
	vk, err := readVK(vkRaw)
	if err != nil {
		return err
	}

	ccs := groth16.NewCS(ecc.BN254)
	t0 := time.Now()
	if err := readChecked(r1csDir, r1csPin, func(rd io.Reader) error { _, err := ccs.ReadFrom(rd); return err }); err != nil {
		return err
	}
	r.LoadR1CS = time.Since(t0).Seconds()
	pk := groth16.NewProvingKey(ecc.BN254)
	t0 = time.Now()
	if err := readChecked(abs, pkPin, func(rd io.Reader) error { _, err := pk.ReadFrom(rd); return err }); err != nil {
		return err
	}
	r.LoadPK = time.Since(t0).Seconds()

	for _, e := range want {
		record, err := hex.DecodeString(*e.Record)
		if err != nil || len(record) != recordBytes {
			return fmt.Errorf("entry %q: record", e.Name)
		}
		a, err := e.Assignment()
		if err != nil {
			return fmt.Errorf("entry %q: %w", e.Name, err)
		}
		full, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
		if err != nil {
			return err
		}
		t0 := time.Now()
		proof, err := groth16.Prove(ccs, pk, full)
		if err != nil {
			return fmt.Errorf("entry %q: prove: %w", e.Name, err)
		}
		seconds := time.Since(t0).Seconds()
		pub, err := full.Public()
		if err != nil {
			return err
		}
		rebuilt, err := publicWitness(record)
		if err != nil {
			return err
		}
		pb, _ := pub.MarshalBinary()
		rb, _ := rebuilt.MarshalBinary()
		if !bytes.Equal(pb, rb) {
			return fmt.Errorf("entry %q: the proof's public witness is not x of the record", e.Name)
		}
		if err := groth16.Verify(proof, vk, rebuilt); err != nil {
			return fmt.Errorf("entry %q: gnark refuses its own proof: %w", e.Name, err)
		}
		pr, err := writeTo(proof)
		if err != nil {
			return err
		}
		if len(pr) != proofBytes {
			return fmt.Errorf("entry %q: proof is %d bytes", e.Name, len(pr))
		}
		file := e.Name + ".proof.bin"
		if err := newFile(filepath.Join(outDir, file), pr); err != nil {
			return err
		}
		sum := sha256.Sum256(pr)
		r.Proofs = append(r.Proofs, batchProof{Entry: e.Name, Record: *e.Record, ProofFile: file, ProofSha256: hex.EncodeToString(sum[:]),
			ProveSeconds: seconds, Verified: true, MaxRSSBytes: maxRSS()})
		fmt.Fprintf(os.Stderr, "gnark-reference: proved %s in %.1f s\n", e.Name, seconds)
	}
	return nil
}

// ---- transform ----

func rescaleScalar() (s, sInv big.Int) {
	sum := sha256.Sum256([]byte(deltaRescaleLabel))
	var e, inv fr.Element
	e.SetBytes(sum[:])
	if e.IsZero() || e.IsOne() {
		panic("degenerate rescale scalar")
	}
	inv.Inverse(&e)
	e.BigInt(&s)
	inv.BigInt(&sInv)
	return
}

func transform(args []string) error {
	fs := flag.NewFlagSet("transform", flag.ContinueOnError)
	vkPath := fs.String("vk", "", "verifying key")
	proofPath := fs.String("proof", "", "proof under that key")
	recordHex := fs.String("record-hex", "", "the proof's record, 314 bytes as hex")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *vkPath == "" || *proofPath == "" || *recordHex == "" {
		usage()
	}
	outDir := fs.Arg(0)
	record, err := hex.DecodeString(*recordHex)
	if err != nil || len(record) != recordBytes {
		return fmt.Errorf("record-hex must be %d bytes", recordBytes)
	}
	vkRaw, err := os.ReadFile(*vkPath)
	if err != nil {
		return err
	}
	proofRaw, err := os.ReadFile(*proofPath)
	if err != nil {
		return err
	}
	if ok, stage, d := verify(vkRaw, proofRaw, record); !ok {
		return fmt.Errorf("the input proof does not verify (%s: %s)", stage, d)
	}
	s, sInv := rescaleScalar()
	vk, _ := readVK(vkRaw)
	vk.G1.Delta.ScalarMultiplication(&vk.G1.Delta, &s)
	vk.G2.Delta.ScalarMultiplication(&vk.G2.Delta, &s)
	altVK, err := writeTo(vk)
	if err != nil {
		return err
	}
	p, _ := readProof(proofRaw)
	p.Krs.ScalarMultiplication(&p.Krs, &sInv)
	altProof, err := writeTo(p)
	if err != nil {
		return err
	}
	checks := []struct {
		name        string
		vk, proof   []byte
		wantAccepts bool
	}{
		{"alt proof under alt vk", altVK, altProof, true},
		{"alt proof under the original vk", vkRaw, altProof, false},
		{"original proof under alt vk", altVK, proofRaw, false},
		{"original proof under the original vk", vkRaw, proofRaw, true},
	}
	type outcome struct {
		Name     string `json:"name"`
		Accepted bool   `json:"gnarkAccepted"`
		Stage    string `json:"stage"`
		Detail   string `json:"detail,omitempty"`
	}
	var outcomes []outcome
	for _, c := range checks {
		ok, stage, d := verify(c.vk, c.proof, record)
		if ok != c.wantAccepts {
			return fmt.Errorf("%s: gnark accepted=%v, want %v (%s %s)", c.name, ok, c.wantAccepts, stage, d)
		}
		outcomes = append(outcomes, outcome{c.name, ok, stage, d})
	}
	if err := os.Mkdir(outDir, 0o755); err != nil {
		return fmt.Errorf("OUT-DIR must be new: %w", err)
	}
	if err := newFile(filepath.Join(outDir, "alt-vk.bin"), altVK); err != nil {
		return err
	}
	if err := newFile(filepath.Join(outDir, "alt-proof.bin"), altProof); err != nil {
		return err
	}
	vkSum, prSum := sha256.Sum256(altVK), sha256.Sum256(altProof)
	return writeJSON(filepath.Join(outDir, "transform.json"), map[string]any{
		"parameters":     keyLabel(vkRaw),
		"sourceVkSha256": hex.EncodeToString(sha256Of(vkRaw)),
		"command":        "transform",
		"construction":   "δ' = s·δ in G1 and G2, C' = s⁻¹·C; α, β, γ, K, the commitment keys, A, B, D and its PoK unchanged. (α, β, γ, s·δ) is the verifying key a setup with toxic δ·s publishes, and (A, B, C/s) a proof under it. No Setup ran.",
		"scalarLabel":    deltaRescaleLabel,
		"scalar":         s.String(),
		"record":         *recordHex,
		"altVkBytes":     len(altVK),
		"altVkSha256":    hex.EncodeToString(vkSum[:]),
		"altProofSha256": hex.EncodeToString(prSum[:]),
		"gnarkChecks":    outcomes,
		"gnark":          poolaction.GnarkVersion,
		"gnarkCrypto":    poolaction.GnarkCryptoVersion,
	})
}

// ---- reference ----

type g1json struct {
	X string `json:"x"`
	Y string `json:"y"`
}
type g2json struct {
	X0 string `json:"x0"`
	X1 string `json:"x1"`
	Y0 string `json:"y0"`
	Y1 string `json:"y1"`
}

func g1of(p curve.G1Affine) g1json {
	x, y := p.X.Bytes(), p.Y.Bytes()
	return g1json{hex.EncodeToString(x[:]), hex.EncodeToString(y[:])}
}
func g2of(p curve.G2Affine) g2json {
	x0, x1, y0, y1 := p.X.A0.Bytes(), p.X.A1.Bytes(), p.Y.A0.Bytes(), p.Y.A1.Bytes()
	return g2json{hex.EncodeToString(x0[:]), hex.EncodeToString(x1[:]), hex.EncodeToString(y0[:]), hex.EncodeToString(y1[:])}
}

type vkPoints struct {
	Sha256         string   `json:"sha256"`
	Alpha          g1json   `json:"alpha"`
	BetaG1         g1json   `json:"betaG1"`
	BetaG2         g2json   `json:"betaG2"`
	GammaG2        g2json   `json:"gammaG2"`
	DeltaG1        g1json   `json:"deltaG1"`
	DeltaG2        g2json   `json:"deltaG2"`
	K              []g1json `json:"k"`
	Committed      [][]int  `json:"publicAndCommitmentCommitted"`
	CommitmentG    g2json   `json:"commitmentG"`
	CommitmentGSN  g2json   `json:"commitmentGSigmaNeg"`
	CommitmentKeys int      `json:"commitmentKeys"`
}

func vkDump(raw []byte) (vkPoints, error) {
	vk, err := readVK(raw)
	if err != nil {
		return vkPoints{}, err
	}
	if len(vk.CommitmentKeys) != 1 {
		return vkPoints{}, fmt.Errorf("%d commitment keys", len(vk.CommitmentKeys))
	}
	sum := sha256.Sum256(raw)
	d := vkPoints{Sha256: hex.EncodeToString(sum[:]), Alpha: g1of(vk.G1.Alpha), BetaG1: g1of(vk.G1.Beta), BetaG2: g2of(vk.G2.Beta),
		GammaG2: g2of(vk.G2.Gamma), DeltaG1: g1of(vk.G1.Delta), DeltaG2: g2of(vk.G2.Delta), Committed: vk.PublicAndCommitmentCommitted,
		CommitmentG: g2of(vk.CommitmentKeys[0].G), CommitmentGSN: g2of(vk.CommitmentKeys[0].GSigmaNeg), CommitmentKeys: len(vk.CommitmentKeys)}
	for _, k := range vk.G1.K {
		d.K = append(d.K, g1of(k))
	}
	return d, nil
}

type proofPoints struct {
	Name           string `json:"name"`
	Proof          string `json:"proof"`
	A              g1json `json:"a"`
	B              g2json `json:"b"`
	C              g1json `json:"c"`
	D              g1json `json:"commitment"`
	PoK            g1json `json:"commitmentPok"`
	CommitmentWire string `json:"commitmentWire"`
}

func proofDump(name string, raw []byte) (proofPoints, error) {
	p, err := readProof(raw)
	if err != nil {
		return proofPoints{}, err
	}
	if len(p.Commitments) != 1 {
		return proofPoints{}, fmt.Errorf("%d commitments", len(p.Commitments))
	}
	// The commitment wire exactly as groth16/bn254 Verify derives it for a
	// commitment that commits no public input.
	h := hash_to_field.New([]byte(constraint.CommitmentDst))
	h.Write(p.Commitments[0].Marshal())
	var wire fr.Element
	wire.SetBytes(h.Sum(nil)[:fr.Bytes])
	wb := wire.Bytes()
	return proofPoints{Name: name, Proof: hex.EncodeToString(raw), A: g1of(p.Ar), B: g2of(p.Bs), C: g1of(p.Krs),
		D: g1of(p.Commitments[0]), PoK: g1of(p.CommitmentPok), CommitmentWire: hex.EncodeToString(wb[:])}, nil
}

// mutation is an XOR of one byte of a base verifying key, so the case file
// does not carry a 13 KB key per case.
type mutation struct {
	Offset int  `json:"offset"`
	Xor    byte `json:"xor"`
}

type refCase struct {
	Name        string     `json:"name"`
	Note        string     `json:"note"`
	VK          string     `json:"vk"` // "batch", "alt" or "action"
	VKMutations []mutation `json:"vkMutations"`
	Proof       string     `json:"proof"`
	Record      string     `json:"record"`
	// PublicInput, when set, is the public input gnark verified with in
	// place of the record's x: a 32-byte big-endian integer, reduced mod r.
	PublicInput string `json:"publicInput,omitempty"`
	Accepted    bool   `json:"gnarkAccepted"`
	Stage       string `json:"gnarkStage"`
	Detail      string `json:"gnarkDetail,omitempty"`
}

func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func xorAt(b []byte, i int, x byte) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= x
	return out
}

func reference(args []string) error {
	fs := flag.NewFlagSet("reference", flag.ContinueOnError)
	vkPath := fs.String("vk", "", "development verifying key of the batch (a stand-in key in the fixtures)")
	altVKPath := fs.String("alt-vk", "", "transform's verifying key")
	altProofPath := fs.String("alt-proof", "", "transform's proof")
	batch := fs.String("batch", "", "directory of <entry>.proof.bin files")
	actionVKPath := fs.String("action-vk", "", "a development verifying key of the action circuit itself")
	actionProofPath := fs.String("action-proof", "", "an action-circuit proof of the first batch record under --action-vk")
	var corpora multi
	fs.Var(&corpora, "corpus", "corpus file (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	withAction := *actionVKPath != ""
	if fs.NArg() != 1 || *vkPath == "" || *altVKPath == "" || *altProofPath == "" || *batch == "" || withAction != (*actionProofPath != "") || len(corpora) == 0 {
		usage()
	}
	var actionVK, actionProof []byte
	var err error
	if withAction {
		if actionVK, err = os.ReadFile(*actionVKPath); err != nil {
			return err
		}
		if actionProof, err = os.ReadFile(*actionProofPath); err != nil {
			return err
		}
	}
	vkRaw, err := os.ReadFile(*vkPath)
	if err != nil {
		return err
	}
	altVK, err := os.ReadFile(*altVKPath)
	if err != nil {
		return err
	}
	altProof, err := os.ReadFile(*altProofPath)
	if err != nil {
		return err
	}
	vkBase := map[string][]byte{"batch": vkRaw, "alt": altVK, "action": actionVK}

	// Every host positive that has a proof in the batch directory, in corpus order.
	type honest struct {
		name   string
		record []byte
		proof  []byte
	}
	var batchProofs []honest
	for _, path := range corpora {
		c, err := poolaction.LoadCorpus(path)
		if err != nil {
			return err
		}
		for _, e := range c.Entries {
			if e.Kind != "positive" || e.Record == nil {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(*batch, e.Name+".proof.bin"))
			if errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return err
			}
			rec, _ := hex.DecodeString(*e.Record)
			batchProofs = append(batchProofs, honest{e.Name, rec, raw})
		}
	}
	if len(batchProofs) < 2 {
		return fmt.Errorf("need at least two batch proofs, found %d", len(batchProofs))
	}
	first, second := batchProofs[0], batchProofs[1]

	var cases []refCase
	addX := func(name, note, vk string, muts []mutation, proof, record []byte, x *big.Int) {
		v := vkBase[vk]
		for _, m := range muts {
			v = xorAt(v, m.Offset, m.Xor)
		}
		ok, stage, d := verifyX(v, proof, record, x)
		c := refCase{Name: name, Note: note, VK: vk, VKMutations: muts, Proof: hex.EncodeToString(proof), Record: hex.EncodeToString(record), Accepted: ok, Stage: stage, Detail: d}
		if x != nil {
			c.PublicInput = fmt.Sprintf("%064x", x)
		}
		cases = append(cases, c)
	}
	add := func(name, note, vk string, muts []mutation, proof, record []byte) {
		addX(name, note, vk, muts, proof, record, nil)
	}

	for _, h := range batchProofs {
		add("honest:"+h.name, "a batch proof with its own record", "batch", nil, h.proof, h.record)
	}
	add("crossed:proof-of-first-with-second-record", "a proof for a different record", "batch", nil, first.proof, second.record)
	add("crossed:proof-of-second-with-first-record", "a proof for a different record", "batch", nil, second.proof, first.record)
	add("alt:alt-proof-under-alt-vk", "transform's pair: a proof under a different vp", "alt", nil, altProof, first.record)
	add("alt:alt-proof-under-batch-vk", "a proof under a different vp, offered under the batch vp", "batch", nil, altProof, first.record)
	add("alt:batch-proof-under-alt-vk", "the batch proof under the transformed vp", "alt", nil, first.proof, first.record)
	// One byte in each field of the 314-byte record: anchor, nf_0, rk_0, cm_0,
	// packet_0, deposit, fee, wlock_hash, and the last byte.
	for _, i := range []int{0, 32, 96, 162, 226, 258, 274, 282, recordBytes - 1} {
		add(fmt.Sprintf("record:byte-%d-xor-01", i), "a tampered record byte", "batch", nil, first.proof, xorAt(first.record, i, 0x01))
	}
	// Proof bytes: A [0,32), B [32,96), C [96,128), u32 count [128,132), D [132,164), PoK [164,196).
	for _, i := range []int{0, 5, 31, 32, 40, 63, 64, 95, 96, 100, 127, 131, 132, 140, 163, 164, 170, 195} {
		add(fmt.Sprintf("proof:byte-%d-xor-01", i), "one proof byte flipped", "batch", nil, xorAt(first.proof, i, 0x01), first.record)
	}
	for _, i := range []int{0, 32, 96, 132, 164} {
		add(fmt.Sprintf("proof:flag-%d-xor-40", i), "the compression flag of one point flipped (other root or infinity)", "batch", nil, xorAt(first.proof, i, 0x40), first.record)
		add(fmt.Sprintf("proof:flag-%d-xor-c0", i), "both flag bits of one point flipped", "batch", nil, xorAt(first.proof, i, 0xc0), first.record)
	}
	{
		// Other valid points in place of the PoK and of D: gnark decodes both.
		p, _ := readProof(first.proof)
		_, _, g1, _ := curve.Generators()
		p.CommitmentPok.Add(&p.CommitmentPok, &g1)
		pokSwapped, _ := writeTo(p)
		add("proof:pok-plus-generator", "the BSB22 knowledge proof replaced by another valid point; the main pairing does not read it", "batch", nil, pokSwapped, first.record)
		q, _ := readProof(first.proof)
		q.Commitments[0].Add(&q.Commitments[0], &g1)
		dSwapped, _ := writeTo(q)
		add("proof:commitment-plus-generator", "the BSB22 commitment replaced by another valid point", "batch", nil, dSwapped, first.record)
		r, _ := readProof(first.proof)
		r.Ar.Neg(&r.Ar)
		negA, _ := writeTo(r)
		add("proof:a-negated", "A replaced by −A", "batch", nil, negA, first.record)
		for _, span := range []struct {
			name       string
			start, len int
		}{{"a", 0, 32}, {"b", 32, 64}, {"c", 96, 32}, {"commitment", 132, 32}, {"pok", 164, 32}} {
			inf := append([]byte(nil), first.proof...)
			for i := span.start; i < span.start+span.len; i++ {
				inf[i] = 0
			}
			inf[span.start] = 0x40
			add("proof:infinity-"+span.name, "one proof point encoded as the point at infinity", "batch", nil, inf, first.record)
		}
		add("proof:truncated", "the proof one byte short", "batch", nil, first.proof[:proofBytes-1], first.record)
		add("proof:extended", "the proof one byte long", "batch", nil, append(append([]byte(nil), first.proof...), 0), first.record)
		add("proof:commitment-count-2", "the commitment count set to 2", "batch", nil, xorAt(first.proof, 131, 0x03), first.record)
	}
	// The one public input reduced other ways (ENG-437). gnark reduces an
	// integer at least r to the same element, so the unreduced digest is
	// accepted; a truncation, a little-endian read or x + 1 is refused. They
	// use the first batch record whose digest is at least r, or the reduction
	// cases would be vacuous.
	{
		var red *honest
		for i := range batchProofs {
			d := sha256.Sum256(batchProofs[i].record)
			if new(big.Int).SetBytes(d[:]).Cmp(ecc.BN254.ScalarField()) >= 0 {
				red = &batchProofs[i]
				break
			}
		}
		if red == nil {
			return fmt.Errorf("no batch record's digest is at least r: the reduction cases would be vacuous")
		}
		d := sha256.Sum256(red.record)
		digest := new(big.Int).SetBytes(d[:])
		x, err := poolaction.PublicInput(red.record)
		if err != nil {
			return err
		}
		le := make([]byte, 32)
		for i := range le {
			le[i] = d[31-i]
		}
		for _, c := range []struct {
			name, note string
			x          *big.Int
		}{
			{"x:honest", "x of the record, given explicitly", x},
			{"x:unreduced-digest", "int_be(digest) >= r given as an integer: gnark reduces it to x", digest},
			{"x:top-253-bits", "int_be(digest) >> 3, a truncation in place of mod r", new(big.Int).Rsh(digest, 3)},
			{"x:little-endian", "the digest read little-endian, a byte-order bug", new(big.Int).Mod(new(big.Int).SetBytes(le), ecc.BN254.ScalarField())},
			{"x:plus-one", "x + 1 mod r", new(big.Int).Mod(new(big.Int).Add(x, big.NewInt(1)), ecc.BN254.ScalarField())},
		} {
			addX(c.name, c.note+" (record "+red.name+")", "batch", nil, red.proof, red.record, c.x)
		}
	}
	// A second key of the action circuit and its proof (of the first batch record), when given.
	if withAction {
		add("action:honest", "the action key's proof of the first batch record", "action", nil, actionProof, first.record)
		add("action:record-fee-byte-xor-01", "the same proof with the record's fee byte flipped", "action", nil, actionProof, xorAt(first.record, 274, 0x01))
		add("action:proof-under-batch-vk", "the action proof under the batch key", "batch", nil, actionProof, first.record)
		add("action:batch-proof-under-action-vk", "the batch proof under the action key", "action", nil, first.proof, first.record)
	}
	// Verifying-key bytes: α [0,32), β1 [32,64), β2 [64,128), γ2 [128,192), δ1 [192,224), δ2 [224,288),
	// |K| [288,292), K [292, 292+32·3), then the commitment topology and keys.
	kStart := 292
	kEnd := kStart + 32*3
	for _, m := range []struct {
		name string
		off  int
		x    byte
	}{
		{"alpha-byte", 10, 0x01}, {"alpha-flag", 0, 0x40}, {"beta-g1-byte", 40, 0x01}, {"beta-g2-byte", 100, 0x01}, {"beta-g2-flag", 64, 0x40},
		{"gamma-g2-byte", 150, 0x01}, {"gamma-g2-flag", 128, 0x40}, {"delta-g1-byte", 200, 0x01}, {"delta-g2-byte", 250, 0x01}, {"delta-g2-flag", 224, 0x40},
		{"k-length", 291, 0x01}, {"k0-byte", kStart + 20, 0x01}, {"k0-flag", kStart, 0x40}, {"k1-x-flag", kStart + 32, 0x40},
		{"k1-x-byte", kStart + 32 + 17, 0x01}, {"k2-commitment-flag", kStart + 32*2, 0x40}, {"k2-commitment-byte", kStart + 32*2 + 9, 0x01},
		{"commitment-topology", kEnd + 3, 0x02}, {"commitment-committed", kEnd + 7, 0x01}, {"commitment-key-count", kEnd + 11, 0x02},
		{"commitment-g-flag", kEnd + 12, 0x40}, {"commitment-g-byte", kEnd + 30, 0x01}, {"commitment-gsigmaneg-flag", kEnd + 76, 0x40},
		{"commitment-gsigmaneg-byte", kEnd + 100, 0x01},
	} {
		add("vk:"+m.name, "one verifying-key byte flipped (the byte's own profile id changes, so this is the verifier alone)", "batch",
			[]mutation{{m.off, m.x}}, first.proof, first.record)
	}

	batchKey, err := vkDump(vkRaw)
	if err != nil {
		return err
	}
	alt, err := vkDump(altVK)
	if err != nil {
		return err
	}
	keys := map[string]vkPoints{"batch": batchKey, "alt": alt}
	if withAction {
		action, err := vkDump(actionVK)
		if err != nil {
			return err
		}
		keys["action"] = action
	}
	var proofs []proofPoints
	for _, h := range batchProofs {
		p, err := proofDump(h.name, h.proof)
		if err != nil {
			return err
		}
		proofs = append(proofs, p)
	}
	ap, err := proofDump("alt", altProof)
	if err != nil {
		return err
	}
	proofs = append(proofs, ap)
	if withAction {
		acp, err := proofDump("action", actionProof)
		if err != nil {
			return err
		}
		proofs = append(proofs, acp)
	}
	return writeJSON(fs.Arg(0), map[string]any{
		"parameters":    keyLabel(vkRaw),
		"description":   "ENG-421 (task 5.4 slice 1), registry entry 1 revision 3 (314-byte records; ENG-454, ENG-486): gnark v0.16.3's decoded points, BSB22 commitment wires and Verify verdicts, for the Rust core's differential test. batch is the --vk key and its batch of proofs, alt its delta-rescaled transform (no Setup), action a second key of the action circuit when given. Written by tools/apnt-pool-aggregate-sp1/gnark-reference reference.",
		"gnark":         poolaction.GnarkVersion,
		"gnarkCrypto":   poolaction.GnarkCryptoVersion,
		"verifyingKeys": keys,
		"proofs":        proofs,
		"cases":         cases,
	})
}

// Package devprove runs gnark Groth16 Setup, Prove and Verify under
// DEVELOPMENT ZERO-VALUE parameters, for the task-5.1b measurement of the
// pool action proof (peak memory and wall time against the 16 GB
// consumer-machine requirement).
//
// Setup takes gnark's internal randomness, and nothing destroys it or attests
// that it is gone. Whoever could read the Setup process's memory could forge
// proofs under these keys. They never guard value, never go on chain, and
// their verifying key is never allowlisted. The Chipnet keys come from the
// ceremony tooling (tools/apnt-pool-ceremony), not from here.
//
// Each phase is its own function, and the command runs each in its own
// process, so each phase's peak RSS is its own:
//
//	Setup   compile, check the R1CS digest, Setup, write R1CS, pk, vk, label, manifest
//	Prove   load R1CS and pk (timed), build the reference witness, prove, write the proof
//	Verify  verify the proof; a public witness with one input flipped must be refused
package devprove

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// Parameters labels every output of this package.
const Parameters = "DEVELOPMENT ZERO-VALUE — toxic waste not destroyed; forgeable; never for value"

// Files in a development-parameter directory.
const (
	LabelFile    = "PARAMETERS-LABEL.txt"
	ManifestFile = "manifest.json"
	R1CSFile     = "circuit.r1cs"
	PKFile       = "pk.bin"
	VKFile       = "vk.bin"
	ProofFile    = "proof.bin"
	PublicFile   = "public-witness.bin"
)

// Target is a circuit with an assignment source. A live source's "positive"
// label is a caller assertion; only solving/proving checks the relation.
type Target struct {
	Name    string
	Compile func() (constraint.ConstraintSystem, error)
	// Assignment is the full assignment of the reference positive, and a
	// description of where it comes from.
	Assignment func() (frontend.Circuit, *Source, error)
	// FlipIndex is the public-witness element Verify's negative flips.
	FlipIndex int
	FlipNote  string
}

// Source says where a witness comes from. Live sources omit private paths,
// witness digests and caller-authored free text.
type Source struct {
	Kind         string `json:"kind,omitempty"`
	Description  string `json:"description"`
	Corpus       string `json:"corpus,omitempty"`
	CorpusSha256 string `json:"corpusSha256,omitempty"`
	Entry        string `json:"entry,omitempty"`
	EntryKind    string `json:"entryKind,omitempty"`
	EntryNote    string `json:"entryNote,omitempty"`
}

// FileDigest is one written or loaded file.
type FileDigest struct {
	File   string `json:"file"`
	Bytes  int64  `json:"bytes"`
	Sha256 string `json:"sha256"`
}

// Manifest is written by Setup and read by Prove and Verify.
type Manifest struct {
	Parameters      string     `json:"parameters"`
	Target          string     `json:"target"`
	Gnark           string     `json:"gnark"`
	GnarkCrypto     string     `json:"gnarkCrypto"`
	Constraints     int        `json:"constraints"`
	FFTDomain       uint64     `json:"fftDomain"`
	NbPublicWitness int        `json:"nbPublicWitness"`
	R1CS            FileDigest `json:"r1cs"`
	PK              FileDigest `json:"provingKey"`
	VK              FileDigest `json:"verifyingKey"`
	Encoding        string     `json:"encoding"`
}

// Process is what every result records about the process that produced it.
type Process struct {
	GoVersion  string `json:"goVersion"`
	GOOS       string `json:"goos"`
	GOARCH     string `json:"goarch"`
	NumCPU     int    `json:"numCPU"`
	GOMAXPROCS int    `json:"gomaxprocs"`
	GOGC       string `json:"GOGC"`
	GOMEMLIMIT string `json:"GOMEMLIMIT"`
	// WallSeconds runs from main() entry to just before the result file is
	// written; MaxRSSBytes is the whole process's getrusage high-water mark
	// at that point. Both are set by Finish.
	WallSeconds float64 `json:"processWallSeconds"`
	MaxRSSBytes int64   `json:"processMaxRSSBytes"`
	// Error is set when the command refused or failed; the result then
	// holds what was measured up to that point.
	Error string `json:"error,omitempty"`
}

func newProcess() Process {
	return Process{
		GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, NumCPU: runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0), GOGC: os.Getenv("GOGC"), GOMEMLIMIT: os.Getenv("GOMEMLIMIT"),
	}
}

// Finish records the whole-process wall time and peak RSS.
func (p *Process) Finish(start time.Time) {
	p.WallSeconds = time.Since(start).Seconds()
	p.MaxRSSBytes = MaxRSS()
}

// Fail records the error a command stopped on.
func (p *Process) Fail(err error) {
	if err != nil {
		p.Error = err.Error()
	}
}

// Phase is one timed step. MaxRSSBytes is the process high-water mark at the
// step's end, so it includes every earlier step. GoHeldPeakBytes is the
// largest sampled Go-runtime memory not released to the OS during this step
// alone (see heldSampler): it shows a step's own peak when an earlier step's
// high-water mark hides it.
type Phase struct {
	Name            string  `json:"name"`
	Seconds         float64 `json:"seconds"`
	MaxRSSBytes     int64   `json:"maxRSSBytesAtEnd"`
	GoHeldPeakBytes uint64  `json:"goHeldPeakBytes"`
}

// SwapUsage is one reading of sysctl vm.swapusage.
type SwapUsage struct {
	Raw       string `json:"raw"`
	UsedBytes int64  `json:"usedBytes"` // -1 when unavailable
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ---- process measurements ----

// MaxRSS is the process's getrusage high-water mark in bytes.
func MaxRSS() int64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return -1
	}
	if runtime.GOOS == "darwin" {
		return ru.Maxrss // bytes on darwin
	}
	return ru.Maxrss * 1024 // KiB on linux
}

var swapUsed = regexp.MustCompile(`used = ([0-9.]+)([KMG])`)

// ReadSwap reads vm.swapusage (darwin); elsewhere it is unavailable.
func ReadSwap() SwapUsage {
	out, err := exec.Command("/usr/sbin/sysctl", "-n", "vm.swapusage").Output()
	if err != nil {
		return SwapUsage{Raw: "unavailable: " + err.Error(), UsedBytes: -1}
	}
	raw := strings.TrimSpace(string(out))
	m := swapUsed.FindStringSubmatch(raw)
	if m == nil {
		return SwapUsage{Raw: raw, UsedBytes: -1}
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return SwapUsage{Raw: raw, UsedBytes: -1}
	}
	mult := map[string]float64{"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}[m[2]]
	return SwapUsage{Raw: raw, UsedBytes: int64(v * mult)}
}

// heldSampler samples, every 100 ms, the Go runtime's memory not released to
// the OS (/memory/classes/total minus /memory/classes/heap/released). It
// excludes memory the runtime does not manage and may miss a spike shorter
// than the interval; it is a per-step proxy, the getrusage figures are the
// measurement.
type heldSampler struct {
	mu   sync.Mutex
	peak uint64
	stop chan struct{}
	done chan struct{}
}

func goHeld() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(s)
	return s[0].Value.Uint64() - s[1].Value.Uint64()
}

func startHeld() *heldSampler {
	h := &heldSampler{peak: goHeld(), stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(h.done)
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-h.stop:
				return
			case <-t.C:
				v := goHeld()
				h.mu.Lock()
				h.peak = max(h.peak, v)
				h.mu.Unlock()
			}
		}
	}()
	return h
}

func (h *heldSampler) end() uint64 {
	close(h.stop)
	<-h.done
	h.mu.Lock()
	defer h.mu.Unlock()
	return max(h.peak, goHeld())
}

// timed runs f as one Phase.
func timed(name string, phases *[]Phase, f func() error) error {
	h := startHeld()
	start := time.Now()
	err := f()
	*phases = append(*phases, Phase{Name: name, Seconds: time.Since(start).Seconds(), MaxRSSBytes: MaxRSS(), GoHeldPeakBytes: h.end()})
	return err
}

// ---- directories ----

// OutsideRepository refuses a path inside a git work tree: any ancestor of
// its resolved absolute form that holds a .git entry. Development parameters
// and their measurements never live in a checkout.
func OutsideRepository(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// Resolve symlinks on the deepest existing ancestor.
	existing, rest := abs, ""
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			break
		}
		rest = filepath.Join(filepath.Base(existing), rest)
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", err
	}
	full := filepath.Join(resolved, rest)
	for dir := full; ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return "", fmt.Errorf("refusing %s: it is inside the git work tree at %s; development parameters and results live outside the repository", path, dir)
		}
		if filepath.Dir(dir) == dir {
			return full, nil
		}
	}
}

func prepareNewDir(dir string) (string, error) {
	abs, err := OutsideRepository(dir)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(abs)
	if err == nil && len(entries) > 0 {
		return "", fmt.Errorf("refusing %s: not empty; Setup never overwrites an earlier setup", abs)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return abs, os.MkdirAll(abs, 0o700)
}

// openDir checks the label and reads the manifest of a Setup directory.
func openDir(t Target, dir string) (string, *Manifest, error) {
	abs, err := OutsideRepository(dir)
	if err != nil {
		return "", nil, err
	}
	label, err := os.ReadFile(filepath.Join(abs, LabelFile))
	if err != nil {
		return "", nil, fmt.Errorf("refusing %s: no parameter label (%w); only a directory written by devsetup is accepted", abs, err)
	}
	if string(label) != Parameters+"\n" {
		return "", nil, fmt.Errorf("refusing %s: parameter label is %q, not the development label", abs, strings.TrimSpace(string(label)))
	}
	raw, err := os.ReadFile(filepath.Join(abs, ManifestFile))
	if err != nil {
		return "", nil, fmt.Errorf("refusing %s: no manifest: %w", abs, err)
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return "", nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Parameters != Parameters {
		return "", nil, fmt.Errorf("refusing %s: manifest parameters %q", abs, m.Parameters)
	}
	if m.Target != t.Name {
		return "", nil, fmt.Errorf("refusing %s: set up for target %q, not %q", abs, m.Target, t.Name)
	}
	return abs, &m, nil
}

// writeFile writes through w and returns the file's size and SHA-256. The
// file is created exclusively: nothing is overwritten.
func writeFile(path string, w func(io.Writer) error) (FileDigest, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return FileDigest{}, err
	}
	h := sha256.New()
	bw := bufio.NewWriterSize(io.MultiWriter(f, h), 1<<20)
	cw := &countWriter{w: bw}
	if err := w(cw); err != nil {
		f.Close()
		return FileDigest{}, err
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		return FileDigest{}, err
	}
	if err := f.Close(); err != nil {
		return FileDigest{}, err
	}
	return FileDigest{filepath.Base(path), cw.n, hex.EncodeToString(h.Sum(nil))}, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// readFile decodes a file through r, hashing every byte of it, and checks the
// result against the manifest entry. Trailing bytes are refused.
func readFile(dir string, want FileDigest, r func(io.Reader) error) error {
	f, err := os.Open(filepath.Join(dir, want.File))
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	cr := &countReader{r: io.TeeReader(bufio.NewReaderSize(f, 1<<20), h)}
	if err := r(cr); err != nil {
		return fmt.Errorf("%s: %w", want.File, err)
	}
	trailing, err := io.Copy(io.Discard, cr)
	if err != nil {
		return err
	}
	if trailing != 0 {
		return fmt.Errorf("refusing %s: %d trailing bytes", want.File, trailing)
	}
	got := FileDigest{want.File, cr.n, hex.EncodeToString(h.Sum(nil))}
	if got != want {
		return fmt.Errorf("refusing %s: %d bytes sha256 %s, manifest says %d bytes sha256 %s", want.File, got.Bytes, got.Sha256, want.Bytes, want.Sha256)
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

// ---- Setup ----

type SetupResult struct {
	Parameters         string     `json:"parameters"`
	Command            string     `json:"command"`
	Target             string     `json:"target"`
	Dir                string     `json:"dir"`
	Gnark              string     `json:"gnark"`
	GnarkCrypto        string     `json:"gnarkCrypto"`
	ExpectedR1CSSha256 string     `json:"expectedR1csSha256"`
	Constraints        int        `json:"constraints"`
	FFTDomain          uint64     `json:"fftDomain"`
	NbPublicWitness    int        `json:"nbPublicWitness"`
	PKNbG1             int        `json:"provingKeyG1Points"`
	PKNbG2             int        `json:"provingKeyG2Points"`
	R1CS               FileDigest `json:"r1cs"`
	PK                 FileDigest `json:"provingKey"`
	VK                 FileDigest `json:"verifyingKey"`
	Phases             []Phase    `json:"phases"`
	Process
	Notes []string `json:"notes"`
}

// Setup compiles the target, refuses unless its R1CS SHA-256 equals
// expectR1CSSha256 (there is no default), runs gnark's groth16.Setup with its
// internal randomness, and writes the R1CS, the keys (gnark's compressed
// WriteTo encoding), the label and the manifest to dir, a new or empty
// directory outside any git work tree.
func Setup(t Target, dir, expectR1CSSha256 string) (*SetupResult, error) {
	if !hex64.MatchString(expectR1CSSha256) {
		return nil, fmt.Errorf("the expected R1CS SHA-256 must be 64 lowercase hex characters (got %q); there is no default", expectR1CSSha256)
	}
	abs, err := prepareNewDir(dir)
	if err != nil {
		return nil, err
	}
	r := &SetupResult{Parameters: Parameters, Command: "devsetup", Target: t.Name, Dir: abs, Gnark: gnarkVersion, GnarkCrypto: gnarkCryptoVersion,
		ExpectedR1CSSha256: expectR1CSSha256, Process: newProcess()}

	var ccs constraint.ConstraintSystem
	if err := timed("compile", &r.Phases, func() (err error) { ccs, err = t.Compile(); return }); err != nil {
		return r, err
	}
	r.Constraints = ccs.GetNbConstraints()
	r.FFTDomain = fft.NewDomain(uint64(r.Constraints)).Cardinality
	_, _, pub := ccs.GetNbVariables()
	r.NbPublicWitness = pub - 1

	// The R1CS is written to a partial file and kept only if its digest is
	// the expected one; a mismatch leaves nothing in dir and runs no Setup.
	partial := filepath.Join(abs, R1CSFile+".partial")
	if err := timed("write-r1cs", &r.Phases, func() (err error) {
		r.R1CS, err = writeFile(partial, func(w io.Writer) error { _, err := ccs.WriteTo(w); return err })
		return
	}); err != nil {
		return r, err
	}
	if r.R1CS.Sha256 != expectR1CSSha256 {
		os.Remove(partial)
		r.R1CS.File = "(deleted: digest mismatch)"
		return r, fmt.Errorf("refusing Setup: R1CS SHA-256 is %s, expected %s", r.R1CS.Sha256, expectR1CSSha256)
	}
	if err := os.Rename(partial, filepath.Join(abs, R1CSFile)); err != nil {
		return r, err
	}
	r.R1CS.File = R1CSFile
	// The label goes in before any key exists.
	if err := os.WriteFile(filepath.Join(abs, LabelFile), []byte(Parameters+"\n"), 0o600); err != nil {
		return r, err
	}
	// Compile garbage goes back to the OS before Setup; the RSS high-water
	// mark already holds the compile peak.
	runtime.GC()
	debug.FreeOSMemory()

	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	if err := timed("setup", &r.Phases, func() (err error) { pk, vk, err = groth16.Setup(ccs); return }); err != nil {
		return r, err
	}
	r.PKNbG1, r.PKNbG2 = pk.NbG1(), pk.NbG2()
	if err := timed("write-pk", &r.Phases, func() (err error) {
		r.PK, err = writeFile(filepath.Join(abs, PKFile), func(w io.Writer) error { _, err := pk.WriteTo(w); return err })
		return
	}); err != nil {
		return r, err
	}
	if err := timed("write-vk", &r.Phases, func() (err error) {
		r.VK, err = writeFile(filepath.Join(abs, VKFile), func(w io.Writer) error { _, err := vk.WriteTo(w); return err })
		return
	}); err != nil {
		return r, err
	}
	m := Manifest{Parameters: Parameters, Target: t.Name, Gnark: gnarkVersion, GnarkCrypto: gnarkCryptoVersion,
		Constraints: r.Constraints, FFTDomain: r.FFTDomain, NbPublicWitness: r.NbPublicWitness, R1CS: r.R1CS, PK: r.PK, VK: r.VK,
		Encoding: "R1CS: gnark (*cs.R1CS).WriteTo; keys: gnark groth16 bn254 WriteTo (compressed points)"}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(abs, ManifestFile), append(b, '\n'), 0o600); err != nil {
		return r, err
	}
	r.Notes = []string{
		"development zero-value parameters: gnark groth16.Setup with its internal randomness; nothing destroys it, so these keys are forgeable and never guard value",
		"the verifying key is never allowlisted and its profile id is never computed for a registry",
		"processMaxRSSBytes includes the compile; the setup phase's goHeldPeakBytes is the Setup step alone (sampled Go-runtime memory, a proxy)",
	}
	return r, nil
}

// ---- Prove ----

type ProveResult struct {
	Parameters string     `json:"parameters"`
	Command    string     `json:"command"`
	Target     string     `json:"target"`
	Dir        string     `json:"dir"`
	Witness    *Source    `json:"witness"`
	R1CS       FileDigest `json:"r1cs"`
	PK         FileDigest `json:"provingKey"`
	Proof      FileDigest `json:"proof"`
	Public     FileDigest `json:"publicWitness"`
	SwapBefore SwapUsage  `json:"swapBefore"`
	SwapAfter  *SwapUsage `json:"swapAfter"` // null when the command stopped early
	Phases     []Phase    `json:"phases"`
	Process
	Notes []string `json:"notes"`
}

// Prove loads the R1CS and proving key from dir (each checked against the
// manifest while it is read), builds the target's reference witness, proves
// and writes the proof and the public witness to dir. A directory without the
// development label is refused.
func Prove(t Target, dir string) (*ProveResult, error) {
	r := &ProveResult{Parameters: Parameters, Command: "devprove", Target: t.Name, SwapBefore: ReadSwap(), Process: newProcess()}
	abs, m, err := openDir(t, dir)
	if err != nil {
		return r, err
	}
	r.Dir, r.R1CS, r.PK = abs, m.R1CS, m.PK
	// Refused before any load: a proof is never overwritten.
	for _, f := range []string{ProofFile, PublicFile} {
		if _, err := os.Lstat(filepath.Join(abs, f)); !errors.Is(err, os.ErrNotExist) {
			return r, fmt.Errorf("refusing %s: it already holds %s; devprove never overwrites a proof", abs, f)
		}
	}

	ccs := groth16.NewCS(ecc.BN254)
	if err := timed("load-r1cs", &r.Phases, func() error {
		return readFile(abs, m.R1CS, func(rd io.Reader) error { _, err := ccs.ReadFrom(rd); return err })
	}); err != nil {
		return r, err
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	if err := timed("load-pk", &r.Phases, func() error {
		return readFile(abs, m.PK, func(rd io.Reader) error { _, err := pk.ReadFrom(rd); return err })
	}); err != nil {
		return r, err
	}

	var full witness.Witness
	if err := timed("witness", &r.Phases, func() error {
		a, src, err := t.Assignment()
		if err != nil {
			return err
		}
		r.Witness = src
		full, err = frontend.NewWitness(a, ecc.BN254.ScalarField())
		return err
	}); err != nil {
		return r, err
	}

	var proof groth16.Proof
	if err := timed("prove", &r.Phases, func() (err error) { proof, err = groth16.Prove(ccs, pk, full); return }); err != nil {
		return r, err
	}
	if err := timed("write-proof", &r.Phases, func() error {
		pub, err := full.Public()
		if err != nil {
			return err
		}
		if r.Proof, err = writeFile(filepath.Join(abs, ProofFile), func(w io.Writer) error { _, err := proof.WriteTo(w); return err }); err != nil {
			return err
		}
		r.Public, err = writeFile(filepath.Join(abs, PublicFile), func(w io.Writer) error { _, err := pub.WriteTo(w); return err })
		return err
	}); err != nil {
		return r, err
	}
	after := ReadSwap()
	r.SwapAfter = &after
	r.Notes = []string{
		"development zero-value parameters: a proof under these keys is evidence of cost only, never of validity to anyone but this process",
		"load-r1cs and load-pk include reading the file, SHA-256 over every byte and gnark's decoding; load-pk uses ReadFrom (compressed points, with gnark's decompression and subgroup checks)",
		"witness is building the assignment and gnark's witness vector; prove is groth16.Prove, which includes gnark's R1CS solve (hint execution)",
		"processWallSeconds runs from main() entry to just before the result file is written; processMaxRSSBytes is the getrusage high-water mark of the whole process",
	}
	return r, nil
}

// ---- Verify ----

type VerifyResult struct {
	Parameters          string     `json:"parameters"`
	Command             string     `json:"command"`
	Target              string     `json:"target"`
	Dir                 string     `json:"dir"`
	Witness             *Source    `json:"witness"`
	VK                  FileDigest `json:"verifyingKey"`
	PublicWitnessStored bool       `json:"storedPublicWitnessEqualsRebuilt"`
	NbPublicWitness     int        `json:"nbPublicWitness"`
	Verified            bool       `json:"verified"`
	VerifyError         string     `json:"verifyError,omitempty"`
	FlipIndex           int        `json:"flippedPublicIndex"`
	FlipNote            string     `json:"flippedPublicNote"`
	FlipFrom            string     `json:"flippedFrom"`
	FlipTo              string     `json:"flippedTo"`
	FlippedRefused      bool       `json:"flippedRefused"`
	FlippedError        string     `json:"flippedError"`
	Phases              []Phase    `json:"phases"`
	Process
	Notes []string `json:"notes"`
}

// Verify verifies the proof in dir against the verifying key and the public
// witness rebuilt from the target's reference positive, then verifies the
// same proof against that public witness with one element's low bit flipped,
// which must be refused. Both outcomes are recorded; either failing is an
// error.
func Verify(t Target, dir string) (*VerifyResult, error) {
	r := &VerifyResult{Parameters: Parameters, Command: "devverify", Target: t.Name, FlipIndex: t.FlipIndex, FlipNote: t.FlipNote, Process: newProcess()}
	abs, m, err := openDir(t, dir)
	if err != nil {
		return r, err
	}
	r.Dir, r.VK = abs, m.VK

	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := timed("load-vk", &r.Phases, func() error {
		return readFile(abs, m.VK, func(rd io.Reader) error { _, err := vk.ReadFrom(rd); return err })
	}); err != nil {
		return r, err
	}
	proof := groth16.NewProof(ecc.BN254)
	rawProof, err := os.ReadFile(filepath.Join(abs, ProofFile))
	if err != nil {
		return r, fmt.Errorf("no proof: %w", err)
	}
	if n, err := proof.ReadFrom(bytes.NewReader(rawProof)); err != nil || n != int64(len(rawProof)) {
		return r, fmt.Errorf("proof: read %d of %d bytes: %v", n, len(rawProof), err)
	}

	// The public witness is rebuilt from the reference positive, not taken
	// from the directory; the stored copy is only compared with it.
	var pubBytes []byte
	if err := timed("public-witness", &r.Phases, func() error {
		a, src, err := t.Assignment()
		if err != nil {
			return err
		}
		r.Witness = src
		w, err := frontend.NewWitness(a, ecc.BN254.ScalarField(), frontend.PublicOnly())
		if err != nil {
			return err
		}
		pubBytes, err = w.MarshalBinary()
		return err
	}); err != nil {
		return r, err
	}
	stored, err := os.ReadFile(filepath.Join(abs, PublicFile))
	r.PublicWitnessStored = err == nil && bytes.Equal(stored, pubBytes)

	pub, err := publicWitness(pubBytes)
	if err != nil {
		return r, err
	}
	vec := pub.Vector().(fr.Vector)
	r.NbPublicWitness = len(vec)
	if t.FlipIndex < 0 || t.FlipIndex >= len(vec) {
		return r, fmt.Errorf("flip index %d outside the %d public inputs", t.FlipIndex, len(vec))
	}

	var verr error
	if err := timed("verify", &r.Phases, func() error { verr = groth16.Verify(proof, vk, pub); return nil }); err != nil {
		return r, err
	}
	r.Verified = verr == nil
	if verr != nil {
		r.VerifyError = verr.Error()
	}

	flipped, err := publicWitness(pubBytes)
	if err != nil {
		return r, err
	}
	fvec := flipped.Vector().(fr.Vector)
	var before, after big.Int
	fvec[t.FlipIndex].BigInt(&before)
	after.Xor(&before, big.NewInt(1))
	fvec[t.FlipIndex].SetBigInt(&after)
	r.FlipFrom, r.FlipTo = before.String(), after.String()
	if fb, err := flipped.MarshalBinary(); err != nil || bytes.Equal(fb, pubBytes) {
		return r, fmt.Errorf("the flipped public witness is not different from the original (%v)", err)
	}
	var ferr error
	if err := timed("verify-flipped", &r.Phases, func() error { ferr = groth16.Verify(proof, vk, flipped); return nil }); err != nil {
		return r, err
	}
	r.FlippedRefused = ferr != nil
	if ferr != nil {
		r.FlippedError = ferr.Error()
	}
	r.Notes = []string{
		"development zero-value parameters: verification under these keys shows the proof system works end to end, never that a statement holds for anyone else",
		"the public witness is rebuilt from the reference positive; the flipped witness is a fresh copy with one element's low bit flipped",
	}
	switch {
	case !r.Verified:
		return r, fmt.Errorf("the proof does not verify: %v", verr)
	case !r.FlippedRefused:
		return r, fmt.Errorf("the proof verifies against a flipped public input")
	case !r.PublicWitnessStored:
		return r, fmt.Errorf("the stored public witness differs from the one rebuilt from the reference positive")
	}
	return r, nil
}

func publicWitness(b []byte) (witness.Witness, error) {
	w, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	return w, w.UnmarshalBinary(b)
}

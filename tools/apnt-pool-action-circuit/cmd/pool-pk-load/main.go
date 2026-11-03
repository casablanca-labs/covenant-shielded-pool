// Command pool-pk-load measures loading the pool action circuit's Groth16
// proving key, and a wallet prove with the fastest pinned loader (task ENG-424).
//
// RESEARCH PROTOTYPE — NOT REVIEWED. The keys it is run on are zero-value
// test keys: the 5.1c Chipnet simulated single-party ceremony key (the project
// could forge proofs under it) or development parameters.
//
// Each command is its own process, so each case's peak RSS is its own. OUT.json
// must lie outside any git work tree; nothing is overwritten.
//
//	pool-pk-load sha256    --key F OUT.json                 SHA-256 of F, streamed (8 MiB reads)
//	pool-pk-load residency --key F OUT.json                 page-cache residency of F (mincore)
//	pool-pk-load evict     --key F OUT.json                 drop F from the page cache (msync MS_INVALIDATE)
//	pool-pk-load load      --case C --key F [PIN] OUT.json  load the proving key one way, timed
//	pool-pk-load derive    --format image|dump --key RAW PIN --out NEW OUT.json
//	pool-pk-load roundtrip --format FMT --key F PIN --raw-bytes N --raw-sha256 H OUT.json
//	pool-pk-load prove     --format FMT --key F PIN --r1cs F --r1cs-bytes N --r1cs-sha256 H
//	                       --vk F --vk-bytes N --vk-sha256 H [--target action|small] --corpus F OUT.json
//	pool-pk-load admit-request --request PRIVATE.json --profile-id H [ALL REVISION-3 PINS] OUT.json
//	pool-pk-load prove         --request PRIVATE.json --profile-id H [ALL REVISION-3 PINS] OUT.json
//
// PIN is --pin-bytes N --pin-sha256 H. Load cases:
//
//	readfrom        gnark ReadFrom from a buffered file: on-curve and subgroup checks, no digest
//	unsafe          gnark UnsafeReadFrom from a buffered file: no point checks, no digest
//	readdump        gnark ReadDump from a buffered file (a WriteDump file): no checks, no digest
//	verified-raw    pin check on the whole file in memory, then UnsafeReadFrom of that buffer
//	verified-dump   pin check, then ReadDump of that buffer
//	verified-image  pin check, then the pkload image view (no copy, no decode of points)
//
// derive decodes the raw key with every check and writes the image or dump;
// roundtrip loads a key and hashes its WriteRawTo encoding against the raw
// pin; prove loads the R1CS, the key and the verifying key (each against its
// pin), proves the corpus's reference host positive, and verifies the proof,
// which must also be refused against one flipped public input.
// Live requests use the same loader/prover after admission, with pinned
// revision-3 keys only and the existing measurement harness required. See README.
package main

import (
	"bufio"
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
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/devprove"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/internal/runneradmission"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/pkload"
)

type Phase struct {
	Name        string  `json:"name"`
	Seconds     float64 `json:"seconds"`
	MaxRSSBytes int64   `json:"maxRSSBytesAtEnd"`
	GoHeldBytes uint64  `json:"goHeldBytesAtEnd"`
}

type Shape struct {
	Wires          int   `json:"wires"`
	NbInfinityA    int   `json:"nbInfinityA"`
	NbInfinityB    int   `json:"nbInfinityB"`
	G1A            int   `json:"g1A"`
	G1B            int   `json:"g1B"`
	G1Z            int   `json:"g1Z"`
	G1K            int   `json:"g1K"`
	G2B            int   `json:"g2B"`
	Commitments    []int `json:"commitmentBasisLengths"`
	DomainCardinal int   `json:"domainCardinality"`
}

type Result struct {
	Notice      string               `json:"notice"`
	Command     string               `json:"command"`
	Args        []string             `json:"args"`
	Case        string               `json:"case,omitempty"`
	Target      string               `json:"target,omitempty"`
	Key         string               `json:"key,omitempty"`
	KeyBytes    int64                `json:"keyBytes,omitempty"`
	Residency   *Residency           `json:"residencyAtStart,omitempty"`
	After       *Residency           `json:"residencyAfter,omitempty"`
	R1CSRes     *Residency           `json:"r1csResidencyAtStart,omitempty"`
	SHA256      string               `json:"sha256,omitempty"`
	Pin         *pkload.Pin          `json:"pin,omitempty"`
	Read        *pkload.ReadStats    `json:"read,omitempty"`
	Decode      *pkload.DecodeStats  `json:"decode,omitempty"`
	Derive      *pkload.DeriveResult `json:"derive,omitempty"`
	Shape       *Shape               `json:"shape,omitempty"`
	RoundTrip   *RoundTrip           `json:"roundTrip,omitempty"`
	Prove       *ProveOut            `json:"prove,omitempty"`
	Admission   *RequestAdmission    `json:"admission,omitempty"`
	Phases      []Phase              `json:"phases"`
	GoVersion   string               `json:"goVersion"`
	GOMAXPROCS  int                  `json:"gomaxprocs"`
	NumCPU      int                  `json:"numCPU"`
	GOGC        string               `json:"GOGC"`
	GOMEMLIMIT  string               `json:"GOMEMLIMIT"`
	WallSeconds float64              `json:"processWallSeconds"`
	MaxRSSBytes int64                `json:"processMaxRSSBytes"`
	Error       string               `json:"error,omitempty"`
	ErrorStage  string               `json:"errorStage,omitempty"`
}

type RoundTrip struct {
	Raw     pkload.Pin `json:"expectedRaw"`
	Got     pkload.Pin `json:"writeRawToOfLoadedKey"`
	Matches bool       `json:"matches"`
}

type ProveOut struct {
	Witness     *devprove.Source `json:"witness"`
	R1CS        pkload.Pin       `json:"r1cs"`
	VK          pkload.Pin       `json:"verifyingKey"`
	Constraints int              `json:"constraints"`
	// Set only for a proof that verified (see prove).
	ProofBytes     int    `json:"proofBytes,omitempty"`
	ProofSHA256    string `json:"proofSha256,omitempty"`
	ProofHex       string `json:"proofHex,omitempty"`
	PublicInputs   int    `json:"publicInputs"`
	Verified       bool   `json:"verified"`
	VerifyError    string `json:"verifyError,omitempty"`
	FlipIndex      int    `json:"flippedPublicIndex"`
	FlipNote       string `json:"flippedPublicNote"`
	FlippedRefused bool   `json:"flippedRefused"`
	FlippedError   string `json:"flippedError,omitempty"`
}

func goHeld() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(s)
	return s[0].Value.Uint64() - s[1].Value.Uint64()
}

func (r *Result) timed(name string, f func() error) error {
	start := time.Now()
	err := f()
	r.Phases = append(r.Phases, Phase{name, time.Since(start).Seconds(), devprove.MaxRSS(), goHeld()})
	return err
}

func shapeOf(pk *groth16bn254.ProvingKey) *Shape {
	s := &Shape{Wires: len(pk.InfinityA), NbInfinityA: int(pk.NbInfinityA), NbInfinityB: int(pk.NbInfinityB),
		G1A: len(pk.G1.A), G1B: len(pk.G1.B), G1Z: len(pk.G1.Z), G1K: len(pk.G1.K), G2B: len(pk.G2.B),
		DomainCardinal: int(pk.Domain.Cardinality)}
	for _, ck := range pk.CommitmentKeys {
		s.Commitments = append(s.Commitments, len(ck.Basis))
	}
	return s
}

// Production passes only fixed dependencies. The tagged prerequisite lives in
// the shared internal owning package; this dispatch has no admission override.
type runDeps struct {
	stderr       io.Writer
	resultWriter func(string, []byte) error
}
type runResult struct {
	status       int
	refusal      *runneradmission.Refusal
	prerequisite error
}

func main() {
	result := runV2(os.Args, runDeps{stderr: os.Stderr, resultWriter: writeNew})
	if result.status != 0 {
		os.Exit(result.status)
	}
}

type liveV2 struct{}

func (liveV2) target(path string) devprove.Target { return devprove.InactiveLiveActionTargetV2(path) }
func (liveV2) guard(work func() error) error      { return guardLiveWorkV2(work) }

// The production composition is fixed, with no CLI or environment selector.
func runV2(args []string, deps runDeps) runResult {
	start := time.Now()
	logger.Disable()
	if len(args) < 3 {
		fmt.Fprintln(deps.stderr, "usage: see the package comment of tools/apnt-pool-action-circuit/cmd/pool-pk-load")
		return runResult{status: 2}
	}
	r := &Result{Notice: pkload.Notice, Command: args[1], Args: args[2:], GoVersion: runtime.Version(),
		GOMAXPROCS: runtime.GOMAXPROCS(0), NumCPU: runtime.NumCPU(), GOGC: os.Getenv("GOGC"), GOMEMLIMIT: os.Getenv("GOMEMLIMIT")}
	live := hasRequestFlag(args[2:]) || (args[1] == "admit-request" || args[1] == "check-live")
	fs := flag.NewFlagSet(args[1], flag.ContinueOnError)
	if live {
		fs.SetOutput(io.Discard)
	}
	key := fs.String("key", "", "key file")
	cse := fs.String("case", "", "load case")
	format := fs.String("format", "", "raw, dump or image")
	pinBytes := fs.Int64("pin-bytes", 0, "pinned byte length of --key")
	pinSHA := fs.String("pin-sha256", "", "pinned SHA-256 of --key")
	out := fs.String("out", "", "derive: the new file")
	rawBytes := fs.Int64("raw-bytes", 0, "roundtrip: the raw key's pinned length")
	rawSHA := fs.String("raw-sha256", "", "roundtrip: the raw key's pinned SHA-256")
	r1cs := fs.String("r1cs", "", "prove: R1CS file")
	r1csBytes := fs.Int64("r1cs-bytes", 0, "")
	r1csSHA := fs.String("r1cs-sha256", "", "")
	vkPath := fs.String("vk", "", "prove: verifying key file (gnark WriteTo)")
	vkBytes := fs.Int64("vk-bytes", 0, "")
	vkSHA := fs.String("vk-sha256", "", "")
	corpus := fs.String("corpus", "", "prove: the action-circuit parity corpus")
	request := fs.String("request", "", "prove/admit-request: private wallet requestJson file (exclusive with --corpus)")
	liveCache := fs.String("live-cache", "asis", "live prove cache preparation: asis, warm, cold")
	profile := fs.String("profile-id", "", "live request: exact revision-3 Chipnet zero-value profile id")
	target := fs.String("target", "action", "prove: action, or small (a test circuit that is not the pool action circuit)")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(deps.stderr, "exactly one OUT.json after the flags")
		return runResult{status: 2}
	}
	outJSON, err := devprove.OutsideRepository(fs.Arg(0))
	if err == nil {
		if _, serr := os.Lstat(outJSON); !errors.Is(serr, os.ErrNotExist) {
			err = fmt.Errorf("refusing %s: it exists; a result is never overwritten", outJSON)
		}
	}
	if err != nil {
		if live {
			err = errors.New("live-request-result-path")
		}
		fmt.Fprintln(deps.stderr, err)
		return runResult{status: 1}
	}
	pin := pkload.Pin{Bytes: *pinBytes, SHA256: *pinSHA}
	// Live provenance never records the private request's path or free text.
	if live {
		r.Args = nil
		r.GOGC, r.GOMEMLIMIT = "", ""
		if r.Command != "prove" && r.Command != "admit-request" && r.Command != "check-live" {
			r.Command = "live-request"
		}
	} else {
		r.Key = *key
	}
	if *key != "" && !live {
		if st, err := os.Stat(*key); err == nil {
			r.KeyBytes = st.Size()
		}
		res := residency(*key)
		r.Residency = &res
	}
	if *r1cs != "" && !live {
		res := residency(*r1cs)
		r.R1CSRes = &res
	}

	if (live && (*request == "" || (args[1] != "prove" && args[1] != "admit-request" && args[1] != "check-live"))) ||
		(*profile != "" && *request == "") || (*liveCache != "asis" && (!live || args[1] != "prove")) {
		err = errors.New("live-request-options")
	} else {
		switch args[1] {
		case "sha256":
			err = r.timed("sha256", func() error { d, err := hashFile(*key); r.SHA256 = d; return err })
		case "residency":
		case "evict":
			err = r.timed("evict", func() error { return evict(*key) })
			after := residency(*key)
			r.After = &after
		case "load":
			r.Case = *cse
			err = load(r, *cse, *key, pin)
		case "derive":
			if *out != "" {
				if o, oerr := devprove.OutsideRepository(*out); oerr != nil {
					err = oerr
				} else {
					*out = o
				}
			}
			if err == nil {
				r.Pin = &pin
				err = r.timed("derive", func() (err error) {
					r.Derive, err = pkload.Derive(*key, pin, *out, pkload.Format(*format))
					return
				})
			}
		case "roundtrip":
			err = roundtrip(r, pkload.Format(*format), *key, pin, pkload.Pin{Bytes: *rawBytes, SHA256: *rawSHA})
		case "prove", "admit-request", "check-live":
			if *request != "" || (args[1] == "admit-request" || args[1] == "check-live") {
				if *request == "" || *corpus != "" || *target != "action" || (*liveCache != "asis" && *liveCache != "warm" && *liveCache != "cold") {
					err = errors.New("live-request-options")
					break
				}
				if requestAliases(*request, *key, *r1cs, *vkPath, *out, fs.Arg(0)) {
					err = errors.New("live-request-options")
					break
				}
				t := (liveV2{}).target(*request)
				r.Target = t.Name
				var full witness.Witness
				err = r.timed("admit-request", func() (err error) {
					full, r.Admission, err = admitRequest(t, pkload.Format(*format), pin,
						pkload.Pin{Bytes: *r1csBytes, SHA256: *r1csSHA}, pkload.Pin{Bytes: *vkBytes, SHA256: *vkSHA}, *profile)
					return
				})
				if err == nil && args[1] != "admit-request" {
					if args[1] == "check-live" {
						// This entry has no work callback: key preparation and proving
						// remain reachable only through the guarded prove branch.
						err = checkLiveV2(args[1])
						break
					}
					err = (liveV2{}).guard(func() error {
						if err := prepareLiveCache(r, *liveCache, []string{*r1cs, *key, *vkPath}); err != nil {
							return err
						}
						return proveAssigned(r, t, full, pkload.Format(*format), *key, pin, *r1cs,
							pkload.Pin{Bytes: *r1csBytes, SHA256: *r1csSHA}, *vkPath, pkload.Pin{Bytes: *vkBytes, SHA256: *vkSHA})
					})
				}
				break
			}
			var t devprove.Target
			switch *target {
			case "action":
				t = devprove.ActionTarget(*corpus)
			case "small":
				t = devprove.SmallTarget(devprove.SmallRounds)
			default:
				err = fmt.Errorf("--target is action or small, not %q", *target)
			}
			if err == nil {
				r.Target = t.Name
				err = prove(r, t, pkload.Format(*format), *key, pin, *r1cs, pkload.Pin{Bytes: *r1csBytes, SHA256: *r1csSHA},
					*vkPath, pkload.Pin{Bytes: *vkBytes, SHA256: *vkSHA})
			}
		default:
			err = fmt.Errorf("unknown command %q", args[1])
		}
	}
	if live {
		var refusal *runneradmission.Refusal
		if errors.As(err, &refusal) {
			return runResult{status: 1, refusal: refusal}
		}
		if err != nil && (err.Error() == "live-request-main-checkout-required" || err.Error() == "live-request-harness-required" || err.Error() == "live-request-prover-lock-required") {
			return runResult{status: 1, prerequisite: err}
		}
	}
	// Preserve the loader's stage before redaction replaces its typed error.
	// The private loader message must never reach a live receipt or terminal.
	err = captureResultError(r, err, live)
	if live {
		if r.Prove != nil {
			if r.Prove.VerifyError != "" {
				r.Prove.VerifyError = "verification failed"
			}
			if r.Prove.FlippedError != "" {
				r.Prove.FlippedError = "flipped input refused"
			}
		}
	}
	if err != nil {
		r.Error = err.Error()
	}
	r.WallSeconds = time.Since(start).Seconds()
	r.MaxRSSBytes = devprove.MaxRSS()
	b, _ := json.MarshalIndent(r, "", "  ")
	if werr := deps.resultWriter(outJSON, append(b, '\n')); werr != nil {
		if live {
			werr = errors.New("live-request-result-write")
		}
		fmt.Fprintln(deps.stderr, werr)
		return runResult{status: 1}
	}
	if err != nil {
		fmt.Fprintln(deps.stderr, err)
		return runResult{status: 1}
	}
	return runResult{}
}

func captureResultError(r *Result, err error, live bool) error {
	r.ErrorStage = string(pkload.StageOf(err))
	if live {
		return redactLiveError(err)
	}
	return err
}

func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, make([]byte, 8<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// streaming decodes the key with one of gnark's own loaders from a 1 MiB
// buffered reader over the file, with no digest; trailing bytes are refused.
// MEASUREMENT ONLY: it is the baseline the pinned loaders are compared with,
// never a way to load a key for proving (the prove command uses pkload.Load).
func streaming(path string, f func(io.Reader, *groth16bn254.ProvingKey) error) (*groth16bn254.ProvingKey, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	br := bufio.NewReaderSize(fd, 1<<20)
	pk := new(groth16bn254.ProvingKey)
	if err := f(br, pk); err != nil {
		return nil, err
	}
	if n, _ := io.Copy(io.Discard, br); n != 0 {
		return nil, fmt.Errorf("%d trailing bytes", n)
	}
	return pk, nil
}

func load(r *Result, cse, path string, pin pkload.Pin) error {
	var pk *groth16bn254.ProvingKey
	var err error
	switch cse {
	case "readfrom", "unsafe", "readdump": // measurement-only baselines: no pin
		dec := map[string]func(io.Reader, *groth16bn254.ProvingKey) error{
			"readfrom": func(rd io.Reader, pk *groth16bn254.ProvingKey) error { _, err := pk.ReadFrom(rd); return err },
			"unsafe":   func(rd io.Reader, pk *groth16bn254.ProvingKey) error { _, err := pk.UnsafeReadFrom(rd); return err },
			"readdump": func(rd io.Reader, pk *groth16bn254.ProvingKey) error { return pk.ReadDump(rd) },
		}[cse]
		err = r.timed("load", func() (err error) { pk, err = streaming(path, dec); return })
	case "verified-raw", "verified-dump", "verified-image":
		r.Pin = &pin
		f := pkload.Format(strings.TrimPrefix(cse, "verified-"))
		var v *pkload.Verified
		if err = r.timed("read-and-hash", func() (err error) { v, r.Read, err = pkload.ReadVerified(path, pin); return }); err != nil {
			return err
		}
		err = r.timed("decode", func() (err error) { pk, r.Decode, err = pkload.Decode(f, v); return })
		v = nil
	default:
		return fmt.Errorf("unknown load case %q", cse)
	}
	if err != nil {
		return err
	}
	r.Shape = shapeOf(pk)
	runtime.KeepAlive(pk)
	return nil
}

func loadKey(r *Result, f pkload.Format, path string, pin pkload.Pin) (*groth16bn254.ProvingKey, error) {
	r.Pin = &pin
	var pk *groth16bn254.ProvingKey
	err := r.timed("load-pk", func() (err error) { pk, r.Read, r.Decode, err = pkload.Load(path, f, pin); return })
	if err != nil {
		return nil, err
	}
	r.Shape = shapeOf(pk)
	return pk, nil
}

func roundtrip(r *Result, f pkload.Format, path string, pin, raw pkload.Pin) error {
	if err := raw.Validate(); err != nil {
		return err
	}
	pk, err := loadKey(r, f, path, pin)
	if err != nil {
		return err
	}
	return r.timed("write-raw-and-hash", func() error {
		got, err := pkload.RawDigest(pk)
		r.RoundTrip = &RoundTrip{Raw: raw, Got: got, Matches: got == raw}
		if err == nil && got != raw {
			err = fmt.Errorf("WriteRawTo of the loaded key is %d bytes sha256 %s, the raw pin %d bytes sha256 %s", got.Bytes, got.SHA256, raw.Bytes, raw.SHA256)
		}
		return err
	})
}

// readPinnedStream decodes a small or checked file while hashing it and
// refuses it unless its length and SHA-256 equal pin.
func readPinnedStream(path string, pin pkload.Pin, dec func(io.Reader) error) error {
	if err := pin.Validate(); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return &pkload.Error{Stage: pkload.StageOpen, Err: err}
	}
	defer f.Close()
	h := sha256.New()
	var n int64
	cr := &countReader{r: io.TeeReader(f, h), n: &n}
	br := bufio.NewReaderSize(cr, 1<<20)
	if err := dec(br); err != nil {
		return err
	}
	if rest, err := io.Copy(io.Discard, br); err != nil || rest != 0 {
		return fmt.Errorf("%s: %d trailing bytes (%v)", path, rest, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); n != pin.Bytes || got != pin.SHA256 {
		return fmt.Errorf("%s is %d bytes sha256 %s, the pin says %d bytes sha256 %s", path, n, got, pin.Bytes, pin.SHA256)
	}
	return nil
}

type countReader struct {
	r io.Reader
	n *int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	*c.n += int64(n)
	return n, err
}

func prove(r *Result, t devprove.Target, f pkload.Format, keyPath string, pin pkload.Pin, r1csPath string, r1csPin pkload.Pin, vkPath string, vkPin pkload.Pin) error {
	return proveAssigned(r, t, nil, f, keyPath, pin, r1csPath, r1csPin, vkPath, vkPin)
}

func proveAssigned(r *Result, t devprove.Target, full witness.Witness, f pkload.Format, keyPath string, pin pkload.Pin, r1csPath string, r1csPin pkload.Pin, vkPath string, vkPin pkload.Pin) error {
	p := &ProveOut{R1CS: r1csPin, VK: vkPin, FlipIndex: t.FlipIndex, FlipNote: t.FlipNote}
	if r.Admission != nil {
		p.Witness = r.Admission.Source
	}
	r.Prove = p
	ccs := groth16.NewCS(ecc.BN254)
	if err := r.timed("load-r1cs", func() error {
		return readPinnedStream(r1csPath, r1csPin, func(rd io.Reader) error { _, err := ccs.ReadFrom(rd); return err })
	}); err != nil {
		return fmt.Errorf("r1cs: %w", err)
	}
	p.Constraints = ccs.GetNbConstraints()
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := r.timed("load-vk", func() error {
		return readPinnedStream(vkPath, vkPin, func(rd io.Reader) error { _, err := vk.ReadFrom(rd); return err })
	}); err != nil {
		return fmt.Errorf("verifying key: %w", err)
	}
	pk, err := loadKey(r, f, keyPath, pin)
	if err != nil {
		return err
	}
	// The verified buffer of a raw or dump load is garbage now; return it to
	// the OS before proving so the prove's peak is not stacked on it.
	if f != pkload.FormatImage {
		runtime.GC()
		debug.FreeOSMemory()
	}
	if full == nil {
		if err := r.timed("witness", func() error {
			a, src, err := t.Assignment()
			if err != nil {
				return err
			}
			p.Witness = src
			full, err = frontend.NewWitness(a, ecc.BN254.ScalarField())
			return err
		}); err != nil {
			return err
		}
	}
	var proof groth16.Proof
	if err := r.timed("prove", func() (err error) { proof, err = groth16.Prove(ccs, pk, full); return }); err != nil {
		if r.Admission != nil {
			return errors.New("live-request-proof-failed")
		}
		return err
	}
	runtime.KeepAlive(pk)
	// The proof leaves this function (into the result, a file or a caller)
	// only after it verifies under the pinned verifying key and is refused
	// against a flipped public input. A proof failing either check may carry
	// witness-dependent data from a bad key, so nothing of it is recorded:
	// not its bytes, its size or its digest (ENG-435 F3).
	pub, err := full.Public()
	if err != nil {
		return err
	}
	p.PublicInputs = len(pub.Vector().(fr.Vector))
	var verr error
	r.timed("verify", func() error { verr = groth16.Verify(proof, vk, pub); return nil })
	p.Verified = verr == nil
	if verr != nil {
		p.VerifyError = verr.Error()
	}
	flipped, _ := full.Public()
	vec := flipped.Vector().(fr.Vector)
	var b big.Int
	vec[p.FlipIndex].BigInt(&b)
	b.Xor(&b, big.NewInt(1))
	vec[p.FlipIndex].SetBigInt(&b)
	var ferr error
	r.timed("verify-flipped", func() error { ferr = groth16.Verify(proof, vk, flipped); return nil })
	p.FlippedRefused = ferr != nil
	if ferr != nil {
		p.FlippedError = ferr.Error()
	}
	switch {
	case !p.Verified:
		return fmt.Errorf("the proof does not verify under the pinned verifying key: %v; it is withheld", verr)
	case !p.FlippedRefused:
		return errors.New("the proof verifies against a flipped public input; it is withheld")
	}
	var pb bytes.Buffer
	if _, err := proof.WriteTo(&pb); err != nil {
		return err
	}
	d := sha256.Sum256(pb.Bytes())
	p.ProofBytes, p.ProofSHA256, p.ProofHex = pb.Len(), hex.EncodeToString(d[:]), hex.EncodeToString(pb.Bytes())
	return nil
}

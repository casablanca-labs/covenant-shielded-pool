// Command pool-action-circuit measures the pool action circuit.
//
// Compile only: no Setup, no proof, no key.
//
//	pool-action-circuit counts    OUT.json   constraints, variables, FFT domain, compile time and memory,
//	                                          vp topology, the vp shape vector and its profile_id, R1CS digest
//	pool-action-circuit attribute OUT.json   constraints per clause, from gnark's profiler
//
// Task 5.1b, under DEVELOPMENT ZERO-VALUE parameters (package devprove):
// gnark's groth16.Setup with its internal randomness, which nothing destroys,
// so the keys are forgeable and never guard value. Each command is its own
// process, so each phase's peak RSS is its own. DIR and OUT.json must lie
// outside any git work tree; nothing is overwritten.
//
//	pool-action-circuit devsetup  --expect-r1cs-sha256 HEX [--target T] DIR OUT.json
//	    compile, refuse unless the R1CS SHA-256 is HEX (no default), Setup, write R1CS, pk, vk, label
//	pool-action-circuit devprove  [--corpus FILE] [--target T] DIR OUT.json
//	    load R1CS and pk (timed), prove the corpus's reference host positive, write the proof
//	pool-action-circuit devverify [--corpus FILE] [--target T] DIR OUT.json
//	    verify the proof; the same proof against one flipped public input must be refused
//
// --target is action (the default) or small, a test circuit that is not the
// pool action circuit, for testing scripts/measure-5-1b.sh.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/bits"
	"os"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/profile"
	pprof "github.com/google/pprof/profile"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit/devprove"
)

const usage = `usage: pool-action-circuit counts|attribute OUT.json
       pool-action-circuit devsetup  --expect-r1cs-sha256 HEX [--target action|small] DIR OUT.json
       pool-action-circuit devprove  [--corpus FILE] [--target action|small] DIR OUT.json
       pool-action-circuit devverify [--corpus FILE] [--target action|small] DIR OUT.json`

func main() {
	start := time.Now()
	logger.Disable() // gnark logs to stdout; results go to the named file only
	if len(os.Args) >= 2 && strings.HasPrefix(os.Args[1], "dev") {
		os.Exit(dev(start, os.Args[1], os.Args[2:]))
	}
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var result any
	var err error
	switch os.Args[1] {
	case "counts":
		result, err = counts()
	case "attribute":
		result, err = attribute(os.Args[2] + ".pprof")
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(os.Args[2], append(b, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func maxRSS() int64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return -1
	}
	return ru.Maxrss // bytes on darwin
}

type pkFormula struct {
	Bytes        int64  `json:"bytes"`
	Wires        int    `json:"wires"`
	PrivateWires int    `json:"privateWires"`
	NonZeroA     int    `json:"wiresInA"`
	NonZeroB     int    `json:"wiresInB"`
	Note         string `json:"note"`
}

// structuralPK is the proving-key size formula of
// tools/apnt-child-circuits-cost/main.go (as the ARCH-141 memo used it). An
// estimate from the constraint system's structure, not a measured key.
func structuralPK(ccs constraint.ConstraintSystem, domain uint64) (pkFormula, error) {
	it, ok := ccs.(interface{ GetR1CIterator() constraint.R1CIterator })
	if !ok {
		return pkFormula{}, fmt.Errorf("no R1C iterator")
	}
	internal, secret, public := ccs.GetNbVariables()
	wires := internal + secret + public
	inA := make([]bool, wires)
	inB := make([]bool, wires)
	iter := it.GetR1CIterator()
	for c := iter.Next(); c != nil; c = iter.Next() {
		for _, t := range c.L {
			inA[t.WireID()] = true
		}
		for _, t := range c.R {
			inB[t.WireID()] = true
		}
	}
	nA, nB := 0, 0
	for i := 0; i < wires; i++ {
		if inA[i] {
			nA++
		}
		if inB[i] {
			nB++
		}
	}
	commitments := ccs.GetCommitments().(constraint.Groth16Commitments)
	privateCommitted := 0
	ckBytes := int64(0)
	for _, cm := range commitments {
		privateCommitted += len(cm.PrivateCommitted)
		ckBytes += 8 + 64*int64(len(cm.PrivateCommitted))
	}
	privateWires := internal + secret - privateCommitted - len(commitments)
	b := int64(441+2*wires) + 32*int64(nA+nB+int(domain)-1+privateWires) + 64*int64(nB) + ckBytes
	return pkFormula{b, wires, privateWires, nA, nB, "structural formula of tools/apnt-child-circuits-cost (ARCH-141); an estimate, no key exists"}, nil
}

type countsResult struct {
	Gnark              string                `json:"gnark"`
	GnarkCrypto        string                `json:"gnarkCrypto"`
	GoVersion          string                `json:"goVersion"`
	GOMAXPROCS         int                   `json:"gomaxprocs"`
	WorkingDirectory   string                `json:"workingDirectory"`
	Constraints        int                   `json:"constraints"`
	InternalVariables  int                   `json:"internalVariables"`
	SecretVariables    int                   `json:"secretVariables"`
	PublicVariables    int                   `json:"publicVariables"`
	FFTDomain          uint64                `json:"fftDomain"`
	FFTDomainLog2      int                   `json:"fftDomainLog2"`
	HeadroomToDomain   int                   `json:"constraintsBelowDomain"`
	NextLowerDomain    uint64                `json:"nextLowerDomain"`
	CompileSeconds     float64               `json:"compileSeconds"`
	HeapSysAfter       uint64                `json:"heapSysBytesAfterCompile"`
	TotalAllocCompile  uint64                `json:"totalAllocBytesDuringCompile"`
	MaxRSSAfterCompile int64                 `json:"maxRSSBytesAfterCompile"`
	R1CSSerialized     int64                 `json:"r1csSerializedBytes"`
	R1CSSha256         string                `json:"r1csSha256"`
	Topology           poolaction.VPTopology `json:"vpTopology"`
	ShapeVP            string                `json:"shapeVP"`
	ShapeProfileID     string                `json:"shapeProfileId"`
	PK                 pkFormula             `json:"provingKeyFormula"`
	MaxRSSEnd          int64                 `json:"maxRSSBytesAtEnd"`
	Notes              []string              `json:"notes"`
}

func counts() (*countsResult, error) {
	wd, _ := os.Getwd()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	ccs, err := poolaction.Compile()
	if err != nil {
		return nil, err
	}
	sec := time.Since(start).Seconds()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	rssCompile := maxRSS()
	internal, secret, public := ccs.GetNbVariables()
	n := ccs.GetNbConstraints()
	domain := fft.NewDomain(uint64(n)).Cardinality
	r := &countsResult{
		Gnark: poolaction.GnarkVersion, GnarkCrypto: poolaction.GnarkCryptoVersion, GoVersion: runtime.Version(), GOMAXPROCS: runtime.GOMAXPROCS(0), WorkingDirectory: wd,
		Constraints: n, InternalVariables: internal, SecretVariables: secret, PublicVariables: public,
		FFTDomain: domain, FFTDomainLog2: bits.Len64(domain) - 1, HeadroomToDomain: int(domain) - n, NextLowerDomain: domain / 2,
		CompileSeconds: sec, HeapSysAfter: after.HeapSys, TotalAllocCompile: after.TotalAlloc - before.TotalAlloc, MaxRSSAfterCompile: rssCompile,
	}
	h := sha256.New()
	nw, err := ccs.WriteTo(h)
	if err != nil {
		return nil, err
	}
	r.R1CSSerialized = nw
	r.R1CSSha256 = hex.EncodeToString(h.Sum(nil))
	if r.Topology, err = poolaction.Topology(ccs); err != nil {
		return nil, err
	}
	vp, err := poolaction.ShapeVP(r.Topology)
	if err != nil {
		return nil, err
	}
	r.ShapeVP = hex.EncodeToString(vp)
	id, err := poolaction.ProfileID(poolaction.SystemIDGnarkGroth16BN254, vp)
	if err != nil {
		return nil, err
	}
	r.ShapeProfileID = hex.EncodeToString(id)
	if r.PK, err = structuralPK(ccs, domain); err != nil {
		return nil, err
	}
	r.MaxRSSEnd = maxRSS()
	r.Notes = []string{
		"compile only: no Setup, no proving key, no proof",
		"shapeVP is a serialization shape vector built from hash-to-curve points, NOT a verifying key; its profile id must never be allowlisted",
		"maxRSS is the process high-water mark (getrusage), including the R1CS serialization and PK-formula passes for maxRSSBytesAtEnd",
	}
	return r, nil
}

// ---- attribution ----

type block struct {
	Block       string `json:"block"`
	Constraints int64  `json:"constraints"`
	OfWhichSHA  int64  `json:"ofWhichSha256Permute"`
}

type attribution struct {
	Constraints int     `json:"constraints"`
	Profiled    int64   `json:"profiledConstraints"`
	Blocks      []block `json:"blocks"`
	Note        string  `json:"note"`
}

// blockOf names the outermost clause frame of a sample's stack.
func blockOf(stack []string) string {
	for i := len(stack) - 1; i >= 0; i-- { // outermost first
		f := stack[i]
		if j := strings.Index(f, "(*action)."); j >= 0 {
			return strings.TrimSuffix(f[j+len("(*action)."):], "-fm")
		}
	}
	return "deferred and gadget setup (lookup and range-check arguments, emulated-field checks, tables)"
}

func attribute(pprofPath string) (*attribution, error) {
	p := profile.Start(profile.WithPath(pprofPath))
	ccs, err := poolaction.Compile()
	p.Stop()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(pprofPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	prof, err := pprof.Parse(io.Reader(f))
	if err != nil {
		return nil, err
	}
	agg := map[string]*block{}
	var total int64
	for _, s := range prof.Sample {
		if len(s.Value) == 0 || s.Value[0] == 0 {
			continue
		}
		var stack []string
		sha := false
		for _, loc := range s.Location {
			for _, ln := range loc.Line {
				name := ln.Function.Name
				stack = append(stack, name)
				if strings.Contains(name, "permutation/sha2.Permute") {
					sha = true
				}
			}
		}
		b := blockOf(stack)
		if agg[b] == nil {
			agg[b] = &block{Block: b}
		}
		agg[b].Constraints += s.Value[0]
		if sha {
			agg[b].OfWhichSHA += s.Value[0]
		}
		total += s.Value[0]
	}
	out := &attribution{Constraints: ccs.GetNbConstraints(), Profiled: total,
		Note: "gnark profiler samples attributed to the outermost clause method on their stack; constraints emitted by deferred callbacks at compile end carry no clause frame"}
	for _, b := range agg {
		out.Blocks = append(out.Blocks, *b)
	}
	sort.Slice(out.Blocks, func(i, j int) bool { return out.Blocks[i].Constraints > out.Blocks[j].Constraints })
	return out, nil
}

// ---- task 5.1b, development zero-value parameters ----

// defaultCorpus is the host's parity corpus, relative to this module.
const defaultCorpus = "../../packages/protocol-runtime/test-vectors/apnt-pool-v1-action-circuit-vectors.json"

type devResult interface {
	Finish(time.Time)
	Fail(error)
}

func dev(start time.Time, cmd string, args []string) int {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	target := fs.String("target", "action", "action, or small: a test circuit that is not the pool action circuit")
	var expect, corpus *string
	switch cmd {
	case "devsetup":
		expect = fs.String("expect-r1cs-sha256", "", "the R1CS SHA-256 Setup requires (no default)")
	case "devprove", "devverify":
		corpus = fs.String("corpus", defaultCorpus, "the action-circuit parity corpus")
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s\n", cmd, usage)
		return 2
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	dir, out := fs.Arg(0), fs.Arg(1)
	if _, err := devprove.OutsideRepository(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "refusing %s: it exists; results are never overwritten\n", out)
		return 1
	}
	var t devprove.Target
	switch *target {
	case "action":
		c := defaultCorpus
		if corpus != nil {
			c = *corpus
		}
		t = devprove.ActionTarget(c)
	case "small":
		t = devprove.SmallTarget(devprove.SmallRounds)
	default:
		fmt.Fprintf(os.Stderr, "unknown target %q\n", *target)
		return 2
	}

	var r devResult
	var err error
	switch cmd {
	case "devsetup":
		var s *devprove.SetupResult
		if s, err = devprove.Setup(t, dir, *expect); s != nil {
			r = s
		}
	case "devprove":
		var p *devprove.ProveResult
		if p, err = devprove.Prove(t, dir); p != nil {
			r = p
		}
	case "devverify":
		var v *devprove.VerifyResult
		if v, err = devprove.Verify(t, dir); v != nil {
			r = v
		}
	}
	if r != nil {
		r.Finish(start)
		r.Fail(err)
		b, _ := json.MarshalIndent(r, "", "  ")
		f, werr := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if werr == nil {
			_, werr = f.Write(append(b, '\n'))
			if cerr := f.Close(); werr == nil {
				werr = cerr
			}
		}
		if werr != nil {
			fmt.Fprintln(os.Stderr, werr)
			return 1
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

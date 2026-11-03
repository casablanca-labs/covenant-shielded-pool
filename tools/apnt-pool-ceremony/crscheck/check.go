package crscheck

import (
	"fmt"
	"math/bits"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
)

// Check names. Result.ZK marks the checks the prover's zero knowledge needs;
// the verdict is decided by those alone.
const (
	// Phase 1, checked once per plan.
	CheckSRSPowers = "SRS_POWERS"        // [τⁱ]₁ geometric with the ratio of [τ]₂, [τ⁰]₁ = g₁, τ ≠ 0
	CheckTauDomain = "TAU_NOT_IN_DOMAIN" // t(τ) = τⁿ − 1 ≠ 0 (Fuchsbauer check 2)

	// The key.
	CheckShape      = "KEY_SHAPE"               // vector lengths, infinity flags, commitment layout
	CheckDomain     = "PK_DOMAIN"               // the FFT domain the prover divides by t(X) on
	CheckNonZero    = "NONZERO"                 // α, β (G1, G2), δ (G1, G2), γ, Pedersen G
	CheckBeta       = "BETA_G1_G2"              // e([β]₁, g₂) = e(g₁, [β]₂)
	CheckDelta      = "DELTA_G1_G2"             // e([δ]₁, g₂) = e(g₁, [δ]₂)
	CheckAQuery     = "A_QUERY"                 // A[j] = [uⱼ(τ)]₁, infinity flags included
	CheckBQueryG1   = "B_QUERY_G1"              // B[j] = [vⱼ(τ)]₁
	CheckBQueryG2   = "B_QUERY_G2"              // B₂[j] = [vⱼ(τ)]₂
	CheckKQuery     = "K_QUERY"                 // K[j] = [(βuⱼ + αvⱼ + wⱼ)(τ)/δ]₁, private wires
	CheckZQuery     = "Z_QUERY"                 // Z[i] = [τ^rev(i)·t(τ)/δ]₁, gnark's bit-reversed order
	CheckCommitBase = "COMMITMENT_BASIS"        // Basis[j] = [(βuⱼ + αvⱼ + wⱼ)(τ)/γ]₁, committed wires
	CheckCommitSig  = "COMMITMENT_SIGMA"        // BasisExpSigma = σ·Basis for the vk's [σ]₂
	CheckCommitMask = "COMMITMENT_MASK_NONZERO" // the random mask's basis element ≠ O (its origin: CheckMaskOrigin)
	CheckVKK        = "VK_K"                    // vk.K[j] = [(βuⱼ + αvⱼ + wⱼ)(τ)/γ]₁: soundness and completeness
	CheckVKMatch    = "VK_MATCHES_PK"           // vk α, β, δ equal the pk's: completeness
	CheckPhase1     = "PHASE1_ALPHA_BETA"       // pk α, β equal phase 1's: provenance only
)

// GnarkVersion and GnarkCryptoVersion are the gnark releases whose Groth16
// prover, setup and key layout this check was written against (the mask
// constraint, the wire classes, the bit-reversed Z order). A key from another
// gnark needs the analysis redone; the release gate (package release)
// refuses one, and refuses a checker build that links other versions.
const (
	GnarkVersion       = "v0.16.3"
	GnarkCryptoVersion = "v0.21.0"
)

// Verdicts.
const (
	VerdictWellFormed = "WELL-FORMED"
	VerdictMalformed  = "MALFORMED"
)

// Result is one check's outcome.
type Result struct {
	Name   string `json:"name"`
	ZK     bool   `json:"zk"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

// Report is the outcome of checking one key against a plan.
type Report struct {
	Verdict string   `json:"verdict"`
	Failed  []string `json:"failed"`
	Results []Result `json:"results"`
	// Seconds per stage of CheckKey.
	Seconds map[string]float64 `json:"seconds"`
}

// Options tune Prepare.
type Options struct {
	// SkipSRSPowers skips the phase-1 self-check (SRS_POWERS), for an SRS
	// already validated by other means; the verdict then says so.
	SkipSRSPowers bool
}

// Plan is the key-independent half of the check for one R1CS and one SRS:
// random weights and the phase-1 side of every equation. The weights are
// drawn from crypto/rand when the plan is made and never leave it, so a key
// fixed before Prepare runs cannot depend on them.
type Plan struct {
	l       *layout
	n       int
	x, y    fr.Element     // wire weights ρⱼ = xʲ; Z weights yⁱ
	alpha1  curve.G1Affine // phase 1's, for CheckPhase1
	beta1   curve.G1Affine
	beta2   curve.G2Affine
	sA, sB  curve.G1Affine // Σⱼ ρⱼ[uⱼ(τ)]₁, Σⱼ ρⱼ[vⱼ(τ)]₁
	sWPriv  curve.G1Affine // Σ_{j private} ρⱼ[wⱼ(τ)]₁
	sWVK    curve.G1Affine // Σ_{j public or commitment wire} ρⱼ[wⱼ(τ)]₁
	sWComm  []curve.G1Affine
	sZ      curve.G1Affine // Σᵢ yⁱ[τ^rev(i)·t(τ)]₁
	results []Result
	Seconds map[string]float64
	// NbCommitted and Masks describe the R1CS's commitments, for reports.
	NbCommitted []int
	Masks       [][]int
}

func msmG1(points []curve.G1Affine, scalars []fr.Element) (curve.G1Affine, error) {
	var r curve.G1Affine
	if len(points) != len(scalars) {
		return r, fmt.Errorf("MSM: %d points, %d scalars", len(points), len(scalars))
	}
	if len(points) == 0 {
		return r, nil
	}
	_, err := r.MultiExp(points, scalars, ecc.MultiExpConfig{NbTasks: runtime.GOMAXPROCS(0)})
	return r, err
}

func msmG2(points []curve.G2Affine, scalars []fr.Element) (curve.G2Affine, error) {
	var r curve.G2Affine
	if len(points) != len(scalars) {
		return r, fmt.Errorf("MSM: %d points, %d scalars", len(points), len(scalars))
	}
	if len(points) == 0 {
		return r, nil
	}
	_, err := r.MultiExp(points, scalars, ecc.MultiExpConfig{NbTasks: runtime.GOMAXPROCS(0)})
	return r, err
}

// pairingOne reports whether Πᵢ e(pᵢ, qᵢ) = 1.
func pairingOne(p []curve.G1Affine, q []curve.G2Affine) bool {
	ok, err := curve.PairingCheck(p, q)
	return err == nil && ok
}

func neg1(p curve.G1Affine) curve.G1Affine {
	var r curve.G1Affine
	r.Neg(&p)
	return r
}

func randomFr() (fr.Element, error) {
	var e fr.Element
	for e.IsZero() {
		if _, err := e.SetRandom(); err != nil {
			return e, err
		}
	}
	return e, nil
}

func bitRev(i uint64, logN int) uint64 { return bits.Reverse64(i) >> (64 - logN) }

// Prepare builds the plan: it classifies the wires, draws the weights,
// accumulates the constraint sums, moves them to the monomial basis with one
// inverse FFT each, and computes the phase-1 side of every equation as one
// MSM over [τᵏ]₁ each. The R1CS and the SRS are not referenced afterwards.
func Prepare(r *cs.R1CS, srs *SRS, opt Options) (*Plan, error) {
	sec := map[string]float64{}
	lap := func(k string, t time.Time) { sec[k] += time.Since(t).Seconds() }
	t0 := time.Now()
	l, err := newLayout(r)
	if err != nil {
		return nil, err
	}
	n := l.domain
	if srs.N != n || len(srs.TauG1) != 2*n-1 {
		return nil, fmt.Errorf("SRS is for domain %d (%d G1 powers); the R1CS needs %d", srs.N, len(srs.TauG1), n)
	}
	p := &Plan{l: l, n: n, Seconds: sec}
	if p.x, err = randomFr(); err != nil {
		return nil, err
	}
	if p.y, err = randomFr(); err != nil {
		return nil, err
	}
	p.alpha1, p.beta1, p.beta2 = srs.Alpha1, srs.Beta1, srs.Beta2
	lap("layout", t0)

	t0 = time.Now()
	sums, err := l.accumulate(r, powers(p.x, l.nbWires))
	if err != nil {
		return nil, err
	}
	lap("constraintSums", t0)
	for _, c := range l.committed {
		p.NbCommitted = append(p.NbCommitted, len(c))
	}
	p.Masks = l.masks

	// The masks' origin and the schedule the prover runs (origin.go).
	t0 = time.Now()
	origin := originResults(r, l.committed, l.masks)
	lap("maskOrigin", t0)

	domain := fft.NewDomain(uint64(n))
	tauN := srs.TauG1[:n]
	toMonomial := func(v []fr.Element) {
		domain.FFTInverse(v, fft.DIF)
		fft.BitReverse(v)
	}
	vecs := []*[]fr.Element{&sums.u, &sums.v, &sums.wPriv, &sums.wVK}
	dsts := []*curve.G1Affine{&p.sA, &p.sB, &p.sWPriv, &p.sWVK}
	p.sWComm = make([]curve.G1Affine, len(sums.wComm))
	for k := range sums.wComm {
		vecs = append(vecs, &sums.wComm[k])
		dsts = append(dsts, &p.sWComm[k])
	}
	for i, v := range vecs {
		t1 := time.Now()
		toMonomial(*v)
		lap("ifft", t1)
		t1 = time.Now()
		if *dsts[i], err = msmG1(tauN, *v); err != nil {
			return nil, err
		}
		*v = nil
		lap("srsMSM", t1)
	}

	// Z: Σ_{i<n−1} yⁱ·([τ^(rev(i)+n)]₁ − [τ^rev(i)]₁).
	t0 = time.Now()
	logN := bits.TrailingZeros(uint(n))
	sz := make([]fr.Element, 2*n-1)
	var yi fr.Element
	yi.SetOne()
	for i := 0; i < n-1; i++ {
		k := int(bitRev(uint64(i), logN))
		sz[k+n].Add(&sz[k+n], &yi)
		sz[k].Sub(&sz[k], &yi)
		yi.Mul(&yi, &p.y)
	}
	if p.sZ, err = msmG1(srs.TauG1, sz); err != nil {
		return nil, err
	}
	sz = nil
	lap("srsMSM", t0)

	_, _, g1, g2 := curve.Generators()
	if opt.SkipSRSPowers {
		p.results = append(p.results, Result{Name: CheckSRSPowers, ZK: true, Pass: false, Detail: "skipped: the SRS was not self-checked in this run"})
	} else {
		t0 = time.Now()
		p.results = append(p.results, checkSRSPowers(srs, g1, g2))
		lap("srsPowers", t0)
	}
	res := Result{Name: CheckTauDomain, ZK: true, Pass: !srs.TauG1[n].Equal(&g1)}
	if !res.Pass {
		res.Detail = "[τⁿ]₁ = [1]₁: τ is in the FFT domain, so t(τ) = 0, every Z element is zero, and every Lagrange basis polynomial but one vanishes at τ"
	}
	p.results = append(p.results, res)
	p.results = append(p.results, origin...)
	return p, nil
}

// checkSRSPowers establishes [τᵏ]₁ = τᵏ·g₁ for k < 2n−1 with τ the logarithm
// of [τ]₂: [τ⁰]₁ = g₁, e([τ]₁, g₂) = e(g₁, [τ]₂), and for random z,
// e(Σ zᵏ[τ^(k+1)]₁, g₂) = e(Σ zᵏ[τᵏ]₁, [τ]₂). τ ≠ 0 because [τ]₁ ≠ O.
func checkSRSPowers(srs *SRS, g1 curve.G1Affine, g2 curve.G2Affine) Result {
	res := Result{Name: CheckSRSPowers, ZK: true}
	fail := func(d string) Result { res.Detail = d; return res }
	t := srs.TauG1
	if !t[0].Equal(&g1) {
		return fail("[τ⁰]₁ is not the generator")
	}
	if t[1].IsInfinity() {
		return fail("[τ]₁ = O")
	}
	// Implied by the geometric check below with [τ⁰]₁ = g₁; kept as a direct
	// check with its own message.
	if !pairingOne([]curve.G1Affine{t[1], neg1(g1)}, []curve.G2Affine{g2, srs.Tau2}) {
		return fail("[τ]₁ and [τ]₂ disagree")
	}
	z, err := randomFr()
	if err != nil {
		return fail(err.Error())
	}
	zp := powers(z, len(t)-1)
	hi, err := msmG1(t[1:], zp)
	if err != nil {
		return fail(err.Error())
	}
	lo, err := msmG1(t[:len(t)-1], zp)
	if err != nil {
		return fail(err.Error())
	}
	if !pairingOne([]curve.G1Affine{hi, neg1(lo)}, []curve.G2Affine{g2, srs.Tau2}) {
		return fail("the [τᵏ]₁ are not a geometric sequence with ratio τ")
	}
	res.Pass = true
	return res
}

// keySide are the key's multi-scalar sums, split by wire class where an
// equation needs one class only.
type keySide struct {
	aPriv, aVK, aAll curve.G1Affine
	aComm            []curve.G1Affine
	b1All            curve.G1Affine
	b2Priv, b2VK     curve.G2Affine
	b2All            curve.G2Affine
	b2Comm           []curve.G2Affine
}

func checkShape(l *layout, pk *groth16bn254.ProvingKey, vk *groth16bn254.VerifyingKey, n int) []string {
	var bad []string
	f := func(ok bool, format string, a ...any) {
		if !ok {
			bad = append(bad, fmt.Sprintf(format, a...))
		}
	}
	m := l.nbWires
	f(len(pk.InfinityA) == m && len(pk.InfinityB) == m, "infinity flags cover %d/%d wires, want %d", len(pk.InfinityA), len(pk.InfinityB), m)
	count := func(b []bool) (c int) {
		for _, v := range b {
			if v {
				c++
			}
		}
		return
	}
	ia, ib := count(pk.InfinityA), count(pk.InfinityB)
	f(uint64(ia) == pk.NbInfinityA && uint64(ib) == pk.NbInfinityB, "infinity counts %d/%d disagree with flags %d/%d", pk.NbInfinityA, pk.NbInfinityB, ia, ib)
	f(len(pk.G1.A) == m-ia, "len(A) = %d, want %d", len(pk.G1.A), m-ia)
	f(len(pk.G1.B) == m-ib && len(pk.G2.B) == m-ib, "len(B₁), len(B₂) = %d, %d, want %d", len(pk.G1.B), len(pk.G2.B), m-ib)
	f(len(pk.G1.K) == len(l.priv), "len(K) = %d, want %d private wires", len(pk.G1.K), len(l.priv))
	f(len(pk.G1.Z) == n-1, "len(Z) = %d, want %d", len(pk.G1.Z), n-1)
	f(len(vk.G1.K) == len(l.vkWires), "len(vk.K) = %d, want %d", len(vk.G1.K), len(l.vkWires))
	f(len(pk.CommitmentKeys) == len(l.committed) && len(vk.CommitmentKeys) == len(l.committed), "%d/%d commitment keys, want %d", len(pk.CommitmentKeys), len(vk.CommitmentKeys), len(l.committed))
	if len(pk.CommitmentKeys) == len(l.committed) {
		for k, c := range l.committed {
			ck := pk.CommitmentKeys[k]
			f(len(ck.Basis) == len(c) && len(ck.BasisExpSigma) == len(c), "commitment %d: basis %d, basis·σ %d, want %d", k, len(ck.Basis), len(ck.BasisExpSigma), len(c))
		}
	}
	same := len(vk.PublicAndCommitmentCommitted) == len(l.publicAndCommitmentCommitted)
	for i := 0; same && i < len(vk.PublicAndCommitmentCommitted); i++ {
		a, b := vk.PublicAndCommitmentCommitted[i], l.publicAndCommitmentCommitted[i]
		same = len(a) == len(b)
		for j := 0; same && j < len(a); j++ {
			same = a[j] == b[j]
		}
	}
	f(same, "vk public-and-commitment-committed indexes differ from the R1CS's")
	return bad
}

func checkDomain(d *fft.Domain, n int) string {
	want := fft.NewDomain(uint64(n), fft.WithoutPrecompute())
	var bad []string
	if d.Cardinality != want.Cardinality {
		bad = append(bad, "cardinality")
	}
	for _, c := range []struct {
		name      string
		got, want fr.Element
	}{
		{"cardinality inverse", d.CardinalityInv, want.CardinalityInv},
		{"generator", d.Generator, want.Generator},
		{"generator inverse", d.GeneratorInv, want.GeneratorInv},
		{"coset generator", d.FrMultiplicativeGen, want.FrMultiplicativeGen},
		{"coset generator inverse", d.FrMultiplicativeGenInv, want.FrMultiplicativeGenInv},
	} {
		if !c.got.Equal(&c.want) {
			bad = append(bad, c.name)
		}
	}
	return strings.Join(bad, ", ")
}

// CheckKey checks one key against the plan. It never modifies pk or vk.
func (p *Plan) CheckKey(pk *groth16bn254.ProvingKey, vk *groth16bn254.VerifyingKey) (*Report, error) {
	rep := &Report{Seconds: map[string]float64{}}
	lap := func(k string, t time.Time) { rep.Seconds[k] += time.Since(t).Seconds() }
	t0 := time.Now()
	l := p.l
	rep.Results = append(rep.Results, p.results...)
	add := func(r Result) { rep.Results = append(rep.Results, r) }
	defer func() {
		rep.Verdict = VerdictWellFormed
		for _, r := range rep.Results {
			if r.ZK && !r.Pass {
				rep.Verdict = VerdictMalformed
				rep.Failed = append(rep.Failed, r.Name)
			}
		}
	}()

	if bad := checkShape(l, pk, vk, p.n); len(bad) > 0 {
		add(Result{Name: CheckShape, ZK: true, Detail: strings.Join(bad, "; ")})
		return rep, nil // the equations below index by this layout
	}
	add(Result{Name: CheckShape, ZK: true, Pass: true})
	if bad := checkDomain(&pk.Domain, p.n); bad != "" {
		add(Result{Name: CheckDomain, ZK: true, Detail: "differs from the canonical domain in: " + bad})
	} else {
		add(Result{Name: CheckDomain, ZK: true, Pass: true})
	}

	_, _, g1, g2 := curve.Generators()
	var zero []string
	for name, isInf := range map[string]bool{
		"[α]₁": pk.G1.Alpha.IsInfinity(), "[β]₁": pk.G1.Beta.IsInfinity(), "[β]₂": pk.G2.Beta.IsInfinity(),
		"[δ]₁": pk.G1.Delta.IsInfinity(), "[δ]₂": pk.G2.Delta.IsInfinity(), "[γ]₂": vk.G2.Gamma.IsInfinity(),
	} {
		if isInf {
			zero = append(zero, name)
		}
	}
	for k := range vk.CommitmentKeys {
		if vk.CommitmentKeys[k].G.IsInfinity() {
			zero = append(zero, fmt.Sprintf("Pedersen G[%d]", k))
		}
	}
	if len(zero) > 0 {
		slices.Sort(zero)
		add(Result{Name: CheckNonZero, ZK: true, Detail: "zero: " + strings.Join(zero, ", ")})
	} else {
		add(Result{Name: CheckNonZero, ZK: true, Pass: true})
	}
	add(Result{Name: CheckBeta, ZK: true, Pass: pairingOne([]curve.G1Affine{pk.G1.Beta, neg1(g1)}, []curve.G2Affine{g2, pk.G2.Beta})})
	add(Result{Name: CheckDelta, ZK: true, Pass: pairingOne([]curve.G1Affine{pk.G1.Delta, neg1(g1)}, []curve.G2Affine{g2, pk.G2.Delta})})
	lap("scalarChecks", t0)

	t0 = time.Now()
	rho := powers(p.x, l.nbWires)
	ks, err := p.keySums(pk, rho)
	if err != nil {
		return nil, err
	}
	lap("keyQueryMSM", t0)

	t0 = time.Now()
	add(Result{Name: CheckAQuery, ZK: true, Pass: ks.aAll.Equal(&p.sA)})
	add(Result{Name: CheckBQueryG1, ZK: true, Pass: ks.b1All.Equal(&p.sB)})
	add(Result{Name: CheckBQueryG2, ZK: true, Pass: pairingOne([]curve.G1Affine{ks.b1All, neg1(g1)}, []curve.G2Affine{g2, ks.b2All})})

	kScal := make([]fr.Element, len(l.priv))
	for i, j := range l.priv {
		kScal[i] = rho[j]
	}
	kSum, err := msmG1(pk.G1.K, kScal)
	if err != nil {
		return nil, err
	}
	kScal = nil
	alphaNeg := neg1(pk.G1.Alpha)
	add(Result{Name: CheckKQuery, ZK: true, Pass: pairingOne(
		[]curve.G1Affine{kSum, neg1(ks.aPriv), alphaNeg, neg1(p.sWPriv)},
		[]curve.G2Affine{pk.G2.Delta, pk.G2.Beta, ks.b2Priv, g2})})

	zScal := powers(p.y, len(pk.G1.Z))
	zSum, err := msmG1(pk.G1.Z, zScal)
	if err != nil {
		return nil, err
	}
	zScal = nil
	add(Result{Name: CheckZQuery, ZK: true, Pass: pairingOne(
		[]curve.G1Affine{zSum, neg1(p.sZ)}, []curve.G2Affine{pk.G2.Delta, g2})})

	for k, c := range l.committed {
		ck, vck := pk.CommitmentKeys[k], vk.CommitmentKeys[k]
		sc := make([]fr.Element, len(c))
		for i, j := range c {
			sc[i] = rho[j]
		}
		basis, err := msmG1(ck.Basis, sc)
		if err != nil {
			return nil, err
		}
		bes, err := msmG1(ck.BasisExpSigma, sc)
		if err != nil {
			return nil, err
		}
		tag := fmt.Sprintf("commitment %d", k)
		r := Result{Name: CheckCommitBase, ZK: true, Detail: tag, Pass: pairingOne(
			[]curve.G1Affine{basis, neg1(ks.aComm[k]), alphaNeg, neg1(p.sWComm[k])},
			[]curve.G2Affine{vk.G2.Gamma, pk.G2.Beta, ks.b2Comm[k], g2})}
		add(r)
		add(Result{Name: CheckCommitSig, ZK: true, Detail: tag, Pass: pairingOne(
			[]curve.G1Affine{bes, basis}, []curve.G2Affine{vck.G, vck.GSigmaNeg})})
		mr := Result{Name: CheckCommitMask, ZK: true, Pass: len(l.masks[k]) > 0}
		if len(l.masks[k]) == 0 {
			mr.Detail = tag + ": no committed wire w with a constraint w·1 = w, so no mask was found"
		}
		for _, m := range l.masks[k] {
			if ck.Basis[m].IsInfinity() {
				mr.Pass = false
				mr.Detail = fmt.Sprintf("%s: the mask's basis element (committed position %d of %d) is O, so the commitment is a deterministic function of the committed private values", tag, m, len(c))
			}
		}
		if mr.Pass {
			mr.Detail = fmt.Sprintf("%s: mask at committed position(s) %v of %d", tag, l.masks[k], len(c))
		}
		add(mr)
	}

	vkScal := make([]fr.Element, len(l.vkWires))
	for i, j := range l.vkWires {
		vkScal[i] = rho[j]
	}
	vkSum, err := msmG1(vk.G1.K, vkScal)
	if err != nil {
		return nil, err
	}
	add(Result{Name: CheckVKK, Pass: pairingOne(
		[]curve.G1Affine{vkSum, neg1(ks.aVK), alphaNeg, neg1(p.sWVK)},
		[]curve.G2Affine{vk.G2.Gamma, pk.G2.Beta, ks.b2VK, g2})})
	add(Result{Name: CheckVKMatch, Pass: vk.G1.Alpha.Equal(&pk.G1.Alpha) && vk.G1.Beta.Equal(&pk.G1.Beta) &&
		vk.G1.Delta.Equal(&pk.G1.Delta) && vk.G2.Beta.Equal(&pk.G2.Beta) && vk.G2.Delta.Equal(&pk.G2.Delta)})
	add(Result{Name: CheckPhase1, Pass: pk.G1.Alpha.Equal(&p.alpha1) && pk.G1.Beta.Equal(&p.beta1) && pk.G2.Beta.Equal(&p.beta2)})
	lap("equations", t0)
	return rep, nil
}

// keySums computes the A, B₁ and B₂ query sums with weights ρ, following the
// infinity flags (a flagged wire has no point in the vector).
func (p *Plan) keySums(pk *groth16bn254.ProvingKey, rho []fr.Element) (*keySide, error) {
	l := p.l
	nc := len(l.committed)
	ks := &keySide{aComm: make([]curve.G1Affine, nc), b2Comm: make([]curve.G2Affine, nc)}
	// A: private wires by a zero-padded MSM over the whole vector, the other
	// classes by gathering their (few) points.
	aPriv := make([]fr.Element, len(pk.G1.A))
	var aVKp []curve.G1Affine
	var aVKs []fr.Element
	aCp := make([][]curve.G1Affine, nc)
	aCs := make([][]fr.Element, nc)
	idx := 0
	for j := 0; j < l.nbWires; j++ {
		if pk.InfinityA[j] {
			continue
		}
		switch l.class[j] {
		case classPrivate:
			aPriv[idx] = rho[j]
		case classPublic, classCommitmentWire:
			aVKp, aVKs = append(aVKp, pk.G1.A[idx]), append(aVKs, rho[j])
		default:
			k := l.commitOf[j]
			aCp[k], aCs[k] = append(aCp[k], pk.G1.A[idx]), append(aCs[k], rho[j])
		}
		idx++
	}
	var err error
	if ks.aPriv, err = msmG1(pk.G1.A, aPriv); err != nil {
		return nil, err
	}
	aPriv = nil
	if ks.aVK, err = msmG1(aVKp, aVKs); err != nil {
		return nil, err
	}
	ks.aAll.Add(&ks.aPriv, &ks.aVK)
	for k := 0; k < nc; k++ {
		if ks.aComm[k], err = msmG1(aCp[k], aCs[k]); err != nil {
			return nil, err
		}
		ks.aAll.Add(&ks.aAll, &ks.aComm[k])
	}

	// B: B₁ over all wires; B₂ split by class like A.
	bAll := make([]fr.Element, len(pk.G1.B))
	bPriv := make([]fr.Element, len(pk.G2.B))
	var bVKp []curve.G2Affine
	var bVKs []fr.Element
	bCp := make([][]curve.G2Affine, nc)
	bCs := make([][]fr.Element, nc)
	idx = 0
	for j := 0; j < l.nbWires; j++ {
		if pk.InfinityB[j] {
			continue
		}
		bAll[idx] = rho[j]
		switch l.class[j] {
		case classPrivate:
			bPriv[idx] = rho[j]
		case classPublic, classCommitmentWire:
			bVKp, bVKs = append(bVKp, pk.G2.B[idx]), append(bVKs, rho[j])
		default:
			k := l.commitOf[j]
			bCp[k], bCs[k] = append(bCp[k], pk.G2.B[idx]), append(bCs[k], rho[j])
		}
		idx++
	}
	if ks.b1All, err = msmG1(pk.G1.B, bAll); err != nil {
		return nil, err
	}
	bAll = nil
	if ks.b2Priv, err = msmG2(pk.G2.B, bPriv); err != nil {
		return nil, err
	}
	bPriv = nil
	if ks.b2VK, err = msmG2(bVKp, bVKs); err != nil {
		return nil, err
	}
	ks.b2All.Add(&ks.b2Priv, &ks.b2VK)
	for k := 0; k < nc; k++ {
		if ks.b2Comm[k], err = msmG2(bCp[k], bCs[k]); err != nil {
			return nil, err
		}
		ks.b2All.Add(&ks.b2All, &ks.b2Comm[k])
	}
	return ks, nil
}

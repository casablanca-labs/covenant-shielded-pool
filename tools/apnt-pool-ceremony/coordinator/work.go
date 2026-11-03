package coordinator

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// Work files let each phase of a ceremony run as its own process, so no
// process holds the phase-1 parameters, the evaluations and a phase-2 state
// longer than its own step needs. New writes the initial state and gnark's
// phase-2 evaluations to a work directory; Open resumes from there and from
// the ceremony directory.
//
// They are the coordinator's own working state, not part of the published
// transcript. The standalone verifier never reads them: it re-derives the
// initial state and the evaluations from the phase-1 file and the R1CS. A
// damaged or edited work file can stall a ceremony, or make the sealed keys
// disagree with the verifier's (SEALED_KEY_MISMATCH), but cannot make a
// transcript verify.
const (
	WorkFormat          = "apnt-pool-ceremony-work/v1"
	WorkFile            = "work.json"
	InitialStateFile    = "phase2-0000.bin"
	EvaluationsFile     = "evaluations.bin"
	EvaluationsEncoding = "apnt-pool-ceremony-evaluations/v1"
	WorkNotice          = "Coordinator working state of an open ceremony. Not part of the published transcript; " +
		"the standalone verifier never reads it and re-derives everything it holds."

	evaluationsMagic = "APNTEVL1"
)

// WorkFileRef is one work file and its digest.
type WorkFileRef struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Length int64  `json:"length"`
}

// WorkRecord binds a work directory to one ceremony.
type WorkRecord struct {
	Format             string      `json:"format"`
	Notice             string      `json:"notice"`
	CeremonyID         string      `json:"ceremonyId"`
	RootChallenge      string      `json:"rootChallenge"`
	R1CSSHA256         string      `json:"r1csSha256"`
	CommonsSHA256      string      `json:"phase1CommonsSha256"`
	InitialState       WorkFileRef `json:"initialState"`
	Evaluations        WorkFileRef `json:"evaluations"`
	EvaluationsEncoded string      `json:"evaluationsEncoding"`
}

// hashingFile writes a file while hashing it.
type hashingFile struct {
	f   *os.File
	buf *bufio.Writer
	h   io.Writer
	sum func() string
	n   int64
}

func createHashed(path string) (*hashingFile, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, failure.Wrap(failure.IO, err, "creating %s", path)
	}
	h := sha256.New()
	return &hashingFile{f: f, buf: bufio.NewWriterSize(io.MultiWriter(f, h), 1<<20), h: h,
		sum: func() string { return hex.EncodeToString(h.Sum(nil)) }}, nil
}

func (w *hashingFile) Write(p []byte) (int, error) {
	n, err := w.buf.Write(p)
	w.n += int64(n)
	return n, err
}

// close flushes and closes the file and returns its digest and length.
func (w *hashingFile) close() (string, int64, error) {
	err := w.buf.Flush()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", 0, failure.Wrap(failure.IO, err, "writing %s", w.f.Name())
	}
	return w.sum(), w.n, nil
}

// writeHashed creates path, lets write fill it, and returns its reference.
func writeHashed(dir, name string, write func(io.Writer) error) (WorkFileRef, error) {
	w, err := createHashed(filepath.Join(dir, name))
	if err != nil {
		return WorkFileRef{}, err
	}
	if err := write(w); err != nil {
		w.f.Close()
		return WorkFileRef{}, failure.Wrap(failure.IO, err, "writing %s", name)
	}
	sum, n, err := w.close()
	return WorkFileRef{File: name, SHA256: sum, Length: n}, err
}

// writeEvaluations encodes e: the magic, then A, B, [B]₂ and VKK, the CKK
// slices and PublicAndCommitmentCommitted, with points in gnark-crypto's raw
// (uncompressed) encoding so that reading them back needs no square roots.
func writeEvaluations(w io.Writer, e *mpcsetup.Phase2Evaluations) error {
	if _, err := io.WriteString(w, evaluationsMagic); err != nil {
		return err
	}
	enc := curve.NewEncoder(w, curve.RawEncoding())
	for _, v := range []any{e.G1.A, e.G1.B, e.G2.B, e.G1.VKK} {
		if err := enc.Encode(v); err != nil {
			return err
		}
	}
	u32 := func(v int) error { return binary.Write(w, binary.BigEndian, uint32(v)) }
	if err := u32(len(e.G1.CKK)); err != nil {
		return err
	}
	for _, s := range e.G1.CKK {
		if err := enc.Encode(s); err != nil {
			return err
		}
	}
	if err := u32(len(e.PublicAndCommitmentCommitted)); err != nil {
		return err
	}
	for _, s := range e.PublicAndCommitmentCommitted {
		if err := u32(len(s)); err != nil {
			return err
		}
		for _, v := range s {
			if err := u32(v); err != nil {
				return err
			}
		}
	}
	return nil
}

// readEvaluations decodes what writeEvaluations wrote. loadEvaluations
// calls it only on a file whose digest is the work record's, so the points
// are the coordinator's own and are not subgroup-checked again.
func readEvaluations(r io.Reader) (*mpcsetup.Phase2Evaluations, error) {
	var magic [len(evaluationsMagic)]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil || string(magic[:]) != evaluationsMagic {
		return nil, errors.New("not an evaluations file")
	}
	e := new(mpcsetup.Phase2Evaluations)
	dec := curve.NewDecoder(r, curve.NoSubgroupChecks())
	for _, v := range []any{&e.G1.A, &e.G1.B, &e.G2.B, &e.G1.VKK} {
		if err := dec.Decode(v); err != nil {
			return nil, err
		}
	}
	u32 := func() (int, error) {
		var v uint32
		err := binary.Read(r, binary.BigEndian, &v)
		return int(v), err
	}
	n, err := u32()
	if err != nil {
		return nil, err
	}
	if n > len(e.G1.VKK) { // every commitment's wire is in VKK
		return nil, errors.New("more commitments than verifying-key bases")
	}
	e.G1.CKK = make([][]curve.G1Affine, n)
	for i := range e.G1.CKK {
		if err := dec.Decode(&e.G1.CKK[i]); err != nil {
			return nil, err
		}
	}
	if n, err = u32(); err != nil {
		return nil, err
	}
	if n != len(e.G1.CKK) {
		return nil, errors.New("committed-wire lists do not match the commitments")
	}
	e.PublicAndCommitmentCommitted = make([][]int, n)
	for i := range e.PublicAndCommitmentCommitted {
		m, err := u32()
		if err != nil {
			return nil, err
		}
		if m > len(e.G1.VKK) {
			return nil, errors.New("committed-wire list longer than the public inputs")
		}
		s := make([]int, m)
		for j := range s {
			if s[j], err = u32(); err != nil {
				return nil, err
			}
		}
		e.PublicAndCommitmentCommitted[i] = s
	}
	var extra [1]byte
	if _, err := r.Read(extra[:]); err != io.EOF {
		return nil, errors.New("trailing bytes after the evaluations")
	}
	return e, nil
}

// saveWork writes the initial state and the evaluations to dir, which must
// be new or empty, and the work record last.
func (c *Coordinator) saveWork(dir string, r1csSHA string) error {
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return failure.New(failure.OutputExists, "%s is not empty", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return failure.Wrap(failure.IO, err, "creating %s", dir)
	}
	state, err := writeHashed(dir, InitialStateFile, func(w io.Writer) error {
		_, err := w.Write(c.currentBytes)
		return err
	})
	if err != nil {
		return err
	}
	evals, err := writeHashed(dir, EvaluationsFile, func(w io.Writer) error { return writeEvaluations(w, c.evals) })
	if err != nil {
		return err
	}
	return transcript.WriteJSON(filepath.Join(dir, WorkFile), &WorkRecord{
		Format:             WorkFormat,
		Notice:             WorkNotice,
		CeremonyID:         c.t.CeremonyID,
		RootChallenge:      c.t.Phase2.RootChallenge,
		R1CSSHA256:         r1csSHA,
		CommonsSHA256:      c.t.Phase1.CommonsSHA256,
		InitialState:       state,
		Evaluations:        evals,
		EvaluationsEncoded: EvaluationsEncoding,
	})
}

// readRef reads a work or ceremony file and refuses it unless its length
// and SHA-256 are the recorded ones.
func readRef(dir string, ref WorkFileRef, code failure.Code) ([]byte, error) {
	if ref.File == "" || filepath.Base(ref.File) != ref.File {
		return nil, failure.New(failure.WorkMismatch, "file name %q is not a plain name", ref.File)
	}
	b, err := os.ReadFile(filepath.Join(dir, ref.File))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, failure.New(code, "%s is missing", ref.File)
	} else if err != nil {
		return nil, failure.Wrap(failure.IO, err, "reading %s", ref.File)
	}
	if int64(len(b)) != ref.Length || transcript.Digest(b) != ref.SHA256 {
		return nil, failure.New(code, "%s does not match its recorded digest", ref.File)
	}
	return b, nil
}

// loadEvaluations reads the evaluations file in two passes, as the phase-1
// importer reads a .ptau file: the first only hashes it and refuses a length
// or digest other than the recorded one before any byte is decoded (the
// decoder allocates from the length prefixes it reads); the second decodes
// while hashing again, and the result is used only if that digest also
// matches, in case the file changed between the passes.
func loadEvaluations(dir string, ref WorkFileRef) (*mpcsetup.Phase2Evaluations, error) {
	if ref.File != EvaluationsFile {
		return nil, failure.New(failure.WorkMismatch, "evaluations file is %q", ref.File)
	}
	f, err := os.Open(filepath.Join(dir, ref.File))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, failure.New(failure.WorkMismatch, "%s is missing", ref.File)
	} else if err != nil {
		return nil, failure.Wrap(failure.IO, err, "opening %s", ref.File)
	}
	defer f.Close()
	pass := func(decode bool) (*mpcsetup.Phase2Evaluations, error) {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, failure.Wrap(failure.IO, err, "seeking %s", ref.File)
		}
		h := &countingWriter{w: sha256.New()}
		var e *mpcsetup.Phase2Evaluations
		var derr error
		if decode {
			e, derr = readEvaluations(bufio.NewReaderSize(io.TeeReader(f, h), 1<<20))
		}
		if _, err := io.Copy(h, f); err != nil {
			return nil, failure.Wrap(failure.IO, err, "reading %s", ref.File)
		}
		if h.n != ref.Length || hex.EncodeToString(h.w.(hash.Hash).Sum(nil)) != ref.SHA256 {
			return nil, failure.New(failure.WorkMismatch, "%s does not match its recorded digest", ref.File)
		}
		if derr != nil {
			return nil, failure.Wrap(failure.WorkMismatch, derr, "decoding %s", ref.File)
		}
		return e, nil
	}
	if _, err := pass(false); err != nil {
		return nil, err
	}
	return pass(true)
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// belongsTo reports whether the work record was written for t: same
// format, ceremony, root challenge, R1CS, phase-1 parameters and initial
// state.
func (w *WorkRecord) belongsTo(t *transcript.Transcript) bool {
	return w.Format == WorkFormat && w.EvaluationsEncoded == EvaluationsEncoding && w.CeremonyID == t.CeremonyID &&
		w.RootChallenge == t.Phase2.RootChallenge && w.R1CSSHA256 == t.Circuit.R1CSSHA256 &&
		w.CommonsSHA256 == t.Phase1.CommonsSHA256 && w.InitialState.File == InitialStateFile &&
		w.InitialState.SHA256 == t.Phase2.InitialStateSHA256 && w.InitialState.Length == t.Phase2.StateLength
}

// OpenConfig resumes a ceremony. Commons is needed only to seal: Open then
// checks it against the transcript's phase-1 record and loads the
// evaluations from the work directory.
type OpenConfig struct {
	Dir     string
	Work    string
	Commons *mpcsetup.SrsCommons
}

// Open resumes an open ceremony from its directory and work directory. It
// loads the transcript and the latest accepted state, and refuses unless the
// work record belongs to the transcript and every file it reads has its
// recorded digest.
func Open(cfg OpenConfig) (*Coordinator, error) {
	t, err := transcript.Load(filepath.Join(cfg.Dir, transcript.TranscriptFile))
	if err != nil {
		return nil, err
	}
	if t.Status != transcript.StatusOpen {
		return nil, failure.New(failure.CeremonySealed, "ceremony status is %q", t.Status)
	}
	if err := t.CheckLabels(); err != nil {
		return nil, err
	}
	var w WorkRecord
	wb, err := os.ReadFile(filepath.Join(cfg.Work, WorkFile))
	if err != nil {
		return nil, failure.Wrap(failure.WorkMismatch, err, "reading the work record")
	}
	if err := transcript.DecodeStrict(wb, &w, failure.WorkMismatch, "work record"); err != nil {
		return nil, err
	}
	if !w.belongsTo(t) {
		return nil, failure.New(failure.WorkMismatch, "work record does not belong to ceremony %q", t.CeremonyID)
	}

	// The latest accepted state: the last contribution, or the initial state.
	latest := WorkFileRef{File: w.InitialState.File, SHA256: w.InitialState.SHA256, Length: w.InitialState.Length}
	latestDir := cfg.Work
	for i, rec := range t.Phase2.Contributions {
		if rec.Index != i+1 {
			return nil, failure.New(failure.TranscriptSequence, "contribution at position %d has index %d", i+1, rec.Index)
		}
	}
	if n := len(t.Phase2.Contributions); n > 0 {
		rec := t.Phase2.Contributions[n-1]
		latest, latestDir = WorkFileRef{File: rec.File, SHA256: rec.StateSHA256, Length: t.Phase2.StateLength}, cfg.Dir
	}
	stateBytes, err := readRef(latestDir, latest, failure.WorkMismatch)
	if err != nil {
		return nil, err
	}
	state, err := transcript.DecodeState(stateBytes)
	if err != nil {
		return nil, err
	}
	c := &Coordinator{dir: cfg.Dir, t: *t, current: state, currentBytes: stateBytes, currentSHA: latest.SHA256}

	if cfg.Commons != nil {
		sha, err := ptau.CommonsDigest(cfg.Commons)
		if err != nil {
			return nil, err
		}
		if sha != t.Phase1.CommonsSHA256 || uint64(len(cfg.Commons.G2.Tau)) != t.Phase1.DomainSize {
			return nil, failure.New(failure.Phase1CommonsMismatch, "phase-1 parameters do not match the transcript")
		}
		if c.evals, err = loadEvaluations(cfg.Work, w.Evaluations); err != nil {
			return nil, err
		}
		c.commons = cfg.Commons
	}
	return c, nil
}

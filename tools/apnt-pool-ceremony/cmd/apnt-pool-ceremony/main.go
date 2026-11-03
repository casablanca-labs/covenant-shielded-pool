// Command apnt-pool-ceremony runs the pool's Groth16 phase-2 ceremony
// tooling: the one-command simulated re-run, the remote contributor's
// command, and phase-1 import and probe utilities. The transcript verifier is
// a separate command, apnt-pool-ceremony-verify.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	cs "github.com/consensys/gnark/constraint/bn254"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/contributor"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/rerun"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/testcircuits"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

const usage = `usage: apnt-pool-ceremony <command> [flags]

commands:
  rerun                 one-command simulated-single-party phase 2 (zero-value tests only);
                        --phase init|contribute|seal runs one phase as its own process
  contribute            answer a challenge message as a remote contributor
  phase1-import         import a pinned .ptau file for a domain and print its record
  phase1-probe          sampled evidence on a .ptau file's layout and points (--file or --url);
                        not importer acceptance, which only phase1-import establishes
  hash                  print a file's sha256 and blake2b-512 pins
  compile-test-circuit  write the R1CS of a small test circuit
  describe-r1cs         print an R1CS's digest and the shape phase 2's cost depends on
  write-toy-ptau        write an INSECURE deterministic .ptau fixture for tests
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"rerun":                cmdRerun,
		"contribute":           cmdContribute,
		"phase1-import":        cmdImport,
		"phase1-probe":         cmdProbe,
		"hash":                 cmdHash,
		"compile-test-circuit": cmdCompile,
		"describe-r1cs":        cmdDescribe,
		"write-toy-ptau":       cmdToy,
	}
	run, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED %s\n", err)
		os.Exit(1)
	}
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func required(fs *flag.FlagSet, names ...string) error {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for _, n := range names {
		if !set[n] {
			return fmt.Errorf("missing --%s", n)
		}
	}
	return nil
}

func cmdRerun(args []string) error {
	fs := flag.NewFlagSet("rerun", flag.ExitOnError)
	phase := fs.String("phase", "all", "all (in one process), or one phase as its own process: init, contribute, seal")
	ptauPath := fs.String("ptau", "", "phase-1 .ptau file")
	pin := fs.String("ptau-pin", "", "phase-1 file pin, sha256:<hex> or blake2b-512:<hex>")
	source := fs.String("ptau-source", "", "where the phase-1 file comes from (recorded in the transcript)")
	r1cs := fs.String("r1cs", "", "gnark bn254 R1CS file")
	label := fs.String("label", "", "circuit label")
	out := fs.String("out", "", "ceremony directory (new and empty for all and init)")
	work := fs.String("work", "", "coordinator work directory between phases (new and empty for init; all defaults to <out>.work and removes it)")
	id := fs.String("ceremony-id", "", "ceremony id")
	n := fs.Int("contributions", rerun.DefaultContributions, "all: automated contributions to make; seal: the number the transcript must hold")
	beacon := fs.String("beacon", "", "beacon bytes as lowercase hex (at least 32 bytes)")
	beaconSource := fs.String("beacon-source", "", "what the beacon is, e.g. a pre-announced Chipnet block hash, display order")
	fs.Parse(args)
	need := map[string][]string{
		"all":                 {"ptau", "ptau-pin", "ptau-source", "r1cs", "label", "out", "ceremony-id", "beacon", "beacon-source"},
		rerun.PhaseInit:       {"ptau", "ptau-pin", "ptau-source", "r1cs", "label", "out", "work", "ceremony-id"},
		rerun.PhaseContribute: {"out", "work"},
		rerun.PhaseSeal:       {"ptau", "ptau-pin", "out", "work", "contributions", "beacon", "beacon-source"},
	}[*phase]
	if need == nil {
		return fmt.Errorf("unknown --phase %q (all, init, contribute, seal)", *phase)
	}
	if err := required(fs, need...); err != nil {
		return err
	}
	o := rerun.Options{
		PtauPath: *ptauPath, PtauSource: *source,
		R1CSPath: *r1cs, CircuitLabel: *label,
		OutDir: *out, WorkDir: *work, CeremonyID: *id, Contributions: *n,
		Beacon: transcript.Beacon{Value: *beacon, Source: *beaconSource},
	}
	if *pin != "" {
		p, err := ptau.ParsePin(*pin)
		if err != nil {
			return err
		}
		o.PtauPin = p
	}
	run := map[string]func(rerun.Options) (*rerun.Summary, error){
		"all": rerun.Run, rerun.PhaseInit: rerun.Init, rerun.PhaseContribute: rerun.Contribute, rerun.PhaseSeal: rerun.Seal,
	}[*phase]
	s, err := run(o)
	if s != nil {
		printJSON(s)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\n%s\n", transcript.SimulatedNotice)
	return nil
}

func cmdContribute(args []string) error {
	fs := flag.NewFlagSet("contribute", flag.ExitOnError)
	in := fs.String("challenge", "", "challenge message file")
	out := fs.String("out", "", "contribution message file to write")
	id := fs.String("id", "", "contributor id to record")
	fs.Parse(args)
	if err := required(fs, "challenge", "out", "id"); err != nil {
		return err
	}
	ch, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	msg, err := contributor.Contribute(ch, transcript.Contributor{ID: *id, Kind: transcript.KindRemote})
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, msg, 0o644); err != nil {
		return err
	}
	h, _, err := transcript.DecodeMessage(msg)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{"index": h.Index, "stateSha256": h.StateSHA256, "previousStateSha256": h.PreviousStateSHA256})
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("phase1-import", flag.ExitOnError)
	path := fs.String("ptau", "", ".ptau file")
	pin := fs.String("ptau-pin", "", "sha256:<hex> or blake2b-512:<hex>")
	domain := fs.Uint64("domain", 0, "FFT domain size (power of two)")
	fs.Parse(args)
	if err := required(fs, "ptau", "ptau-pin", "domain"); err != nil {
		return err
	}
	p, err := ptau.ParsePin(*pin)
	if err != nil {
		return err
	}
	_, info, err := ptau.ImportFile(*path, p, *domain)
	if err != nil {
		return err
	}
	return printJSON(info)
}

// httpReaderAt reads byte ranges of a URL.
type httpReaderAt struct {
	url      string
	requests int
}

func (h *httpReaderAt) ReadAt(p []byte, off int64) (int, error) {
	req, err := http.NewRequest("GET", h.url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+int64(len(p))-1))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	h.requests++
	if resp.StatusCode != http.StatusPartialContent {
		return 0, fmt.Errorf("range request returned %s", resp.Status)
	}
	return io.ReadFull(resp.Body, p)
}

func (h *httpReaderAt) size() (int64, error) {
	req, err := http.NewRequest("GET", h.url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Range", "bytes=0-0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	h.requests++
	cr := resp.Header.Get("Content-Range")
	i := strings.LastIndexByte(cr, '/')
	if resp.StatusCode != http.StatusPartialContent || i < 0 {
		return 0, fmt.Errorf("no Content-Range total (status %s)", resp.Status)
	}
	return strconv.ParseInt(cr[i+1:], 10, 64)
}

func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("phase1-probe", flag.ExitOnError)
	file := fs.String("file", "", "local .ptau file")
	url := fs.String("url", "", "URL of a .ptau file served with HTTP range requests")
	fs.Parse(args)
	var (
		ra   io.ReaderAt
		size int64
		hr   *httpReaderAt
	)
	switch {
	case *file != "":
		f, err := os.Open(*file)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		ra, size = f, st.Size()
	case *url != "":
		hr = &httpReaderAt{url: *url}
		var err error
		if size, err = hr.size(); err != nil {
			return err
		}
		ra = hr
	default:
		return fmt.Errorf("give --file or --url")
	}
	rep, err := ptau.Probe(ra, size)
	out := map[string]any{"source": *file + *url, "scope": ptau.ProbeScope, "report": rep}
	if hr != nil {
		out["httpRangeRequests"] = hr.requests
	}
	if err != nil {
		out["refusal"] = err.Error()
		out["code"] = failure.CodeOf(err)
	}
	printJSON(out)
	return err
}

func cmdHash(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	file := fs.String("file", "", "file to hash")
	fs.Parse(args)
	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer f.Close()
	sha, b2, size, err := ptau.HashFile(f)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{"size": size, "sha256": ptau.AlgSHA256 + ":" + sha, "blake2b512": ptau.AlgBLAKE2b512 + ":" + b2})
}

func cmdCompile(args []string) error {
	fs := flag.NewFlagSet("compile-test-circuit", flag.ExitOnError)
	name := fs.String("circuit", "", "cubic, chain, committed, or shaped")
	size := fs.Int("size", 0, "cubic: constant K (default 5); chain/committed: rounds; shaped: constraints")
	like := fs.String("like", "", "shaped: the R1CS whose per-constraint shape to scale (see describe-r1cs)")
	seed := fs.Uint64("seed", 1, "shaped: seed of the wire references and coefficient values")
	out := fs.String("out", "", "R1CS file to write")
	fs.Parse(args)
	if err := required(fs, "circuit", "out"); err != nil {
		return err
	}
	var (
		r   *cs.R1CS
		err error
		ref *testcircuits.Shape
	)
	if *name == "shaped" {
		if err := required(fs, "like", "size"); err != nil {
			return err
		}
		lr, _, err := transcript.ReadR1CS(*like)
		if err != nil {
			return err
		}
		sh := testcircuits.ShapeOf(lr)
		ref, lr = &sh, nil
		r, err = testcircuits.Shaped(sh, *size, *seed)
	} else {
		r, err = testcircuits.Compile(*name, *size)
	}
	if err != nil {
		return err
	}
	if err := testcircuits.WriteR1CS(*out, r); err != nil {
		return err
	}
	r, digest, err := transcript.ReadR1CS(*out)
	if err != nil {
		return err
	}
	if ref == nil {
		return printJSON(transcript.DescribeCircuit(*name, r, digest))
	}
	return printJSON(map[string]any{
		"circuit":    transcript.DescribeCircuit(*name, r, digest),
		"domainSize": transcript.DomainSize(r),
		"shape":      testcircuits.ShapeOf(r),
		"like":       ref,
	})
}

func cmdDescribe(args []string) error {
	fs := flag.NewFlagSet("describe-r1cs", flag.ExitOnError)
	path := fs.String("r1cs", "", "gnark bn254 R1CS file")
	fs.Parse(args)
	if err := required(fs, "r1cs"); err != nil {
		return err
	}
	r, digest, err := transcript.ReadR1CS(*path)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{
		"circuit":    transcript.DescribeCircuit("", r, digest),
		"domainSize": transcript.DomainSize(r),
		"shape":      testcircuits.ShapeOf(r),
	})
}

func cmdToy(args []string) error {
	fs := flag.NewFlagSet("write-toy-ptau", flag.ExitOnError)
	power := fs.Uint("power", 0, "log2 of the domain")
	out := fs.String("out", "", ".ptau file to write")
	fs.Parse(args)
	if err := required(fs, "power", "out"); err != nil {
		return err
	}
	if *power < 1 || *power > 20 {
		return fmt.Errorf("power must be 1..20")
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	if err := ptau.Write(f, ptau.ToyCommons(uint32(*power), 7, 11, 13)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "INSECURE toy phase-1 fixture: tau, alpha and beta are public constants.")
	return cmdHash([]string{"--file", *out})
}

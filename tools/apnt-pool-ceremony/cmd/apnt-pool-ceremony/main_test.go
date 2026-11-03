package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/internal/fixture"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/ptau"
)

// quiet discards what a command prints for the duration of a test.
func quiet(t *testing.T) {
	t.Helper()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = null
	t.Cleanup(func() { os.Stdout = stdout; null.Close() })
}

// BEGIN socket-free probe fixture (also qualified in isolated stdlib controls).
type probeFixtureTransport func(*http.Request) (*http.Response, error)

func (f probeFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func installProbeFixture(t *testing.T, dir string) string {
	t.Helper()
	const origin = "http://p2-probe.invalid"
	files := http.FileServer(http.Dir(dir))
	ranges := regexp.MustCompile(`^bytes=([0-9]+)-([0-9]+)$`)
	client := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: probeFixtureTransport(func(req *http.Request) (*http.Response, error) {
		u := req.URL
		if req.Method != http.MethodGet || u.Scheme != "http" || u.Host != "p2-probe.invalid" ||
			u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" ||
			(u.Path != "/good.ptau" && u.Path != "/v2.ptau" && u.Path != "/reordered.ptau") {
			return nil, errors.New("probe fixture refuses URL or method")
		}
		parts := ranges.FindStringSubmatch(req.Header.Get("Range"))
		if parts == nil {
			return nil, errors.New("probe fixture requires one bounded byte range")
		}
		start, errStart := strconv.ParseInt(parts[1], 10, 64)
		end, errEnd := strconv.ParseInt(parts[2], 10, 64)
		info, err := os.Stat(filepath.Join(dir, u.Path[1:]))
		if err != nil || errStart != nil || errEnd != nil || start > end || start >= info.Size() {
			return nil, errors.New("probe fixture refuses range")
		}
		if end >= info.Size() {
			end = info.Size() - 1
		}
		recorder := httptest.NewRecorder()
		files.ServeHTTP(recorder, req)
		resp := recorder.Result()
		want := fmt.Sprintf("bytes %d-%d/%d", start, end, info.Size())
		if resp.StatusCode != http.StatusPartialContent || resp.Header.Get("Content-Range") != want ||
			resp.ContentLength != end-start+1 {
			resp.Body.Close()
			return nil, errors.New("probe fixture Range/Content-Range mismatch")
		}
		return resp, nil
	})}
	t.Cleanup(func() { http.DefaultClient = client })
	return origin
}

// END socket-free probe fixture.

// phase1-probe refuses an unsupported .ptau version, and a point section
// before the header, through both of its readers, --file and --url (HTTP
// range requests), with the importer's code.
func TestPhase1ProbeRefusesUnsupportedVersion(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	var b bytes.Buffer
	if err := ptau.Write(&b, ptau.ToyCommons(5, fixture.ToyTau, fixture.ToyAlpha, fixture.ToyBeta)); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good.ptau")
	v2 := filepath.Join(dir, "v2.ptau")
	bad := append([]byte(nil), b.Bytes()...)
	binary.LittleEndian.PutUint32(bad[4:8], 2)
	if err := os.WriteFile(good, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(v2, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	reordered := filepath.Join(dir, "reordered.ptau")
	if err := os.WriteFile(reordered, fixture.MoveSectionFirst(t, b.Bytes(), 2), 0o644); err != nil {
		t.Fatal(err)
	}
	origin := installProbeFixture(t, dir)

	for _, c := range []struct {
		args []string
		want failure.Code
	}{
		{[]string{"--file", good}, ""},
		{[]string{"--url", origin + "/good.ptau"}, ""},
		{[]string{"--file", v2}, failure.Phase1Format},
		{[]string{"--url", origin + "/v2.ptau"}, failure.Phase1Format},
		{[]string{"--file", reordered}, failure.Phase1Format},
		{[]string{"--url", origin + "/reordered.ptau"}, failure.Phase1Format},
	} {
		err := cmdProbe(c.args)
		if got := failure.CodeOf(err); got != c.want || (c.want == "" && err != nil) {
			t.Fatalf("%v: got %v (code %q), want code %q", c.args, err, got, c.want)
		}
	}
}

// rerun --phase refuses an unknown phase, and each phase refuses to start
// without the flags it uses; seal in particular needs the number of
// contributions the transcript must hold.
func TestRerunPhaseFlags(t *testing.T) {
	quiet(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--phase", "verify"}, `unknown --phase "verify" (all, init, contribute, seal)`},
		{[]string{"--phase", "contribute", "--out", "x"}, "missing --work"},
		{[]string{"--phase", "init", "--out", "x", "--work", "w"}, "missing --ptau"},
		{[]string{"--phase", "seal", "--ptau", "p", "--ptau-pin", "sha256:00", "--out", "x", "--work", "w",
			"--beacon", "00", "--beacon-source", "s"}, "missing --contributions"},
	} {
		err := cmdRerun(c.args)
		if err == nil || err.Error() != c.want {
			t.Fatalf("%v: got %v, want %q", c.args, err, c.want)
		}
	}
}

package pkload

import (
	"errors"
	"os"
	"runtime/debug"
	"strings"
	"testing"

	poolaction "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-action-circuit"
)

// registryRecords is build info whose gnark and gnark-crypto records name the
// registry's versions, unreplaced, among unrelated modules: what go build
// records for this module.
func registryRecords() *debug.BuildInfo {
	return &debug.BuildInfo{Deps: []*debug.Module{
		{Path: "github.com/bits-and-blooms/bitset", Version: "v1.24.6"},
		{Path: gnarkModule, Version: poolaction.GnarkVersion},
		{Path: gnarkCryptoModule, Version: poolaction.GnarkCryptoVersion},
		{Path: "golang.org/x/sys", Version: "v0.47.0"},
	}}
}

// testVersions is the version source this package's tests read and write
// images through: the real decision (moduleVersions) over registryRecords.
// A go test binary carries no dependency records, so the real source
// (linkedVersions) refuses every image in it; only the record source is
// substituted, here, in a _test.go file.
func testVersions() (string, string, error) { return moduleVersions(registryRecords(), true) }

func TestMain(m *testing.M) {
	runtimeVersions = testVersions
	os.Exit(m.Run())
}

var versionErrors = []error{ErrNoBuildInfo, ErrModuleMissing, ErrModuleReplaced, ErrModuleVersion}

// TestModuleVersionsFailsClosed: every branch of the decision, from
// constructed records, independent of this binary's own build info.
func TestModuleVersionsFailsClosed(t *testing.T) {
	with := func(edit func(*debug.BuildInfo)) *debug.BuildInfo { bi := registryRecords(); edit(bi); return bi }
	drop := func(path string) func(*debug.BuildInfo) {
		return func(bi *debug.BuildInfo) {
			var kept []*debug.Module
			for _, d := range bi.Deps {
				if d.Path != path {
					kept = append(kept, d)
				}
			}
			bi.Deps = kept
		}
	}
	set := func(path string, f func(*debug.Module)) func(*debug.BuildInfo) {
		return func(bi *debug.BuildInfo) {
			for _, d := range bi.Deps {
				if d.Path == path {
					f(d)
				}
			}
		}
	}
	for _, c := range []struct {
		name string
		bi   *debug.BuildInfo
		ok   bool
		want error
		says string
	}{
		{"no build info", nil, false, ErrNoBuildInfo, ""},
		{"build info reported absent", registryRecords(), false, ErrNoBuildInfo, ""},
		{"nil build info reported present", nil, true, ErrNoBuildInfo, ""},
		{"no dependency records (a go test binary)", &debug.BuildInfo{}, true, ErrModuleMissing, gnarkModule},
		{"only unrelated records", with(func(bi *debug.BuildInfo) { bi.Deps = bi.Deps[:1] }), true, ErrModuleMissing, gnarkModule},
		{"gnark missing", with(drop(gnarkModule)), true, ErrModuleMissing, gnarkModule},
		{"gnark-crypto missing", with(drop(gnarkCryptoModule)), true, ErrModuleMissing, gnarkCryptoModule},
		{"gnark replaced by a directory", with(set(gnarkModule, func(d *debug.Module) { d.Replace = &debug.Module{Path: "../gnark"} })), true, ErrModuleReplaced, gnarkModule},
		{"gnark-crypto replaced, same version", with(set(gnarkCryptoModule, func(d *debug.Module) {
			d.Replace = &debug.Module{Path: "example.com/fork/gnark-crypto", Version: poolaction.GnarkCryptoVersion}
		})), true, ErrModuleReplaced, gnarkCryptoModule},
		{"gnark another version", with(set(gnarkModule, func(d *debug.Module) { d.Version = "v0.16.4" })), true, ErrModuleVersion, "v0.16.4"},
		{"gnark-crypto another version", with(set(gnarkCryptoModule, func(d *debug.Module) { d.Version = "v0.21.1" })), true, ErrModuleVersion, "v0.21.1"},
		{"gnark-crypto without a version", with(set(gnarkCryptoModule, func(d *debug.Module) { d.Version = "" })), true, ErrModuleVersion, gnarkCryptoModule},
		{"gnark-crypto recorded twice", with(func(bi *debug.BuildInfo) {
			bi.Deps = append(bi.Deps, &debug.Module{Path: gnarkCryptoModule, Version: "v0.20.1"})
		}), true, ErrModuleVersion, "twice"},
	} {
		g, cr, err := moduleVersions(c.bi, c.ok)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
			continue
		}
		for _, other := range versionErrors {
			if other != c.want && errors.Is(err, other) {
				t.Errorf("%s: also matches %v; each refusal has its own error", c.name, other)
			}
		}
		if g != "" || cr != "" {
			t.Errorf("%s: refused but returned versions %q %q", c.name, g, cr)
		}
		if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %q does not name %q", c.name, err, c.says)
		}
	}
	// The one accepted case: both records, unreplaced, at the registry's versions.
	g, cr, err := moduleVersions(registryRecords(), true)
	if err != nil || g != poolaction.GnarkVersion || cr != poolaction.GnarkCryptoVersion {
		t.Fatalf("the registry's own records are refused or misread: %q %q %v", g, cr, err)
	}
}

// TestImagePathRefusesUnverifiedVersions: writing and reading an image go
// through the version source, so a refusal there refuses the image.
func TestImagePathRefusesUnverifiedVersions(t *testing.T) {
	s := newSetup(t)
	defer func() { runtimeVersions = testVersions }()
	for _, c := range []struct {
		name string
		src  func() (string, string, error)
		want error
	}{
		{"no build info", func() (string, string, error) { return moduleVersions(nil, false) }, ErrNoBuildInfo},
		{"no dependency records", func() (string, string, error) { return moduleVersions(&debug.BuildInfo{}, true) }, ErrModuleMissing},
	} {
		name, want := c.name, c.want
		runtimeVersions = c.src
		if _, err := WriteImage(new(strings.Builder), s.pk); !errors.Is(err, want) {
			t.Errorf("%s: WriteImage: %v", name, err)
		}
		_, _, _, err := Load(s.image, FormatImage, s.imagePin)
		if StageOf(err) != StageDecode || !errors.Is(err, want) {
			t.Errorf("%s: Load: %v", name, err)
		}
	}
}

// TestLinkedVersionsFailsClosedWithoutRecords checks this binary: when its
// build info lacks either record (every go test binary so far), the real
// version source must refuse, and so must an image load through it. A binary
// that does carry both records is covered by the constructed cases above and
// by the command tests, which run a go-built binary.
func TestLinkedVersionsFailsClosedWithoutRecords(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	has := map[string]bool{}
	if ok {
		for _, d := range bi.Deps {
			has[d.Path] = true
		}
	}
	if has[gnarkModule] && has[gnarkCryptoModule] {
		t.Skip("this binary records both modules; the missing-record path is covered by TestModuleVersionsFailsClosed")
	}
	if g, cr, err := linkedVersions(); err == nil {
		t.Fatalf("this binary has no records of gnark and gnark-crypto, yet linkedVersions returned %q %q without error", g, cr)
	}
	s := newSetup(t)
	defer func() { runtimeVersions = testVersions }()
	runtimeVersions = linkedVersions
	if _, _, _, err := Load(s.image, FormatImage, s.imagePin); err == nil {
		t.Fatal("an image loaded through the real version source in a binary without module records")
	}
}

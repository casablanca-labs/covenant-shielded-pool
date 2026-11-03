package verifier

import (
	"os"
	"runtime/debug"
	"strings"
	"testing"
)

// The build records Go 1.26.5 embeds, as measured with go version -m on the
// verify command built in a git worktree and in a clean clone of 75c4e624.
func worktreeRecords() *debug.BuildInfo {
	return &debug.BuildInfo{
		Main: debug.Module{Path: Module, Version: "(devel)"},
		Deps: []*debug.Module{
			{Path: "github.com/consensys/gnark", Version: "v0.16.3"},
			{Path: "github.com/consensys/gnark-crypto", Version: "v0.21.0"},
		},
		Settings: []debug.BuildSetting{{Key: "-buildmode", Value: "exe"}, {Key: "GOARCH", Value: "arm64"}},
	}
}

func cloneRecords() *debug.BuildInfo {
	bi := worktreeRecords()
	bi.Settings = append(bi.Settings,
		debug.BuildSetting{Key: "vcs", Value: "git"},
		debug.BuildSetting{Key: "vcs.revision", Value: "75c4e6246e463284fc8c32e98e2be11ce0d63812"},
		debug.BuildSetting{Key: "vcs.modified", Value: "false"})
	return bi
}

func TestBuildOfACleanCloneIsVerified(t *testing.T) {
	b := buildOf(cloneRecords(), true)
	want := Build{Status: BuildVerified, Module: Module, VCSRevision: "75c4e6246e463284fc8c32e98e2be11ce0d63812",
		VCSModified: "false", Gnark: "v0.16.3", GnarkCrypto: "v0.21.0"}
	if b != want {
		t.Fatalf("got %+v\nwant %+v", b, want)
	}
}

// Every build whose records do not establish the binding is unverified, and
// what is absent stays absent.
func TestBuildOfIsUnverifiedWithoutEveryRecord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*debug.BuildInfo) *debug.BuildInfo
		reason string
		check  func(Build) bool
	}{
		{"worktree build: no VCS records", func(*debug.BuildInfo) *debug.BuildInfo { return worktreeRecords() }, "no VCS revision",
			func(b Build) bool { return b.VCSRevision == "" && b.VCSModified == "" && b.Gnark == "v0.16.3" }},
		{"modified tree", func(bi *debug.BuildInfo) *debug.BuildInfo { set(bi, "vcs.modified", "true"); return bi }, "unmodified tree",
			func(b Build) bool { return b.VCSModified == "true" && b.VCSRevision != "" }},
		{"no vcs.modified record", func(bi *debug.BuildInfo) *debug.BuildInfo { set(bi, "vcs.modified", ""); return bi }, "unmodified tree", nil},
		{"malformed revision", func(bi *debug.BuildInfo) *debug.BuildInfo { set(bi, "vcs.revision", "75c4e624"); return bi }, "no VCS revision", nil},
		{"gnark replaced", func(bi *debug.BuildInfo) *debug.BuildInfo {
			bi.Deps[0].Replace = &debug.Module{Path: "example.com/fork", Version: "v0.0.1"}
			return bi
		}, "replaced", func(b Build) bool { return b.Gnark == "v0.16.3" }},
		{"other gnark version", func(bi *debug.BuildInfo) *debug.BuildInfo { bi.Deps[0].Version = "v0.16.2"; return bi }, "the tool record names", nil},
		{"other gnark-crypto version", func(bi *debug.BuildInfo) *debug.BuildInfo { bi.Deps[1].Version = "v0.21.1"; return bi }, "the tool record names", nil},
		{"no gnark-crypto record", func(bi *debug.BuildInfo) *debug.BuildInfo { bi.Deps = bi.Deps[:1]; return bi }, "no record of", nil},
		{"gnark recorded twice", func(bi *debug.BuildInfo) *debug.BuildInfo {
			bi.Deps = append(bi.Deps, &debug.Module{Path: "github.com/consensys/gnark", Version: "v0.16.3"})
			return bi
		}, "recorded twice", nil},
		{"other main module", func(bi *debug.BuildInfo) *debug.BuildInfo { bi.Main.Path = "example.com/other"; return bi }, "main module",
			func(b Build) bool { return b.Module == "example.com/other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := buildOf(tc.edit(cloneRecords()), true)
			if b.Status != BuildUnverified || !strings.Contains(b.Reason, tc.reason) || (tc.check != nil && !tc.check(b)) {
				t.Fatalf("%+v", b)
			}
		})
	}
	// No build info, and records that come with ok = false, are not read.
	for _, bi := range []*debug.BuildInfo{nil, cloneRecords()} {
		if b := buildOf(bi, false); b != (Build{Status: BuildUnverified, Reason: b.Reason}) || !strings.Contains(b.Reason, "no module build info") {
			t.Fatalf("no build info: %+v", b)
		}
	}
}

// A go test binary lists no dependencies and records no VCS revision: this
// test's own binary is unverified.
func TestThisTestBinaryIsUnverified(t *testing.T) {
	if b := ThisBuild(); b.Status != BuildUnverified || b.Reason == "" {
		t.Fatalf("%+v", b)
	}
}

func TestModuleMatchesGoMod(t *testing.T) {
	b, err := os.ReadFile("../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if first, _, _ := strings.Cut(string(b), "\n"); first != "module "+Module {
		t.Fatalf("go.mod says %q, verifier.Module is %s", first, Module)
	}
}

// set sets a build setting, removing it when value is empty.
func set(bi *debug.BuildInfo, key, value string) {
	out := bi.Settings[:0]
	for _, s := range bi.Settings {
		if s.Key != key {
			out = append(out, s)
		}
	}
	if value != "" {
		out = append(out, debug.BuildSetting{Key: key, Value: value})
	}
	bi.Settings = out
}

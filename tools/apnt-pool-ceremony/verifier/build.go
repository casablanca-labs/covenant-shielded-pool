package verifier

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"sync"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// Module is the module the verifier is built from. TestModuleMatchesGoMod
// holds it equal to go.mod.
const Module = "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony"

// Build statuses.
const (
	BuildVerified   = "verified"
	BuildUnverified = "unverified"
)

// Build identifies the binary that ran the verifier, from the build records
// Go embeds in it. It is the binary's own record, not an authentication of
// it: it lets a report be bound to a source revision, and says so only when
// every record the binding needs is present.
//
// Status is BuildVerified only if the records name Module as the main
// module, gnark and gnark-crypto at transcript.CurrentTool's versions and
// not replaced, a VCS revision, and vcs.modified=false. Otherwise it is
// BuildUnverified and Reason says the first record that failed. The other
// fields are copied from the records as found, empty when a record is
// absent, never inferred.
//
// Go (1.26.5 measured) stamps no VCS revision in a binary built inside a git
// worktree, where .git is a file, or in a copy with no .git, and a go test
// binary lists no dependencies: all of these report BuildUnverified. A build
// from a clean clone of a commit reports BuildVerified with that commit.
type Build struct {
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
	Module      string `json:"module"`
	VCSRevision string `json:"vcsRevision"`
	VCSModified string `json:"vcsModified"`
	Gnark       string `json:"gnark"`
	GnarkCrypto string `json:"gnarkCrypto"`
}

var (
	buildOnce sync.Once
	thisBuild Build
)

// ThisBuild is the running binary's Build.
func ThisBuild() Build {
	buildOnce.Do(func() { thisBuild = buildOf(debug.ReadBuildInfo()) })
	return thisBuild
}

var vcsRevision = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

func buildSetting(bi *debug.BuildInfo, key string) string {
	for _, s := range bi.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}

// buildOf classifies a binary's build records. It fails closed: a record
// that is absent is never assumed.
func buildOf(bi *debug.BuildInfo, ok bool) Build {
	b := Build{Status: BuildUnverified}
	if !ok || bi == nil {
		b.Reason = "the binary carries no module build info"
		return b
	}
	b.Module = bi.Main.Path
	b.VCSRevision, b.VCSModified = buildSetting(bi, "vcs.revision"), buildSetting(bi, "vcs.modified")
	if bi.Main.Path != Module {
		b.Reason = fmt.Sprintf("the main module is %q, not %s", bi.Main.Path, Module)
		return b
	}
	for _, w := range []struct {
		path, version string
		dst           *string
	}{
		{"github.com/consensys/gnark", transcript.CurrentTool.Gnark, &b.Gnark},
		{"github.com/consensys/gnark-crypto", transcript.CurrentTool.GnarkCrypto, &b.GnarkCrypto},
	} {
		var rec *debug.Module
		for _, d := range bi.Deps {
			if d != nil && d.Path == w.path {
				if rec != nil {
					b.Reason = fmt.Sprintf("%s is recorded twice", w.path)
					return b
				}
				rec = d
			}
		}
		if rec == nil {
			b.Reason = fmt.Sprintf("no record of %s", w.path)
			return b
		}
		*w.dst = rec.Version
		switch {
		case rec.Replace != nil:
			b.Reason = fmt.Sprintf("%s %s is replaced by %s %s", w.path, rec.Version, rec.Replace.Path, rec.Replace.Version)
			return b
		case rec.Version != w.version:
			b.Reason = fmt.Sprintf("%s is %s, the tool record names %s", w.path, rec.Version, w.version)
			return b
		}
	}
	if !vcsRevision.MatchString(b.VCSRevision) {
		b.Reason = fmt.Sprintf("no VCS revision recorded (vcs.revision %q; Go records none in a git worktree)", b.VCSRevision)
		return b
	}
	if b.VCSModified != "false" {
		b.Reason = fmt.Sprintf("not recorded as built from an unmodified tree (vcs.modified %q)", b.VCSModified)
		return b
	}
	b.Status = BuildVerified
	return b
}

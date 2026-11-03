package release

import (
	"errors"
	"fmt"
	"regexp"
	"runtime/debug"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/crscheck"
)

// MainModule is the module the gate must be built from.
// TestModuleMatchesGoMod holds it equal to go.mod.
const MainModule = "github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony"

const (
	gnarkModule       = "github.com/consensys/gnark"
	gnarkCryptoModule = "github.com/consensys/gnark-crypto"
)

// Checker identifies the gate's build: the module and VCS revision it was
// built from and the gnark versions it links. The binary's own SHA-256 is
// path-dependent and goes in the run section, not here.
type Checker struct {
	Module      string `json:"module"`
	VCSRevision string `json:"vcsRevision"`
	VCSModified string `json:"vcsModified"`
	Gnark       string `json:"gnark"`
	GnarkCrypto string `json:"gnarkCrypto"`
}

// The refusals of checkerOf, each its own error so a test can tell them apart
// with errors.Is. All of them are CodeCheckerBuild.
var (
	ErrNoBuildInfo    = errors.New("the gate binary carries no module build info, so what it was built from cannot be verified")
	ErrMainModule     = errors.New("the gate binary was not built from the ceremony module")
	ErrModuleMissing  = errors.New("the gate binary's build info has no record of a module the check is bound to")
	ErrModuleReplaced = errors.New("the gate binary replaces a module the check is bound to")
	ErrModuleVersion  = errors.New("the gate binary links another version of a module the check is bound to")
	ErrNoRevision     = errors.New("the gate binary records no VCS revision")
	ErrModified       = errors.New("the gate binary was not recorded as built from an unmodified tree")
)

// readBuildInfo is the running binary's build info. It is a variable only so
// this package's tests can give a go test binary, which lists no
// dependencies and records no VCS revision, a record source (TestMain);
// nothing outside the tests assigns it.
var readBuildInfo = debug.ReadBuildInfo

var vcsRevision = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

func setting(bi *debug.BuildInfo, key string) string {
	for _, s := range bi.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}

// checkerOf decides, from a build's records alone, whether the gate may issue
// a verdict. It fails closed: it requires build info from MainModule, an
// affirmative, unreplaced record of gnark and gnark-crypto at the versions
// crscheck was written against, a VCS revision, and vcs.modified=false.
// Nothing is assumed for a record that is absent. It returns what it read
// even when it refuses, for the report.
func checkerOf(bi *debug.BuildInfo, ok bool) (Checker, error) {
	var c Checker
	if !ok || bi == nil {
		return c, ErrNoBuildInfo
	}
	c.Module = bi.Main.Path
	c.VCSRevision, c.VCSModified = setting(bi, "vcs.revision"), setting(bi, "vcs.modified")
	if bi.Main.Path != MainModule {
		return c, fmt.Errorf("%w: %q", ErrMainModule, bi.Main.Path)
	}
	for _, w := range []struct {
		path, version string
		dst           *string
	}{
		{gnarkModule, crscheck.GnarkVersion, &c.Gnark},
		{gnarkCryptoModule, crscheck.GnarkCryptoVersion, &c.GnarkCrypto},
	} {
		var rec *debug.Module
		for _, d := range bi.Deps {
			if d != nil && d.Path == w.path {
				if rec != nil {
					return c, fmt.Errorf("%w: %s is recorded twice", ErrModuleVersion, w.path)
				}
				rec = d
			}
		}
		switch {
		case rec == nil:
			return c, fmt.Errorf("%w: %s", ErrModuleMissing, w.path)
		case rec.Replace != nil:
			return c, fmt.Errorf("%w: %s %s => %s %s", ErrModuleReplaced, w.path, rec.Version, rec.Replace.Path, rec.Replace.Version)
		case rec.Version != w.version:
			return c, fmt.Errorf("%w: %s %s, crscheck is written against %s", ErrModuleVersion, w.path, rec.Version, w.version)
		}
		*w.dst = rec.Version
	}
	if !vcsRevision.MatchString(c.VCSRevision) {
		return c, fmt.Errorf("%w (vcs.revision %q)", ErrNoRevision, c.VCSRevision)
	}
	if c.VCSModified != "false" {
		return c, fmt.Errorf("%w (vcs.modified %q)", ErrModified, c.VCSModified)
	}
	return c, nil
}

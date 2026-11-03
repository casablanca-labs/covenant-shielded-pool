package poolaction

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// requiredVersions returns every version go.mod requires for module mod,
// matching the module path exactly (gnark is a prefix of gnark-crypto), and
// every replace directive that names it.
func requiredVersions(gomod []byte, mod string) (versions, replaces []string) {
	for _, line := range strings.Split(string(gomod), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.HasPrefix(line, "replace ") || (strings.Contains(line, "=>") && strings.Contains(line, mod)) {
			if f := strings.Fields(strings.TrimPrefix(line, "replace ")); len(f) > 0 && f[0] == mod {
				replaces = append(replaces, line)
			}
			continue
		}
		f := strings.Fields(strings.TrimPrefix(line, "require "))
		if len(f) == 2 && f[0] == mod {
			versions = append(versions, f[1])
		}
	}
	return versions, replaces
}

// TestGnarkVersionsMatchGoMod: the gnark versions registry entry 1 names are
// the ones this module's go.mod requires, and tools/apnt-pool-ceremony, whose
// phase 2 must run on the same gnark as this circuit's R1CS, requires the same
// ones. Neither module may replace them.
func TestGnarkVersionsMatchGoMod(t *testing.T) {
	defer protectedPanic(t)
	// The parser separates gnark from gnark-crypto and sees a replace.
	fixture := []byte("require (\n\tgithub.com/consensys/gnark v0.15.0\n\tgithub.com/consensys/gnark-crypto v0.20.1 // indirect\n)\nreplace github.com/consensys/gnark => ../gnark\n")
	if v, r := requiredVersions(fixture, "github.com/consensys/gnark"); !reflect.DeepEqual(v, []string{"v0.15.0"}) || len(r) != 1 {
		protectedFatal(t, "parser self-check: gnark %v, replaces %v", v, r)
	}
	if v, r := requiredVersions(fixture, "github.com/consensys/gnark-crypto"); !reflect.DeepEqual(v, []string{"v0.20.1"}) || len(r) != 0 {
		protectedFatal(t, "parser self-check: gnark-crypto %v, replaces %v", v, r)
	}
	for _, path := range []string{"go.mod", "../apnt-pool-ceremony/go.mod"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			protectedFatal(t, err)
		}
		for mod, want := range map[string]string{
			"github.com/consensys/gnark":        GnarkVersion,
			"github.com/consensys/gnark-crypto": GnarkCryptoVersion,
		} {
			v, r := requiredVersions(raw, mod)
			if !reflect.DeepEqual(v, []string{want}) || len(r) != 0 {
				protectedError(t, "%s: %s requires %v (replaces %v), want exactly %s", path, mod, v, r, want)
			}
		}
	}
}

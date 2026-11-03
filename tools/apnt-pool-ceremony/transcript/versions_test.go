package transcript_test

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
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

// TestToolRecordMatchesGoMod: the tool record every transcript carries (and
// the verifier requires) names the gnark this module builds with, and the
// pool action circuit module, whose R1CS phase 2 takes, requires the same
// gnark. Neither module may replace it.
func TestToolRecordMatchesGoMod(t *testing.T) {
	fixture := []byte("require (\n\tgithub.com/consensys/gnark v0.15.0\n\tgithub.com/consensys/gnark-crypto v0.20.1 // indirect\n)\nreplace github.com/consensys/gnark => ../gnark\n")
	if v, r := requiredVersions(fixture, "github.com/consensys/gnark"); !reflect.DeepEqual(v, []string{"v0.15.0"}) || len(r) != 1 {
		t.Fatalf("parser self-check: gnark %v, replaces %v", v, r)
	}
	if v, r := requiredVersions(fixture, "github.com/consensys/gnark-crypto"); !reflect.DeepEqual(v, []string{"v0.20.1"}) || len(r) != 0 {
		t.Fatalf("parser self-check: gnark-crypto %v, replaces %v", v, r)
	}
	tool := transcript.CurrentTool
	for _, enc := range []string{transcript.ProvingKeyEncoding, transcript.VerifyingKeyEncoding} {
		if !strings.HasPrefix(enc, "gnark-"+tool.Gnark+"-") {
			t.Errorf("key encoding %q does not name gnark %s", enc, tool.Gnark)
		}
	}
	for _, path := range []string{"../go.mod", "../../apnt-pool-action-circuit/go.mod"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for mod, want := range map[string]string{
			"github.com/consensys/gnark":        tool.Gnark,
			"github.com/consensys/gnark-crypto": tool.GnarkCrypto,
		} {
			v, r := requiredVersions(raw, mod)
			if !reflect.DeepEqual(v, []string{want}) || len(r) != 0 {
				t.Errorf("%s: %s requires %v (replaces %v), want exactly %s", path, mod, v, r, want)
			}
		}
	}
}

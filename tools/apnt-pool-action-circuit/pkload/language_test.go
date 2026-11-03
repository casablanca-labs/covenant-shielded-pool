package pkload

import (
	"os"
	"strings"
	"testing"
)

// TestSafetyLanguageIsQualified (F4): the pin gives byte identity with the
// ceremony key; zero knowledge under that key also needs the ceremony verifier
// to cover CRS well-formedness, which is open (ARCH-238). The package comment
// and the README must say so and must not claim more.
func TestSafetyLanguageIsQualified(t *testing.T) {
	forbidden := []string{
		"is safe only because", // REV-191 H2: pkload.go and README.md said the pin made skipping the checks safe
		"fastest safe loader",
	}
	for _, f := range []string{"pkload.go", "../README.md", "../cmd/pool-pk-load/main.go"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(raw)), " ")
		for _, phrase := range forbidden {
			if strings.Contains(text, phrase) {
				t.Errorf("%s claims %q; the pin gives byte identity only (ARCH-238 is open)", f, phrase)
			}
		}
		if f == "../cmd/pool-pk-load/main.go" {
			continue
		}
		for _, need := range []string{"byte identity", "ARCH-238", "well-formed"} {
			if !strings.Contains(text, need) {
				t.Errorf("%s does not say %q: the qualification of what the pin gives is missing", f, need)
			}
		}
	}
}

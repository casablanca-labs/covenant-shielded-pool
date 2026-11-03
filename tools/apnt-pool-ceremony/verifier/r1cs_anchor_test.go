package verifier_test

import (
	"strings"
	"testing"

	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/verifier"
)

// With ExpectedR1CSSHA256 the transcript must be for that circuit, and the
// report says the circuit was anchored; without it the verdict is unchanged
// and the report says it was not.
func TestExpectedR1CSDigestIsEnforced(t *testing.T) {
	c := base(t)
	in := c.inputs()
	rep, err := verifier.Verify(in)
	if err != nil || rep.Verdict != verifier.VerdictValid || rep.Anchors.R1CS {
		t.Fatalf("no circuit anchor: %+v, %v", rep, err)
	}
	digest := rep.R1CSSHA256

	in.ExpectedR1CSSHA256 = digest
	rep, err = verifier.Verify(in)
	if err != nil || rep.Verdict != verifier.VerdictValid || !rep.Anchors.R1CS {
		t.Fatalf("matching circuit anchor: %+v, %v", rep, err)
	}

	in.ExpectedR1CSSHA256 = strings.Repeat("0", 64)
	rep, err = verifier.Verify(in)
	if rep != nil || failure.CodeOf(err) != failure.R1CSUnexpected {
		t.Fatalf("other circuit anchor: %+v, %v; want %s", rep, err, failure.R1CSUnexpected)
	}
}

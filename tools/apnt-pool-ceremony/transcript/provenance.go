package transcript

import (
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
)

// Provenance says who produced a setup's randomness. It is a claim about the
// ceremony's process that the tooling binds and enforces structurally; it is
// not, and cannot be, a proof that any contributor was honest.
type Provenance string

const (
	// SimulatedSingleParty: the project ran every contribution itself. The
	// project could have kept the randomness and can forge proofs under the
	// resulting keys. Explicitly labelled zero-value tests only (Chipnet).
	SimulatedSingleParty Provenance = "simulated-single-party"
	// PermissionlessMultiParty: anyone could contribute and verify their own
	// contribution's inclusion. Soundness assumes 1-of-N honest.
	PermissionlessMultiParty Provenance = "permissionless-multi-party"
)

// Notices are fixed per provenance; a transcript or key metadata file with any
// other text is refused, so the warning cannot be softened.
const (
	SimulatedNotice = "SIMULATED SINGLE-PARTY SETUP - ZERO-VALUE TEST ONLY. " +
		"The project ran every contribution and could have kept the randomness, " +
		"so it can forge proofs under these keys. These keys must never guard value; " +
		"a Chipnet pool deployment that uses them is an explicitly labelled zero-value test " +
		"and its testers are told the project could forge proofs. " +
		"These keys never carry to mainnet: there, every setup-backed proof system needs a " +
		"permissionless multi-party ceremony, and HUM-51/52 (setup-free proving or two proof systems) still applies."
	MultiPartyNotice = "PERMISSIONLESS MULTI-PARTY SETUP. " +
		"Soundness assumes at least one honest contribution whose randomness was destroyed, " +
		"in phase 1 and in phase 2 (1-of-N honest). A contributor can rely on its own contribution; " +
		"being outside the project is not the assumption."
)

// ParseProvenance accepts exactly the two labels.
func ParseProvenance(s string) (Provenance, error) {
	switch p := Provenance(s); p {
	case SimulatedSingleParty, PermissionlessMultiParty:
		return p, nil
	}
	return "", failure.New(failure.ProvenanceInvalid, "unknown provenance %q", s)
}

// ZeroValueOnly reports whether keys of this provenance are restricted to
// explicitly labelled zero-value tests.
func (p Provenance) ZeroValueOnly() bool { return p != PermissionlessMultiParty }

// Notice returns the fixed notice for p.
func (p Provenance) Notice() string {
	if p == PermissionlessMultiParty {
		return MultiPartyNotice
	}
	return SimulatedNotice
}

// ContributorKind says how a contribution reached the coordinator.
type ContributorKind string

const (
	// KindAutomatedLocal: produced by the coordinator's own automated
	// contributor, in a process the project runs.
	KindAutomatedLocal ContributorKind = "automated-local"
	// KindRemote: submitted as a contribution message from outside the
	// coordinator process. Who ran it is not provable.
	KindRemote ContributorKind = "remote"
)

// Contributor identifies one contribution's author as claimed.
type Contributor struct {
	ID   string          `json:"id"`
	Kind ContributorKind `json:"kind"`
}

// CheckContributor enforces the per-contribution rules of a provenance:
// a known kind, a non-empty id, and no automated local contribution in a
// multi-party ceremony.
func CheckContributor(p Provenance, c Contributor) error {
	if c.ID == "" || len(c.ID) > 128 {
		return failure.New(failure.ProvenanceConflict, "contributor id must be 1..128 bytes")
	}
	switch c.Kind {
	case KindAutomatedLocal:
		if p == PermissionlessMultiParty {
			return failure.New(failure.ProvenanceConflict, "an automated local contribution cannot be part of a %s ceremony", p)
		}
	case KindRemote:
	default:
		return failure.New(failure.ProvenanceConflict, "unknown contributor kind %q", c.Kind)
	}
	return nil
}

// CheckLabels enforces that a transcript's labels agree with each other and
// with its contributions.
func (t *Transcript) CheckLabels() error {
	p, err := ParseProvenance(string(t.Provenance))
	if err != nil {
		return err
	}
	if t.ZeroValueOnly != p.ZeroValueOnly() {
		return failure.New(failure.ProvenanceConflict, "zeroValueOnly=%v contradicts provenance %s", t.ZeroValueOnly, p)
	}
	if t.Notice != p.Notice() {
		return failure.New(failure.ProvenanceConflict, "notice is not the fixed notice for %s", p)
	}
	for _, c := range t.Phase2.Contributions {
		if err := CheckContributor(p, c.Contributor); err != nil {
			return err
		}
	}
	return nil
}

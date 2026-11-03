// Package failure holds the stable failure codes of the pool ceremony tooling.
//
// Every refusal carries exactly one code. Tests assert codes, not messages, so
// a check that stops firing changes the code a negative test observes.
package failure

import (
	"errors"
	"fmt"
)

// Code is a stable, machine-readable refusal reason.
type Code string

const (
	// Phase 1 (Powers of Tau import).
	Phase1PinInvalid        Code = "PHASE1_PIN_INVALID"
	Phase1HashMismatch      Code = "PHASE1_HASH_MISMATCH"
	Phase1PinUnexpected     Code = "PHASE1_PIN_UNEXPECTED"
	Phase1Format            Code = "PHASE1_FORMAT"
	Phase1PointInvalid      Code = "PHASE1_POINT_INVALID"
	Phase1DomainTooLarge    Code = "PHASE1_DOMAIN_TOO_LARGE"
	Phase1NotPowersOfTau    Code = "PHASE1_NOT_POWERS_OF_TAU"
	Phase1CommonsMismatch   Code = "PHASE1_COMMONS_DIGEST_MISMATCH"
	Phase1DomainMismatch    Code = "PHASE1_DOMAIN_MISMATCH"
	Phase1ProbeInconsistent Code = "PHASE1_PROBE_INCONSISTENT"
	// Degenerate trapdoors that pass every other phase-1 check (ARCH-238):
	// τ a root of unity of the domain (t(τ) = 0), and β = −1.
	Phase1TauInDomain  Code = "PHASE1_TAU_IN_DOMAIN"
	Phase1BetaMinusOne Code = "PHASE1_BETA_MINUS_ONE"

	// Circuit.
	R1CSDigestMismatch Code = "R1CS_DIGEST_MISMATCH"
	R1CSDecode         Code = "R1CS_DECODE"
	R1CSShapeMismatch  Code = "R1CS_SHAPE_MISMATCH"
	// CommitmentMaskMissing: no random mask can be located for a BSB22
	// commitment, so its hiding cannot be checked.
	CommitmentMaskMissing Code = "COMMITMENT_MASK_MISSING"
	// CommitmentMaskNotRandomized: a committed wire has the mask's
	// constraint w·1 = w but is not the sole output of gnark's Randomize
	// hint, so nothing makes the prover draw it at random.
	CommitmentMaskNotRandomized Code = "COMMITMENT_MASK_NOT_RANDOMIZED"
	// R1CSUnexpected: the transcript is for another circuit than the R1CS
	// digest the caller trusts out of band.
	R1CSUnexpected Code = "R1CS_UNEXPECTED"
	// R1CSScheduleInvalid: the R1CS's Levels, the schedule gnark's solver
	// runs, are not the one gnark's builder derives from its instructions.
	R1CSScheduleInvalid Code = "R1CS_SCHEDULE_INVALID"

	// Transcript structure and labels.
	TranscriptFormat   Code = "TRANSCRIPT_FORMAT"
	TranscriptSequence Code = "TRANSCRIPT_SEQUENCE"
	ProvenanceInvalid  Code = "PROVENANCE_INVALID"
	ProvenanceConflict Code = "PROVENANCE_CONFLICT"
	RootMismatch       Code = "ROOT_CHALLENGE_MISMATCH"
	InitialMismatch    Code = "INITIAL_STATE_MISMATCH"

	// Contribution messages and states.
	MessageMalformed        Code = "MESSAGE_MALFORMED"
	MessageWrongCeremony    Code = "MESSAGE_WRONG_CEREMONY"
	MessageDigestMismatch   Code = "MESSAGE_DIGEST_MISMATCH"
	ContributionSequence    Code = "CONTRIBUTION_OUT_OF_SEQUENCE"
	ContributionStale       Code = "CONTRIBUTION_STALE"
	ContributionShape       Code = "CONTRIBUTION_SHAPE"
	ContributionDecode      Code = "CONTRIBUTION_DECODE"
	ContributionChainBroken Code = "CONTRIBUTION_CHAIN_BROKEN"
	ContributionInvalid     Code = "CONTRIBUTION_INVALID"
	ContributionMissing     Code = "CONTRIBUTION_MISSING"
	ContributionFileDigest  Code = "CONTRIBUTION_FILE_DIGEST_MISMATCH"

	// Sealing and keys.
	CeremonyNoContributions Code = "CEREMONY_NO_CONTRIBUTIONS"
	CeremonySealed          Code = "CEREMONY_SEALED"
	BeaconInvalid           Code = "BEACON_INVALID"
	BeaconUnexpected        Code = "BEACON_UNEXPECTED"
	SealedKeyMismatch       Code = "SEALED_KEY_MISMATCH"
	KeyFileDigestMismatch   Code = "KEY_FILE_DIGEST_MISMATCH"
	KeyMetadataMismatch     Code = "KEY_METADATA_MISMATCH"
	KeyMetadataMalformed    Code = "KEY_METADATA_MALFORMED"
	OutputExists            Code = "OUTPUT_EXISTS"
	// CommitmentMaskZero: a sealed key's basis element for a commitment's
	// random mask is the point at infinity, so the commitment does not hide.
	CommitmentMaskZero Code = "COMMITMENT_MASK_ZERO"
	// WorkMismatch: a coordinator work file or record is missing, damaged or
	// from another ceremony. Work files are the coordinator's own state
	// between phases; the verifier never reads them.
	WorkMismatch Code = "WORK_MISMATCH"
	IO           Code = "IO"
)

// Error is a refusal with a stable code.
type Error struct {
	Code   Code
	Detail string
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Detail, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Detail)
}

func (e *Error) Unwrap() error { return e.Err }

// New returns a refusal with the given code.
func New(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Wrap returns a refusal with the given code that wraps err.
func Wrap(code Code, err error, format string, args ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...), Err: err}
}

// CodeOf returns the code of the first failure.Error in err's chain, or "".
func CodeOf(err error) Code {
	var fe *Error
	if errors.As(err, &fe) {
		return fe.Code
	}
	return ""
}

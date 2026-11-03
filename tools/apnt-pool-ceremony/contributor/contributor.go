// Package contributor is the contributor's side of phase 2: it takes a
// challenge message, adds fresh randomness and returns a contribution
// message. The coordinator's automated local contributors and a remote
// contributor's command run the same code on the same bytes.
package contributor

import (
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/failure"
	"github.com/bastiancarmy/bch-cloak/tools/apnt-pool-ceremony/transcript"
)

// Contribute answers a challenge message. gnark's Phase2.Contribute draws δ
// and every σᵢ from crypto/rand and proves knowledge of them bound to the
// challenge; the values are not returned, stored or logged here. Go does not
// zero freed memory, so no erasure claim is made.
func Contribute(challenge []byte, who transcript.Contributor) ([]byte, error) {
	h, state, err := transcript.DecodeMessage(challenge)
	if err != nil {
		return nil, err
	}
	if h.Type != transcript.MessageChallenge {
		return nil, failure.New(failure.MessageMalformed, "message type %q, want %q", h.Type, transcript.MessageChallenge)
	}
	if err := transcript.CheckContributor(h.Provenance, who); err != nil {
		return nil, err
	}
	p, err := transcript.DecodeState(state)
	if err != nil {
		return nil, err
	}
	p.Contribute()
	next, err := transcript.StateBytes(p)
	if err != nil {
		return nil, err
	}
	return transcript.EncodeMessage(transcript.MessageHeader{
		Type:                transcript.MessageContribution,
		Format:              transcript.Format,
		CeremonyID:          h.CeremonyID,
		Provenance:          h.Provenance,
		Index:               h.Index,
		PreviousStateSHA256: h.StateSHA256,
		StateSHA256:         transcript.Digest(next),
		StateLength:         int64(len(next)),
		Contributor:         &who,
	}, next)
}

// Automated is a contributor the coordinator's operator runs in-process.
// Its contributions are labelled automated-local, which a
// permissionless-multi-party ceremony refuses.
type Automated struct{ id string }

// NewAutomated returns an automated local contributor.
func NewAutomated(id string) *Automated { return &Automated{id: id} }

// ID returns the contributor id.
func (a *Automated) ID() string { return a.id }

// Contribute answers a challenge with fresh randomness.
func (a *Automated) Contribute(challenge []byte) ([]byte, error) {
	return Contribute(challenge, transcript.Contributor{ID: a.id, Kind: transcript.KindAutomatedLocal})
}

package pulsar

import (
	"errors"
	"sort"
)

// Ringtail-style two-round online signing. Pulsar is consumed as a Quasar
// certificate profile inside luxfi/consensus: consensus owns orchestration
// (validator set, metastable sampling, session binding, QC aggregation,
// networking, retries, slashing); this package owns the crypto primitives and
// the round shape. NonceCerts come from a BACKGROUND validator NonceTranscript
// subprotocol (not the block hot path). Hot path: Round1 binds the canonical
// nonce; Round2 broadcasts a proof-carrying z partial; Finalize aggregates z,
// recovers the public hint, and emits an ordinary ML-DSA signature.

type CertProfile uint8

const (
	ProfileBLS CertProfile = iota
	ProfileCorona
	ProfilePulsar
	ProfileMagnetar
)

// SignRound1 binds the canonical nonce cert to the consensus session.
type SignRound1 struct {
	SessionID [32]byte
	NonceID   [32]byte
	NonceCert NonceCert
}

// SignRound2 carries one signer's proof-carrying z partial.
type SignRound2 struct {
	SessionID [32]byte
	NonceID   [32]byte
	Partial   Partial
}

// RoundSigner is the Quasar cert-profile interface that consensus calls.
// Pulsar implements it; Pulsar never calls consensus.
type RoundSigner interface {
	Profile() CertProfile
	Round1(sessionID, nonceID [32]byte, cert NonceCert) (SignRound1, error)
	Round2(r1 SignRound1, in PartialInput) (Partial, error)
	Finalize(r1 SignRound1, partials []Partial) (Aggregate, ConsensusCert, error)
}

var ErrInsufficientSigners = errors.New("pulsar: fewer valid partials than threshold")

// CanonicalSignerSet picks the deterministic first-threshold valid partials
// (sorted by PartyID) so an aggregator cannot grind the signer subset — hence
// z, the hint, and the final signature bytes — by choosing among valid sets.
// Returns the chosen partials and the signer bitmap.
func CanonicalSignerSet(valid []Partial, threshold int) ([]Partial, []byte, error) {
	if len(valid) < threshold {
		return nil, nil, ErrInsufficientSigners
	}
	cp := append([]Partial(nil), valid...)
	sort.Slice(cp, func(i, j int) bool { return cp[i].PartyID < cp[j].PartyID })
	chosen := cp[:threshold]
	maxID := uint32(0)
	for _, p := range chosen {
		if uint32(p.PartyID) > maxID {
			maxID = uint32(p.PartyID)
		}
	}
	bitmap := make([]byte, maxID/8+1)
	for _, p := range chosen {
		bitmap[uint32(p.PartyID)/8] |= 1 << (uint32(p.PartyID) % 8)
	}
	return chosen, bitmap, nil
}

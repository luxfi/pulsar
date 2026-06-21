package pulsar

import (
	"bytes"
	"errors"
)

// Partial-z correctness (PULSAR-V13-PARTIAL-Z-PROOF). Each z-share proves
// z_i = λ_i·y_i + c·λ_i·s1_i bound to (session, nonce, party, challenge, DKG
// share commitment, nonce commitment) WITHOUT revealing y_i or s1_i. The
// public bindings below are enforced unconditionally; the zero-knowledge
// correctness check is delegated to the registered (fail-closed)
// PartialZVerifier. Do not tree-aggregate until a sound verifier is registered.

type ZPartialPublicInput struct {
	PartyID         uint32
	Lambda          []byte
	Challenge       []byte
	SessionID       [32]byte
	NonceID         [32]byte
	DKGCommitment   []byte
	NonceCommitment []byte
	ZShare          []byte
}

var (
	ErrWrongParty       = errors.New("pulsar: z-partial party mismatch")
	ErrWrongSession     = errors.New("pulsar: z-partial session mismatch")
	ErrWrongNonce       = errors.New("pulsar: z-partial nonce mismatch")
	ErrBadZPartialProof = errors.New("pulsar: z-partial correctness proof failed")
)

// VerifyZPartial enforces the public bindings, then delegates the ZK
// correctness check to the registered PartialZVerifier (fail-closed default).
func VerifyZPartial(p *Partial, in ZPartialPublicInput) error {
	if p.PartyID != in.PartyID {
		return ErrWrongParty
	}
	if p.SessionID != in.SessionID {
		return ErrWrongSession
	}
	if p.NonceID != in.NonceID {
		return ErrWrongNonce
	}
	if !bytes.Equal(p.ZShare, in.ZShare) {
		return ErrBadZPartialProof
	}
	return registeredPartialZVerifier.VerifyPartial(p, in.Challenge, in.DKGCommitment, in.NonceCommitment)
}

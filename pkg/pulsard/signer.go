// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// signer.go — the Signer: pulsard's implementation of warp.PulsarThresholdSigner.
// It binds a key era, a committee, and a ThresholdEngine, and turns a 32-byte
// subject into a warp.PulsarEvidence the chain accepts. The load-bearing
// invariant is the release gate: NO evidence leaves this process unless it
// verifies under warp.VerifyPulsar — the very function the chain runs. Emitted-
// evidence correctness is therefore a property of pulsard, independent of which
// engine produced the signature.

package pulsard

import (
	"errors"
	"fmt"

	"github.com/luxfi/warp"
)

// ErrReleaseGate wraps a release-gate rejection: the engine returned a signature
// that did not verify under warp.VerifyPulsar, so it is discarded, never emitted.
var ErrReleaseGate = errors.New(
	"pulsard: release gate rejected — produced signature did not verify under warp.VerifyPulsar")

// Signer drives threshold signing sessions for a single key era and emits
// warp.PulsarEvidence. It is bound to one era (the era's identifiers pin every
// evidence it produces); a fresh era or a reshared generation yields a fresh
// Signer state via New/Reshare.
type Signer struct {
	era       warp.PulsarKeyEra
	engine    ThresholdEngine
	committee Committee
}

// Option configures a Signer.
type Option func(*Signer)

// WithEngine sets the threshold crypto engine. Default: Unimplemented()
// (fail-closed).
func WithEngine(e ThresholdEngine) Option {
	return func(s *Signer) {
		if e != nil {
			s.engine = e
		}
	}
}

// WithCommittee sets the committee shape (T-of-N). Default: {1,1}. The committee
// is recorded on each session for quorum bookkeeping; it does not affect the
// emitted signature's format or its verification.
func WithCommittee(c Committee) Option {
	return func(s *Signer) { s.committee = c }
}

// New constructs a Signer for era. With no options it uses the fail-closed
// Unimplemented engine and a degenerate 1-of-1 committee, so ThresholdSign fails
// closed with ErrThresholdMLDSAUnimplemented until a real engine is supplied.
// It validates that the era pins the Pulsar suite and carries a well-formed
// group key, so a misconfigured era is rejected at construction, not at sign.
func New(era warp.PulsarKeyEra, opts ...Option) (*Signer, error) {
	if era.SchemeID != Suite {
		return nil, fmt.Errorf("pulsard: key era scheme %q is not the Pulsar suite %q",
			era.SchemeID, Suite)
	}
	if _, err := NewKeyEra(
		era.ChainID, era.SignerSetID, era.KeyEraID, era.Generation, era.PChainHeight,
		era.MLDSAPubKey, era.Threshold, era.KeygenMode,
	); err != nil {
		return nil, err // malformed group key
	}
	s := &Signer{
		era:       era,
		engine:    Unimplemented(),
		committee: Committee{Threshold: 1, Parties: 1},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Era returns the era this Signer is bound to.
func (s *Signer) Era() warp.PulsarKeyEra { return s.era }

// Engine returns the configured engine's name (audit).
func (s *Signer) Engine() string { return s.engine.Name() }

// ThresholdSign drives a signing session over subject and returns the
// PulsarEvidence the chain verifies. It implements warp.PulsarThresholdSigner.
//
// Order of operations (all fail closed):
//  1. subject must be a 32-byte digest (ValidateSubject) — never spend a nonce
//     on an unsignable width.
//  2. open a Session under this era/committee.
//  3. ask the engine for one standard FIPS-204 ML-DSA-65 signature.
//  4. RELEASE GATE: build evidence and re-verify it with warp.VerifyPulsar; a
//     signature that fails the chain's own verifier is discarded.
func (s *Signer) ThresholdSign(subject []byte) (warp.PulsarEvidence, error) {
	if err := ValidateSubject(subject); err != nil {
		return warp.PulsarEvidence{}, err
	}
	sess, err := NewSession(subject, s.era, s.committee)
	if err != nil {
		return warp.PulsarEvidence{}, err
	}
	sig, err := s.engine.ProduceSignature(sess)
	if err != nil {
		return warp.PulsarEvidence{}, err
	}
	ev := warp.PulsarEvidence{
		SignerSetID: s.era.SignerSetID,
		KeyEraID:    s.era.KeyEraID,
		Generation:  s.era.Generation,
		SuiteID:     s.era.SchemeID,
		Signature:   sig,
	}
	if err := ReleaseGate(ev, subject, s.era); err != nil {
		return warp.PulsarEvidence{}, err
	}
	return ev, nil
}

// Reshare runs a proactive refresh via the engine, advancing the era's
// Generation while preserving the group public key, and rebinds the Signer to
// the refreshed era. It implements warp.PulsarThresholdSigner.
func (s *Signer) Reshare() error {
	newEra, err := s.engine.Reshare(s.era)
	if err != nil {
		return err
	}
	// Defensive: a reshare MUST preserve the group public key — old signatures
	// must still verify. A reshare that changes the key is a keygen, not a
	// refresh; reject it.
	if string(newEra.MLDSAPubKey) != string(s.era.MLDSAPubKey) {
		return errors.New("pulsard: reshare changed the group public key — that is a keygen, not a refresh")
	}
	s.era = newEra
	return nil
}

// ReleaseGate verifies ev over subject under era using the CHAIN's own verifier
// (warp.VerifyPulsar). It is the single, mandatory check every signature passes
// before pulsard emits evidence. Exported so callers wiring a custom engine can
// assert the gate directly in tests.
func ReleaseGate(ev warp.PulsarEvidence, subject []byte, era warp.PulsarKeyEra) error {
	if err := warp.VerifyPulsar(ev, subject, era); err != nil {
		return fmt.Errorf("%w: %v", ErrReleaseGate, err)
	}
	return nil
}

// compile-time: Signer is a warp.PulsarThresholdSigner.
var _ warp.PulsarThresholdSigner = (*Signer)(nil)

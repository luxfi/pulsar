// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// session.go — the signing-session state machine. A Session is the shared,
// in-memory transcript a coordinator maintains while a [ThresholdEngine] drives
// the TALUS rounds: it enforces legal phase transitions (protocol.go), records
// the public round messages, counts per-phase quorums, and routes blame to a
// terminal identifiable-abort. It holds NO secret material and runs no crypto;
// that is the engine's job. Everything here is deterministic and unit-tested.

package pulsard

import (
	"errors"
	"fmt"

	"github.com/luxfi/warp"
)

var (
	// ErrIllegalTransition is returned by Advance for a transition not in the
	// phaseTransitions table.
	ErrIllegalTransition = errors.New("pulsard: illegal phase transition")

	// ErrWrongPhase is returned when a round message is recorded in a phase that
	// does not accept it.
	ErrWrongPhase = errors.New("pulsard: round message recorded in the wrong phase")

	// ErrBadCommittee is returned for a committee that is not 1 ≤ T ≤ N.
	ErrBadCommittee = errors.New("pulsard: committee must satisfy 1 <= threshold <= parties")
)

// Committee is the signing committee size: a reconstruction threshold T of N
// parties. It is the offline-side shape; the on-chain era separately records the
// stake-weighted quorum the key authorizes (warp.PulsarKeyEra.Threshold).
type Committee struct {
	Threshold int // T: signers required to produce a signature
	Parties   int // N: committee members
}

// Validate fails closed unless 1 ≤ Threshold ≤ Parties.
func (c Committee) Validate() error {
	if c.Threshold < 1 || c.Parties < c.Threshold {
		return fmt.Errorf("%w: T=%d N=%d", ErrBadCommittee, c.Threshold, c.Parties)
	}
	return nil
}

// MinPartiesMPC is the minimum committee size N for a TEE-free (MPC) profile at
// threshold T, encoding TALUS Theorem 10.1: a single-round Shamir carry protocol
// with T ≥ 3 needs N ≥ 2T−1 for information-theoretic privacy of the degree-2(T−1)
// product the BGW multiplication forms during carry comparison; for T ≤ 2 any
// N ≥ T suffices. A TEE-assisted profile has no such bound.
func (c Committee) MinPartiesMPC() int {
	if c.Threshold < 3 {
		return c.Threshold
	}
	return 2*c.Threshold - 1
}

// Session is one signing session over a subject under a key era.
type Session struct {
	id        [32]byte
	subject   []byte
	era       warp.PulsarKeyEra
	committee Committee
	phase     Phase

	// Public round transcript (no secrets).
	nonceDeals []NonceDKGDeal
	bccShares  []BCCShare
	cefShares  []CEFCarryShare
	cscpShares []CSCPShare
	partials   []PartialZ
	blame      []BlameAccusation
}

// NewSession starts a session at PhaseInit. It fails closed if the subject is
// not a 32-byte digest or the committee is malformed — no nonce is ever spent on
// an unsignable request.
func NewSession(subject []byte, era warp.PulsarKeyEra, committee Committee) (*Session, error) {
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}
	if err := committee.Validate(); err != nil {
		return nil, err
	}
	s := &Session{
		subject:   append([]byte(nil), subject...),
		era:       era,
		committee: committee,
		phase:     PhaseInit,
	}
	s.id = DeriveSessionID(subject, era)
	return s, nil
}

// ID is the deterministic session identifier (DeriveSessionID).
func (s *Session) ID() [32]byte { return s.id }

// Subject returns a copy of the 32-byte subject.
func (s *Session) Subject() []byte { return append([]byte(nil), s.subject...) }

// Era returns the key era this session signs under.
func (s *Session) Era() warp.PulsarKeyEra { return s.era }

// Committee returns the committee shape.
func (s *Session) Committee() Committee { return s.committee }

// Phase returns the current phase.
func (s *Session) Phase() Phase { return s.phase }

// Done reports terminal success; Aborted reports terminal failure.
func (s *Session) Done() bool    { return s.phase == PhaseDone }
func (s *Session) Aborted() bool { return s.phase == PhaseAborted }

// Advance moves to the next phase, enforcing the legal-transition table.
func (s *Session) Advance(to Phase) error {
	if !CanTransition(s.phase, to) {
		return fmt.Errorf("%w: %s -> %s", ErrIllegalTransition, s.phase, to)
	}
	s.phase = to
	return nil
}

// RecordNonceDeal records a nonce-DKG deal; valid only in PhaseNonceDKG.
func (s *Session) RecordNonceDeal(d NonceDKGDeal) error {
	if s.phase != PhaseNonceDKG {
		return fmt.Errorf("%w: nonce-deal in %s", ErrWrongPhase, s.phase)
	}
	s.nonceDeals = append(s.nonceDeals, d)
	return nil
}

// RecordBCC records a BCC commitment share; valid only in PhaseBCC.
func (s *Session) RecordBCC(sh BCCShare) error {
	if s.phase != PhaseBCC {
		return fmt.Errorf("%w: bcc-share in %s", ErrWrongPhase, s.phase)
	}
	s.bccShares = append(s.bccShares, sh)
	return nil
}

// RecordCEF records a carry-elimination share; valid only in PhaseCEF.
func (s *Session) RecordCEF(sh CEFCarryShare) error {
	if s.phase != PhaseCEF {
		return fmt.Errorf("%w: cef-share in %s", ErrWrongPhase, s.phase)
	}
	s.cefShares = append(s.cefShares, sh)
	return nil
}

// RecordCSCP records a secure-comparison share; valid only in PhaseCSCP.
func (s *Session) RecordCSCP(sh CSCPShare) error {
	if s.phase != PhaseCSCP {
		return fmt.Errorf("%w: cscp-share in %s", ErrWrongPhase, s.phase)
	}
	s.cscpShares = append(s.cscpShares, sh)
	return nil
}

// RecordPartialZ records an online z-partial; valid only in PhaseAggregate.
func (s *Session) RecordPartialZ(p PartialZ) error {
	if s.phase != PhaseAggregate {
		return fmt.Errorf("%w: partial-z in %s", ErrWrongPhase, s.phase)
	}
	s.partials = append(s.partials, p)
	return nil
}

// Blame records an accusation and moves the session to identifiable abort
// (PhaseBlame). It is legal from any active phase; the session is expected to
// then Advance to PhaseAborted.
func (s *Session) Blame(acc BlameAccusation) error {
	if !CanTransition(s.phase, PhaseBlame) {
		return fmt.Errorf("%w: blame from %s", ErrIllegalTransition, s.phase)
	}
	s.blame = append(s.blame, acc)
	s.phase = PhaseBlame
	return nil
}

// BlameLog returns the accusations recorded this session.
func (s *Session) BlameLog() []BlameAccusation {
	return append([]BlameAccusation(nil), s.blame...)
}

// HasQuorum reports whether the given phase has collected messages from at least
// Threshold DISTINCT senders. Used by a coordinator to decide when a round is
// complete. Only the four contribution phases and Aggregate carry messages.
func (s *Session) HasQuorum(phase Phase) bool {
	return s.distinctSenders(phase) >= s.committee.Threshold
}

// distinctSenders counts unique NodeIDs that contributed in a phase.
func (s *Session) distinctSenders(phase Phase) int {
	seen := make(map[NodeID]struct{})
	switch phase {
	case PhaseNonceDKG:
		for _, m := range s.nonceDeals {
			seen[m.From] = struct{}{}
		}
	case PhaseBCC:
		for _, m := range s.bccShares {
			seen[m.From] = struct{}{}
		}
	case PhaseCEF:
		for _, m := range s.cefShares {
			seen[m.From] = struct{}{}
		}
	case PhaseCSCP:
		for _, m := range s.cscpShares {
			seen[m.From] = struct{}{}
		}
	case PhaseAggregate:
		for _, m := range s.partials {
			seen[m.From] = struct{}{}
		}
	}
	return len(seen)
}

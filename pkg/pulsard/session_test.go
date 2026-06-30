// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// session_test.go — the control plane: the phase state machine, transition
// legality, per-phase recording guards, distinct-sender quorum, and blame
// routing. No crypto here; this is what makes the protocol structure reviewable
// and correct independently of the (pending) dealerless engine.

package pulsard_test

import (
	"errors"
	"testing"

	"github.com/luxfi/pulsar/pkg/pulsard"
)

func newSession(t *testing.T, committee pulsard.Committee) *pulsard.Session {
	t.Helper()
	s, err := pulsard.NewSession(subject32("session-subject"), validEra(t), committee)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	return s
}

// TestSession_HappyPath walks the full TALUS phase sequence with quorum at each
// contribution phase, ending in PhaseDone.
func TestSession_HappyPath(t *testing.T) {
	s := newSession(t, pulsard.Committee{Threshold: 3, Parties: 5})
	var nonceID [32]byte

	mustAdvance := func(to pulsard.Phase) {
		if err := s.Advance(to); err != nil {
			t.Fatalf("Advance(%s): %v", to, err)
		}
	}

	mustAdvance(pulsard.PhaseNonceDKG)
	for i := pulsard.NodeID(0); i < 3; i++ {
		if err := s.RecordNonceDeal(pulsard.NonceDKGDeal{NonceID: nonceID, From: i}); err != nil {
			t.Fatalf("RecordNonceDeal: %v", err)
		}
	}
	if !s.HasQuorum(pulsard.PhaseNonceDKG) {
		t.Fatal("expected nonce-DKG quorum at 3/5")
	}

	mustAdvance(pulsard.PhaseBCC)
	for i := pulsard.NodeID(0); i < 3; i++ {
		_ = s.RecordBCC(pulsard.BCCShare{NonceID: nonceID, From: i})
	}
	mustAdvance(pulsard.PhaseCEF)
	for i := pulsard.NodeID(0); i < 3; i++ {
		_ = s.RecordCEF(pulsard.CEFCarryShare{NonceID: nonceID, From: i})
	}
	mustAdvance(pulsard.PhaseCSCP)
	for i := pulsard.NodeID(0); i < 3; i++ {
		_ = s.RecordCSCP(pulsard.CSCPShare{NonceID: nonceID, From: i})
	}
	mustAdvance(pulsard.PhaseAggregate)
	for i := pulsard.NodeID(0); i < 3; i++ {
		_ = s.RecordPartialZ(pulsard.PartialZ{NonceID: nonceID, From: i})
	}
	if !s.HasQuorum(pulsard.PhaseAggregate) {
		t.Fatal("expected aggregate quorum at 3/5")
	}
	mustAdvance(pulsard.PhaseDone)
	if !s.Done() {
		t.Fatal("session not Done")
	}
}

// TestSession_IllegalTransition asserts the transition table is enforced: phases
// cannot be skipped, and terminal states are terminal.
func TestSession_IllegalTransition(t *testing.T) {
	s := newSession(t, pulsard.Committee{Threshold: 1, Parties: 1})

	// Init cannot jump straight to BCC.
	if err := s.Advance(pulsard.PhaseBCC); !errors.Is(err, pulsard.ErrIllegalTransition) {
		t.Fatalf("Init->BCC err = %v, want ErrIllegalTransition", err)
	}
	// Drive to a terminal state and confirm it is terminal.
	if err := s.Advance(pulsard.PhaseAborted); err != nil {
		t.Fatalf("Init->Aborted: %v", err)
	}
	if err := s.Advance(pulsard.PhaseNonceDKG); !errors.Is(err, pulsard.ErrIllegalTransition) {
		t.Fatalf("Aborted->NonceDKG err = %v, want ErrIllegalTransition", err)
	}
}

// TestSession_WrongPhaseRecord asserts round messages are rejected outside their
// phase.
func TestSession_WrongPhaseRecord(t *testing.T) {
	s := newSession(t, pulsard.Committee{Threshold: 1, Parties: 1})
	if err := s.Advance(pulsard.PhaseNonceDKG); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	// Recording a BCC share in the nonce-DKG phase must fail.
	if err := s.RecordBCC(pulsard.BCCShare{}); !errors.Is(err, pulsard.ErrWrongPhase) {
		t.Fatalf("RecordBCC in nonce-DKG err = %v, want ErrWrongPhase", err)
	}
}

// TestSession_QuorumCountsDistinctSenders asserts a duplicate sender does not
// inflate the quorum count.
func TestSession_QuorumCountsDistinctSenders(t *testing.T) {
	s := newSession(t, pulsard.Committee{Threshold: 3, Parties: 5})
	_ = s.Advance(pulsard.PhaseNonceDKG)
	_ = s.RecordNonceDeal(pulsard.NonceDKGDeal{From: 0})
	_ = s.RecordNonceDeal(pulsard.NonceDKGDeal{From: 1})
	_ = s.RecordNonceDeal(pulsard.NonceDKGDeal{From: 1}) // duplicate sender
	if s.HasQuorum(pulsard.PhaseNonceDKG) {
		t.Fatal("duplicate sender inflated quorum to 3 (only 2 distinct)")
	}
	_ = s.RecordNonceDeal(pulsard.NonceDKGDeal{From: 2})
	if !s.HasQuorum(pulsard.PhaseNonceDKG) {
		t.Fatal("expected quorum at 3 distinct senders")
	}
}

// TestSession_BlameRoutesToAbort asserts blame from an active phase moves to
// PhaseBlame and only PhaseAborted is reachable from there.
func TestSession_BlameRoutesToAbort(t *testing.T) {
	s := newSession(t, pulsard.Committee{Threshold: 2, Parties: 3})
	_ = s.Advance(pulsard.PhaseNonceDKG)
	_ = s.Advance(pulsard.PhaseBCC)
	_ = s.Advance(pulsard.PhaseCEF)

	if err := s.Blame(pulsard.BlameAccusation{Round: pulsard.PhaseCEF, Accuser: 0, Accused: 2}); err != nil {
		t.Fatalf("Blame: %v", err)
	}
	if s.Phase() != pulsard.PhaseBlame {
		t.Fatalf("phase = %s, want blame", s.Phase())
	}
	if len(s.BlameLog()) != 1 {
		t.Fatalf("blame log len = %d, want 1", len(s.BlameLog()))
	}
	// From blame, Done is illegal; only Aborted is allowed.
	if err := s.Advance(pulsard.PhaseDone); !errors.Is(err, pulsard.ErrIllegalTransition) {
		t.Fatalf("Blame->Done err = %v, want ErrIllegalTransition", err)
	}
	if err := s.Advance(pulsard.PhaseAborted); err != nil {
		t.Fatalf("Blame->Aborted: %v", err)
	}
	if !s.Aborted() {
		t.Fatal("session not Aborted")
	}
}

// TestNewSession_RejectsBadInputs asserts subject width and committee validity
// are enforced at session creation.
func TestNewSession_RejectsBadInputs(t *testing.T) {
	era := validEra(t)
	if _, err := pulsard.NewSession(make([]byte, 31), era, pulsard.Committee{Threshold: 1, Parties: 1}); !errors.Is(err, pulsard.ErrBadSubject) {
		t.Errorf("short subject err = %v, want ErrBadSubject", err)
	}
	if _, err := pulsard.NewSession(subject32("ok"), era, pulsard.Committee{Threshold: 0, Parties: 3}); !errors.Is(err, pulsard.ErrBadCommittee) {
		t.Errorf("bad committee err = %v, want ErrBadCommittee", err)
	}
}

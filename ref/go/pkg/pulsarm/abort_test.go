// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

import (
	"bytes"
	"testing"
)

func TestAbortEvidence_RoundTrip(t *testing.T) {
	original := &AbortEvidence{
		Kind:      ComplaintEquivocation,
		Accuser:   NodeID{1, 2, 3},
		Accused:   NodeID{4, 5, 6},
		Epoch:     42,
		Evidence:  []byte("some-evidence-blob"),
		Signature: []byte("identity-key-signature"),
	}
	wire, err := MarshalAbortEvidence(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalAbortEvidence(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != original.Kind {
		t.Fatalf("Kind mismatch")
	}
	if got.Accuser != original.Accuser {
		t.Fatalf("Accuser mismatch")
	}
	if got.Accused != original.Accused {
		t.Fatalf("Accused mismatch")
	}
	if got.Epoch != original.Epoch {
		t.Fatalf("Epoch mismatch")
	}
	if !bytes.Equal(got.Evidence, original.Evidence) {
		t.Fatalf("Evidence mismatch")
	}
	if !bytes.Equal(got.Signature, original.Signature) {
		t.Fatalf("Signature mismatch")
	}
}

func TestAbortEvidence_RejectsSelfAccusation(t *testing.T) {
	e := &AbortEvidence{
		Kind:    ComplaintEquivocation,
		Accuser: NodeID{1},
		Accused: NodeID{1},
	}
	if _, err := MarshalAbortEvidence(e); err != ErrComplaintSelfAcc {
		t.Fatalf("self-accusation not rejected: %v", err)
	}
}

func TestAbortEvidence_RejectsTruncated(t *testing.T) {
	if _, err := UnmarshalAbortEvidence([]byte{0x01}); err != ErrInvalidComplaint {
		t.Fatalf("truncated bytes not rejected: %v", err)
	}
}

func TestAbortEvidence_Nil(t *testing.T) {
	if _, err := MarshalAbortEvidence(nil); err != ErrInvalidComplaint {
		t.Fatalf("nil evidence not rejected: %v", err)
	}
}

func TestAbortEvidence_TranscriptStable(t *testing.T) {
	e := &AbortEvidence{
		Kind:     ComplaintBadDelivery,
		Accuser:  NodeID{1},
		Accused:  NodeID{2},
		Epoch:    7,
		Evidence: []byte("evidence"),
	}
	t1 := TranscriptForComplaint(e)
	t2 := TranscriptForComplaint(e)
	if !bytes.Equal(t1, t2) {
		t.Fatalf("transcript not deterministic")
	}
	if len(t1) == 0 {
		t.Fatalf("empty transcript")
	}
}

func TestComplaintKind_String(t *testing.T) {
	for _, tc := range []struct {
		k    ComplaintKind
		want string
	}{
		{ComplaintEquivocation, "equivocation"},
		{ComplaintBadDelivery, "bad-delivery"},
		{ComplaintMACFailure, "mac-failure"},
		{ComplaintRangeFailure, "range-failure"},
		{ComplaintKind(99), "unknown"},
	} {
		if got := tc.k.String(); got != tc.want {
			t.Fatalf("kind %d: got %q want %q", tc.k, got, tc.want)
		}
	}
}

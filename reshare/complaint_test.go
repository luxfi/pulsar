// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

// TestComplaintSignVerify — round-trip signing and verification of a
// well-formed complaint.
func TestComplaintSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	c := &Complaint{
		TranscriptHash: [32]byte{0xaa, 0xbb, 0xcc},
		SenderID:       3,
		ComplainerID:   7,
		Reason:         ComplaintBadDelivery,
		Evidence:       []byte("test-evidence-blob"),
	}
	c.Sign(priv)
	if !ed25519.Verify(pub, c.Bytes(), c.Signature) {
		t.Fatal("ed25519.Verify against base public key failed")
	}
	if err := c.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestComplaintTamperDetected — modifying any field after signing
// invalidates the signature.
func TestComplaintTamperDetected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	c := &Complaint{
		TranscriptHash: [32]byte{0x01},
		SenderID:       3,
		ComplainerID:   7,
		Reason:         ComplaintBadDelivery,
		Evidence:       []byte("evidence"),
	}
	c.Sign(priv)
	// Tamper.
	c.Reason = ComplaintEquivocation
	if err := c.Verify(); err == nil {
		t.Fatal("Verify accepted tampered complaint")
	}
}

// TestDisqualificationThreshold — the canonical formula yields t-1.
func TestDisqualificationThresholdValues(t *testing.T) {
	cases := []struct {
		tOld int
		want int
	}{
		{1, 1},
		{2, 1},
		{3, 2},
		{5, 4},
		{11, 10},
	}
	for _, c := range cases {
		got := DisqualificationThreshold(c.tOld)
		if got != c.want {
			t.Errorf("DisqualificationThreshold(%d) = %d, want %d", c.tOld, got, c.want)
		}
	}
}

// TestComputeDisqualifiedSet — basic counting + dedup behaviour.
func TestComputeDisqualifiedSet(t *testing.T) {
	const tOld = 5 // threshold = 4 distinct complainers required

	mkComplaint := func(sender, complainer int) *Complaint {
		return &Complaint{
			SenderID:     sender,
			ComplainerID: complainer,
			Reason:       ComplaintBadDelivery,
		}
	}

	// 4 distinct complainers against sender 3 → disqualified.
	// 3 distinct complainers against sender 5 → NOT disqualified.
	// 5 complaints against sender 7 but only from complainers {1, 1, 1, 1, 1}
	// (all by complainer 1, deduped) → only 1 distinct complainer → NOT
	// disqualified.
	complaints := []*Complaint{
		mkComplaint(3, 1), mkComplaint(3, 2), mkComplaint(3, 3), mkComplaint(3, 4),
		mkComplaint(5, 1), mkComplaint(5, 2), mkComplaint(5, 3),
		mkComplaint(7, 1), mkComplaint(7, 1), mkComplaint(7, 1), mkComplaint(7, 1), mkComplaint(7, 1),
	}
	dq := ComputeDisqualifiedSet(complaints, tOld)
	if _, ok := dq[3]; !ok {
		t.Errorf("sender 3 should be disqualified")
	}
	if _, ok := dq[5]; ok {
		t.Errorf("sender 5 should NOT be disqualified (only 3 complainers)")
	}
	if _, ok := dq[7]; ok {
		t.Errorf("sender 7 should NOT be disqualified (1 distinct complainer)")
	}
}

// TestFilterQualifiedQuorum — survivors of disqualification.
func TestFilterQualifiedQuorum(t *testing.T) {
	originalQuorum := []int{1, 2, 3, 4, 5}
	dq := map[int]struct{}{2: {}, 4: {}}

	got, err := FilterQualifiedQuorum(originalQuorum, dq, 3)
	if err != nil {
		t.Fatalf("FilterQualifiedQuorum: %v", err)
	}
	want := []int{1, 3, 5}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	// Disqualifying too many makes the quorum insufficient.
	tooMany := map[int]struct{}{1: {}, 2: {}, 3: {}, 4: {}}
	_, err = FilterQualifiedQuorum(originalQuorum, tooMany, 3)
	if err == nil || !errors.Is(err, ErrInsufficientQuorum) {
		t.Fatalf("expected ErrInsufficientQuorum, got %v", err)
	}
}

// TestComplaintHashStable — same complaint → same hash.
func TestComplaintHashStable(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	c := &Complaint{
		TranscriptHash: [32]byte{0x42},
		SenderID:       9,
		ComplainerID:   1,
		Reason:         ComplaintMissing,
		Evidence:       nil,
	}
	c.Sign(priv)
	a := ComplaintHash(c)
	b := ComplaintHash(c)
	if a != b {
		t.Fatal("ComplaintHash non-deterministic")
	}
}

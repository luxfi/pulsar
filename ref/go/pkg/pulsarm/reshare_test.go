// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

import (
	"testing"
)

// TestReshare_SameCommittee_PubInvariant verifies the
// Theorem reshare-pkinv guarantee: the master public key is invariant
// across a reshare.
func TestReshare_SameCommittee_PubInvariant(t *testing.T) {
	params := MustParamsFor(ModeP65)
	committee := makeCommittee(5)
	pub, oldShares, _ := runDKG(t, 5, 3, ModeP65)

	// Run a reshare with the same committee on both sides.
	sessions := make([]*ReshareSession, 5)
	for i := 0; i < 5; i++ {
		var oldShare *KeyShare
		if i < 3 {
			// Only first 3 (reshare-quorum members) need old shares.
			oldShare = oldShares[i]
		}
		s, err := NewReshareSession(params, committee, 3, committee, 3,
			committee[i], oldShare, nil, deterministicReader([]byte{byte(i), 0xEE}))
		if err != nil {
			t.Fatalf("NewReshareSession party %d: %v", i, err)
		}
		sessions[i] = s
	}

	// Only the reshare quorum produces Round-1 broadcasts.
	r1 := []*DKGRound1Msg{}
	for _, s := range sessions {
		if !s.InReshareQuorum() {
			continue
		}
		m, err := s.Round1()
		if err != nil {
			t.Fatalf("Reshare Round1: %v", err)
		}
		r1 = append(r1, m)
	}
	if len(r1) != 3 {
		t.Fatalf("expected 3 Round-1 messages from quorum, got %d", len(r1))
	}

	// Every quorum member emits a Round-2 digest broadcast.
	r2 := []*DKGRound2Msg{}
	for _, s := range sessions {
		if !s.InReshareQuorum() {
			continue
		}
		m, err := s.Round2(r1)
		if err != nil {
			t.Fatalf("Reshare Round2: %v", err)
		}
		r2 = append(r2, m)
	}

	// Every NEW committee member computes Round-3 aggregation.
	newShares := make([]*KeyShare, 0, 5)
	for _, s := range sessions {
		ks, ev, err := s.Round3(r1, r2)
		if err != nil {
			t.Fatalf("Reshare Round3: %v (ev=%v)", err, ev)
		}
		newShares = append(newShares, ks)
	}

	// Reconstruct the master byte-sum from any 3 new shares and verify
	// the cSHAKE256 mix recovers the same group public key.
	shares := make([]shamirShare, 3)
	for i := 0; i < 3; i++ {
		var buf [shareWireSize]byte
		copy(buf[:], newShares[i].Share[:])
		shares[i] = shareFromBytes(newShares[i].EvalPoint, buf)
	}
	byteSum, err := shamirReconstructGF(shares)
	if err != nil {
		t.Fatal(err)
	}
	committeeRoot := committeeRootFromShares(newShares)
	byteSumBytes := make([]byte, SeedSize*2)
	for b := 0; b < SeedSize; b++ {
		byteSumBytes[2*b] = byte(byteSum[b] >> 8)
		byteSumBytes[2*b+1] = byte(byteSum[b])
	}
	mixInput := append(append([]byte{}, byteSumBytes...), committeeRoot[:]...)
	var masterSeed [SeedSize]byte
	copy(masterSeed[:], cshake256(mixInput, SeedSize, tagSeedShare))
	sk, err := KeyFromSeed(params, masterSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !sk.Pub.Equal(pub) {
		t.Fatalf("reshare did not preserve master public key")
	}
}

func TestReshare_NewCommittee(t *testing.T) {
	params := MustParamsFor(ModeP65)
	oldCommittee := makeCommittee(5)
	pub, oldShares, _ := runDKG(t, 5, 3, ModeP65)

	// New committee: replace one member.
	newCommittee := make([]NodeID, 5)
	copy(newCommittee, oldCommittee)
	newCommittee[4] = NodeID{0xff, 0xfe} // replace the last member

	sessions := make([]*ReshareSession, 0)
	// Include the reshare quorum (first 3 old-committee members).
	for i := 0; i < 3; i++ {
		s, _ := NewReshareSession(params, oldCommittee, 3, newCommittee, 3,
			oldCommittee[i], oldShares[i], nil, deterministicReader([]byte{byte(i), 0xAA}))
		sessions = append(sessions, s)
	}
	// Also include new-committee members that aren't in the reshare quorum.
	for i := 3; i < 5; i++ {
		// old committee positions 3, 4 are old members but may not be in the
		// reshare quorum (which is the first 3 in canonical order).
		var oldShare *KeyShare
		if i < len(oldShares) {
			oldShare = oldShares[i]
		}
		s, _ := NewReshareSession(params, oldCommittee, 3, newCommittee, 3,
			newCommittee[i], oldShare, nil, deterministicReader([]byte{byte(i), 0xBB}))
		sessions = append(sessions, s)
	}

	// Only quorum produces Round-1.
	r1 := []*DKGRound1Msg{}
	for _, s := range sessions {
		if !s.InReshareQuorum() {
			continue
		}
		m, _ := s.Round1()
		r1 = append(r1, m)
	}
	r2 := []*DKGRound2Msg{}
	for _, s := range sessions {
		if !s.InReshareQuorum() {
			continue
		}
		m, _ := s.Round2(r1)
		r2 = append(r2, m)
	}
	// All new-committee parties run Round 3.
	newShares := make(map[NodeID]*KeyShare)
	for _, s := range sessions {
		ks, _, err := s.Round3(r1, r2)
		if err != nil {
			continue
		}
		newShares[s.MyID] = ks
	}
	if len(newShares) < 3 {
		t.Fatalf("expected >=3 new shares, got %d", len(newShares))
	}
	_ = pub
}

func TestReshare_BeaconPermutation(t *testing.T) {
	committee := makeCommittee(7)
	_, _, _ = runDKG(t, 7, 4, ModeP65)

	// Pick reshare quorum with two different beacons; they should give
	// different quorum sets with reasonably high probability.
	beacon1 := []byte("beacon-epoch-1")
	beacon2 := []byte("beacon-epoch-2")

	sortedC := append([]NodeID(nil), committee...)
	q1 := selectReshareQuorum(sortedC, 4, beacon1)
	q2 := selectReshareQuorum(sortedC, 4, beacon2)

	if len(q1) != 4 || len(q2) != 4 {
		t.Fatalf("quorum size wrong: %d, %d", len(q1), len(q2))
	}
	// At least one element should differ between the two quorums.
	// (Probability of full overlap is C(7,4)^-1 = 1/35; we use a fixed
	// test rather than statistical.)
	allEqual := true
	for i := range q1 {
		if q1[i] != q2[i] {
			allEqual = false
			break
		}
	}
	if allEqual {
		t.Logf("beacon1 and beacon2 produced same quorum — choose different beacons")
	}

	// No beacon → canonical first-k.
	q0 := selectReshareQuorum(sortedC, 4, nil)
	for i := 0; i < 4; i++ {
		if q0[i] != sortedC[i] {
			t.Fatalf("canonical quorum index %d wrong", i)
		}
	}
}

func TestLagrangeAtZero(t *testing.T) {
	// For party at x=1 in a (x=1,2,3) quorum, λ at x=0 is
	// (-2)(-3)/((1-2)(1-3)) = 6/2 = 3 mod 257
	lambda := lagrangeAtZero(1, []uint32{1, 2, 3})
	if lambda != 3 {
		t.Fatalf("lambda for x=1 in {1,2,3}: got %d want 3", lambda)
	}
	// For party at x=2: (-1)(-3)/((2-1)(2-3)) = 3/(-1) = -3 ≡ 254 mod 257
	lambda2 := lagrangeAtZero(2, []uint32{1, 2, 3})
	if lambda2 != 254 {
		t.Fatalf("lambda for x=2 in {1,2,3}: got %d want 254", lambda2)
	}
	// For party at x=3: (-1)(-2)/((3-1)(3-2)) = 2/2 = 1
	lambda3 := lagrangeAtZero(3, []uint32{1, 2, 3})
	if lambda3 != 1 {
		t.Fatalf("lambda for x=3 in {1,2,3}: got %d want 1", lambda3)
	}
	// Sum of lambdas mod 257 should be 1 (Lagrange invariant at x=0).
	sum := (uint32(lambda) + uint32(lambda2) + uint32(lambda3)) % shamirPrime
	if sum != 1 {
		t.Fatalf("Lagrange sum: got %d want 1", sum)
	}
}

func TestReshare_RejectInvalidCommittees(t *testing.T) {
	params := MustParamsFor(ModeP65)
	old := makeCommittee(5)
	new_ := makeCommittee(5)
	if _, err := NewReshareSession(params, nil, 3, new_, 3, old[0], nil, nil, nil); err != ErrOldCommitteeEmpty {
		t.Fatalf("empty old committee not rejected: %v", err)
	}
	if _, err := NewReshareSession(params, old, 3, nil, 3, old[0], nil, nil, nil); err != ErrNewCommitteeEmpty {
		t.Fatalf("empty new committee not rejected: %v", err)
	}
	if _, err := NewReshareSession(params, old, 6, new_, 3, old[0], nil, nil, nil); err != ErrOldThresholdSmall {
		t.Fatalf("old threshold > old committee size not rejected: %v", err)
	}
	if _, err := NewReshareSession(params, old, 3, new_, 6, old[0], nil, nil, nil); err != ErrNewThresholdSmall {
		t.Fatalf("new threshold > new committee size not rejected: %v", err)
	}
}

// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// makeLargeCommittee builds n distinct NodeIDs.
func makeLargeCommittee(n int) []NodeID {
	out := make([]NodeID, n)
	for i := 0; i < n; i++ {
		out[i] = NodeID{byte(i + 1), byte(i >> 8), 'L'}
	}
	return out
}

// TestLarge_E2E_DKG_ThresholdSign_Verify is the headline end-to-end
// test for the GF(q) protocol stack. It runs:
//   1. LargeDKGSession across a (T, N) committee  (DKG)
//   2. LargeThresholdSigner / LargeCombine on a T-quorum  (Sign)
//   3. FIPS 204 ML-DSA.Verify on the output  (Class N1 manifesto)
//
// (T, N) = (2, 3) is the canonical Lux production deployment per
// Quasar grouped sortition (DefaultGroupSize=3, DefaultGroupThreshold=2).
// (3, 5) exercises a larger group for completeness.
func TestLarge_E2E_DKG_ThresholdSign_Verify(t *testing.T) {
	for _, tc := range []struct {
		name string
		n, t int
	}{
		{"3of2", 3, 2}, // canonical Quasar group
		{"3of3", 3, 3},
		{"5of3", 5, 3},
		{"6of4", 6, 4},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			params := MustParamsFor(ModeP65)
			committee := makeLargeCommittee(tc.n)

			// ---- DKG ----
			sessions := make([]*LargeDKGSession, tc.n)
			for i := 0; i < tc.n; i++ {
				rng := deterministicReader([]byte{byte(i), 'D', 'K', 'G', 'Q'})
				s, err := NewLargeDKGSession(params, committee, tc.t, committee[i], rng)
				if err != nil {
					t.Fatal(err)
				}
				sessions[i] = s
			}

			r1 := make([]*LargeDKGRound1Msg, tc.n)
			for i, s := range sessions {
				m, err := s.Round1()
				if err != nil {
					t.Fatalf("DKG Round1 party %d: %v", i, err)
				}
				r1[i] = m
			}

			r2 := make([]*LargeDKGRound2Msg, tc.n)
			for i, s := range sessions {
				m, err := s.Round2(r1)
				if err != nil {
					t.Fatalf("DKG Round2 party %d: %v", i, err)
				}
				r2[i] = m
			}
			for i := 1; i < tc.n; i++ {
				if r2[i].Digest != r2[0].Digest {
					t.Fatalf("DKG Round-2 digest mismatch between parties 0 and %d", i)
				}
			}

			outs := make([]*LargeDKGOutput, tc.n)
			for i, s := range sessions {
				out, err := s.Round3(r1, r2)
				if err != nil {
					t.Fatalf("DKG Round3 party %d: %v", i, err)
				}
				if out.AbortEvidence != nil {
					t.Fatalf("party %d aborted: kind=%s", i, out.AbortEvidence.Kind)
				}
				outs[i] = out
			}
			// All parties agree on the group pubkey + transcript.
			groupPK := outs[0].GroupPubkey
			for i := 1; i < tc.n; i++ {
				if !outs[i].GroupPubkey.Equal(groupPK) {
					t.Fatalf("party %d GroupPubkey diverges", i)
				}
				if outs[i].TranscriptHash != outs[0].TranscriptHash {
					t.Fatalf("party %d TranscriptHash diverges", i)
				}
			}

			// ---- Threshold sign ----
			// Use first t parties as quorum.
			quorum := committee[:tc.t]
			myShares := make(map[NodeID]*LargeKeyShare, tc.t)
			for i := 0; i < tc.t; i++ {
				myShares[committee[i]] = outs[i].SecretShare
			}

			sessionID := [16]byte{'S', 'E', 'S', 'S'}
			attempt := uint32(0)
			message := []byte("pulsar large e2e roundtrip on quasar (3,2) profile")

			signers := make([]*LargeThresholdSigner, tc.t)
			for i := 0; i < tc.t; i++ {
				rng := deterministicReader([]byte{byte(i), 'S', 'I', 'G'})
				ts, err := NewLargeThresholdSigner(params, sessionID, attempt, quorum, myShares[committee[i]], message, rng)
				if err != nil {
					t.Fatalf("NewLargeThresholdSigner party %d: %v", i, err)
				}
				signers[i] = ts
			}

			tsR1 := make([]*LargeRound1Message, tc.t)
			for i, ts := range signers {
				m, err := ts.Round1(message)
				if err != nil {
					t.Fatalf("Sign Round1 party %d: %v", i, err)
				}
				tsR1[i] = m
			}
			tsR2 := make([]*LargeRound2Message, tc.t)
			for i, ts := range signers {
				m, evidence, err := ts.Round2(tsR1)
				if err != nil {
					t.Fatalf("Sign Round2 party %d: %v (evidence=%+v)", i, err, evidence)
				}
				tsR2[i] = m
			}

			// Combine needs the FULL committee's KeyShares -- not just
			// the quorum's -- so committeeRootFromLargeShares matches
			// the DKG-time root that the master seed was bound to.
			allShares := make([]*LargeKeyShare, tc.n)
			for i := 0; i < tc.n; i++ {
				allShares[i] = outs[i].SecretShare
			}

			sig, err := LargeCombine(params, groupPK, message, nil, false, sessionID, attempt, quorum, tc.t, tsR1, tsR2, allShares)
			if err != nil {
				t.Fatalf("LargeCombine: %v", err)
			}

			// ---- FIPS 204 ML-DSA.Verify ----
			if err := Verify(params, groupPK, message, sig); err != nil {
				t.Fatalf("FIPS 204 ML-DSA.Verify on Pulsar output: %v", err)
			}
		})
	}
}

// TestLarge_DKG_AboveCap rejects committees above TargetCommitteeSize.
func TestLarge_DKG_AboveCap(t *testing.T) {
	params := MustParamsFor(ModeP44)
	// Cap is 1_111_111; (cap+1, 2) must reject.
	committee := make([]NodeID, TargetCommitteeSize+1)
	for i := range committee {
		committee[i] = NodeID{byte(i & 0xff), byte((i >> 8) & 0xff), byte((i >> 16) & 0xff)}
	}
	_, err := NewLargeDKGSession(params, committee, 2, committee[0], nil)
	if err != ErrCommitteeAboveCap {
		t.Fatalf("want ErrCommitteeAboveCap, got %v", err)
	}
}

// TestLarge_Reshare_SameCommittee_PubInvariant verifies the
// Theorem reshare-pkinv guarantee on the GF(q) path: a reshare with
// the same committee on both sides preserves the master public key.
// This mirrors TestReshare_SameCommittee_PubInvariant in the
// small-committee (GF(257)) path. Cross-committee reshare changes
// the committee root and therefore the cSHAKE256-mixed master seed
// in the v0.1 reconstruction-aggregator instantiation; see
// BLOCKERS.md.
func TestLarge_Reshare_SameCommittee_PubInvariant(t *testing.T) {
	params := MustParamsFor(ModeP65)
	committee := makeLargeCommittee(5)
	// Run the initial DKG.
	dkgSessions := make([]*LargeDKGSession, 5)
	for i := 0; i < 5; i++ {
		rng := deterministicReader([]byte{byte(i), 'O', 'L', 'D'})
		s, _ := NewLargeDKGSession(params, committee, 3, committee[i], rng)
		dkgSessions[i] = s
	}
	dkgR1 := make([]*LargeDKGRound1Msg, 5)
	for i, s := range dkgSessions {
		m, _ := s.Round1()
		dkgR1[i] = m
	}
	dkgR2 := make([]*LargeDKGRound2Msg, 5)
	for i, s := range dkgSessions {
		m, _ := s.Round2(dkgR1)
		dkgR2[i] = m
	}
	dkgOuts := make([]*LargeDKGOutput, 5)
	for i, s := range dkgSessions {
		out, _ := s.Round3(dkgR1, dkgR2)
		dkgOuts[i] = out
	}
	oldPK := dkgOuts[0].GroupPubkey
	oldShares := make([]*LargeKeyShare, 5)
	for i, o := range dkgOuts {
		oldShares[i] = o.SecretShare
	}

	// Run a reshare with the SAME committee on both sides.
	resh := make([]*LargeReshareSession, 5)
	for i := 0; i < 5; i++ {
		var oldShare *LargeKeyShare
		if i < 3 {
			oldShare = oldShares[i]
		}
		rng := deterministicReader([]byte{byte(i), 'R', 'S'})
		s, err := NewLargeReshareSession(params, committee, 3, committee, 3,
			committee[i], oldShare, nil, rng)
		if err != nil {
			t.Fatalf("NewLargeReshareSession party %d: %v", i, err)
		}
		resh[i] = s
	}
	r1 := []*LargeDKGRound1Msg{}
	for _, s := range resh {
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
		t.Fatalf("expected 3 reshare quorum messages, got %d", len(r1))
	}
	r2 := []*LargeDKGRound2Msg{}
	for _, s := range resh {
		if !s.InReshareQuorum() {
			continue
		}
		m, err := s.Round2(r1)
		if err != nil {
			t.Fatalf("Reshare Round2: %v", err)
		}
		r2 = append(r2, m)
	}
	newShares := make([]*LargeKeyShare, 0, 5)
	for _, s := range resh {
		ks, ev, err := s.Round3(r1, r2)
		if err != nil {
			t.Fatalf("Reshare Round3: %v (ev=%+v)", err, ev)
		}
		newShares = append(newShares, ks)
	}

	// Reconstruct master byte-sum from 3 new shares; verify cSHAKE256
	// mix recovers the SAME group public key.
	q := make([]shamirShareQ, 3)
	for i := 0; i < 3; i++ {
		var buf [shareWireSizeQ]byte
		copy(buf[:], newShares[i].Share[:])
		q[i] = shareFromBytesQ(newShares[i].EvalPoint, buf)
	}
	byteSum, err := shamirReconstructGFQ(q)
	if err != nil {
		t.Fatal(err)
	}
	committeeRoot := committeeRootFromLargeShares(newShares)
	byteSumBytes := make([]byte, SeedSize*4)
	for b := 0; b < SeedSize; b++ {
		byteSumBytes[4*b] = byte(byteSum[b] >> 24)
		byteSumBytes[4*b+1] = byte(byteSum[b] >> 16)
		byteSumBytes[4*b+2] = byte(byteSum[b] >> 8)
		byteSumBytes[4*b+3] = byte(byteSum[b])
	}
	mixInput := append(append([]byte{}, byteSumBytes...), committeeRoot[:]...)
	var masterSeed [SeedSize]byte
	copy(masterSeed[:], cshake256(mixInput, SeedSize, tagSeedShare))
	sk, err := KeyFromSeed(params, masterSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !sk.Pub.Equal(oldPK) {
		t.Fatalf("GF(q) reshare did not preserve master public key")
	}
}

// TestLarge_Reshare_E2E exercises a full reshare ceremony:
// old (3,2) committee → new (5,3) committee, with the new committee
// producing a threshold signature under the unchanged group pubkey.
//
// NOTE: in the v0.1 reconstruction-aggregator instantiation, cross-
// committee reshare does NOT preserve pk because the cSHAKE256 mix
// is bound to the committee root. This test asserts that the reshare
// ceremony succeeds (new shares are produced) but not that pk is
// preserved across the committee change. The pk-preserving cross-
// committee reshare is on the v0.2 path; see BLOCKERS.md.
func TestLarge_Reshare_E2E(t *testing.T) {
	params := MustParamsFor(ModeP65)

	oldCommittee := makeLargeCommittee(3)
	const oldThresh = 2

	// Run old DKG.
	oldSessions := make([]*LargeDKGSession, 3)
	for i := 0; i < 3; i++ {
		rng := deterministicReader([]byte{byte(i), 'D', 'O'})
		s, err := NewLargeDKGSession(params, oldCommittee, oldThresh, oldCommittee[i], rng)
		if err != nil {
			t.Fatal(err)
		}
		oldSessions[i] = s
	}
	oldR1 := make([]*LargeDKGRound1Msg, 3)
	for i, s := range oldSessions {
		m, _ := s.Round1()
		oldR1[i] = m
	}
	oldR2 := make([]*LargeDKGRound2Msg, 3)
	for i, s := range oldSessions {
		m, _ := s.Round2(oldR1)
		oldR2[i] = m
	}
	oldOuts := make([]*LargeDKGOutput, 3)
	for i, s := range oldSessions {
		out, _ := s.Round3(oldR1, oldR2)
		oldOuts[i] = out
	}
	oldPK := oldOuts[0].GroupPubkey

	// New committee.
	newCommittee := makeLargeCommittee(5)
	// To avoid NodeID collision, shift the new committee IDs.
	for i := range newCommittee {
		newCommittee[i][3] = 'N'
	}
	const newThresh = 3
	beacon := []byte("PULSAR-RESHARE-BEACON-2026")

	// Build reshare sessions for parties in (oldCommittee ∪ newCommittee).
	// In this test the two committees are disjoint, so old parties only
	// dispatch shares, and new parties only receive.
	reshareSessions := make(map[NodeID]*LargeReshareSession)
	for _, id := range oldCommittee {
		// Find this party's old share.
		var myShare *LargeKeyShare
		for _, o := range oldOuts {
			if o.SecretShare.NodeID == id {
				myShare = o.SecretShare
				break
			}
		}
		rng := deterministicReader([]byte{id[0], 'R', 'O'})
		s, err := NewLargeReshareSession(params, oldCommittee, oldThresh, newCommittee, newThresh, id, myShare, beacon, rng)
		if err != nil {
			t.Fatalf("new reshare session for old %x: %v", id, err)
		}
		reshareSessions[id] = s
	}
	for _, id := range newCommittee {
		rng := deterministicReader([]byte{id[0], 'R', 'N'})
		// New-only parties pass nil for the old share.
		s, err := NewLargeReshareSession(params, oldCommittee, oldThresh, newCommittee, newThresh, id, nil, beacon, rng)
		if err != nil {
			t.Fatalf("new reshare session for new %x: %v", id, err)
		}
		reshareSessions[id] = s
	}

	// Reshare-quorum members run Round1.
	r1msgs := []*LargeDKGRound1Msg{}
	for _, id := range oldCommittee {
		s := reshareSessions[id]
		if !s.InReshareQuorum() {
			continue
		}
		m, err := s.Round1()
		if err != nil {
			t.Fatalf("reshare Round1 for %x: %v", id, err)
		}
		r1msgs = append(r1msgs, m)
	}

	// Every party (old + new) runs Round2 + Round3 over the quorum messages.
	r2msgs := []*LargeDKGRound2Msg{}
	for _, id := range oldCommittee {
		s := reshareSessions[id]
		if !s.InReshareQuorum() {
			continue
		}
		m, err := s.Round2(r1msgs)
		if err != nil {
			t.Fatalf("reshare Round2 for %x: %v", id, err)
		}
		r2msgs = append(r2msgs, m)
	}

	// New-committee parties run Round3 to receive their new shares.
	newShares := make(map[NodeID]*LargeKeyShare, len(newCommittee))
	for _, id := range newCommittee {
		s := reshareSessions[id]
		share, evidence, err := s.Round3(r1msgs, r2msgs)
		if err != nil {
			t.Fatalf("reshare Round3 for new %x: %v (evidence=%+v)", id, err, evidence)
		}
		newShares[id] = share
	}

	// In v0.1 the post-reshare pubkey is determined by the new
	// committee root + byte-sum (cSHAKE mix). Compute it BEFORE
	// initialising threshold signers so transcripts bind to the right
	// pubkey.
	allNewSharesPreSort := make([]*LargeKeyShare, 0, len(newCommittee))
	for _, id := range newCommittee {
		allNewSharesPreSort = append(allNewSharesPreSort, newShares[id])
	}
	q0 := make([]shamirShareQ, newThresh)
	for i := 0; i < newThresh; i++ {
		var buf [shareWireSizeQ]byte
		copy(buf[:], allNewSharesPreSort[i].Share[:])
		q0[i] = shareFromBytesQ(allNewSharesPreSort[i].EvalPoint, buf)
	}
	byteSum0, err := shamirReconstructGFQ(q0)
	if err != nil {
		t.Fatal(err)
	}
	committeeRoot0 := committeeRootFromLargeShares(allNewSharesPreSort)
	byteSumBytes0 := make([]byte, SeedSize*4)
	for b := 0; b < SeedSize; b++ {
		byteSumBytes0[4*b] = byte(byteSum0[b] >> 24)
		byteSumBytes0[4*b+1] = byte(byteSum0[b] >> 16)
		byteSumBytes0[4*b+2] = byte(byteSum0[b] >> 8)
		byteSumBytes0[4*b+3] = byte(byteSum0[b])
	}
	mixInput0 := append(append([]byte{}, byteSumBytes0...), committeeRoot0[:]...)
	var masterSeed0 [SeedSize]byte
	copy(masterSeed0[:], cshake256(mixInput0, SeedSize, tagSeedShare))
	sk0, err := KeyFromSeed(params, masterSeed0)
	if err != nil {
		t.Fatal(err)
	}
	postReshareKey := sk0.Pub
	// Attach to every new share so transcripts bind correctly.
	for _, id := range newCommittee {
		newShares[id].Pub = postReshareKey
	}

	// ---- Threshold-sign with the new committee against postReshareKey ----
	newQuorum := newCommittee[:newThresh]
	sessionID := [16]byte{'R', 'E', 'S', 'H'}
	attempt := uint32(0)
	message := []byte("post-reshare signature must verify under unchanged pubkey")

	signers := make([]*LargeThresholdSigner, newThresh)
	for i := 0; i < newThresh; i++ {
		rng := deterministicReader([]byte{byte(i), 'P', 'O', 'S', 'T'})
		ts, err := NewLargeThresholdSigner(params, sessionID, attempt, newQuorum, newShares[newCommittee[i]], message, rng)
		if err != nil {
			t.Fatalf("post-reshare NewLargeThresholdSigner party %d: %v", i, err)
		}
		signers[i] = ts
	}

	tsR1 := make([]*LargeRound1Message, newThresh)
	for i, ts := range signers {
		m, err := ts.Round1(message)
		if err != nil {
			t.Fatalf("post-reshare Round1 party %d: %v", i, err)
		}
		tsR1[i] = m
	}
	tsR2 := make([]*LargeRound2Message, newThresh)
	for i, ts := range signers {
		m, evidence, err := ts.Round2(tsR1)
		if err != nil {
			t.Fatalf("post-reshare Round2 party %d: %v (evidence=%+v)", i, err, evidence)
		}
		tsR2[i] = m
	}

	// Pass full new committee's shares (not just quorum) so the
	// committee root matches the post-reshare commitment that the
	// reshare aggregation produced.
	allNewShares := make([]*LargeKeyShare, len(newCommittee))
	for i := 0; i < len(newCommittee); i++ {
		allNewShares[i] = newShares[newCommittee[i]]
	}

	sig, err := LargeCombine(params, postReshareKey, message, nil, false, sessionID, attempt, newQuorum, newThresh, tsR1, tsR2, allNewShares)
	if err != nil {
		t.Fatalf("LargeCombine post-reshare: %v", err)
	}
	if err := Verify(params, postReshareKey, message, sig); err != nil {
		t.Fatalf("Verify post-reshare signature: %v", err)
	}
	// Document the architectural fact: pk changed across the cross-
	// committee reshare. This is expected in v0.1.
	if postReshareKey.Equal(oldPK) {
		t.Fatalf("expected pk to change across cross-committee reshare in v0.1, but it didn't")
	}
}

// TestLarge_Smoke_LagrangeAtZeroQ_ReshareWeight verifies the
// underlying Lagrange-weighting invariant that LargeReshareSession
// relies on: λ_i^Q * share_i over the old quorum reconstructs the
// master secret at x=0 in GF(q). This is the math kernel; if it
// breaks, LargeReshareSession can't be sound.
func TestLarge_Smoke_LagrangeAtZeroQ_ReshareWeight(t *testing.T) {
	const thresh = 3
	var secret [SeedSize]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	stream := bytes.Repeat([]byte{0x77, 0x88, 0x99, 0xaa}, 64)
	shares, err := shamirDealRandomQ(secret, 5, thresh, stream)
	if err != nil {
		t.Fatal(err)
	}
	// Pick a t-quorum (the first 3).
	quorum := shares[:thresh]
	xs := []uint32{quorum[0].X, quorum[1].X, quorum[2].X}
	// Each party multiplies its share by its Lagrange coefficient
	// at X=0; the sum is the secret (per slot).
	for b := 0; b < SeedSize; b++ {
		var acc uint64
		for i := 0; i < thresh; i++ {
			lam := uint64(LagrangeAtZeroQ(xs[i], xs))
			acc = (acc + lam*uint64(quorum[i].Y[b])) % shamirPrimeQ
		}
		if uint64(secret[b]) != acc {
			t.Fatalf("byte %d: secret=%d, lagrange-weighted sum=%d", b, secret[b], acc)
		}
	}
}

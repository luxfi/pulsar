// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03_iso_test.go — TEMPORARY isolation test for v0.3
// algebra debug. Compares per-party z_i computation against an
// inline replica to find where the bug lives.

import "testing"

// TestAlgebraic_Debug_PartyZRecomputation re-runs ONE party's
// Round2Sign computation step-by-step using the SAME inputs the
// real party uses, then compares.
func TestAlgebraic_Debug_PartyZRecomputation(t *testing.T) {
	params := MustParamsFor(ModeP65)
	msg := []byte("v0.3 iso z")
	var sid [16]byte
	copy(sid[:], "v03-iso-z-000001")

	var seed [SeedSize]byte
	copy(seed[:], "v03-iso-master-seed-bytes-fix-32")
	committee := makeCommittee(5)
	ident := newIdentityFixture(t, committee, []byte{0xAA, 0x03})
	setup, shares, err := DealAlgebraicV03Shares(params, committee, 3, seed, deterministicReader([]byte{0xAA, 0x03}))
	if err != nil {
		t.Fatal(err)
	}

	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)
	evalPoints, _ := V03QuorumEvalPoints(quorum, shares)

	signers := make([]*AlgebraicThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, _ := NewAlgebraicThresholdSigner(params, setup, sid, 1, quorum, shares[i],
			sessionKeys[quorum[i]], msg, deterministicReader([]byte{0xAA, byte(i), 0x03}))
		_ = s.SetQuorumEvalPoints(evalPoints)
		signers[i] = s
	}
	r1 := make([]*AlgebraicRound1Message, 3)
	for i, s := range signers {
		r1[i], _ = s.Round1()
	}
	r2W := make([]*AlgebraicRound2Message, 3)
	for i, s := range signers {
		r2W[i], _, _ = s.Round2W(r1)
	}
	K, L, _ := modeShape(ModeP65)
	peerWByParty := make([]map[NodeID]polyVec, 3)
	for i := 0; i < 3; i++ {
		peerW := make(map[NodeID]polyVec, 2)
		for j := 0; j < 3; j++ {
			if j == i {
				continue
			}
			peerW[r2W[j].NodeID] = unpackPolyVec(r2W[j].W, K)
		}
		peerWByParty[i] = peerW
	}
	r2 := make([]*AlgebraicRound2Message, 3)
	for i, s := range signers {
		r2[i], _, _ = s.Round2Sign(r1, peerWByParty[i])
	}

	// Pick party 0 and recompute its z_i, expecting byte-equality.
	p := signers[0]
	r2msg := r2[0]
	partyIdx := 0
	expectedZ := unpackPolyVec(r2msg.Z, L)

	t.Logf("party0 lambda=%d", p.lambda)
	t.Logf("party0 myY[0][0..4]=%v", p.myY[0][0:5])
	t.Logf("party0 Share.S1[0][0..4]=%v", p.Share.S1[0][0:5])
	t.Logf("party0 myWCoeff[0][0..4]=%v", p.myWCoeff[0][0:5])
	t.Logf("expectedZ[0][0..4]=%v", expectedZ[0][0:5])

	// Re-derive c the same way the party did.
	w := make(polyVec, K)
	for i := 0; i < K; i++ {
		w[i] = p.myWCoeff[i]
	}
	for _, m := range r1 {
		if m.NodeID == p.NodeID {
			continue
		}
		wj := peerWByParty[partyIdx][m.NodeID]
		for k := 0; k < K; k++ {
			w[k].add(&w[k], &wj[k])
		}
	}
	for k := 0; k < K; k++ {
		w[k].normalize()
	}
	_, _, _, gamma2 := modeTauOmega(ModeP65)
	w1, _ := decomposeVec(w, gamma2)
	w1Packed := packW1Vec(w1, gamma2, K)
	var mu [64]byte
	{
		h := newShake256()
		_, _ = h.Write(setup.Tr[:])
		_, _ = h.Write(msg)
		_, _ = h.Read(mu[:])
	}
	cTildeSize := modeCTildeSize(ModeP65)
	cTilde := make([]byte, cTildeSize)
	{
		h := newShake256()
		_, _ = h.Write(mu[:])
		_, _ = h.Write(w1Packed)
		_, _ = h.Read(cTilde)
	}
	tau, _, _, _ := modeTauOmega(ModeP65)
	var c poly
	polyDeriveUniformBall(&c, cTilde, tau)

	// Recompute z_i = y_i + (c · λ_0) · s_{1,0}
	lambdaQ := uint64(p.lambda)
	var cLambda poly
	for j := 0; j < mldsaN; j++ {
		cLambda[j] = uint32((uint64(c[j]) * lambdaQ) % uint64(mldsaQ))
	}
	cLambdaHat := cLambda
	cLambdaHat.ntt()

	t.Logf("c[0..4]=%v", c[0:5])
	t.Logf("c[251..255]=%v", c[251:256])
	nz := 0
	for i := 0; i < mldsaN; i++ {
		if c[i] != 0 {
			nz++
		}
	}
	t.Logf("c nonzeros=%d", nz)
	t.Logf("cTilde[0..7]=%v", cTilde[0:8])
	t.Logf("mu[0..7]=%v", mu[0:8])
	t.Logf("w1Packed[0..7]=%v len=%d", w1Packed[0:8], len(w1Packed))
	t.Logf("w[0][0..4]=%v", w[0][0:5])
	t.Logf("cLambda[0..4]=%v", cLambda[0:5])

	recomputedZ := make(polyVec, L)
	for i := 0; i < L; i++ {
		s1iHat := p.Share.S1[i]
		s1iHat.ntt()
		var tmp poly
		tmp.mulHat(&cLambdaHat, &s1iHat)
		tmp.invNTT()
		tmp.normalize()
		yi := p.myY[i]
		if i == 0 {
			t.Logf("recompute i=0: tmp[0..4]=%v yi[0..4]=%v", tmp[0:5], yi[0:5])
		}
		recomputedZ[i].add(&yi, &tmp)
		recomputedZ[i].normalize()
	}
	t.Logf("recomputedZ[0][0..4]=%v", recomputedZ[0][0:5])

	diffs := 0
	for i := 0; i < L; i++ {
		for j := 0; j < mldsaN; j++ {
			if expectedZ[i][j] != recomputedZ[i][j] {
				if diffs < 10 {
					t.Logf("party0 z mismatch L=%d ci=%d: expected (from R2) =%d recomputed=%d", i, j, expectedZ[i][j], recomputedZ[i][j])
				}
				diffs++
			}
		}
	}
	if diffs > 0 {
		t.Fatalf("party0 z self-mismatch in %d positions — the party's z calculation is non-deterministic", diffs)
	}
}

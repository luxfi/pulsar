// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03_debug_test.go — TEMPORARY low-level debug
// instrumentation for the v0.3 algebraic-aggregator path. Once v0.3
// converges, the verbose printlns here go quiet (tests still pass);
// the file stays as in-tree documentation of which invariants the
// implementation depends on.

import (
	"fmt"
	"testing"
)

// TestAlgebraic_Debug_AlgebraicReconstruction probes the load-bearing
// algebraic identity:
//
//   For a t-quorum Q with Lagrange coefficients (λ_i)_{i ∈ Q},
//
//     Σ_{i ∈ Q}  λ_i · s_{1,i}   ≡   s_1   (mod q)    (coefficient-wise)
//
// where s_{1,i} = polynomial-Shamir share of master s_1 at party i's
// evaluation point. If this fails, the v0.3 z = Σ z_j formula is
// wrong by construction.
func TestAlgebraic_Debug_AlgebraicReconstruction(t *testing.T) {
	params := MustParamsFor(ModeP65)
	committee := makeCommittee(5)
	var seed [SeedSize]byte
	copy(seed[:], "v03-dbg-reconstruction-seed-32!!")

	setup, shares, err := DealAlgebraicV03Shares(params, committee, 3, seed, deterministicReader([]byte{0x01, 0x03}))
	if err != nil {
		t.Fatal(err)
	}

	// Re-derive master sk for comparison.
	km, err := deriveKeyMaterial(params.Mode, &seed)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroizeKeyMaterial(km)
	// Normalise master s_1, s_2, t_0 to [0, q) like the dealer does.
	masterS1 := make(polyVec, len(km.s1))
	for i := range km.s1 {
		masterS1[i] = km.s1[i]
		masterS1[i].normalize()
	}
	masterS2 := make(polyVec, len(km.s2))
	for i := range km.s2 {
		masterS2[i] = km.s2[i]
		masterS2[i].normalize()
	}
	masterT0 := make(polyVec, len(km.t0))
	for i := range km.t0 {
		masterT0[i] = km.t0[i]
		for j := 0; j < mldsaN; j++ {
			masterT0[i][j] = modQ(masterT0[i][j])
		}
	}

	// Pick a t-quorum (first 3 shares).
	_ = []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	quorumShares := []*AlgebraicKeyShare{shares[0], shares[1], shares[2]}
	xs := []uint32{shares[0].EvalPoint, shares[1].EvalPoint, shares[2].EvalPoint}

	// Reconstruct s_1: Σ_i λ_i(0) · s_{1,i}
	K, L, _ := modeShape(params.Mode)
	reconS1 := make(polyVec, L)
	for i := range quorumShares {
		lambda := shamirPolyLambda(xs, i)
		for li := 0; li < L; li++ {
			for ci := 0; ci < mldsaN; ci++ {
				contrib := (uint64(lambda) * uint64(quorumShares[i].S1[li][ci])) % uint64(mldsaQ)
				reconS1[li][ci] = uint32((uint64(reconS1[li][ci]) + contrib) % uint64(mldsaQ))
			}
		}
	}
	for li := 0; li < L; li++ {
		if reconS1[li] != masterS1[li] {
			// Look for first diff.
			for ci := 0; ci < mldsaN; ci++ {
				if reconS1[li][ci] != masterS1[li][ci] {
					t.Fatalf("S1 reconstruction mismatch at li=%d ci=%d: got %d want %d", li, ci, reconS1[li][ci], masterS1[li][ci])
				}
			}
		}
	}

	// Reconstruct s_2.
	reconS2 := make(polyVec, K)
	for i := range quorumShares {
		lambda := shamirPolyLambda(xs, i)
		for ki := 0; ki < K; ki++ {
			for ci := 0; ci < mldsaN; ci++ {
				contrib := (uint64(lambda) * uint64(quorumShares[i].S2[ki][ci])) % uint64(mldsaQ)
				reconS2[ki][ci] = uint32((uint64(reconS2[ki][ci]) + contrib) % uint64(mldsaQ))
			}
		}
	}
	for ki := 0; ki < K; ki++ {
		if reconS2[ki] != masterS2[ki] {
			for ci := 0; ci < mldsaN; ci++ {
				if reconS2[ki][ci] != masterS2[ki][ci] {
					t.Fatalf("S2 reconstruction mismatch at ki=%d ci=%d: got %d want %d", ki, ci, reconS2[ki][ci], masterS2[ki][ci])
				}
			}
		}
	}

	// Reconstruct t_0.
	reconT0 := make(polyVec, K)
	for i := range quorumShares {
		lambda := shamirPolyLambda(xs, i)
		for ki := 0; ki < K; ki++ {
			for ci := 0; ci < mldsaN; ci++ {
				contrib := (uint64(lambda) * uint64(quorumShares[i].T0[ki][ci])) % uint64(mldsaQ)
				reconT0[ki][ci] = uint32((uint64(reconT0[ki][ci]) + contrib) % uint64(mldsaQ))
			}
		}
	}
	for ki := 0; ki < K; ki++ {
		if reconT0[ki] != masterT0[ki] {
			for ci := 0; ci < mldsaN; ci++ {
				if reconT0[ki][ci] != masterT0[ki][ci] {
					t.Fatalf("T0 reconstruction mismatch at ki=%d ci=%d: got %d want %d", ki, ci, reconT0[ki][ci], masterT0[ki][ci])
				}
			}
		}
	}

	_ = setup
	_ = fmt.Sprintf("")
}

// TestAlgebraic_Debug_ZSumVsCircl compares Σ z_j (computed via the v0.3
// per-party arithmetic) against the FIPS 204 reference z = y + c·s_1
// where y, c are recovered from the protocol state.
func TestAlgebraic_Debug_ZSumVsCircl(t *testing.T) {
	params := MustParamsFor(ModeP65)
	msg := []byte("v0.3 debug z-sum vs circl")
	var sid [16]byte
	copy(sid[:], "v03-dbg-zsum0001")

	var seed [SeedSize]byte
	copy(seed[:], "v03-dbg-zsum-master-seed-bytes32")
	committee := makeCommittee(5)
	ident := newIdentityFixture(t, committee, []byte{0xDD, 0x03})
	setup, shares, err := DealAlgebraicV03Shares(params, committee, 3, seed, deterministicReader([]byte{0xDD, 0x03}))
	if err != nil {
		t.Fatal(err)
	}

	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)
	evalPoints, _ := V03QuorumEvalPoints(quorum, shares)

	signers := make([]*AlgebraicThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, _ := NewAlgebraicThresholdSigner(params, setup, sid, 1, quorum, shares[i],
			sessionKeys[quorum[i]], msg, deterministicReader([]byte{0xDD, byte(i), 0x03}))
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

	// Recover y_total = Σ y_j from the signer states.
	yTotal := make(polyVec, L)
	for _, s := range signers {
		for l := 0; l < L; l++ {
			yTotal[l].add(&yTotal[l], &s.myY[l])
		}
	}
	for l := 0; l < L; l++ {
		yTotal[l].normalize()
	}

	// Recompute w_total + c̃ + c the same way the protocol did.
	w := make(polyVec, K)
	for _, r2m := range r2 {
		wj := unpackPolyVec(r2m.W, K)
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
	// μ = SHAKE-256(tr || 0x00 || |ctx| || ctx || M, 64) per FIPS 204 §5.4.
	var mu [64]byte
	{
		h := newShake256()
		_, _ = h.Write(setup.Tr[:])
		_, _ = h.Write([]byte{0x00, 0x00})
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

	// Reconstruct s_1 from shares (only valid because this is debug; never do this in production).
	xs := evalPoints
	reconS1 := make(polyVec, L)
	for i := 0; i < 3; i++ {
		lambda := shamirPolyLambda(xs, i)
		for li := 0; li < L; li++ {
			for ci := 0; ci < mldsaN; ci++ {
				contrib := (uint64(lambda) * uint64(shares[i].S1[li][ci])) % uint64(mldsaQ)
				reconS1[li][ci] = uint32((uint64(reconS1[li][ci]) + contrib) % uint64(mldsaQ))
			}
		}
	}

	// Reference z_ref = y_total + c · reconS1 (single-party formula).
	cHat := c
	cHat.ntt()
	zRef := make(polyVec, L)
	for l := 0; l < L; l++ {
		s1hat := reconS1[l]
		s1hat.ntt()
		var tmp poly
		tmp.mulHat(&cHat, &s1hat)
		tmp.invNTT()
		tmp.normalize()
		zRef[l].add(&yTotal[l], &tmp)
		zRef[l].normalize()
	}

	// Aggregator's z = Σ z_j.
	zAgg := make(polyVec, L)
	for _, r2m := range r2 {
		zj := unpackPolyVec(r2m.Z, L)
		for l := 0; l < L; l++ {
			zAgg[l].add(&zAgg[l], &zj[l])
		}
	}
	for l := 0; l < L; l++ {
		zAgg[l].normalize()
	}

	// Now also compute z directly from y_total + c · reconS1, BUT
	// using exactly the same internal path as parties do:
	// for each party: compute (c·λ_i)·s_{1,i} → invNTT → normalize.
	// Then sum.
	zAggReconstructed := make(polyVec, L)
	for i := 0; i < 3; i++ {
		lambdaI := shamirPolyLambda(evalPoints, i)
		var cLambda poly
		for j := 0; j < mldsaN; j++ {
			cLambda[j] = uint32((uint64(c[j]) * uint64(lambdaI)) % uint64(mldsaQ))
		}
		cLambdaHat := cLambda
		cLambdaHat.ntt()
		for l := 0; l < L; l++ {
			s1iHat := shares[i].S1[l]
			s1iHat.ntt()
			var tmp poly
			tmp.mulHat(&cLambdaHat, &s1iHat)
			tmp.invNTT()
			tmp.normalize()
			for j := 0; j < mldsaN; j++ {
				zAggReconstructed[l][j] = uint32((uint64(zAggReconstructed[l][j]) + uint64(tmp[j])) % uint64(mldsaQ))
			}
		}
	}
	// Add y_total.
	for l := 0; l < L; l++ {
		for j := 0; j < mldsaN; j++ {
			zAggReconstructed[l][j] = uint32((uint64(zAggReconstructed[l][j]) + uint64(yTotal[l][j])) % uint64(mldsaQ))
		}
	}

	// Compare zAggReconstructed vs zRef
	rDiffs := 0
	for l := 0; l < L; l++ {
		for ci := 0; ci < mldsaN; ci++ {
			if zAggReconstructed[l][ci] != zRef[l][ci] {
				if rDiffs < 5 {
					t.Logf("zRecon vs zRef mismatch L=%d ci=%d: recon=%d ref=%d", l, ci, zAggReconstructed[l][ci], zRef[l][ci])
				}
				rDiffs++
			}
		}
	}
	t.Logf("zRecon vs zRef: %d diffs (out of %d)", rDiffs, L*mldsaN)

	// Compare.
	diffs := 0
	for l := 0; l < L; l++ {
		for ci := 0; ci < mldsaN; ci++ {
			if zAgg[l][ci] != zRef[l][ci] {
				if diffs < 5 {
					t.Logf("zAgg vs zRef mismatch L=%d ci=%d: agg=%d ref=%d (zRecon=%d)", l, ci, zAgg[l][ci], zRef[l][ci], zAggReconstructed[l][ci])
				}
				diffs++
			}
		}
	}

	// Compare zAgg vs zAggReconstructed
	rdiffs := 0
	for l := 0; l < L; l++ {
		for ci := 0; ci < mldsaN; ci++ {
			if zAgg[l][ci] != zAggReconstructed[l][ci] {
				if rdiffs < 5 {
					t.Logf("zAgg vs zRecon mismatch L=%d ci=%d: agg=%d recon=%d", l, ci, zAgg[l][ci], zAggReconstructed[l][ci])
				}
				rdiffs++
			}
		}
	}
	t.Logf("zAgg vs zRecon: %d diffs", rdiffs)

	if diffs > 0 {
		t.Fatalf("z mismatch in %d positions", diffs)
	}
}

// newShake256 lives in transcript.go via the sha3 package — provide a
// local fake so we don't pull sha3 into the test file directly. (We
// pull it via the package's import chain anyway.)
func newShake256() shakeWriter {
	return newShake256Impl()
}

// Helpers in threshold_v03_debug_shake.go.

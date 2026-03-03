// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"math/big"
	"testing"

	"github.com/luxfi/pulsar/primitives"
	"github.com/luxfi/pulsar/sign"
	"github.com/luxfi/pulsar/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// TestResharePreservesPublicKey — end-to-end proof that resharing keeps
// the SAME public key b verifying signatures from the new committee.
//
// Test flow:
//
//  1. Genesis: trusted-dealer Gen produces (A, s, e, b̃, share_old)
//     using primitives.ShamirSecretSharingGeneral so we have honest
//     standard-Shamir shares of s. We bypass sign.Gen here because
//     sign.Gen uses the OPTIMIZED t=K Shamir path (committee-specific
//     Lagrange basis) which is incompatible with arbitrary-committee
//     resharing — this is precisely the architectural shortcoming
//     this package fixes for Quasar.
//
//  2. Run the 2-round Sign protocol with the OLD committee, verify
//     the resulting signature against b̃. Confirms that genesis
//     setup is correct.
//
//  3. Reshare onto a brand-new committee with a different size and
//     threshold. NO trusted dealer participates; only the old shares
//     and fresh randomness from each old party.
//
//  4. Run Sign again with the NEW committee. Verify against the SAME
//     b̃ from step 1. Pass = master secret invariant proven; only the
//     share distribution rotated.
//
// This is the canonical "Quasar epoch rotation without DKG" test.
func TestResharePreservesPublicKey(t *testing.T) {
	r, err := ring.NewRing(1<<sign.LogN, []uint64{sign.Q})
	if err != nil {
		t.Fatal(err)
	}
	rXi, _ := ring.NewRing(1<<sign.LogN, []uint64{sign.QXi})
	rNu, _ := ring.NewRing(1<<sign.LogN, []uint64{sign.QNu})

	// ─── Phase 1: Genesis (trusted-dealer) ────────────────────────────
	const tOld, nOld = 2, 3
	const nVec, mPk = sign.N, sign.M

	prng, _ := sampling.NewKeyedPRNG([]byte("genesis-prng-seed"))
	uniformSampler := ring.NewUniformSampler(prng, r)

	// Sample s ← D(σ_E)^{nVec}, public matrix A, error e ← D(σ_E)^{mPk}.
	// We do NOT call sign.Gen because it uses the optimized Shamir
	// path. Instead we sample directly and use primitives.Shamir...
	// General to share s across nOld parties.
	gaussian := ring.DiscreteGaussian{Sigma: sign.SigmaE, Bound: sign.BoundE}
	gaussianSampler := ring.NewGaussianSampler(prng, r, gaussian, false)

	A := utils.SamplePolyMatrix(r, mPk, nVec, uniformSampler, true, true)
	s := utils.SamplePolyVector(r, nVec, gaussianSampler, false, false)

	// Standard-Shamir share s across the old committee.
	primSharesMap := primitives.ShamirSecretSharingGeneral(r, s, tOld, nOld)

	// Convert to (1-indexed → Share) map for reshare API.
	oldSharesStd := make(map[int]Share, nOld)
	for partyIdx, vec := range primSharesMap {
		oldSharesStd[partyIdx+1] = structs.Vector[ring.Poly](vec)
	}

	// Compute b = A·s + e in NTT-Montgomery. The same path sign.Gen
	// uses internally.
	utils.ConvertVectorToNTT(r, s) // s now in NTT-Mont
	e := utils.SamplePolyVector(r, mPk, gaussianSampler, true, true)
	b := utils.InitializeVector(r, mPk)
	utils.MatrixVectorMul(r, A, s, b)
	utils.VectorAdd(r, b, e, b)

	utils.ConvertVectorFromNTT(r, b)
	bTilde := utils.RoundVector(r, rXi, b, sign.Xi)

	// ─── Phase 2: Sign with old committee, verify against b̃ ─────────
	// Each old party uses its OLD share + on-the-fly Lagrange coeff
	// for the active signing set T_old.

	tOldSig := tOld
	signersOld := make([]*sign.Party, tOldSig)
	signerSet := []int{0, 1} // 0-indexed for sign.Party

	// Set globals required by sign package.
	sign.K = tOldSig
	sign.Threshold = tOldSig

	// On-the-fly Lagrange coefficients for the signing set.
	lagrangeOld := primitives.ComputeLagrangeCoefficients(
		r, signerSet, big.NewInt(int64(sign.Q)),
	)

	// Pre-set: seeds and MAC keys are normally produced by sign.Gen.
	// For the test we generate them deterministically here. They are
	// public-coin (per pairwise channel), so it's fine to derive them
	// from a known seed.
	seeds, macKeys := buildSeedsAndMACs(tOldSig)

	for idx, partyID0 := range signerSet {
		party := sign.NewParty(partyID0, r, rXi, rNu, uniformSampler)
		// SkShare needs to be in NTT-Mont form for sign.SignRound2's
		// VectorPolyMul calls.
		skShare := cloneVector(r, oldSharesStd[partyID0+1])
		utils.ConvertVectorToNTT(r, skShare)
		party.SkShare = skShare
		party.Seed = seeds
		party.MACKeys = macKeys[partyID0]
		// Lambda: NTT-Montgomery form.
		lambda := r.NewPoly()
		lambda.Copy(lagrangeOld[idx])
		r.NTT(lambda, lambda)
		r.MForm(lambda, lambda)
		party.Lambda = lambda
		signersOld[idx] = party
	}

	if !runRoundsAndVerify(t, "OLD", r, rXi, rNu, A, bTilde, signersOld, signerSet) {
		t.Fatal("OLD-committee signature did not verify")
	}

	// ─── Phase 3: Reshare to a fresh committee ─────────────────────────
	// New committee: 5 parties, threshold 3, party IDs {7, 8, 9, 10, 11}.
	const tNew = 3
	newSet := []int{7, 8, 9, 10, 11}

	newSharesStd, err := Reshare(
		r, oldSharesStd, tOld, newSet, tNew,
		newFakeRand([]byte("integration-reshare-seed")),
	)
	if err != nil {
		t.Fatalf("Reshare: %v", err)
	}

	// Sanity: reconstruct s from new shares and confirm equality.
	utils.ConvertVectorFromNTT(r, s) // bring s back to standard form for compare
	recoveredS, err := Verify(r, newSharesStd, tNew)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(recoveredS, s) {
		t.Fatal("reshared shares interpolate to a different secret")
	}

	// ─── Phase 4: Sign with new committee, verify against ORIGINAL b̃ ──
	// Active signing set T_new is the lowest-tNew IDs of newSet.
	activeNewIDs := newSet[:tNew] // {7, 8, 9}

	// sign.Party uses 0-indexed party IDs; we map [7, 8, 9] → [0, 1, 2]
	// internally — the signing protocol does not care about the
	// underlying ID values, only that all parties agree. The Lagrange
	// coefficients must be evaluated at the REAL evaluation points
	// (i.e. partyID + 1 for the old committee, partyID for ours). To
	// keep sign.Party happy AND have correct Lagrange we re-run
	// ComputeLagrangeCoefficients with the real evaluation points.

	// signSet is the set of evaluation points (1-indexed party IDs) the
	// new active signers occupy on the polynomial P. We pass them
	// directly to ComputeLagrangeCoefficients which subtracts 1 from
	// each (it expects 0-indexed party indices). To match: we want
	// λ_j evaluated at 0 with x_j = activeNewIDs[idx]. The existing
	// helper uses x_i = T[i] + 1; so we feed T = activeNewIDs[idx] - 1.
	signSetForLagrange := make([]int, tNew)
	for i, j := range activeNewIDs {
		signSetForLagrange[i] = j - 1
	}
	lagrangeNew := primitives.ComputeLagrangeCoefficients(
		r, signSetForLagrange, big.NewInt(int64(sign.Q)),
	)

	// Now build sign.Party instances. We use 0-indexed party IDs
	// {0, 1, 2} for the protocol-internal MAC keying because the
	// MAC keys are pairwise and we generate fresh ones for the
	// new committee.
	sign.K = tNew
	sign.Threshold = tNew

	newSeeds, newMACKeys := buildSeedsAndMACs(tNew)
	signSetProtocol := make([]int, tNew)
	for i := range activeNewIDs {
		signSetProtocol[i] = i
	}

	signersNew := make([]*sign.Party, tNew)
	for idx, realID := range activeNewIDs {
		party := sign.NewParty(idx, r, rXi, rNu, uniformSampler)
		skShare := cloneVector(r, newSharesStd[realID])
		utils.ConvertVectorToNTT(r, skShare)
		party.SkShare = skShare
		party.Seed = newSeeds
		party.MACKeys = newMACKeys[idx]
		lambda := r.NewPoly()
		lambda.Copy(lagrangeNew[idx])
		r.NTT(lambda, lambda)
		r.MForm(lambda, lambda)
		party.Lambda = lambda
		signersNew[idx] = party
	}

	if !runRoundsAndVerify(t, "NEW", r, rXi, rNu, A, bTilde, signersNew, signSetProtocol) {
		t.Fatal("NEW-committee signature did not verify against ORIGINAL public key")
	}

	t.Log("PASS: NEW-committee signature verifies against UNCHANGED public key b̃")
}

// runRoundsAndVerify drives the 2-round Sign protocol across the given
// signers and checks that the resulting signature verifies against
// (A, bTilde). Returns true on success.
func runRoundsAndVerify(
	t *testing.T,
	label string,
	r *ring.Ring, rXi *ring.Ring, rNu *ring.Ring,
	A structs.Matrix[ring.Poly], bTilde structs.Vector[ring.Poly],
	parties []*sign.Party, signSet []int,
) bool {
	t.Helper()

	const sid = 1
	prfKey := []byte("integration-test-prfkey-32-bytes")
	mu := "test-message-" + label

	// Round 1.
	D := make(map[int]structs.Matrix[ring.Poly], len(parties))
	macs := make(map[int]map[int][]byte, len(parties))
	for _, p := range parties {
		Di, MAi := p.SignRound1(A, sid, prfKey, signSet)
		D[p.ID] = Di
		macs[p.ID] = MAi
	}

	// Round 2 preprocess + Round 2.
	Z := make(map[int]structs.Vector[ring.Poly], len(parties))
	var DSum structs.Matrix[ring.Poly]
	var hash []byte
	for _, p := range parties {
		ok, ds, h := p.SignRound2Preprocess(A, bTilde, D, macs, sid, signSet)
		if !ok {
			t.Errorf("%s: SignRound2Preprocess failed for party %d", label, p.ID)
			return false
		}
		if DSum == nil {
			DSum = ds
			hash = h
		}
		zi := p.SignRound2(A, bTilde, DSum, sid, mu, signSet, prfKey, hash)
		Z[p.ID] = zi
	}

	// Finalize.
	c, zSum, delta := parties[0].SignFinalize(Z, A, bTilde)
	ok := sign.Verify(r, rXi, rNu, zSum, A, mu, bTilde, c, delta)
	if !ok {
		t.Errorf("%s: signature failed to verify", label)
		return false
	}
	t.Logf("%s: signature verified", label)
	return true
}

// buildSeedsAndMACs returns deterministic, public-coin seeds and MAC
// key maps in the format sign.Party expects. The values themselves are
// out-of-scope for the resharing security argument (they're just per-
// pairwise-channel keys).
func buildSeedsAndMACs(K int) (map[int][][]byte, map[int]map[int][]byte) {
	seeds := make(map[int][][]byte, K)
	for i := 0; i < K; i++ {
		seeds[i] = make([][]byte, K)
		for j := 0; j < K; j++ {
			s := make([]byte, sign.KeySize)
			s[0] = byte(i*K + j + 1) // any non-zero pattern
			seeds[i][j] = s
		}
	}
	macKeys := make(map[int]map[int][]byte, K)
	for i := 0; i < K; i++ {
		macKeys[i] = make(map[int][]byte, K)
	}
	for i := 0; i < K; i++ {
		for j := i + 1; j < K; j++ {
			k := make([]byte, sign.KeySize)
			k[0] = byte(0xA0 + i)
			k[1] = byte(0xB0 + j)
			macKeys[i][j] = k
			macKeys[j][i] = k
		}
	}
	return seeds, macKeys
}

// cloneVector deep-copies a Share so that NTT mutation does not affect
// the original (Reshare returns shares in standard form; the signing
// path mutates them into NTT-Mont form).
func cloneVector(r *ring.Ring, in Share) structs.Vector[ring.Poly] {
	out := make(structs.Vector[ring.Poly], len(in))
	for i, p := range in {
		out[i] = *p.CopyNew()
	}
	_ = r // consume parameter to keep symmetry with other helpers
	return out
}

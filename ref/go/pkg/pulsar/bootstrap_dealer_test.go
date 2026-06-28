// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// bootstrap_dealer_test.go — the TRUSTED-DEALER s1-share keygen, RIPPED OUT
// of production and confined to test/bootstrap scope.
//
// WHY THIS IS A _test.go FILE. The no-reconstruct committee SIGN path
// (DistributedBCCSigner / AggregateBCC in distributed_bcc.go) needs each
// validator to hold one poly-vector Shamir share of the EXPANDED signing
// component s1 (AlgShare). A genuinely DEALERLESS keygen that emits such
// s1-shares does NOT exist in this package (it is the research-blocked
// Part-2 problem — naive_additive_seta_obstruction.go computes the
// obstruction; Mithril short-replicated shares, ia.cr/2026/013, is the
// adoption target). The only currently-available s1-share source is a
// TRUSTED DEALER that forms the master key for one call and wipes it.
//
// Per the no-reconstruct mandate, that dealer MUST NOT be reachable from
// production dispatch. Living in a `_test.go` file is the strongest
// guarantee: the Go toolchain never compiles `_test.go` files into a
// production binary, so DealAlgShares cannot be linked into luxd/consensus.
// It remains available to the package's own tests (distributed_bcc_test.go,
// talus_test.go, no_reconstruct_committee_test.go) to seed the SIGNING
// proofs — exactly the "tests/bootstrap" carve-out.
//
// CLAIM DISCIPLINE. This makes SIGNING no-reconstruct (the combiner never
// forms s1/seed/sk), NOT keygen dealerless. The dealer reconstructs the key
// once at genesis; that residual is intentional and quarantined here.

import "io"

// DealAlgShares is the Part-1 TRUSTED-DEALER keygen: it expands the seed
// into the FIPS 204 key material ONCE, Shamir-shares the signing component
// s1 over GF(q) across the committee, wipes every secret, and returns the
// public setup plus one AlgShare per committee member.
//
// TRUST MODEL — TRUSTED DEALER (explicit, test/bootstrap scope). The dealer
// holds the master key for the duration of this one call. This makes
// SIGNING no-reconstruct (no party ever reconstructs s1), but KEYGEN is not
// dealerless. Dealerless ML-DSA DKG is the research-blocked Part-2 problem
// (naive_additive_seta_obstruction.go documents the precise, COMPUTED
// obstruction). For production permissionless safety, the consensus cert is
// AND-mode dual-PQ: the Corona leg is genuinely dealerless; this Pulsar
// leg's genesis is dealer/TEE-gated.
//
// rng supplies the Shamir polynomial coefficients; pass a deterministic
// reader for KAT-reproducible shares. committee must be distinct NodeIDs;
// threshold is the reconstruction threshold t (1 ≤ t ≤ n).
func DealAlgShares(params *Params, committee []NodeID, threshold int, seed [SeedSize]byte, rng io.Reader) (*AlgSetup, []*AlgShare, error) {
	if err := params.Validate(); err != nil {
		return nil, nil, err
	}
	if _, _, _, ok := bccParams(params.Mode); !ok {
		// BCC/CEF (and therefore this no-reconstruct signer) is proven only
		// for ML-DSA-65/87 (the ‖c·t0‖∞ < γ2 scope). Refuse other sets.
		return nil, nil, ErrBCCParamSet
	}
	n := len(committee)
	if threshold < 1 || n < threshold {
		return nil, nil, ErrInvalidThreshold
	}
	K, L, _ := modeShape(params.Mode)

	km, err := deriveKeyMaterial(params.Mode, &seed)
	if err != nil {
		return nil, nil, err
	}

	// Public setup: copy the public matrix A, t1, tr, rho, and packed pk.
	setup := &AlgSetup{
		Mode: params.Mode,
		Pub:  &PublicKey{Mode: params.Mode, Bytes: append([]byte(nil), km.pub...)},
		rho:  km.rho,
		tr:   km.tr,
		t1:   make(polyVec, K),
		a:    make([]polyVec, K),
	}
	copy(setup.t1, km.t1)
	for i := 0; i < K; i++ {
		setup.a[i] = append(polyVec(nil), km.a[i]...)
	}

	// Eval points: deterministic, non-zero, distinct GF(q) points per party.
	evalPoints := make([]uint32, n)
	seen := make(map[uint32]struct{}, n)
	for i, id := range committee {
		x := EvalPointFromIDQ(id)
		if _, dup := seen[x]; dup {
			return nil, nil, ErrDuplicateEvalPoint
		}
		seen[x] = struct{}{}
		evalPoints[i] = x
	}

	// Shamir-share s1 coefficient-wise over GF(q). The constant term of
	// every per-coefficient sharing polynomial is the [0,q) representative
	// of that s1 coefficient, so Σ_p λ_p · share_p == s1 (Lagrange at 0).
	s1Norm := make(polyVec, L)
	for l := 0; l < L; l++ {
		s1Norm[l] = km.s1[l]
		s1Norm[l].normalize() // [q-η, q+η] → [0, q)
	}
	perParty, err := shamirSharePolyVecGFq(s1Norm, evalPoints, threshold, rng)
	if err != nil {
		zeroizeKeyMaterial(km)
		return nil, nil, err
	}

	shares := make([]*AlgShare, n)
	for i := range committee {
		shares[i] = &AlgShare{
			NodeID:    committee[i],
			EvalPoint: evalPoints[i],
			S1Share:   perParty[i],
			Mode:      params.Mode,
		}
	}

	// Wipe every secret the dealer touched. After this point the master key
	// exists nowhere; only the n single shares and the public setup remain.
	for l := 0; l < L; l++ {
		s1Norm[l] = poly{}
	}
	zeroizeKeyMaterial(km)
	for i := range seed {
		seed[i] = 0
	}

	return setup, shares, nil
}

// zeroizeKeyMaterial scrubs the secret polynomials and packed private key
// of a dealer's expanded key material.
func zeroizeKeyMaterial(km *mldsaKeyMaterial) {
	for i := range km.s1 {
		km.s1[i] = poly{}
	}
	for i := range km.s2 {
		km.s2[i] = poly{}
	}
	for i := range km.t0 {
		km.t0[i] = poly{}
	}
	for i := range km.prv {
		km.prv[i] = 0
	}
}

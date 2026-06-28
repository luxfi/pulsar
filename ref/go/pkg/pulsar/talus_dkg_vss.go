// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// talus_dkg_vss.go — Phase-3b DKG rewire (luxfi/dkg step 2): the no-reconstruct
// Pedersen-VSS key DKG via the shared github.com/luxfi/dkg/vss package, REPLACING
// the in-house v0.1 RECONSTRUCT DKG (dkg.go DKGSession.Round3, which forms the
// master seed σ via KeyFromSeed — the centralized seam this rewire removes).
//
// WHAT THIS PRODUCES (the no-reconstruct ROOT). DealerlessDKGViaVSS runs the
// dealerless VSS DKG over the ML-DSA-65 ring bound to A = ExpandA(rho) (the
// chain-genesis binding) and B = the domain-separated default. NO party ever
// forms the master seed σ, s1, or the full sk: the group public key is derived
// from the aggregated PUBLIC Pedersen commit T = Σ_i C_{i,0} = A·s1 + B·u, and
// each party retains only its Shamir share of s1. The output is shaped as the
// (*AlgSetup, []*AlgShare) the TALUS signer consumes.
//
// ──────────────────────────────────────────────────────────────────────────────
// HONEST OBSTRUCTION (HANDOFF-PHASE3 §67-79; do NOT overclaim). The vss group key
// T = A·s1 + B·u has a LARGE s2 = B·u (M-LWE-indistinguishable from a fresh χ_η
// sample, but NOT small). The TALUS BCC signer recovers the FIPS hint from the
// PUBLIC w' = A·z − c·t1·2^d = w + c·(t0 − B·u); with a large B·u the per-
// coefficient correction w' − w spans many HighBits buckets, so FindHint returns
// no ±1 hint (weight > ω) and a stock-FIPS-204 signature CANNOT be produced
// against this key. Concretely: this is the no-reconstruct DKG PRIMITIVE and the
// no-reconstruct ROOT, NOT the stock-signable key. The stock-verifiable threshold
// signature keeps the trusted-dealer key (DealAlgShares, test/bootstrap scope) —
// dealerless byte-FIPS-204 keygen is unreachable (naive_additive_seta_obstruction
// / assessDealerlessFIPS: the joint S_η sum violates the BCC norm bound at N≥2).
// Permissionless safety rests on the genuinely-dealerless CORONA leg in the
// AND-mode dual-PQ cert. TestDKG_VSS_NotDirectlyBCCSignable pins the obstruction
// so it is proven, not asserted.
//
// SCOPE. dkg ships ring.MLDSA65() (K=6) only; ML-DSA-87 (K=8) needs an MLDSA87
// profile in luxfi/dkg first. This adapter is ML-DSA-65.

import (
	"errors"
	"io"

	"golang.org/x/crypto/sha3"

	dkgchannel "github.com/luxfi/dkg/channel"
	dkgring "github.com/luxfi/dkg/ring"
	dkgvss "github.com/luxfi/dkg/vss"
)

// ErrVSSDKGScope is returned for a parameter set the vss DKG adapter does not
// bind (only ML-DSA-65: dkg ships ring.MLDSA65() only).
var ErrVSSDKGScope = errors.New(
	"pulsar: dealerless VSS DKG is wired for ML-DSA-65 only (luxfi/dkg ships ring.MLDSA65(); " +
		"ML-DSA-87 needs an MLDSA87 profile upstream)")

// expandAPulsar derives pulsar's public matrix A = ExpandA(rho) (FIPS-204 §3.5),
// K×L polynomials in pulsar's NTT-Montgomery domain — byte-identical to circl's
// stored pk.A and to deriveKeyMaterial's km.a.
func expandAPulsar(rho [32]byte, K, L int) []polyVec {
	a := make([]polyVec, K)
	for i := 0; i < K; i++ {
		a[i] = make(polyVec, L)
		for j := 0; j < L; j++ {
			polyDeriveUniform(&a[i][j], &rho, uint16(i)<<8|uint16(j))
		}
	}
	return a
}

// aCoeffFromPulsarA recovers A in convention-neutral STANDARD coefficient form by
// the unit-vector multiply A·e_j through pulsar's own (circl-correct) pipeline —
// the same extraction the pin-4 KAT validated. (A·e_j)[i] = A[i][j], so no
// Montgomery-factor ambiguity is possible.
func aCoeffFromPulsarA(a []polyVec, K, L int) []polyVec {
	aCoeff := make([]polyVec, K)
	for i := range aCoeff {
		aCoeff[i] = make(polyVec, L)
	}
	for j := 0; j < L; j++ {
		ejHat := make(polyVec, L)
		for l := 0; l < L; l++ {
			var ej poly
			if l == j {
				ej[0] = 1
			}
			ejHat[l] = ej
			ejHat[l].ntt()
		}
		for i := 0; i < K; i++ {
			var col poly
			polyDotHat(&col, a[i], ejHat)
			col.reduceLe2Q()
			col.invNTT()
			col.normalize()
			aCoeff[i][j] = col
		}
	}
	return aCoeff
}

// dkgMatrixFromCoeff builds a dkg-ring NTT-Montgomery matrix from standard
// coefficient form (coeff -> NTT -> MForm, matching dkg/ring.DeriveUniformMatrix).
func dkgMatrixFromCoeff(r *dkgring.Ring, aCoeff []polyVec, K, L int) dkgring.Matrix {
	m := make(dkgring.Matrix, K)
	for i := 0; i < K; i++ {
		m[i] = make([]dkgring.Poly, L)
		for j := 0; j < L; j++ {
			p := r.NewPoly()
			for c := 0; c < mldsaN; c++ {
				p.Coeffs[0][c] = uint64(aCoeff[i][j][c])
			}
			r.NTT(p, p)
			r.MForm(p, p)
			m[i][j] = p
		}
	}
	return m
}

// mldsa65ProfileBoundToRho returns the dkg ML-DSA-65 profile with A replaced by
// ExpandA(rho) (WithMatrices) — the chain-genesis binding. B is the default
// domain-separated matrix.
func mldsa65ProfileBoundToRho(rho [32]byte, K, L int) (*dkgring.Profile, error) {
	base, err := dkgring.MLDSA65()
	if err != nil {
		return nil, err
	}
	aCoeff := aCoeffFromPulsarA(expandAPulsar(rho, K, L), K, L)
	dkgA := dkgMatrixFromCoeff(base.Ring, aCoeff, K, L)
	return base.WithMatrices(dkgA, base.B), nil
}

// DealerlessDKGViaVSS runs the luxfi/dkg no-reconstruct Pedersen-VSS DKG and
// returns the group setup and per-party s1-shares in the AlgSetup/AlgShare shape
// the TALUS signer consumes — WITHOUT any party forming σ, s1, or sk. The public
// matrix is bound to A = ExpandA(rho). committee carries the n parties' NodeIDs;
// threshold is the reconstruction threshold t (n ≥ t). rng drives all sampling.
//
// The returned AlgSetup.t1 is the no-reconstruct group key HighBits (T = A·s1 +
// B·u); see the file header — this key is the no-reconstruct ROOT and is NOT
// directly stock-FIPS-204-signable (large s2 = B·u). The stock-verifiable
// threshold signing path keeps the trusted-dealer key.
func DealerlessDKGViaVSS(mode Mode, rho [32]byte, committee []NodeID, threshold int, rng io.Reader) (*AlgSetup, []*AlgShare, error) {
	if mode != ModeP65 {
		return nil, nil, ErrVSSDKGScope
	}
	n := len(committee)
	if threshold < 1 || n < threshold {
		return nil, nil, ErrInvalidThreshold
	}
	K, L, _ := modeShape(mode)

	profile, err := mldsa65ProfileBoundToRho(rho, K, L)
	if err != nil {
		return nil, nil, err
	}

	// Per-party long-term identities (ML-DSA-65 signed + ML-KEM-768 sealed
	// authenticated channels) and the vss NodeIDs.
	ids := make([]*dkgchannel.IdentityKey, n)
	nodes := make([]dkgchannel.NodeID, n)
	for i := 0; i < n; i++ {
		id, err := dkgchannel.GenerateIdentity(rng)
		if err != nil {
			return nil, nil, err
		}
		ids[i] = id
		var nid dkgchannel.NodeID
		copy(nid[:], committee[i][:])
		nodes[i] = nid
	}

	// Context binds the run to the genesis A seed (rho).
	var ctx [32]byte
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("PULSAR-DKG-VSS/context/v1"))
	_, _ = h.Write(rho[:])
	_, _ = h.Read(ctx[:])

	res, err := dkgvss.RunDKG(profile, n, threshold, ids, nodes, ctx, rng)
	if err != nil {
		return nil, nil, err
	}

	// Group setup. t1 = HighBits(T) from the vss group key (no reconstruction).
	t1 := vecFromDKG(res.GroupKey.Finalized, K)
	aPulsar := expandAPulsar(rho, K, L)
	pub := packMLDSAPub(rho, t1, K)
	var tr [64]byte
	h.Reset()
	_, _ = h.Write(pub)
	_, _ = h.Read(tr[:])
	setup := &AlgSetup{
		Mode: mode,
		Pub:  &PublicKey{Mode: mode, Bytes: pub},
		rho:  rho,
		tr:   tr,
		a:    aPulsar,
		t1:   t1,
	}

	// Per-party s1-shares at Shamir eval point index+1 (the vss convention).
	shares := make([]*AlgShare, n)
	for i := 0; i < n; i++ {
		shares[i] = &AlgShare{
			NodeID:    committee[i],
			EvalPoint: uint32(i + 1),
			S1Share:   vecFromDKG(res.Shares[i], L),
			Mode:      mode,
		}
	}
	return setup, shares, nil
}

// vecFromDKG converts a dkg ring.Vector (standard coefficient form) of length d to
// a pulsar poly-vector by direct coefficient copy (the GF(q) field and ring
// degree are identical, so no NTT/domain change is involved).
func vecFromDKG(v dkgring.Vector, d int) polyVec {
	out := make(polyVec, d)
	for i := 0; i < d; i++ {
		for j := 0; j < mldsaN; j++ {
			out[i][j] = uint32(v[i].Coeffs[0][j])
		}
	}
	return out
}

// packMLDSAPub packs an ML-DSA public key (rho || PackT1(t1)) per FIPS-204 §5.1,
// identical to deriveKeyMaterial's km.pub layout.
func packMLDSAPub(rho [32]byte, t1 polyVec, K int) []byte {
	pub := make([]byte, 32+320*K)
	copy(pub[:32], rho[:])
	for i := 0; i < K; i++ {
		polyPackT1(&t1[i], pub[32+320*i:32+320*(i+1)])
	}
	return pub
}

// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// dkg_vss_kat_test.go — Phase-3b foundation KAT (luxfi/dkg rewire, step 1).
//
// Proves the shared luxfi/dkg ring substrate, bound to pulsar's ExpandA(rho)
// matrix via ring.MLDSA65().WithMatrices, reproduces pulsar's own FIPS-204
// arithmetic — the precondition for replacing the in-house reconstruct DKG with
// the dkg/vss no-reconstruct Pedersen-VSS.
//
// Two anchors:
//
//  1. A-MATRIX BINDING. pulsar's A = ExpandA(rho) is extracted in
//     convention-neutral coefficient form (unit-vector extraction through
//     pulsar's own circl-correct keygen pipeline), loaded into the dkg ring, and
//     round-tripped back out: INTT(IMForm(dkgA)) == A_coeff. This proves the
//     WithMatrices binding carries pulsar's exact matrix through the dkg ring's
//     NTT-Montgomery domain with no spurious Montgomery R factor (pin 4).
//
//  2. FIPS-204 t1 FIDELITY (the pin-4 anchor). For a known seed, the dkg ring —
//     bound to that A — recomputes t = A·s1 + s2 and Power2Round → t1 using its
//     INTT-ONLY ConvertVecFromNTT convention, and the result is byte-identical to
//     pulsar's km.t1 (which is byte-identical to cloudflare/circl). This is the
//     TRUE A·s1 (not an R^{-1}-scaled self-consistent value): the dkg ring
//     reproduces the exact FIPS-204 public key from the same secrets.
//
// Note on the no-reconstruct group key. The dkg/vss DKG's group key is the
// no-reconstruct root T = A·s1 + B·u (large s2 = B·u), NOT the small-s2 FIPS key
// exercised here. The KAT anchors the dkg ring's ARITHMETIC against FIPS ground
// truth; the vss group key uses the SAME ring with B·u in place of s2 (its
// Power2Round fidelity follows from this arithmetic fidelity). The stock-
// verifiable threshold *signature* keeps the trusted-dealer key (honest residual
// HANDOFF-PHASE3 §67-79): the vss key's large s2 is not directly BCC-signable.

import (
	"testing"

	dkgring "github.com/luxfi/dkg/ring"
)

// extractACoeffViaPulsar recovers pulsar's public matrix A = ExpandA(rho) in
// convention-neutral STANDARD coefficient form. It runs pulsar's own (circl-
// correct) keygen multiply A·e_j for each unit vector e_j (the constant
// polynomial 1 in slot j, zero elsewhere): (A·e_j)[i] = A[i][j]. Because this is
// the exact arithmetic that produces pulsar's circl-identical km.t1, the
// extracted A_coeff is the true coefficient-form matrix with no Montgomery-factor
// ambiguity.
func extractACoeffViaPulsar(km *mldsaKeyMaterial, K, L int) []polyVec {
	aCoeff := make([]polyVec, K)
	for i := range aCoeff {
		aCoeff[i] = make(polyVec, L)
	}
	for j := 0; j < L; j++ {
		ejHat := make(polyVec, L)
		for l := 0; l < L; l++ {
			var ej poly
			if l == j {
				ej[0] = 1 // constant polynomial 1
			}
			ejHat[l] = ej
			ejHat[l].ntt()
		}
		for i := 0; i < K; i++ {
			var col poly
			polyDotHat(&col, km.a[i], ejHat)
			col.reduceLe2Q()
			col.invNTT()
			col.normalize()
			aCoeff[i][j] = col
		}
	}
	return aCoeff
}

// dkgMatrixFromCoeff builds a dkg-ring NTT-Montgomery Matrix from a standard
// coefficient-form A (the WithMatrices injection path: coeff -> NTT -> MForm,
// matching dkg/ring.DeriveUniformMatrix's domain convention).
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

// TestDKGVSS_RingMLDSA65_ExpandABinding_KAT is Phase-3b step-1: the dkg ring,
// bound to pulsar's ExpandA(rho) A via ring.MLDSA65().WithMatrices, reproduces
// pulsar's A matrix and pulsar's expected FIPS-204 t1 for a known seed (pin 4).
func TestDKGVSS_RingMLDSA65_ExpandABinding_KAT(t *testing.T) {
	const K, L = 6, 5 // ML-DSA-65 module shape (== dkg ring.MLDSA65)

	var seed [SeedSize]byte
	for i := range seed {
		seed[i] = byte(0x40 + i) // known, fixed seed
	}
	km, err := deriveKeyMaterial(ModeP65, &seed)
	if err != nil {
		t.Fatalf("deriveKeyMaterial: %v", err)
	}

	// pulsar's A = ExpandA(rho), in convention-neutral coefficient form.
	aCoeff := extractACoeffViaPulsar(km, K, L)

	// dkg ring.MLDSA65, with A bound to pulsar's ExpandA(rho) via WithMatrices.
	profile, err := dkgring.MLDSA65()
	if err != nil {
		t.Fatalf("dkg ring.MLDSA65: %v", err)
	}
	R := profile.Ring
	if R.Q() != mldsaQ || R.N() != mldsaN {
		t.Fatalf("dkg ring mismatch: q=%d n=%d, want q=%d n=%d", R.Q(), R.N(), mldsaQ, mldsaN)
	}
	dkgA := dkgMatrixFromCoeff(R, aCoeff, K, L)
	bound := profile.WithMatrices(dkgA, profile.B)
	if err := bound.Validate(); err != nil {
		t.Fatalf("bound profile invalid: %v", err)
	}

	// (1) A-MATRIX BINDING: round-trip dkgA back to coefficient form
	// (INTT(IMForm(.))) and assert byte-identity to pulsar's A_coeff. Catches any
	// spurious Montgomery-R scaling in the binding (the pin-4 failure mode).
	for i := 0; i < K; i++ {
		for j := 0; j < L; j++ {
			p := *bound.A[i][j].CopyNew()
			R.IMForm(p, p)
			R.INTT(p, p)
			for c := 0; c < mldsaN; c++ {
				if p.Coeffs[0][c] != uint64(aCoeff[i][j][c]) {
					t.Fatalf("A binding mismatch at [%d][%d][%d]: dkg=%d pulsar=%d",
						i, j, c, p.Coeffs[0][c], aCoeff[i][j][c])
				}
			}
		}
	}

	// (2) FIPS-204 t1 FIDELITY (pin 4): recompute t = A·s1 + s2 -> Power2Round
	// via the dkg ring (INTT-only ConvertVecFromNTT) and assert t1 == km.t1.
	s1 := make(polyVec, L)
	for l := 0; l < L; l++ {
		s1[l] = km.s1[l]
		s1[l].normalize() // [q-η, q+η] -> [0, q)
	}
	s2 := make(polyVec, K)
	for k := 0; k < K; k++ {
		s2[k] = km.s2[k]
		s2[k].normalize()
	}

	s1v := dkgring.NewVec(R, L)
	for l := 0; l < L; l++ {
		for c := 0; c < mldsaN; c++ {
			s1v[l].Coeffs[0][c] = uint64(s1[l][c])
		}
	}
	dkgring.NTTVec(R, s1v) // plain NTT (Mont matrix × plain vec -> plain product)

	tvec := dkgring.NewVec(R, K)
	dkgring.MatVecMul(R, dkgA, s1v, tvec)
	dkgring.ConvertVecFromNTT(R, tvec) // INTT-ONLY -> true A·s1 (pin 4)

	for k := 0; k < K; k++ {
		for c := 0; c < mldsaN; c++ {
			tvec[k].Coeffs[0][c] = (tvec[k].Coeffs[0][c] + uint64(s2[k][c])) % mldsaQ
		}
	}
	t1dkg, _ := dkgring.Power2RoundVec(R, tvec)

	for k := 0; k < K; k++ {
		for c := 0; c < mldsaN; c++ {
			if t1dkg[k].Coeffs[0][c] != uint64(km.t1[k][c]) {
				t.Fatalf("t1 fidelity mismatch at [%d][%d]: dkg=%d pulsar(circl)=%d",
					k, c, t1dkg[k].Coeffs[0][c], km.t1[k][c])
			}
		}
	}
}

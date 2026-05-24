// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03_aprime_test.go — REGRESSION GUARD for v1.0.20.
//
// TestAMatrix_IsAlreadyInNTTDomain pins the invariant that km.a (the
// public matrix A stored in mldsaKeyMaterial) is byte-equal to circl's
// internally-cached pk.A field. circl samples A directly into NTT
// domain via FIPS 204 §3.5 ExpandA (polyDeriveUniform == circl's
// SampleNTT) and does NOT apply a further forward NTT. The pulsar
// deriveKeyMaterial path must do the same.
//
// Prior to v1.0.20 (commit 023a3ed), deriveKeyMaterial post-NTT'd km.a
// after sampling, producing double-NTT'd matrix values; AlgebraicAggregate
// then consumed setup.A = km.a in its double-NTT form and emitted
// signatures that failed mldsa{44,65,87}.Verify even though pub was
// byte-equal. See BLOCKERS.md::PULSAR-V03-1.
//
// This guard compares the actual km.a field — not a re-sampled local
// copy — so re-introducing the double-NTT regression in mldsa_keyderive.go
// causes this test to fail. Both [0][0] and [K-1][L-1] (= [5][4]) are
// checked so a nonce-derivation bug (rows/cols off-by-one) cannot slip
// through unnoticed either.

import (
	"testing"
	"unsafe"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// TestAMatrix_IsAlreadyInNTTDomain asserts km.a == circl.pk.A byte-for-byte
// at the corner positions [0][0] and [K-1][L-1]. ML-DSA-65 has K=6, L=5,
// so the second corner is [5][4].
func TestAMatrix_IsAlreadyInNTTDomain(t *testing.T) {
	var seed [SeedSize]byte
	copy(seed[:], "pulsar-aprime-master-seed-32byte")

	// circl side: derive cached A matrix via unsafe pointer-cast.
	circlPk, _ := mldsa65.NewKeyFromSeed(&seed)
	circlPkAny := (*circlPubKeyShape)(unsafe.Pointer(circlPk))
	A := (*circlMatShape)(circlPkAny.A)
	if A == nil {
		t.Fatal("circl A is nil; can't compare")
	}

	// pulsar side: derive km via deriveKeyMaterial — the SAME path used
	// by AlgebraicAggregate's setup. This is the field that was wrong.
	params := MustParamsFor(ModeP65)
	km, err := deriveKeyMaterial(params.Mode, &seed)
	if err != nil {
		t.Fatalf("deriveKeyMaterial: %v", err)
	}
	defer zeroizeKeyMaterial(km)

	// ML-DSA-65 shape — second corner is [K-1][L-1] = [5][4].
	const K, L = 6, 5

	// Quick visibility — confirms what we are comparing.
	t.Logf("circl  A[0][0][0..4]: %v", A[0][0][0:5])
	t.Logf("pulsar km.a[0][0][0..4]: %v", km.a[0][0][0:5])
	t.Logf("circl  A[%d][%d][0..4]: %v", K-1, L-1, A[K-1][L-1][0:5])
	t.Logf("pulsar km.a[%d][%d][0..4]: %v", K-1, L-1, km.a[K-1][L-1][0:5])

	// Compare A[0][0] coefficient-by-coefficient.
	diffs00 := 0
	for j := 0; j < mldsaN; j++ {
		if A[0][0][j] != km.a[0][0][j] {
			if diffs00 < 5 {
				t.Errorf("km.a[0][0][%d] != circl.A[0][0][%d]: pulsar=%d circl=%d",
					j, j, km.a[0][0][j], A[0][0][j])
			}
			diffs00++
		}
	}
	if diffs00 > 0 {
		t.Errorf("km.a[0][0] DIFFERS from circl.A[0][0] in %d/%d positions — "+
			"deriveKeyMaterial likely re-introduced the post-NTT regression "+
			"(see BLOCKERS.md::PULSAR-V03-1, fixed in v1.0.20)", diffs00, mldsaN)
	}

	// Compare A[K-1][L-1] — the far corner. Catches off-by-one nonce
	// derivation (e.g. row/column swap, wrong nonce-packing endianness).
	diffsCorner := 0
	for j := 0; j < mldsaN; j++ {
		if A[K-1][L-1][j] != km.a[K-1][L-1][j] {
			if diffsCorner < 5 {
				t.Errorf("km.a[%d][%d][%d] != circl.A[%d][%d][%d]: pulsar=%d circl=%d",
					K-1, L-1, j, K-1, L-1, j,
					km.a[K-1][L-1][j], A[K-1][L-1][j])
			}
			diffsCorner++
		}
	}
	if diffsCorner > 0 {
		t.Errorf("km.a[%d][%d] DIFFERS from circl.A[%d][%d] in %d/%d positions — "+
			"deriveKeyMaterial likely has wrong nonce derivation for the last row/col",
			K-1, L-1, K-1, L-1, diffsCorner, mldsaN)
	}

	if diffs00 == 0 && diffsCorner == 0 {
		t.Logf("km.a == circl.A at [0][0] and [%d][%d] — v1.0.20 fix holds", K-1, L-1)
	}
}

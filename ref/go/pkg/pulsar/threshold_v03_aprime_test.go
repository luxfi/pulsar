// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03_aprime_test.go — DIAGNOSTIC: confirm that circl's A
// matrix from PublicKey is byte-equal to PolyDeriveUniform output
// (i.e., A is stored in NTT-domain directly, not raw + post-NTT).

import (
	"testing"
	"unsafe"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// TestAMatrix_IsAlreadyInNTTDomain tests the hypothesis that circl's
// A matrix is sampled DIRECTLY into NTT-domain (per FIPS 204 ExpandA),
// not raw values that are later NTT'd. If true, our deriveKeyMaterial
// has a bug: it post-NTTs A after sampling.
func TestAMatrix_IsAlreadyInNTTDomain(t *testing.T) {
	var seed [SeedSize]byte
	copy(seed[:], "pulsar-aprime-master-seed-32byte")

	// Get circl's stored A matrix via unsafe.
	circlPk, _ := mldsa65.NewKeyFromSeed(&seed)
	circlPkAny := (*circlPubKeyShape)(unsafe.Pointer(circlPk))
	A := (*circlMatShape)(circlPkAny.A)
	if A == nil {
		t.Fatal("circl A is nil; can't compare")
	}

	// Independently sample A[0][0] via PolyDeriveUniform.
	var rho32 [32]byte
	copy(rho32[:], circlPkAny.rho[:])
	var a00Sampled poly
	polyDeriveUniform(&a00Sampled, &rho32, uint16(0)<<8|uint16(0))

	t.Logf("circl  A[0][0][0..4]:    %v", A[0][0][0:5])
	t.Logf("polyDU A[0][0][0..4]:    %v", a00Sampled[0:5])

	// If A[0][0] == polyDeriveUniform output, then circl's A is NOT
	// post-NTT'd; it's stored as raw PolyDeriveUniform output (which
	// is FIPS 204 NTT-domain by spec).
	allMatch := true
	for j := 0; j < mldsaN; j++ {
		if A[0][0][j] != a00Sampled[j] {
			t.Logf("A[0][0][%d] differs: circl=%d sampled=%d", j, A[0][0][j], a00Sampled[j])
			allMatch = false
			if j > 8 {
				break
			}
		}
	}
	if allMatch {
		t.Log("HYPOTHESIS CONFIRMED: A is FIPS 204 ExpandA output (NTT-domain), no post-NTT needed")
	} else {
		t.Error("HYPOTHESIS REJECTED: A differs from PolyDeriveUniform output")
	}

	// Also check: a00Sampled.ntt() should give the post-NTT values our
	// deriveKeyMaterial currently produces.
	var a00PostNTT poly
	a00PostNTT = a00Sampled
	a00PostNTT.ntt()
	t.Logf("polyDU+NTT A[0][0][0..4]: %v (this is what km.a stores)", a00PostNTT[0:5])
}

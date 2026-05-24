// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03_unsafediff_test.go — DIAGNOSTIC: use unsafe to access
// circl's internal PublicKey fields and compare them against our
// reconstructed values. This bypasses the "internal package not
// importable" wall and lets us isolate exactly which intermediate
// diverges.

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// circlPubKeyShape mirrors the internal layout of circl's mldsa65
// PublicKey (sign/mldsa/mldsa65/internal/dilithium.go). MUST match the
// circl source exactly. K=6 for ML-DSA-65.
type circlPubKeyShape struct {
	rho [32]byte
	t1  [6][256]uint32 // VecK = [K]Poly = [6][N]uint32
	t1p [320 * 6]byte
	A   unsafe.Pointer  // *Mat
	tr  unsafe.Pointer  // *[64]byte
}

// circlMatShape mirrors circl's Mat = [K]VecL = [6][5][256]uint32.
type circlMatShape [6][5][256]uint32

// TestCirclInternalShape_VsPulsar reaches into circl's internal types
// via unsafe and compares cached fields (A, t1, tr) against the
// reconstructions we use in verify. If any of A/t1 differs byte-wise,
// the bug is in the corresponding derivation primitive.
func TestCirclInternalShape_VsPulsar(t *testing.T) {
	var seed [SeedSize]byte
	copy(seed[:], "pulsar-unsafediff-master-seed-32")

	// circl side: build PublicKey via NewKeyFromSeed.
	circlPk, _ := mldsa65.NewKeyFromSeed(&seed)
	circlPkAny := (*circlPubKeyShape)(unsafe.Pointer(circlPk))

	t.Logf("circl  rho[0..8]: %x", circlPkAny.rho[0:8])
	t.Logf("circl  t1[0][0..4]: %v", circlPkAny.t1[0][0:5])

	A := (*circlMatShape)(circlPkAny.A)
	if A != nil {
		t.Logf("circl  A[0][0][0..4]: %v", A[0][0][0:5])
	}

	// our side: derive km from the same seed and unpack pub.
	params := MustParamsFor(ModeP65)
	km, err := deriveKeyMaterial(params.Mode, &seed)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroizeKeyMaterial(km)

	t.Logf("pulsar rho[0..8]: %x", km.rho[0:8])
	t.Logf("pulsar t1[0][0..4]: %v", km.t1[0][0:5])
	t.Logf("pulsar A[0][0][0..4]: %v (note: km.a is post-NTT)", km.a[0][0][0:5])

	// Compare rho.
	if circlPkAny.rho != km.rho {
		t.Errorf("rho DIFFERS")
	} else {
		t.Logf("rho ✓")
	}

	// Compare t1 polynomial-wise.
	t1Diffs := 0
	for k := 0; k < 6; k++ {
		for j := 0; j < 256; j++ {
			if circlPkAny.t1[k][j] != km.t1[k][j] {
				if t1Diffs < 5 {
					t.Logf("t1[%d][%d] differs: circl=%d pulsar=%d", k, j, circlPkAny.t1[k][j], km.t1[k][j])
				}
				t1Diffs++
			}
		}
	}
	if t1Diffs > 0 {
		t.Errorf("t1 DIFFERS in %d positions", t1Diffs)
	} else {
		t.Logf("t1 ✓")
	}

	// Compare A polynomial-wise. circl's A is post-NTT (cached); ours is also post-NTT.
	if A != nil {
		aDiffs := 0
		for k := 0; k < 6; k++ {
			for l := 0; l < 5; l++ {
				for j := 0; j < 256; j++ {
					if A[k][l][j] != km.a[k][l][j] {
						if aDiffs < 5 {
							t.Logf("A[%d][%d][%d] differs: circl=%d pulsar=%d", k, l, j, A[k][l][j], km.a[k][l][j])
						}
						aDiffs++
					}
				}
			}
		}
		if aDiffs > 0 {
			t.Errorf("A DIFFERS in %d positions", aDiffs)
		} else {
			t.Logf("A ✓")
		}
	}

	// Also: cross-check by comparing tr.
	trPtr := (*[64]byte)(circlPkAny.tr)
	if trPtr == nil {
		t.Log("circl tr is nil (computed lazily?)")
	} else {
		t.Logf("circl  tr[0..16]: %x", trPtr[0:16])
		t.Logf("pulsar tr[0..16]: %x", km.tr[0:16])
		if *trPtr != km.tr {
			t.Errorf("tr DIFFERS")
		} else {
			t.Logf("tr ✓")
		}
	}

	// Suppress unused warning.
	_ = reflect.TypeOf(circlPk)
}

// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold_v03_primdiff_test.go — DIAGNOSTIC: compare our verify-side
// primitives against circl by computing both sides starting from a
// circl-produced (pub, msg, sig). If the c̃-derived from our pipeline
// differs from the c̃-in-the-signature, the bug is in one of the
// primitives along the chain:
//   z unpack → ntt → polyDotHat(A, z) → t1·2^D·c·ntt·mulHat → sub →
//   reduceLe2Q → invNTT → normalizeAssumingLe2Q → useHint → packW1
//
// This test isolates each step using known-good circl outputs.

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// TestPrimDiff_VerifyPipeline_OnCirclSig sequentially compares each
// verify-side primitive against circl by re-running the verify chain
// step-by-step on a circl-produced signature.
func TestPrimDiff_VerifyPipeline_OnCirclSig(t *testing.T) {
	msg := []byte("primdiff verify pipeline")
	var seed [SeedSize]byte
	copy(seed[:], "pulsar-primdiff-master-seed-32!!")

	params := MustParamsFor(ModeP65)
	masterSk, err := KeyFromSeed(params, seed)
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}

	var circlSk mldsa65.PrivateKey
	if err := circlSk.UnmarshalBinary(masterSk.Bytes); err != nil {
		t.Fatalf("circl sk: %v", err)
	}
	sigBytes := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(&circlSk, msg, nil, false, sigBytes); err != nil {
		t.Fatalf("circl sign: %v", err)
	}
	var circlPub mldsa65.PublicKey
	circlPub.UnmarshalBinary(masterSk.Pub.Bytes)
	if !mldsa65.Verify(&circlPub, msg, nil, sigBytes) {
		t.Fatal("circl sig fails self-verify (sanity)")
	}
	pubBytes := masterSk.Pub.Bytes

	cTildeSize := modeCTildeSize(params.Mode)
	gamma1Bits := modeGamma1Bits(params.Mode)
	K, L, _ := modeShape(params.Mode)
	tau, omega, _, gamma2 := modeTauOmega(params.Mode)
	cTildeFromSig := sigBytes[:cTildeSize]

	// STEP 1: unpack z using our unpacker.
	polyLeGamma1Size := int((uint32(gamma1Bits) + 1) * mldsaN / 8)
	z := make(polyVec, L)
	off := cTildeSize
	for l := 0; l < L; l++ {
		polyUnpackLeGamma1(&z[l], sigBytes[off:off+polyLeGamma1Size], uint32(gamma1Bits))
		off += polyLeGamma1Size
	}

	// STEP 1b: roundtrip z back through our packer; must equal circl's bytes.
	zRepack := make([]byte, L*polyLeGamma1Size)
	for l := 0; l < L; l++ {
		polyPackLeGamma1(&z[l], zRepack[l*polyLeGamma1Size:(l+1)*polyLeGamma1Size], uint32(gamma1Bits))
	}
	zCirclBytes := sigBytes[cTildeSize : cTildeSize+L*polyLeGamma1Size]
	if !bytes.Equal(zRepack, zCirclBytes) {
		t.Fatalf("STEP 1: z unpack/repack diverges from circl bytes")
	}
	t.Logf("STEP 1: z unpack/repack roundtrip ✓")

	// STEP 2: unpack hint.
	hint := make(polyVec, K)
	hintBuf := sigBytes[cTildeSize+L*polyLeGamma1Size : cTildeSize+L*polyLeGamma1Size+omega+K]
	if !unpackHintForTest(hint, hintBuf, omega) {
		t.Fatalf("STEP 2: hint unpack failed (malformed)")
	}
	t.Logf("STEP 2: hint unpack ✓ (popcount tracked below)")

	// STEP 3: c = SampleInBall(c̃).
	var c poly
	polyDeriveUniformBall(&c, cTildeFromSig, tau)
	// Verify popcount τ for c.
	nz := 0
	for i := 0; i < mldsaN; i++ {
		if c[i] != 0 {
			nz++
		}
	}
	if nz != tau {
		t.Errorf("STEP 3: SampleInBall popcount=%d expected τ=%d", nz, tau)
	}
	t.Logf("STEP 3: c popcount=%d ✓ (expected %d)", nz, tau)

	// STEP 4: Derive A from ρ. FIPS 204 §3.5 ExpandA samples coefficients
	// DIRECTLY into the NTT representation; no forward NTT here.
	rho := pubBytes[:32]
	var rho32 [32]byte
	copy(rho32[:], rho)
	A := make([]polyVec, K)
	for i := 0; i < K; i++ {
		A[i] = make(polyVec, L)
		for j := 0; j < L; j++ {
			polyDeriveUniform(&A[i][j], &rho32, uint16(i)<<8|uint16(j))
		}
	}
	// Sanity: A[0][0] should equal what circl produces for the same ρ.
	// We don't have circl's A exposed, but we can check internal consistency.
	t.Logf("STEP 4: A derived (sanity: A[0][0][0..4]=%v)", A[0][0][0:5])

	// STEP 5: Unpack t_1.
	t1 := make(polyVec, K)
	for k := 0; k < K; k++ {
		polyUnpackT1(&t1[k], pubBytes[32+320*k:32+320*(k+1)])
	}
	// Sanity: t_1 unpack should be lossless — repack and compare.
	for k := 0; k < K; k++ {
		var repack [320]byte
		polyPackT1(&t1[k], repack[:])
		if !bytes.Equal(repack[:], pubBytes[32+320*k:32+320*(k+1)]) {
			t.Fatalf("STEP 5: t_1[%d] unpack/repack diverges", k)
		}
	}
	t.Logf("STEP 5: t_1 unpack/repack ✓")

	// STEP 6: zHat = NTT(z).
	zHat := make(polyVec, L)
	for l := 0; l < L; l++ {
		zHat[l] = z[l]
		zHat[l].ntt()
	}
	t.Logf("STEP 6: zHat[0][0..4]=%v", zHat[0][0:5])

	// STEP 7: Az = A · zHat (NTT-domain pointwise).
	Az := make(polyVec, K)
	for k := 0; k < K; k++ {
		polyDotHat(&Az[k], A[k], zHat)
	}
	t.Logf("STEP 7: Az[0][0..4]=%v", Az[0][0:5])

	// STEP 8: Compute c·t_1·2^D in NTT domain.
	cHat := c
	cHat.ntt()
	ct1_2d := make(polyVec, K)
	for k := 0; k < K; k++ {
		ct1_2d[k].mulBy2toD(&t1[k])
		ct1_2d[k].ntt()
		ct1_2d[k].mulHat(&ct1_2d[k], &cHat)
	}
	t.Logf("STEP 8: ct1_2d[0][0..4]=%v", ct1_2d[0][0:5])

	// STEP 9: wPrime = Az - c·t_1·2^D, reduceLe2Q, invNTT, normalizeAssumingLe2Q.
	wPrime := make(polyVec, K)
	for k := 0; k < K; k++ {
		wPrime[k].sub(&Az[k], &ct1_2d[k])
		wPrime[k].reduceLe2Q()
		wPrime[k].invNTT()
		wPrime[k].normalizeAssumingLe2Q()
	}
	t.Logf("STEP 9: wPrime[0][0..4]=%v", wPrime[0][0:5])

	// STEP 10: w1 = useHint(wPrime, hint).
	w1Rec := useHintVec(wPrime, hint, gamma2)
	t.Logf("STEP 10: w1Rec[0][0..4]=%v", w1Rec[0][0:5])

	// STEP 11: Pack w_1.
	w1Packed := packW1Vec(w1Rec, gamma2, K)
	t.Logf("STEP 11: w1Packed[0..8]=%x len=%d", w1Packed[0:8], len(w1Packed))

	// STEP 12: tr = SHAKE256(pk).
	tr := make([]byte, 64)
	{
		h := newShake256()
		_, _ = h.Write(pubBytes)
		_, _ = h.Read(tr)
	}

	// STEP 13: mu = SHAKE256(tr || 0x00 || 0x00 || msg).
	var mu [64]byte
	{
		h := newShake256()
		_, _ = h.Write(tr)
		_, _ = h.Write([]byte{0x00, 0x00})
		_, _ = h.Write(msg)
		_, _ = h.Read(mu[:])
	}
	t.Logf("STEP 13: mu[0..8]=%x", mu[0:8])

	// STEP 14: c̃' = SHAKE256(mu || w1Packed).
	cTildePrime := make([]byte, cTildeSize)
	{
		h := newShake256()
		_, _ = h.Write(mu[:])
		_, _ = h.Write(w1Packed)
		_, _ = h.Read(cTildePrime)
	}
	t.Logf("STEP 14: c̃ from sig:  %x", cTildeFromSig[0:16])
	t.Logf("STEP 14: c̃' recompute: %x", cTildePrime[0:16])

	if bytes.Equal(cTildeFromSig, cTildePrime) {
		t.Log("ALL STEPS ✓ — manual verify matches circl. So the bug is in v0.3 sign-side.")
		return
	}
	t.Fatal("DIVERGENCE: c̃ from sig ≠ c̃' from recompute. Bug is in verify-side primitives.")
}

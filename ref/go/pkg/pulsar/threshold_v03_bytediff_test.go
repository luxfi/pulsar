// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// TestAlgebraic_DebugVsCirclVerify is the focused debug test.
//
// Approach:
//  1. Stage a v0.3 ceremony to produce sig.Bytes
//  2. Reconstruct the master sk from the dealer's seed (this is what
//     the v0.1 path does internally)
//  3. Pack the equivalent FIPS 204 PUBLIC KEY and call mldsa65.Verify
//     directly on (pub, msg, sig.Bytes) — same as Pulsar.Verify does
//  4. If verify fails, trace which sig field is wrong by:
//     a. Unpacking sig.Bytes into (c̃, z, h)
//     b. Comparing each component against a v0.1-Combine-produced sig
//     on the same message (v0.1 uses circl directly so it WILL
//     verify; its bytes are the ground truth)
//
// This is a structural debug test — its failure means we have a
// concrete diff to chase. Once it passes, byte-equality is achieved.
func TestAlgebraic_DebugVsCirclVerify(t *testing.T) {
	msg := []byte("v0.3 byte-diff vs circl ground truth")
	var sid [16]byte
	copy(sid[:], "v03-bytediff-001")

	// Stage v0.3 ceremony.
	var sigV03 *Signature
	var pubV03 *PublicKey
	var err error
	for attempt := uint32(0); attempt < 32; attempt++ {
		sigV03, pubV03, _, _, _, _, _, err = stageAlgebraic(t, 5, 3, msg, sid, attempt)
		if err == nil {
			break
		}
		if err != ErrAlgebraicRestart {
			t.Fatalf("attempt %d unexpected: %v", attempt, err)
		}
	}
	if err != nil {
		t.Fatalf("v0.3 did not converge in 32 attempts")
	}
	t.Logf("v0.3 sig size: %d", len(sigV03.Bytes))
	t.Logf("v0.3 pub size: %d", len(pubV03.Bytes))

	// Reconstruct the master sk from the dealer seed.
	var seed [SeedSize]byte
	copy(seed[:], "pulsar-v03-test-master-seed-32!!")
	params := MustParamsFor(ModeP65)
	masterSk, err := KeyFromSeed(params, seed)
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}

	// Master pub must equal v0.3 setup.Pub (this confirms DKG public-key derivation).
	if !bytes.Equal(masterSk.Pub.Bytes, pubV03.Bytes) {
		t.Fatalf("v0.3 setup.Pub != master KeyFromSeed.Pub (DKG bug)")
	}
	t.Logf("v0.3 pub byte-equals master KeyFromSeed pub ✓")

	// Unpack v0.3 pub into circl's mldsa65 type and call circl.Verify directly.
	// This bypasses Pulsar's verify wrapper to ensure we're testing
	// stock circl behavior.
	var circlPub mldsa65.PublicKey
	if err := circlPub.UnmarshalBinary(pubV03.Bytes); err != nil {
		t.Fatalf("circl pub unmarshal: %v", err)
	}

	if mldsa65.Verify(&circlPub, msg, nil, sigV03.Bytes) {
		t.Logf("✓ v0.3 sig VERIFIES under stock circl mldsa65.Verify")
		return // SUCCESS
	}
	t.Logf("✗ v0.3 sig FAILS stock circl mldsa65.Verify — bug present, diagnosing...")

	// Bug present. Sign the same message with circl directly using the
	// master sk to get a reference sig. NOTE: circl uses fresh random
	// y per attempt, so circl's sig WILL differ from ours byte-wise
	// for the bulk (z field). What we CAN check:
	//   - sig structure (cTildeSize + z_packed + hint_packed) lengths
	//   - circl's sig passes verify (sanity)
	var circlSk mldsa65.PrivateKey
	if err := circlSk.UnmarshalBinary(masterSk.Bytes); err != nil {
		t.Fatalf("circl sk unmarshal: %v", err)
	}
	circlSig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(&circlSk, msg, nil, false, circlSig); err == nil {
		t.Logf("circl sig size: %d", len(circlSig))
		if mldsa65.Verify(&circlPub, msg, nil, circlSig) {
			t.Logf("circl sig passes its own Verify (sanity ✓)")
		}
		// SHA-256 fingerprints — different is expected (different y).
		v03Hash := sha256.Sum256(sigV03.Bytes)
		circlHash := sha256.Sum256(circlSig)
		t.Logf("v0.3 sig SHA256:  %x", v03Hash)
		t.Logf("circl sig SHA256: %x", circlHash)
	}

	// TARGETED DIAGNOSIS: roundtrip our sig through circl's unpacker.
	// If circl unpacks (c̃, z, h) but they don't satisfy verify's
	// internal equation, the bug is in our SIGNATURE CONTENT (z/h
	// computed wrong), NOT pack-layout.
	t.Fatalf("v0.3 sig does not verify under stock circl mldsa65.Verify (see logs)")
}

// TestManualVerify_OnV01SigSanity runs the manual verify on a v0.1
// Combine sig (which IS circl-verifiable). If this PASSES, the manual
// verify is correct; if this FAILS too, the manual verify itself is
// buggy and ManualVerify on v0.3 doesn't tell us anything useful.
func TestManualVerify_OnV01SigSanity(t *testing.T) {
	msg := []byte("v0.1 manual verify sanity")
	var seed [SeedSize]byte
	copy(seed[:], "pulsar-v01-sanity-master-seed!!")
	params := MustParamsFor(ModeP65)

	masterSk, err := KeyFromSeed(params, seed)
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}

	// Produce a sig via stock mldsa.SignTo (the gold standard).
	var circlSk mldsa65.PrivateKey
	if err := circlSk.UnmarshalBinary(masterSk.Bytes); err != nil {
		t.Fatalf("circl sk unmarshal: %v", err)
	}
	sigBytes := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(&circlSk, msg, nil, false, sigBytes); err != nil {
		t.Fatalf("circl sign: %v", err)
	}

	// Manually verify. Should PASS if my manual verify code is correct.
	pubBytes := masterSk.Pub.Bytes
	var circlPub mldsa65.PublicKey
	circlPub.UnmarshalBinary(pubBytes)
	if !mldsa65.Verify(&circlPub, msg, nil, sigBytes) {
		t.Fatal("circl sig fails its own Verify (sanity)")
	}
	t.Logf("circl sig passes circl Verify ✓")

	ok := manualVerifyOnce(t, params, pubBytes, msg, sigBytes)
	if !ok {
		t.Fatal("MANUAL VERIFY FAILED on a circl-produced sig — test code bug")
	}
	t.Logf("manual verify accepts circl sig ✓ — test code is sound")
}

// manualVerifyOnce returns true if Pulsar's manual verify accepts
// (pub, msg, sig). Used both as sanity test and v0.3 diagnostic.
func manualVerifyOnce(t *testing.T, params *Params, pubBytes, msg, sigBytes []byte) bool {
	cTildeSize := modeCTildeSize(params.Mode)
	gamma1Bits := modeGamma1Bits(params.Mode)
	K, L, _ := modeShape(params.Mode)
	tau, omega, _, gamma2 := modeTauOmega(params.Mode)

	cTilde := sigBytes[:cTildeSize]
	polyLeGamma1Size := int((uint32(gamma1Bits) + 1) * mldsaN / 8)
	z := make(polyVec, L)
	off := cTildeSize
	for l := 0; l < L; l++ {
		polyUnpackLeGamma1(&z[l], sigBytes[off:off+polyLeGamma1Size], uint32(gamma1Bits))
		off += polyLeGamma1Size
	}
	hint := make(polyVec, K)
	if !unpackHintForTest(hint, sigBytes[off:off+omega+K], omega) {
		return false
	}

	beta := uint32(tau) * uint32(params.Eta)
	gamma1 := uint32(1) << gamma1Bits
	if polyVecExceeds(z, gamma1-beta) {
		return false
	}

	var c poly
	polyDeriveUniformBall(&c, cTilde, tau)
	cHat := c
	cHat.ntt()

	rho := pubBytes[:32]
	t1 := make(polyVec, K)
	for k := 0; k < K; k++ {
		polyUnpackT1(&t1[k], pubBytes[32+320*k:32+320*(k+1)])
	}
	var rho32 [32]byte
	copy(rho32[:], rho)
	// FIPS 204 §3.5 ExpandA samples A coefficients DIRECTLY into the
	// NTT representation; no forward NTT is required (or wanted) here.
	A := make([]polyVec, K)
	for i := 0; i < K; i++ {
		A[i] = make(polyVec, L)
		for j := 0; j < L; j++ {
			polyDeriveUniform(&A[i][j], &rho32, uint16((i<<8)|j))
		}
	}

	zHat := make(polyVec, L)
	for l := 0; l < L; l++ {
		zHat[l] = z[l]
		zHat[l].ntt()
	}
	Az := make(polyVec, K)
	for k := 0; k < K; k++ {
		polyDotHat(&Az[k], A[k], zHat)
	}
	ct1_2d := make(polyVec, K)
	for k := 0; k < K; k++ {
		ct1_2d[k].mulBy2toD(&t1[k])
		ct1_2d[k].ntt()
		ct1_2d[k].mulHat(&ct1_2d[k], &cHat)
	}
	wPrime := make(polyVec, K)
	for k := 0; k < K; k++ {
		wPrime[k].sub(&Az[k], &ct1_2d[k])
		wPrime[k].reduceLe2Q()
		wPrime[k].invNTT()
		wPrime[k].normalizeAssumingLe2Q()
	}

	w1Rec := useHintVec(wPrime, hint, gamma2)
	w1Packed := packW1Vec(w1Rec, gamma2, K)

	tr := make([]byte, 64)
	{
		h := newShake256()
		_, _ = h.Write(pubBytes)
		_, _ = h.Read(tr)
	}
	var mu [64]byte
	{
		h := newShake256()
		_, _ = h.Write(tr)
		_, _ = h.Write([]byte{0x00, 0x00})
		_, _ = h.Write(msg)
		_, _ = h.Read(mu[:])
	}
	cTildePrime := make([]byte, cTildeSize)
	{
		h := newShake256()
		_, _ = h.Write(mu[:])
		_, _ = h.Write(w1Packed)
		_, _ = h.Read(cTildePrime)
	}
	if t != nil {
		t.Logf("manualVerify: c̃[0..8]=%x  c̃'[0..8]=%x", cTilde[0:8], cTildePrime[0:8])
	}
	return bytes.Equal(cTilde, cTildePrime)
}

// TestPulsarSigPackRoundtrip verifies Pulsar's sigEncode is byte-equal
// to circl's. Take a circl-produced sig, unpack with our unpacker,
// repack with our packer, compare to original. If they differ, our
// pack/unpack diverges from circl's.
func TestPulsarSigPackRoundtrip(t *testing.T) {
	var seed [SeedSize]byte
	copy(seed[:], "pulsar-packrt-master-seed-32!!!")
	params := MustParamsFor(ModeP65)

	masterSk, err := KeyFromSeed(params, seed)
	if err != nil {
		t.Fatalf("KeyFromSeed: %v", err)
	}
	var circlSk mldsa65.PrivateKey
	if err := circlSk.UnmarshalBinary(masterSk.Bytes); err != nil {
		t.Fatalf("circl sk unmarshal: %v", err)
	}
	msg := []byte("pack roundtrip test")
	circlSig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(&circlSk, msg, nil, false, circlSig); err != nil {
		t.Fatalf("circl sign: %v", err)
	}
	var circlPub mldsa65.PublicKey
	circlPub.UnmarshalBinary(masterSk.Pub.Bytes)
	if !mldsa65.Verify(&circlPub, msg, nil, circlSig) {
		t.Fatal("circl sanity")
	}

	// Unpack via Pulsar.
	cTildeSize := modeCTildeSize(params.Mode)
	gamma1Bits := modeGamma1Bits(params.Mode)
	K, L, _ := modeShape(params.Mode)
	_, omega, _, _ := modeTauOmega(params.Mode)

	cTilde := make([]byte, cTildeSize)
	copy(cTilde, circlSig[:cTildeSize])
	polyLeGamma1Size := int((uint32(gamma1Bits) + 1) * mldsaN / 8)
	z := make(polyVec, L)
	off := cTildeSize
	for l := 0; l < L; l++ {
		polyUnpackLeGamma1(&z[l], circlSig[off:off+polyLeGamma1Size], uint32(gamma1Bits))
		off += polyLeGamma1Size
	}
	hint := make(polyVec, K)
	if !unpackHintForTest(hint, circlSig[off:off+omega+K], omega) {
		t.Fatal("hint unpack failed")
	}

	// Repack via Pulsar.
	sigBytes := make([]byte, params.SignatureSize)
	copy(sigBytes[:cTildeSize], cTilde)
	off = cTildeSize
	for l := 0; l < L; l++ {
		polyPackLeGamma1(&z[l], sigBytes[off:off+polyLeGamma1Size], uint32(gamma1Bits))
		off += polyLeGamma1Size
	}
	polyVecPackHint(hint, sigBytes[off:off+omega+K], omega)

	if !bytes.Equal(sigBytes, circlSig) {
		// Find first diverging byte to localise.
		for i := 0; i < len(circlSig); i++ {
			if sigBytes[i] != circlSig[i] {
				t.Logf("first diff at byte %d (offset within: cTilde[0..%d], z[%d..%d], hint[%d..])",
					i, cTildeSize, cTildeSize, cTildeSize+L*polyLeGamma1Size, cTildeSize+L*polyLeGamma1Size)
				region := "c̃"
				if i >= cTildeSize {
					region = "z"
				}
				if i >= cTildeSize+L*polyLeGamma1Size {
					region = "hint"
				}
				t.Logf("  region: %s. circl=%02x, ours=%02x", region, circlSig[i], sigBytes[i])
				// Print 16 bytes around the divergence
				start := i - 8
				if start < 0 {
					start = 0
				}
				end := i + 8
				if end > len(circlSig) {
					end = len(circlSig)
				}
				t.Logf("  circl[%d:%d]: %x", start, end, circlSig[start:end])
				t.Logf("  ours [%d:%d]: %x", start, end, sigBytes[start:end])
				break
			}
		}
		t.Fatalf("pack/unpack roundtrip is NOT byte-equal — bug in polyPackLeGamma1, polyUnpackLeGamma1, polyVecPackHint, or unpackHintForTest")
	}
	t.Logf("✓ Pulsar pack/unpack roundtrip byte-equal to circl sig")
}

// TestV03_CTildeConsistency confirms each party computes the SAME c̃
// as the aggregator. If they differ, parties use different c, and
// their z_i don't form a coherent z.
func TestV03_CTildeConsistency(t *testing.T) {
	msg := []byte("v0.3 ctilde consistency check")
	var sid [16]byte
	copy(sid[:], "v03-ctilde-cons1")

	// Run a 5-of-3 ceremony manually so we can inspect parties' c̃.
	params := MustParamsFor(ModeP65)
	committee := makeCommittee(5)
	ident := newIdentityFixture(t, committee, []byte{0xAA, 0xBB, 0xCC, 0x03})

	var seed [SeedSize]byte
	copy(seed[:], "pulsar-ctilde-cons-master-seed!!")
	setup, shares, err := DealAlgebraicV03Shares(params, committee, 3, seed, deterministicReader([]byte{0xDD, 0xEE}))
	if err != nil {
		t.Fatalf("Deal: %v", err)
	}

	quorum := []NodeID{shares[0].NodeID, shares[1].NodeID, shares[2].NodeID}
	quorumShares := []*AlgebraicKeyShare{shares[0], shares[1], shares[2]}
	sessionKeys := ident.quorumSessionKeys(t, quorum, sid, msg)
	evalPoints, _ := V03QuorumEvalPoints(quorum, shares)

	signers := make([]*AlgebraicThresholdSigner, 3)
	for i := 0; i < 3; i++ {
		s, err := NewAlgebraicThresholdSigner(params, setup, sid, 1, quorum, quorumShares[i],
			sessionKeys[quorum[i]], msg, deterministicReader([]byte{0xFF, byte(i)}))
		if err != nil {
			t.Fatalf("party %d: %v", i, err)
		}
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
	K, _, _ := modeShape(params.Mode)
	_, _, _, gamma2 := modeTauOmega(params.Mode)
	cTildeSize := modeCTildeSize(params.Mode)

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
		m, _, err := s.Round2Sign(r1, peerWByParty[i])
		if err != nil {
			t.Fatalf("Round2Sign %d: %v", i, err)
		}
		r2[i] = m
	}

	// Recompute c̃ as the AGGREGATOR would.
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
	w1, _ := decomposeVec(w, gamma2)
	w1Packed := packW1Vec(w1, gamma2, K)
	var mu [64]byte
	{
		h := newShake256()
		_, _ = h.Write(setup.Tr[:])
		_, _ = h.Write([]byte{0x00, 0x00})
		_, _ = h.Write(msg)
		_, _ = h.Read(mu[:])
	}
	cTildeAgg := make([]byte, cTildeSize)
	{
		h := newShake256()
		_, _ = h.Write(mu[:])
		_, _ = h.Write(w1Packed)
		_, _ = h.Read(cTildeAgg)
	}
	t.Logf("aggregator c̃[0..16]: %x", cTildeAgg[0:16])

	// Each party would compute the same c̃ in Round2Sign — we can't
	// directly inspect (it's not exposed), but we can re-run the
	// computation party-by-party.
	for i := 0; i < 3; i++ {
		wParty := make(polyVec, K)
		for k := 0; k < K; k++ {
			wParty[k] = signers[i].myWCoeff[k]
		}
		for j := 0; j < 3; j++ {
			if j == i {
				continue
			}
			wj := unpackPolyVec(r2W[j].W, K)
			for k := 0; k < K; k++ {
				wParty[k].add(&wParty[k], &wj[k])
			}
		}
		for k := 0; k < K; k++ {
			wParty[k].normalize()
		}
		w1P, _ := decomposeVec(wParty, gamma2)
		w1PackedP := packW1Vec(w1P, gamma2, K)
		cTildeP := make([]byte, cTildeSize)
		{
			h := newShake256()
			_, _ = h.Write(mu[:])
			_, _ = h.Write(w1PackedP)
			_, _ = h.Read(cTildeP)
		}
		t.Logf("party %d c̃[0..16]:    %x", i, cTildeP[0:16])
		if !bytes.Equal(cTildeP, cTildeAgg) {
			t.Errorf("party %d c̃ differs from aggregator c̃ — INCONSISTENCY BUG", i)
		}
	}

}

// TestV03_StageAlgebraicAndCheckSig stages a v0.3 ceremony to
// acceptance, then checks that the sig c̃ matches what an external
// observer computes.
func TestV03_StageAlgebraicAndCheckSig(t *testing.T) {
	msg := []byte("v0.3 stage and check")
	var sid [16]byte
	copy(sid[:], "v03-stage-checks")

	var sig *Signature
	var pub *PublicKey
	var setup *AlgebraicSetup
	var err error
	for attempt := uint32(0); attempt < 64; attempt++ {
		sig, pub, setup, _, _, _, _, err = stageAlgebraic(t, 5, 3, msg, sid, attempt)
		if err == nil {
			t.Logf("converged at attempt %d", attempt)
			break
		}
		if err != ErrAlgebraicRestart {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	if err != nil {
		t.Fatal("no convergence")
	}

	// Try circl verify.
	params := MustParamsFor(ModeP65)
	cTildeSize := modeCTildeSize(params.Mode)
	var circlPub mldsa65.PublicKey
	circlPub.UnmarshalBinary(pub.Bytes)
	ok := mldsa65.Verify(&circlPub, msg, nil, sig.Bytes)
	t.Logf("circl verify: %v", ok)
	t.Logf("sig c̃[0..8]: %x", sig.Bytes[0:8])

	// Inspect hint bits.
	K, L, _ := modeShape(params.Mode)
	_, omega, _, _ := modeTauOmega(params.Mode)
	gamma1Bits := modeGamma1Bits(params.Mode)
	polyLeGamma1Size := int((uint32(gamma1Bits) + 1) * mldsaN / 8)
	hint := make(polyVec, K)
	hintBuf := sig.Bytes[cTildeSize+L*polyLeGamma1Size : cTildeSize+L*polyLeGamma1Size+omega+K]
	if !unpackHintForTest(hint, hintBuf, omega) {
		t.Fatal("hint unpack failed")
	}
	var totalOnes int
	for k := 0; k < K; k++ {
		for j := 0; j < mldsaN; j++ {
			if hint[k][j] != 0 {
				totalOnes++
			}
		}
	}
	t.Logf("hint total 1-bits: %d (max omega=%d)", totalOnes, omega)
	_ = setup
}

// TestAlgebraic_ManualVerify reproduces FIPS 204 Verify on our v0.3
// sig using Pulsar's own primitives — the same primitives that
// produced the sig. If THIS verify succeeds but circl's verify fails,
// the bug is in a primitive that diverges from circl. If THIS verify
// ALSO fails, the bug is in our sig generation logic (z, h, or pack).
func TestAlgebraic_ManualVerify(t *testing.T) {
	msg := []byte("v0.3 manual verify with our primitives")
	var sid [16]byte
	copy(sid[:], "v03-manualv-0001")

	var sigV03 *Signature
	var pubV03 *PublicKey
	var err error
	for attempt := uint32(0); attempt < 32; attempt++ {
		sigV03, pubV03, _, _, _, _, _, err = stageAlgebraic(t, 5, 3, msg, sid, attempt)
		if err == nil {
			break
		}
		if err != ErrAlgebraicRestart {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	if err != nil {
		t.Fatalf("v0.3 didn't converge")
	}

	// Unpack our sig.
	params := MustParamsFor(ModeP65)
	cTildeSize := modeCTildeSize(params.Mode)
	gamma1Bits := modeGamma1Bits(params.Mode)
	K, L, _ := modeShape(params.Mode)
	tau, omega, _, gamma2 := modeTauOmega(params.Mode)

	cTilde := sigV03.Bytes[:cTildeSize]
	polyLeGamma1Size := int((uint32(gamma1Bits) + 1) * mldsaN / 8)
	z := make(polyVec, L)
	off := cTildeSize
	for l := 0; l < L; l++ {
		polyUnpackLeGamma1(&z[l], sigV03.Bytes[off:off+polyLeGamma1Size], uint32(gamma1Bits))
		off += polyLeGamma1Size
	}
	hint := make(polyVec, K)
	hintBuf := sigV03.Bytes[off : off+omega+K]
	if !unpackHintForTest(hint, hintBuf, omega) {
		t.Fatalf("hint unpack failed (malformed)")
	}

	// Check ||z||_∞ < γ_1 - β.
	beta := uint32(tau) * uint32(params.Eta)
	gamma1 := uint32(1) << gamma1Bits
	if polyVecExceeds(z, gamma1-beta) {
		t.Fatalf("z norm fails (verifier-side): ||z|| >= γ_1 - β")
	}

	// c = SampleInBall(c̃)
	var c poly
	polyDeriveUniformBall(&c, cTilde, tau)
	cHat := c
	cHat.ntt()

	// Unpack public key (ρ, t_1).
	rho := pubV03.Bytes[:32]
	t1 := make(polyVec, K)
	for k := 0; k < K; k++ {
		polyUnpackT1(&t1[k], pubV03.Bytes[32+320*k:32+320*(k+1)])
	}

	// FIPS 204 §3.5 ExpandA samples A coefficients DIRECTLY into the
	// NTT representation; no forward NTT is required (or wanted) here.
	var rho32 [32]byte
	copy(rho32[:], rho)
	A := make([]polyVec, K)
	for i := 0; i < K; i++ {
		A[i] = make(polyVec, L)
		for j := 0; j < L; j++ {
			polyDeriveUniform(&A[i][j], &rho32, uint16((i<<8)|j))
		}
	}

	// Mirror circl's Verify (lines 296-318 of dilithium.go):
	//   zh = z; zh.NTT()
	//   Az[i] = PolyDotHat(A[i], zh)
	//   Az2dct1 = t1 << D; .NTT(); for each row .MulHat(., ch)
	//   Az2dct1.Sub(Az, Az2dct1); .ReduceLe2Q(); .InvNTT(); .NormalizeAssumingLe2Q()
	zHat := make(polyVec, L)
	for l := 0; l < L; l++ {
		zHat[l] = z[l]
		zHat[l].ntt()
	}
	Az := make(polyVec, K)
	for k := 0; k < K; k++ {
		polyDotHat(&Az[k], A[k], zHat)
	}
	// Compute c · t_1 · 2^D in NTT domain.
	ct1_2d := make(polyVec, K)
	for k := 0; k < K; k++ {
		ct1_2d[k].mulBy2toD(&t1[k])
		ct1_2d[k].ntt()
		ct1_2d[k].mulHat(&ct1_2d[k], &cHat)
	}
	// A·z - c·t_1·2^D, then reduce + invNTT + normalize.
	wPrime := make(polyVec, K)
	for k := 0; k < K; k++ {
		wPrime[k].sub(&Az[k], &ct1_2d[k])
		wPrime[k].reduceLe2Q()
		wPrime[k].invNTT()
		wPrime[k].normalizeAssumingLe2Q()
	}

	// Apply UseHint to get reconstructed w_1.
	w1Rec := useHintVec(wPrime, hint, gamma2)
	w1Packed := packW1Vec(w1Rec, gamma2, K)

	// μ = SHAKE-256(tr || 0x00 || 0x00 || msg, 64).
	tr := make([]byte, 64)
	{
		h := newShake256()
		_, _ = h.Write(pubV03.Bytes)
		_, _ = h.Read(tr)
	}
	var mu [64]byte
	{
		h := newShake256()
		_, _ = h.Write(tr)
		_, _ = h.Write([]byte{0x00, 0x00})
		_, _ = h.Write(msg)
		_, _ = h.Read(mu[:])
	}

	// Recompute c̃' from μ + w_1Encode.
	cTildePrime := make([]byte, cTildeSize)
	{
		h := newShake256()
		_, _ = h.Write(mu[:])
		_, _ = h.Write(w1Packed)
		_, _ = h.Read(cTildePrime)
	}

	t.Logf("our   c̃[0..8]:    %x", cTilde[0:8])
	t.Logf("rec   c̃'[0..8]:   %x", cTildePrime[0:8])
	t.Logf("our   c̃ SHA256:   %x", sha256.Sum256(cTilde))
	t.Logf("rec   c̃' SHA256:  %x", sha256.Sum256(cTildePrime))

	if bytes.Equal(cTilde, cTildePrime) {
		t.Logf("✓ manual verify SUCCEEDS — our primitives are self-consistent")
		t.Logf("  But circl verify FAILS — divergence is in a primitive that")
		t.Logf("  circl computes differently than ours. Likely NTT or matrix-A expansion.")
	} else {
		t.Logf("✗ manual verify FAILS — our sig is internally inconsistent")
		t.Logf("  The (z, h) we computed don't bridge back to our c̃ via verify equation.")
		// Diagnose which step diverges.
		t.Logf("  w_1 reconstructed[0][0..4]: %v", w1Rec[0][0:5])
	}
}

// unpackHintForTest unpacks a hint poly-vec from buf (length omega+K).
// Returns true on success.
func unpackHintForTest(hint polyVec, buf []byte, omega int) bool {
	K := len(hint)
	prev := uint8(0)
	for i := 0; i < K; i++ {
		end := buf[omega+i]
		if end < prev {
			return false
		}
		if int(end) > omega {
			return false
		}
		var lastPos int = -1
		for j := int(prev); j < int(end); j++ {
			pos := int(buf[j])
			if pos <= lastPos {
				return false
			}
			lastPos = pos
			hint[i][pos] = 1
		}
		prev = end
	}
	for j := int(prev); j < omega; j++ {
		if buf[j] != 0 {
			return false
		}
	}
	return true
}

// useHintVec applies FIPS 204 §4.5 UseHint to a polynomial vector.
// Mirrors circl/sign/mldsa/mldsa65/internal/rounding.go useHint().
// For ML-DSA-65 the modulus m = (q-1)/(2γ2) = 16, so we mask with &15.
func useHintVec(r polyVec, h polyVec, gamma2 uint32) polyVec {
	K := len(r)
	out := make(polyVec, K)
	for k := 0; k < K; k++ {
		for j := 0; j < mldsaN; j++ {
			rp0plusQ, rp1 := decompose(r[k][j], gamma2)
			if h[k][j] == 0 {
				out[k][j] = rp1
				continue
			}
			// circl: if rp0plusQ > Q → (rp1+1) & 15 (positive r_0 path)
			//        else                  → (rp1-1) & 15 (non-positive r_0)
			// The add-q in decompose makes positive-r_0 values land > Q,
			// while negative-r_0 values stay in (Q/2, Q).
			if rp0plusQ > mldsaQ {
				out[k][j] = (rp1 + 1) & 15
			} else {
				out[k][j] = (rp1 - 1) & 15
			}
		}
	}
	return out
}

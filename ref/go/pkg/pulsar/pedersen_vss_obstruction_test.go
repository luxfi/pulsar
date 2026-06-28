// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// pedersen_vss_obstruction_test.go — the EMPIRICAL, end-to-end proof that the
// v0.2 Pedersen-VSS key (s2 = B·u) cannot be signed under unmodified FIPS 204,
// PLUS the sound no-leak dealing layer working multi-party.
//
// The decisive artifact is the A/B isolation: two keys built from the SAME s1
// (and the SAME nonce machinery) differing ONLY in s2 — a real small FIPS s2
// vs. the v0.2 s2 = B·u. The small-s2 key produces a signature that
// cloudflare/circl mldsa65.Verify ACCEPTS; the B·u key cannot produce a hint at
// all (FindHint fails on a boundary-clear nonce; the production bccSign exhausts
// its budget). This is not a budget artifact — it is structural: ‖B·u‖∞ ≈ q/2.

import (
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/sha3"
)

// maxCentralLinf returns the maximum |central-rep| coefficient of a normalized
// poly-vector: min(a, q−a) over every coefficient.
func maxCentralLinf(v polyVec) uint32 {
	var m uint32
	for i := range v {
		for j := 0; j < mldsaN; j++ {
			a := v[i][j] % mldsaQ
			c := a
			if q := mldsaQ - a; q < c {
				c = q
			}
			if c > m {
				m = c
			}
		}
	}
	return m
}

// sampleChiEta samples a length-L poly-vector with coefficients in [−η,η],
// normalized to [0,q), from a labelled deterministic seed.
func sampleChiEta(mode Mode, label string) polyVec {
	_, L, eta := modeShape(mode)
	var seed [64]byte
	copy(seed[:], cshake256([]byte(label), 64, "PVSS-TEST-CHI"))
	out := make(polyVec, L)
	for l := 0; l < L; l++ {
		polyDeriveUniformLeqEta(&out[l], &seed, uint16(l), eta)
		out[l].normalize()
	}
	return out
}

// computeBu returns s2 = B·u ∈ R_q^k for the v0.2 substitution, reusing
// modulePedersenCommit(A, B, 0, u) = A·0 + B·u.
func computeBu(mode Mode, aRows, bRows []polyVec, u polyVec) polyVec {
	_, L, _ := modeShape(mode)
	zero := make(polyVec, L)
	return modulePedersenCommit(aRows, bRows, zero, u)
}

// rebuildKMWithS2 recomputes t, (t1,t0), pub, tr of an in-memory key after
// replacing s2 with the given (normalized) vector. Mirrors deriveKeyMaterial's
// t-computation EXACTLY, so the only change vs. the original key is s2 → s2new.
// bccSign consumes km.a, km.s1, km.t1, km.tr — all consistent afterward.
func rebuildKMWithS2(km *mldsaKeyMaterial, mode Mode, s2new polyVec) {
	K, L, _ := modeShape(mode)
	s1Hat := make(polyVec, L)
	for i := 0; i < L; i++ {
		s1Hat[i] = km.s1[i]
		s1Hat[i].reduceLe2Q()
		s1Hat[i].ntt()
	}
	t := make(polyVec, K)
	for i := 0; i < K; i++ {
		polyDotHat(&t[i], km.a[i], s1Hat)
		t[i].reduceLe2Q()
		t[i].invNTT()
	}
	for i := 0; i < K; i++ {
		t[i].add(&t[i], &s2new[i]) // s2new normalized [0,q)
	}
	for i := 0; i < K; i++ {
		t[i].normalize()
		t[i].power2Round(&km.t0[i], &km.t1[i])
	}
	pubKeySize := 32 + 320*K
	km.pub = make([]byte, pubKeySize)
	copy(km.pub[:32], km.rho[:])
	for i := 0; i < K; i++ {
		polyPackT1(&km.t1[i], km.pub[32+320*i:32+320*(i+1)])
	}
	h := sha3.NewShake256()
	_, _ = h.Write(km.pub)
	_, _ = h.Read(km.tr[:])
	km.s2 = s2new
}

// bccOneAttempt runs ONE boundary-clear BCC attempt for the given key and mask
// seed, returning whether the nonce is boundary-clear and (if so) whether a
// valid FIPS hint exists. w / w1 / boundary-clearance depend only on (A, y) — so
// for a fixed ySeed they are IDENTICAL across two keys sharing A; only the hint
// (via t1) differs. This isolates s2 as the sole cause.
func bccOneAttempt(t *testing.T, km *mldsaKeyMaterial, mode Mode, ySeed *[64]byte, msg []byte) (clear, hintOK bool) {
	t.Helper()
	gamma2, beta, omega, ok := bccParams(mode)
	if !ok {
		t.Fatalf("mode %v out of BCC scope", mode)
	}
	K, L, _ := modeShape(mode)
	tau, _, gamma1Bits, _ := modeTauOmega(mode)
	gamma1 := uint32(1) << gamma1Bits

	var mu [64]byte
	deriveMuCtx(km.tr, nil, msg, mu[:])

	// y, w = A·y.
	y := make(polyVec, L)
	for i := 0; i < L; i++ {
		expandMaskPoly(&y[i], ySeed, uint16(i), gamma1Bits)
	}
	yHat := make(polyVec, L)
	for i := 0; i < L; i++ {
		yHat[i] = y[i]
		yHat[i].ntt()
	}
	w := make(polyVec, K)
	for k := 0; k < K; k++ {
		polyDotHat(&w[k], km.a[k], yHat)
		w[k].reduceLe2Q()
		w[k].invNTT()
		w[k].normalize()
	}
	if !BoundaryClear(w, gamma2, beta) {
		return false, false
	}
	w1 := highBitsVec(w, gamma2)

	// c = SampleInBall(H(μ, packW1(w1))).
	cTilde := make([]byte, modeCTildeSize(mode))
	{
		h := sha3.NewShake256()
		_, _ = h.Write(mu[:])
		_, _ = h.Write(packW1Vec(w1, gamma2, K))
		_, _ = h.Read(cTilde)
	}
	var c poly
	polyDeriveUniformBall(&c, cTilde, tau)
	cHat := c
	cHat.ntt()

	// z = y + c·s1.
	s1Hat := make(polyVec, L)
	for l := 0; l < L; l++ {
		s1Hat[l] = km.s1[l]
		s1Hat[l].reduceLe2Q()
		s1Hat[l].ntt()
	}
	z := make(polyVec, L)
	for l := 0; l < L; l++ {
		var cs1 poly
		cs1.mulHat(&cHat, &s1Hat[l])
		cs1.reduceLe2Q()
		cs1.invNTT()
		z[l].add(&y[l], &cs1)
		z[l].normalize()
	}
	if polyVecExceeds(z, gamma1-beta) {
		return true, false
	}

	// w' = A·z − c·t1·2^d, then FindHint(w', w1).
	t1Scaled := make(polyVec, K)
	for k := 0; k < K; k++ {
		t1Scaled[k].mulBy2toD(&km.t1[k])
		t1Scaled[k].ntt()
	}
	zHat := make(polyVec, L)
	for l := 0; l < L; l++ {
		zHat[l] = z[l]
		zHat[l].ntt()
	}
	wPrime := make(polyVec, K)
	for k := 0; k < K; k++ {
		var az poly
		polyDotHat(&az, km.a[k], zHat)
		az.reduceLe2Q()
		var ct1 poly
		ct1.mulHat(&cHat, &t1Scaled[k])
		az.sub(&az, &ct1)
		az.reduceLe2Q()
		az.invNTT()
		az.normalize()
		wPrime[k] = az
	}
	_, hintOK = FindHint(wPrime, w1, gamma2, omega)
	return true, hintOK
}

// TestPedersenVSS_S2_BuIsPseudoUniform proves the root cause: s2 = B·u is
// M-LWE-pseudo-uniform (‖B·u‖∞ ≈ q/2), NOT small like a FIPS s2 (‖·‖∞ ≤ η).
// Pins the computed obstruction.
func TestPedersenVSS_S2_BuIsPseudoUniform(t *testing.T) {
	for _, mode := range []Mode{ModeP65, ModeP87} {
		seed := bccTestSeed(0x11)
		km, err := deriveKeyMaterial(mode, seed)
		if err != nil {
			t.Fatalf("deriveKeyMaterial: %v", err)
		}
		B, err := expandB(mode)
		if err != nil {
			t.Fatalf("expandB: %v", err)
		}
		_, _, eta := modeShape(mode)

		u := sampleChiEta(mode, "u/"+mode.String())
		s2Bu := computeBu(mode, km.a, B, u)

		// The real FIPS s2 is small; B·u is huge.
		fipsS2Linf := maxCentralLinf(km.s2)
		buLinf := maxCentralLinf(s2Bu)
		if fipsS2Linf > eta {
			t.Fatalf("%v: real FIPS s2 ‖·‖∞=%d should be ≤ η=%d", mode, fipsS2Linf, eta)
		}
		gamma2, beta, _, _ := bccParams(mode)
		if buLinf <= gamma2 {
			t.Fatalf("%v: B·u ‖·‖∞=%d should be ≫ γ2=%d (pseudo-uniform); is B uniform?",
				mode, buLinf, gamma2)
		}
		// It is in fact within striking distance of the half-modulus.
		if buLinf < mldsaQ/4 {
			t.Fatalf("%v: B·u ‖·‖∞=%d unexpectedly small vs q/4=%d", mode, buLinf, mldsaQ/4)
		}
		t.Logf("%v: FIPS s2 ‖·‖∞=%d ≤ η=%d ; B·u ‖·‖∞=%d ≈ q/2=%d ; β=%d, γ2=%d",
			mode, fipsS2Linf, eta, buLinf, (mldsaQ-1)/2, beta, gamma2)

		// Pin the computed obstruction.
		o, ok := assessPedersenVSSFIPS(mode)
		if !ok {
			t.Fatalf("%v: assessPedersenVSSFIPS not ok in BCC scope", mode)
		}
		if o.ByteFIPSReachable {
			t.Fatalf("%v: byte-FIPS-204 must be UNREACHABLE for s2=B·u", mode)
		}
		if o.S2LinfPseudoUniform != (mldsaQ-1)/2 || o.BoundaryCovers != beta {
			t.Fatalf("%v: obstruction numbers drifted: s2Linf=%d (want %d), covers=%d (want β=%d)",
				mode, o.S2LinfPseudoUniform, (mldsaQ-1)/2, o.BoundaryCovers, beta)
		}
	}
}

// TestPedersenVSS_FindHint_FailsForBu_SucceedsForSmallS2 is the deterministic,
// single-shot isolation: ONE boundary-clear nonce, the SAME s1, only s2 differs.
// FindHint succeeds for the small-s2 key and fails for the s2=B·u key — proving
// the wall is structural, not a sampling-budget artifact.
func TestPedersenVSS_FindHint_FailsForBu_SucceedsForSmallS2(t *testing.T) {
	mode := ModeP65
	msg := []byte("pvss-findhint-isolation")

	seed := bccTestSeed(0x22)
	kmGood, err := deriveKeyMaterial(mode, seed)
	if err != nil {
		t.Fatalf("deriveKeyMaterial: %v", err)
	}
	// kmBad: copy, then swap s2 → B·u (same A, same s1).
	kmBad, err := deriveKeyMaterial(mode, seed)
	if err != nil {
		t.Fatalf("deriveKeyMaterial: %v", err)
	}
	B, err := expandB(mode)
	if err != nil {
		t.Fatalf("expandB: %v", err)
	}
	u := sampleChiEta(mode, "findhint-u")
	rebuildKMWithS2(kmBad, mode, computeBu(mode, kmBad.a, B, u))

	// Search for ONE boundary-clear nonce (independent of s2: w = A·y).
	rng := newBCCDeterministicRNG("PVSS/findhint")
	var foundClear bool
	for attempt := 0; attempt < 4096; attempt++ {
		var ySeed [64]byte
		if _, err := rng.Read(ySeed[:]); err != nil {
			t.Fatalf("rng: %v", err)
		}
		clearG, hintG := bccOneAttempt(t, kmGood, mode, &ySeed, msg)
		clearB, hintB := bccOneAttempt(t, kmBad, mode, &ySeed, msg)
		if clearG != clearB {
			t.Fatalf("boundary-clearance must be identical (depends only on A,y): good=%v bad=%v", clearG, clearB)
		}
		if !clearG {
			continue
		}
		foundClear = true
		if !hintG {
			t.Fatalf("small-s2 key: a boundary-clear nonce must admit a FIPS hint, got none")
		}
		if hintB {
			t.Fatalf("s2=B·u key: FindHint UNEXPECTEDLY succeeded — re-examine the obstruction")
		}
		t.Logf("%v: boundary-clear nonce — small-s2 hint=%v, B·u hint=%v (structural wall)", mode, hintG, hintB)
		break
	}
	if !foundClear {
		t.Fatalf("no boundary-clear nonce found in budget (yield issue, not the obstruction)")
	}
}

// TestPedersenVSS_BCCSign_FailsForBu_SucceedsForSmallS2 is the end-to-end proof
// with the PRODUCTION reference signer + the independent circl verifier: a small
// -s2 key signs and circl ACCEPTS; the s2=B·u key (same s1) exhausts the budget —
// no FIPS-204-verifiable signature exists.
func TestPedersenVSS_BCCSign_FailsForBu_SucceedsForSmallS2(t *testing.T) {
	mode := ModeP65
	msg := []byte("pvss-bccsign-isolation")

	seed := bccTestSeed(0x44)
	kmGood, err := deriveKeyMaterial(mode, seed)
	if err != nil {
		t.Fatalf("deriveKeyMaterial: %v", err)
	}
	// Good key: real BCC signature, verified by circl.
	rngG := newBCCDeterministicRNG("PVSS/bccsign/good")
	sig, _, err := bccSign(kmGood, mode, msg, nil, rngG, 4096)
	if err != nil {
		t.Fatalf("small-s2 key: bccSign must succeed, got %v", err)
	}
	var pkC mldsa65.PublicKey
	if err := pkC.UnmarshalBinary(kmGood.pub); err != nil {
		t.Fatalf("circl unmarshal: %v", err)
	}
	if !mldsa65.Verify(&pkC, msg, nil, sig) {
		t.Fatal("small-s2 BCC signature rejected by circl — baseline broken")
	}

	// Bad key (same s1, s2 = B·u): bccSign must exhaust its budget.
	kmBad, err := deriveKeyMaterial(mode, seed)
	if err != nil {
		t.Fatalf("deriveKeyMaterial: %v", err)
	}
	B, err := expandB(mode)
	if err != nil {
		t.Fatalf("expandB: %v", err)
	}
	u := sampleChiEta(mode, "bccsign-u")
	rebuildKMWithS2(kmBad, mode, computeBu(mode, kmBad.a, B, u))

	rngB := newBCCDeterministicRNG("PVSS/bccsign/bad")
	_, _, err = bccSign(kmBad, mode, msg, nil, rngB, 4096)
	if err != ErrBCCExhausted {
		t.Fatalf("s2=B·u key: bccSign must fail with ErrBCCExhausted (no FIPS hint exists), got %v", err)
	}
	t.Logf("%v: small-s2 → circl-verified sig; s2=B·u → ErrBCCExhausted over 4096 attempts (the wall)", mode)
}

// TestPedersenVSS_SoundDealing_ShareOnly_VerifiesAndAggregates exercises the
// SOUND, no-leak dealing layer multi-party: each dealer deals share-only
// (f_i(j), g_i(j)); the Round-2 Pedersen identity verifies honest shares and
// rejects a tampered one; aggregation yields Shamir-consistent s1 shares with no
// seed / s1 / sk ever formed.
func TestPedersenVSS_SoundDealing_ShareOnly_VerifiesAndAggregates(t *testing.T) {
	mode := ModeP65
	const n, threshold = 5, 3 // n ≥ 2t−1

	A := func() []polyVec {
		km, err := deriveKeyMaterial(mode, bccTestSeed(0x55))
		if err != nil {
			t.Fatalf("deriveKeyMaterial: %v", err)
		}
		return km.a
	}()
	B, err := expandB(mode)
	if err != nil {
		t.Fatalf("expandB: %v", err)
	}

	ids := make([]NodeID, n)
	evalPoints := make([]uint32, n)
	for i := 0; i < n; i++ {
		ids[i][0] = byte(i + 1)
		evalPoints[i] = EvalPointFromIDQ(ids[i])
	}

	rng := newBCCDeterministicRNG("PVSS/dealing")
	commits := make([]VSSCommit, n)
	// dealtShares[i][p] = dealer i's private message to party p.
	dealtShares := make([][]VSSShare, n)
	for i := 0; i < n; i++ {
		c, sh, err := VSSDealerRound1(mode, A, B, ids[i], evalPoints, threshold, rng)
		if err != nil {
			t.Fatalf("VSSDealerRound1[%d]: %v", i, err)
		}
		commits[i] = c
		dealtShares[i] = sh
	}

	// Round 2: every party verifies every dealer's share against its commits.
	for p := 0; p < n; p++ {
		for i := 0; i < n; i++ {
			if !VerifyVSSShare(A, B, dealtShares[i][p], commits[i]) {
				t.Fatalf("honest share dealer=%d party=%d failed Pedersen identity", i, p)
			}
		}
	}

	// A tampered share must fail the identity (identifiable abort).
	bad := dealtShares[0][0]
	tampered := VSSShare{DealerID: bad.DealerID, EvalPoint: bad.EvalPoint,
		S1Share: append(polyVec(nil), bad.S1Share...), BlindShare: bad.BlindShare}
	tampered.S1Share[0][0] = (tampered.S1Share[0][0] + 1) % mldsaQ
	if VerifyVSSShare(A, B, tampered, commits[0]) {
		t.Fatal("tampered share passed the Pedersen identity — binding broken (test vacuous)")
	}

	// Round 3 (aggregate): each party sums its received shares into its s1 share.
	algShares := make([]*AlgShare, n)
	for p := 0; p < n; p++ {
		recv := make([]VSSShare, n)
		for i := 0; i < n; i++ {
			recv[i] = dealtShares[i][p]
		}
		as, _, err := AggregateVSSShares(mode, ids[p], recv)
		if err != nil {
			t.Fatalf("AggregateVSSShares party=%d: %v", p, err)
		}
		algShares[p] = as
	}

	// Shamir consistency: reconstruct s1 from two DIFFERENT t-subsets — equal,
	// without any party ever forming s1.
	s1A := reconstructS1AtZero(algShares, []int{0, 1, 2})
	s1B := reconstructS1AtZero(algShares, []int{2, 3, 4})
	if !polyVecEqMod(s1A, s1B) {
		t.Fatal("aggregated s1 shares are not Shamir-consistent across quorums")
	}

	// The aggregated public commit t = Σ C_{i,0}; forming a FIPS key fails closed.
	tCommit, err := AggregateVSSCommits(mode, commits)
	if err != nil {
		t.Fatalf("AggregateVSSCommits: %v", err)
	}
	o, err := PedersenVSSFormFIPSKey(mode, tCommit)
	if err != ErrPedersenVSSNotByteFIPS {
		t.Fatalf("PedersenVSSFormFIPSKey must fail closed with ErrPedersenVSSNotByteFIPS, got %v", err)
	}
	if o == nil || o.ByteFIPSReachable {
		t.Fatal("fail-closed key formation must return the computed (unreachable) obstruction")
	}
}

// reconstructS1AtZero Lagrange-interpolates the AlgShare s1 shares of a t-subset
// at X=0 over GF(q), returning the joint s1 = f(0). Test-only (a real party never
// does this — it is the consistency oracle).
func reconstructS1AtZero(shares []*AlgShare, subset []int) polyVec {
	L := len(shares[subset[0]].S1Share)
	evals := make([]uint32, len(subset))
	for i, idx := range subset {
		evals[i] = shares[idx].EvalPoint
	}
	out := make(polyVec, L)
	for i, idx := range subset {
		lambda := uint64(LagrangeAtZeroQ(evals[i], evals))
		sh := shares[idx].S1Share
		for l := 0; l < L; l++ {
			for j := 0; j < mldsaN; j++ {
				out[l][j] = uint32((uint64(out[l][j]) + lambda*uint64(sh[l][j])) % shamirPrimeQ)
			}
		}
	}
	return out
}

func polyVecEqMod(a, b polyVec) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		for j := 0; j < mldsaN; j++ {
			if a[i][j]%mldsaQ != b[i][j]%mldsaQ {
				return false
			}
		}
	}
	return true
}

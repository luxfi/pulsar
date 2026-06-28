// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// bcc_sign.go — the Boundary-Cleared / Carry-Elimination (BCC/CEF)
// single-key signing reference.
//
// This is the algebraic heart of the no-leak threshold path made
// concrete on ONE secret key: it produces a genuinely byte-valid
// FIPS 204 ML-DSA signature WITHOUT ever forming c·s2, c·t0, r0, or
// LowBits(w). The hint is recovered from PUBLIC data alone via the
// FIPS 204 UseHint primitive (boundary.go FindHint), exactly as a
// public verifier would, rather than from the secret residual.
//
// Why this matters. A standard FIPS 204 signer computes the hint as
//
//	h = MakeHint(w0 − c·s2 + c·t0, w1)
//
// which requires c·s2 and c·t0 — long-term-key-bearing quantities.
// In the threshold setting, broadcasting per-party c·s2 / c·t0 shares
// leaks the key (PULSAR-V13-HINT-LEAK). BCC/CEF eliminates them:
//
//  1. Only sign with a nonce whose commitment w is BOUNDARY-CLEAR
//     (every coefficient's centred low part is < γ2 − 2β − slack).
//     Then the hidden ‖c·s2‖∞ ≤ β perturbation cannot move HighBits
//     and ‖c·t0‖∞ < γ2 is vacuous, so HighBits(w − c·s2) = HighBits(w)
//     for EVERY admissible challenge. (boundary.go BoundaryClear.)
//  2. Recover the hint from the PUBLIC reconstructed
//     w' = A·z − c·t1·2^d and the PUBLIC target w1 via FindHint. By
//     the algebra below, w' = w + (c·t0 − c·s2), so a boundary-clear
//     nonce admits a weight-≤ω FIPS hint that maps w' back to w1.
//
// The resulting (c̃, z, h) is encoded byte-for-byte as FIPS 204
// sigEncode and verifies under any unmodified FIPS 204 verifier.
//
// ALGEBRA (single key, t = A·s1 + s2, t = t1·2^d + t0):
//
//	A·z = A·(y + c·s1) = A·y + c·(t − s2) = w + c·t1·2^d + c·t0 − c·s2
//	⇒  w' := A·z − c·t1·2^d = w + (c·t0 − c·s2)
//
// Verification accepts iff c̃ == H(μ, UseHint(h, w')). Because
// UseHint(h, w') = w1 by construction (FindHint) and c̃ = H(μ, w1)
// was the challenge that produced z, the check closes — provided the
// nonce was boundary-clear so that such an h exists with weight ≤ ω.
//
// This file is TEST/REFERENCE scaffolding for the no-leak boundary
// path: it operates on a single in-memory key (deriveKeyMaterial) and
// records a transcript so the no-leak property can be asserted by a
// debug oracle. It is NOT the production threshold orchestrator (that
// lives behind the fail-closed ZK gate in proof.go) — it is the
// concrete witness that the BCC carry-elimination arithmetic yields a
// real FIPS 204 signature.

import (
	"errors"
	"io"

	"golang.org/x/crypto/sha3"
)

// ErrBCCExhausted is returned when bccSign cannot find a boundary-clear
// nonce that also clears the ‖z‖ and hint-weight bounds within the
// attempt budget. With ~10% boundary-clear yield for ML-DSA-65 the
// expected attempt count is small; exhaustion indicates a degenerate
// RNG or a parameter set outside the proven scope.
var ErrBCCExhausted = errors.New(
	"pulsar: BCC signing exhausted its attempt budget without a " +
		"boundary-clear, norm-valid, hint-admissible nonce")

// bccTranscript records every algebraic quantity that the BCC signer
// touches for ONE successful attempt. It exists so a debug oracle can
// prove the no-leak invariant: the transcript that builds the
// signature must contain NONE of c·s2, c·t0, r0, LowBits(w), or the
// full hidden commitment w. Only public quantities (w', w1, z, c̃, the
// hint) and the offline boundary-clear flag are retained.
//
// debugFullW / debugY are TEST-ONLY witnesses for the equivalence
// assertions; they are never serialized and the no-leak oracle checks
// that the public transcript bytes do not contain them.
type bccTranscript struct {
	// Public quantities — these are what a real BCC transcript carries.
	wPrime   polyVec // A·z − c·t1·2^d   (public; = w + c·t0 − c·s2)
	w1       polyVec // HighBits(w)       (public; in the challenge hash)
	z        polyVec // y + c·s1          (public; in the signature)
	cTilde   []byte  // H(μ, w1)          (public; in the signature)
	hint     polyVec // UseHint-recovered (public; in the signature)
	clear    bool    // offline BoundaryClear(w) flag (public predicate)
	attempts int

	// TEST-ONLY witnesses (never serialized; the no-leak oracle asserts
	// these byte-strings do NOT appear in the public transcript).
	debugFullW polyVec // w = A·y       (SECRET-equivalent: w' − w = residual)
	debugY     polyVec // the mask y    (SECRET)
}

// publicBytes serializes ONLY the public transcript quantities — the
// exact set a real no-leak transcript would expose (w', w1, z, c̃,
// hint, clear bit). The no-leak oracle scans this for forbidden secret
// material. Crucially it never includes debugFullW / debugY / any
// low-bits or residual.
func (tr *bccTranscript) publicBytes() []byte {
	out := make([]byte, 0, 4096)
	out = append(out, packPolyVec(tr.wPrime)...)
	out = append(out, packPolyVec(tr.w1)...)
	out = append(out, packPolyVec(tr.z)...)
	out = append(out, tr.cTilde...)
	out = append(out, packPolyVec(tr.hint)...)
	if tr.clear {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	return out
}

// bccSign produces a FIPS 204 ML-DSA signature on (message, ctx) under
// the in-memory key material km, using the no-leak BCC/CEF hint path.
//
// It mirrors the FIPS 204 sign loop EXCEPT the hint step: instead of
// MakeHint(w0 − c·s2 + c·t0, w1) it (a) only accepts boundary-clear
// nonces and (b) recovers the hint from the public w' via FindHint.
//
// km must be a ModeP65 or ModeP87 key (the BCC proven scope; bccParams
// gates this). rng supplies the per-attempt mask seed; pass a
// deterministic reader for reproducible signatures. maxAttempts bounds
// the resample loop.
//
// Returns the packed signature bytes, the recording transcript (for
// the no-leak oracle), and an error.
func bccSign(km *mldsaKeyMaterial, mode Mode, message, ctx []byte, rng io.Reader, maxAttempts int) ([]byte, *bccTranscript, error) {
	params, err := ParamsFor(mode)
	if err != nil {
		return nil, nil, err
	}
	gamma2, beta, omega, ok := bccParams(mode)
	if !ok {
		return nil, nil, ErrBCCParamSet
	}
	K, L, _ := modeShape(mode)
	tau, _, gamma1Bits, _ := modeTauOmega(mode)
	gamma1 := uint32(1) << gamma1Bits

	// μ = SHAKE-256(tr || 0x00 || |ctx| || ctx || M). Single source of
	// truth shared with the threshold path (deriveMuCtx).
	if len(ctx) > 255 {
		return nil, nil, ErrCtxTooLong
	}
	var mu [64]byte
	deriveMuCtx(km.tr, ctx, message, mu[:])

	// Pre-NTT the secret s1 and the public t1·2^d once; both are reused
	// across attempts. s1 is stored un-normalised in [q-η, q+η]; reduce
	// then NTT. t1 is the packed-in-pk high part; scale by 2^d, then NTT.
	s1Hat := make(polyVec, L)
	for i := 0; i < L; i++ {
		s1Hat[i] = km.s1[i]
		s1Hat[i].reduceLe2Q()
		s1Hat[i].ntt()
	}
	t1Scaled := make(polyVec, K)
	for i := 0; i < K; i++ {
		t1Scaled[i].mulBy2toD(&km.t1[i]) // t1 · 2^d, coefficients < 2^(10+13)=2^23
		t1Scaled[i].ntt()
	}

	cTildeSize := modeCTildeSize(mode)
	polyLeGamma1Size := int((gamma1Bits + 1) * mldsaN / 8)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// 1. Sample the mask y ∈ (−γ1, γ1]^L from a fresh 64-byte seed.
		var ySeed [64]byte
		if _, err := io.ReadFull(rng, ySeed[:]); err != nil {
			return nil, nil, err
		}
		y := make(polyVec, L)
		for i := 0; i < L; i++ {
			expandMaskPoly(&y[i], &ySeed, uint16(i), gamma1Bits)
		}

		// 2. w = A·y. ŷ = NTT(y); ŵ_k = Σ_l A[k][l]·ŷ[l]; w = InvNTT(ŵ).
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

		// 3 + 4. Offline boundary-clearance gate. A non-clear nonce is
		// rejected BEFORE the challenge is formed — message-independent,
		// fully public, no secret touched.
		if !BoundaryClear(w, gamma2, beta) {
			continue
		}
		w1 := highBitsVec(w, gamma2)

		// 5. c̃ = H(μ, packW1(w1)); c = SampleInBall(c̃).
		w1Packed := packW1Vec(w1, gamma2, K)
		cTilde := make([]byte, cTildeSize)
		{
			h := sha3.NewShake256()
			_, _ = h.Write(mu[:])
			_, _ = h.Write(w1Packed)
			_, _ = h.Read(cTilde)
		}
		var c poly
		polyDeriveUniformBall(&c, cTilde, tau)
		cHat := c
		cHat.ntt()

		// 6. z = y + c·s1. (ĉ·ŝ1 then InvNTT, add to y.)
		z := make(polyVec, L)
		for l := 0; l < L; l++ {
			var cs1 poly
			cs1.mulHat(&cHat, &s1Hat[l])
			cs1.reduceLe2Q()
			cs1.invNTT()
			z[l].add(&y[l], &cs1)
			z[l].normalize()
		}

		// 7. ‖z‖∞ < γ1 − β ? (FIPS 204 reject bound on z.)
		if polyVecExceeds(z, gamma1-beta) {
			continue
		}

		// 8. w' = A·z − c·t1·2^d. (ẑ = NTT(z); A·ẑ − ĉ·NTT(t1·2^d);
		// InvNTT.) This is PUBLIC — it is exactly the quantity a FIPS 204
		// verifier reconstructs.
		zHat := make(polyVec, L)
		for l := 0; l < L; l++ {
			zHat[l] = z[l]
			zHat[l].ntt()
		}
		wPrime := make(polyVec, K)
		for k := 0; k < K; k++ {
			var az poly
			polyDotHat(&az, km.a[k], zHat) // coefficients < 2·L·q
			az.reduceLe2Q()                // now < 2q
			var ct1 poly
			ct1.mulHat(&cHat, &t1Scaled[k]) // < 2q
			// w'_k = A·z_k − c·t1·2^d_k in NTT domain. poly.sub computes
			// az[i] + (2q − ct1[i]); with both operands < 2q the result is
			// < 4q < 2^32, safe for reduceLe2Q (valid for any uint32 input).
			az.sub(&az, &ct1)
			az.reduceLe2Q()
			az.invNTT()
			az.normalize()
			wPrime[k] = az
		}

		// 9. Recover the hint from PUBLIC (w', w1) via FindHint. Rejects
		// (ok=false) when some coefficient has no valid FIPS hint
		// (boundary/region violated) or when weight(h) > ω. Either way,
		// consume the nonce and retry.
		hint, ok := FindHint(wPrime, w1, gamma2, omega)
		if !ok {
			continue
		}

		// 10. sigEncode(c̃, z, h) per FIPS 204 Algorithm 28 — identical
		// encoding to the single-party and v0.3 paths.
		sigBytes := make([]byte, params.SignatureSize)
		copy(sigBytes[:cTildeSize], cTilde)
		off := cTildeSize
		for l := 0; l < L; l++ {
			polyPackLeGamma1(&z[l], sigBytes[off:off+polyLeGamma1Size], gamma1Bits)
			off += polyLeGamma1Size
		}
		polyVecPackHint(hint, sigBytes[off:off+int(omega)+K], int(omega))

		tr := &bccTranscript{
			wPrime:     wPrime,
			w1:         w1,
			z:          z,
			cTilde:     cTilde,
			hint:       hint,
			clear:      true,
			attempts:   attempt + 1,
			debugFullW: w,
			debugY:     y,
		}
		return sigBytes, tr, nil
	}
	return nil, nil, ErrBCCExhausted
}

// polyVecExceeds reports whether any coefficient of v exceeds bound in
// centered (FIPS 204 ‖·‖∞) magnitude — the rejection-sampling norm gate.
func polyVecExceeds(v polyVec, bound uint32) bool {
	for i := range v {
		if v[i].exceeds(bound) {
			return true
		}
	}
	return false
}

// deriveMuCtx computes μ = SHAKE256(tr ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ msg, 64) per
// FIPS 204 §5.4 — the message representative both the single-key signer here
// and the threshold path bind their challenge to.
func deriveMuCtx(tr [64]byte, ctx, msg, out []byte) {
	h := sha3.NewShake256()
	_, _ = h.Write(tr[:])
	_, _ = h.Write([]byte{0x00, byte(len(ctx))})
	if len(ctx) > 0 {
		_, _ = h.Write(ctx)
	}
	_, _ = h.Write(msg)
	_, _ = h.Read(out[:64])
}

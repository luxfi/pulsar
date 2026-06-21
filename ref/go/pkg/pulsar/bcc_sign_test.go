// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"golang.org/x/crypto/sha3"
)

// bcc_sign_test.go — the crown-jewel round-trip: prove that the no-leak
// Boundary-Cleared / Carry-Elimination hint path (boundary.go +
// bcc_sign.go) produces a GENUINELY byte-valid FIPS 204 ML-DSA
// signature, accepted by independent FIPS 204 verifiers, while the
// transcript that builds it contains NONE of the leaking quantities
// (c·s2, c·t0, r0, LowBits(w), full w).
//
// The pq-crystals leg of this round-trip lives in
// bcc_sign_pqcrystals_test.go behind the `pulsar_pqcrystals` build tag
// (cgo binding to the upstream reference verifier). This file always
// runs the cloudflare/circl leg + the package's own Verify + the
// no-leak debug oracle.

// bccDeterministicRNG is a SHAKE-256-based deterministic byte source so
// the round-trip is reproducible (no crypto/rand flake). It is NOT a
// production RNG — it exists purely to make the per-attempt mask seeds
// deterministic for the KAT-style test.
type bccDeterministicRNG struct {
	sh sha3.ShakeHash
}

func newBCCDeterministicRNG(label string) *bccDeterministicRNG {
	sh := sha3.NewShake256()
	_, _ = sh.Write([]byte(label))
	return &bccDeterministicRNG{sh: sh}
}

func (r *bccDeterministicRNG) Read(p []byte) (int, error) {
	return r.sh.Read(p)
}

// bccTestSeed returns a fixed 32-byte ML-DSA seed for the round-trip.
func bccTestSeed(b byte) *[SeedSize]byte {
	var s [SeedSize]byte
	for i := range s {
		s[i] = b ^ byte(i*7+1)
	}
	return &s
}

// runBCCSign drives bccSign for the given mode and returns the signature,
// transcript, the derived key material (for the no-leak oracle), and the
// public key bytes. Fails the test on any error. The public key is taken
// from km.pub (FIPS 204 pk encoding, byte-identical to circl
// NewKeyFromSeed — guarded elsewhere).
func runBCCSign(t *testing.T, mode Mode, seedByte byte, message, ctx []byte) (sig []byte, tr *bccTranscript, km *mldsaKeyMaterial, pub []byte) {
	t.Helper()
	seed := bccTestSeed(seedByte)
	km, err := deriveKeyMaterial(mode, seed)
	if err != nil {
		t.Fatalf("deriveKeyMaterial(%v): %v", mode, err)
	}
	rng := newBCCDeterministicRNG("PULSAR/BCC/roundtrip/" + mode.String())
	// ~10% boundary-clear yield ⇒ ample budget; exhaustion would be a bug.
	sig, tr, err = bccSign(km, mode, message, ctx, rng, 4096)
	if err != nil {
		t.Fatalf("bccSign(%v): %v (attempts may be exhausted — check yield)", mode, err)
	}
	pub = append([]byte(nil), km.pub...)
	return sig, tr, km, pub
}

// TestBCCSignRoundTripVerifiesCIRCL is the headline test: a BCC/CEF
// no-leak signature verifies BYTE-FOR-BYTE under (a) the package's own
// Verify (FIPS 204 via circl), (b) cloudflare/circl's mldsa65.Verify
// invoked directly with a pk re-derived from the seed by circl alone
// (independent-verifier discipline), and (c) the no-leak debug oracle.
//
// This is the strongest possible evidence that the carry-elimination
// hint — recovered from PUBLIC w' = A·z − c·t1·2^d via FindHint, never
// from the secret residual — yields a real ML-DSA signature.
func TestBCCSignRoundTripVerifiesCIRCL(t *testing.T) {
	for _, mode := range []Mode{ModeP65, ModeP87} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			message := []byte("Pulsar BCC/CEF no-leak round-trip — FIPS 204 byte equality")
			var ctx []byte // empty context

			sig, tr, km, pub := runBCCSign(t, mode, 0x5A, message, ctx)

			params := MustParamsFor(mode)

			// (a) Package's own Verify (FIPS 204 dispatch).
			pk := &PublicKey{Mode: mode, Bytes: pub}
			if err := Verify(params, pk, message, &Signature{Mode: mode, Bytes: sig}); err != nil {
				t.Fatalf("pulsar.Verify rejected the BCC signature: %v", err)
			}

			// (b) cloudflare/circl directly, with a pk circl re-derives
			// from the SAME seed — proves the seed→pk→sig chain reaches an
			// independent FIPS 204 verifier with no pulsar code in the pk
			// path. (Only ModeP65 has a circl pk re-derivation here; for
			// ModeP87 we re-derive via the circl mldsa87 package below.)
			verifyUnderCirclFromSeed(t, mode, bccTestSeed(0x5A), message, ctx, sig)

			// (c) No-leak debug oracle: the transcript that BUILT this
			// signature must not contain any leaking secret quantity.
			assertBCCTranscriptNoLeak(t, mode, km, tr)

			t.Logf("%s BCC signature (%d bytes) verified under FIPS 204 (own Verify + circl) in %d attempt(s)",
				mode.String(), len(sig), tr.attempts)
		})
	}
}

// TestBCCSignRoundTripWithContext exercises a non-empty FIPS 204 context
// string through the same round-trip, confirming the μ derivation binds
// ctx identically to the verifier.
func TestBCCSignRoundTripWithContext(t *testing.T) {
	mode := ModeP65
	message := []byte("context-bound BCC message")
	ctx := []byte("PULSAR-BCC-CTX")

	sig, tr, km, pub := runBCCSign(t, mode, 0x33, message, ctx)
	params := MustParamsFor(mode)

	pk := &PublicKey{Mode: mode, Bytes: pub}
	if err := VerifyCtx(params, pk, message, ctx, &Signature{Mode: mode, Bytes: sig}); err != nil {
		t.Fatalf("VerifyCtx rejected BCC signature with ctx: %v", err)
	}
	// Independent circl check with ctx.
	var pkC mldsa65.PublicKey
	if err := pkC.UnmarshalBinary(pub); err != nil {
		t.Fatalf("circl unmarshal pk: %v", err)
	}
	if !mldsa65.Verify(&pkC, message, ctx, sig) {
		t.Fatal("circl mldsa65.Verify rejected BCC signature with ctx")
	}
	// Wrong ctx must be rejected (binding check).
	if mldsa65.Verify(&pkC, message, []byte("WRONG-CTX"), sig) {
		t.Fatal("circl accepted BCC signature under the wrong ctx — binding broken")
	}
	assertBCCTranscriptNoLeak(t, mode, km, tr)
}

// TestBCCSignRoundTripTamperRejected closes the vacuous-pass hole: a
// single flipped signature byte must be rejected by the independent
// verifier. If a tampered signature still verified, the acceptance
// tests above would be meaningless.
func TestBCCSignRoundTripTamperRejected(t *testing.T) {
	mode := ModeP65
	message := []byte("tamper-evidence message")
	sig, _, _, pub := runBCCSign(t, mode, 0x77, message, nil)

	var pkC mldsa65.PublicKey
	if err := pkC.UnmarshalBinary(pub); err != nil {
		t.Fatalf("circl unmarshal pk: %v", err)
	}
	if !mldsa65.Verify(&pkC, message, nil, sig) {
		t.Fatal("baseline BCC signature did not verify under circl")
	}
	tampered := append([]byte(nil), sig...)
	tampered[len(tampered)/2] ^= 0x01
	if mldsa65.Verify(&pkC, message, nil, tampered) {
		t.Fatal("tampered BCC signature verified — verifier vacuous (test would be meaningless)")
	}
	// Wrong message must also be rejected.
	if mldsa65.Verify(&pkC, []byte("a different message entirely"), nil, sig) {
		t.Fatal("BCC signature verified against the wrong message — joint binding broken")
	}
}

// verifyUnderCirclFromSeed re-derives the public key from the seed using
// circl's own deterministic keygen and verifies the signature under the
// matching circl parameter set. This keeps the pulsar package out of the
// pk derivation path for the independent-verifier check.
func verifyUnderCirclFromSeed(t *testing.T, mode Mode, seed *[SeedSize]byte, message, ctx, sig []byte) {
	t.Helper()
	switch mode {
	case ModeP65:
		pk, _ := mldsa65.NewKeyFromSeed(seed)
		if !mldsa65.Verify(pk, message, ctx, sig) {
			t.Fatal("circl mldsa65.Verify (pk re-derived from seed) rejected the BCC signature")
		}
	case ModeP87:
		pk, _ := mldsa87.NewKeyFromSeed(seed)
		if !mldsa87.Verify(pk, message, ctx, sig) {
			t.Fatal("circl mldsa87.Verify (pk re-derived from seed) rejected the BCC signature")
		}
	default:
		t.Fatalf("unsupported mode for circl re-derivation: %v", mode)
	}
}

// assertBCCTranscriptNoLeak is the no-leak debug oracle. Using the
// test-only witnesses (w, y) AND the key material (to form the genuine
// secret-bearing products), it reconstructs every FORBIDDEN quantity and
// asserts NONE of them appears in the public transcript bytes that build
// the signature:
//
//   - full w = A·y                     (w' − w reveals the residual)
//   - LowBits(w) (centred low part)    (long-term-key correlated)
//   - the mask y itself                (z − c·s1 reveals s1)
//   - c·s2                             (long-term key material)
//   - c·t0                             (long-term key material)
//   - r0 = LowBits(w − c·s2)           (the FIPS rejection residual)
//   - residual w' − w = c·t0 − c·s2    (reveals key when paired with w)
//
// The transcript carries ONLY public quantities (w', w1, z, c̃, hint,
// clear bit). A hit means the no-leak invariant has been violated — the
// exact failure mode (PULSAR-V13-HINT-LEAK / PULSAR-V13-W-LEAK) the BCC
// path exists to prevent.
func assertBCCTranscriptNoLeak(t *testing.T, mode Mode, km *mldsaKeyMaterial, tr *bccTranscript) {
	t.Helper()
	gamma2, _, _, _ := bccParams(mode)
	tau, _, _, _ := modeTauOmega(mode)
	K, _, _ := modeShape(mode)

	pub := tr.publicBytes()

	// c from the PUBLIC c̃ (allowed — c̃ is public, in the signature).
	var c poly
	polyDeriveUniformBall(&c, tr.cTilde, tau)
	cHat := c
	cHat.ntt()

	// Genuine secret products c·s2 and c·t0 (the leaking quantities the
	// v0.3 path broadcast). s2 is un-normalised in [q-η, q+η]; t0 is the
	// centred low part of t. Form both via NTT mul, normalise.
	cs2 := make(polyVec, K)
	ct0 := make(polyVec, K)
	for k := 0; k < K; k++ {
		s2Hat := km.s2[k]
		s2Hat.reduceLe2Q()
		s2Hat.ntt()
		cs2[k].mulHat(&cHat, &s2Hat)
		cs2[k].reduceLe2Q()
		cs2[k].invNTT()
		cs2[k].normalize()

		t0Hat := km.t0[k]
		t0Hat.reduceLe2Q()
		t0Hat.ntt()
		ct0[k].mulHat(&cHat, &t0Hat)
		ct0[k].reduceLe2Q()
		ct0[k].invNTT()
		ct0[k].normalize()
	}

	// r0 = LowBits(w − c·s2): the FIPS rejection residual.
	wMinusCs2 := subVecMod(tr.debugFullW, cs2)
	r0 := centeredLowVec(wMinusCs2, gamma2)

	forbidden := map[string][]byte{
		"full w (A·y)":         packPolyVec(tr.debugFullW),
		"mask y":               packPolyVec(tr.debugY),
		"LowBits(w)":           packPolyVec(centeredLowVec(tr.debugFullW, gamma2)),
		"c·s2":                 packPolyVec(cs2),
		"c·t0":                 packPolyVec(ct0),
		"r0 = LowBits(w−c·s2)": packPolyVec(r0),
		"residual w'−w":        packPolyVec(subVecMod(tr.wPrime, tr.debugFullW)),
	}
	for name, secret := range forbidden {
		if len(secret) == 0 {
			continue
		}
		if bytes.Contains(pub, secret) {
			t.Fatalf("no-leak VIOLATION: public BCC transcript contains %s (mode %v)", name, mode)
		}
	}

	// The residual MUST actually equal c·t0 − c·s2 (proving the witnesses
	// are consistent — otherwise the "residual absent" check is testing
	// the wrong bytes). w' − w = c·t0 − c·s2 (mod q).
	wantResidual := subVecMod(ct0, cs2)
	gotResidual := subVecMod(tr.wPrime, tr.debugFullW)
	if !bytes.Equal(packPolyVec(wantResidual), packPolyVec(gotResidual)) {
		t.Fatal("BCC algebra check failed: w' − w != c·t0 − c·s2 (the carry-elimination identity is wrong)")
	}

	// Sanity: the transcript MUST contain the public quantities it is
	// supposed to (w1, z, c̃) — otherwise publicBytes is degenerate and
	// the absence checks above are vacuous.
	if !bytes.Contains(pub, packPolyVec(tr.w1)) {
		t.Fatal("transcript missing w1 (publicBytes degenerate — absence checks vacuous)")
	}
	if !bytes.Contains(pub, tr.cTilde) {
		t.Fatal("transcript missing c̃ (publicBytes degenerate)")
	}
}

// centeredLowVec returns the centred LowBits of every coefficient of w,
// stored as (a0 + q) mod q so it can be packed and scanned for. This is
// the quantity that MUST NOT leak (it correlates with the long-term key
// through r0).
func centeredLowVec(w polyVec, gamma2 uint32) polyVec {
	out := make(polyVec, len(w))
	for i := range w {
		for j := 0; j < mldsaN; j++ {
			a0 := centeredLowBits(w[i][j], gamma2)
			v := a0
			if v < 0 {
				v += int32(mldsaQ)
			}
			out[i][j] = uint32(v)
		}
	}
	return out
}

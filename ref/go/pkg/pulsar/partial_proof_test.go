// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"testing"
)

// partial_proof_test.go — soundness, binding, and zero-knowledge tests
// for the linear-sigma partial-z proof (partial_proof.go).
//
// The relation under proof is z_i = λ_i·y_i + c·λ_i·s1_i over R_q^L. The
// tests build a witness for which the relation HOLDS, prove it, and check
// that (a) a valid proof is accepted, (b) every binding (z, session,
// nonce, party, challenge c, λ_i) mutation is rejected, and (c) the
// serialized proof reveals no y_i/s1_i.

// partialFixture builds a consistent (statement, witness) pair: random
// y_i, s1_i, λ_i, c; z_i computed as the true image φ(y_i, s1_i).
func partialFixture(t *testing.T, mode Mode, seed string) (*PartialStatement, *PartialWitness) {
	t.Helper()
	_, L, _ := modeShape(mode)
	rng := newBCCDeterministicRNG("PULSAR/Partial/test/" + seed)

	y := sampleUniformVec(rng, L)
	s1 := sampleUniformVec(rng, L)

	// λ_i: a nonzero Z_q scalar from the stream.
	var lambda uint32
	{
		var b [4]byte
		for {
			_, _ = rng.Read(b[:])
			v := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
			v &= 0x7FFFFF
			if v != 0 && v < mldsaQ {
				lambda = v
				break
			}
		}
	}

	// c: a SampleInBall-style challenge polynomial (τ ±1 coefficients),
	// derived from a fresh seed — representative of a real ML-DSA c.
	var cSeed [64]byte
	_, _ = rng.Read(cSeed[:])
	tau, _, _, _ := modeTauOmega(mode)
	var c poly
	polyDeriveUniformBall(&c, cSeed[:], tau)

	// z_i = φ(y_i, s1_i) — the TRUE public image.
	cHat := c
	cHat.ntt()
	z := partialLinearMap(lambda, &cHat, y, s1)

	st := &PartialStatement{
		Mode:            mode,
		Lambda:          lambda,
		C:               c,
		Z:               z,
		SessionID:       [32]byte{0xA1, 0x02},
		NonceID:         [32]byte{0xB3, 0x04},
		PartyID:         7,
		DKGCommitment:   []byte("dkg-share-commit"),
		NonceCommitment: []byte("nonce-commit"),
	}
	w := &PartialWitness{Y: y, S1: s1}
	return st, w
}

func proveFixture(t *testing.T, st *PartialStatement, w *PartialWitness, seed string) []byte {
	t.Helper()
	rng := newBCCDeterministicRNG("PULSAR/Partial/prove/" + seed)
	proof, err := ProvePartial(st, w, rng)
	if err != nil {
		t.Fatalf("ProvePartial: %v", err)
	}
	return proof
}

// TestPartialProofValidAccepted: a proof for a true statement verifies.
func TestPartialProofValidAccepted(t *testing.T) {
	for _, mode := range []Mode{ModeP65, ModeP87} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			st, w := partialFixture(t, mode, "valid")
			proof := proveFixture(t, st, w, "valid")
			if err := VerifyPartialProof(st, proof); err != nil {
				t.Fatalf("valid partial-z proof rejected: %v", err)
			}
		})
	}
}

// TestPartialProofRejectsDegenerateChallenge: a challenge that is not a real
// SampleInBall (c = 0, or a low-weight c) strips the s1 binding — z_i = λy_i +
// cλs1_i collapses toward z_i = λy_i — so both proving and verifying must
// refuse it (PULSAR-V13-PARTIAL-Z, Fix 5).
func TestPartialProofRejectsDegenerateChallenge(t *testing.T) {
	st, w := partialFixture(t, ModeP65, "degenc")
	proof := proveFixture(t, st, w, "degenc")

	// c = 0: zero-weight challenge.
	zero := *st
	zero.C = poly{}
	if _, err := ProvePartial(&zero, w, newBCCDeterministicRNG("x")); err != ErrChallengeNotInBall {
		t.Fatalf("ProvePartial must refuse c=0, got %v", err)
	}
	if err := VerifyPartialProof(&zero, proof); err != ErrChallengeNotInBall {
		t.Fatalf("VerifyPartialProof must refuse c=0, got %v", err)
	}

	// Low-weight c: a single ±1 coefficient (weight 1 ≠ τ).
	low := *st
	low.C = poly{}
	low.C[0] = 1
	if err := VerifyPartialProof(&low, proof); err != ErrChallengeNotInBall {
		t.Fatalf("VerifyPartialProof must refuse a low-weight c, got %v", err)
	}

	// An out-of-range coefficient (not 0/±1) is also refused.
	bad := *st
	bad.C = st.C
	bad.C[0] = 2
	if err := VerifyPartialProof(&bad, proof); err != ErrChallengeNotInBall {
		t.Fatalf("VerifyPartialProof must refuse a non-±1 coefficient, got %v", err)
	}
}

// TestPartialProofBadZRejected: corrupting z_i (so the relation no longer
// holds) must be rejected — this is the soundness core.
func TestPartialProofBadZRejected(t *testing.T) {
	st, w := partialFixture(t, ModeP65, "badz")
	proof := proveFixture(t, st, w, "badz")

	bad := *st
	bad.Z = append(polyVec(nil), st.Z...) // poly is a value type; slice copy is deep
	corrupted := bad.Z[0]
	corrupted[0] = (corrupted[0] + 1) % mldsaQ
	bad.Z[0] = corrupted
	if err := VerifyPartialProof(&bad, proof); err == nil {
		t.Fatal("proof accepted against a corrupted z_i — soundness broken")
	}

	// A forged proof claiming a z that is NOT the true image must also
	// fail: take a random z and try to verify the honest proof against it.
	bad2 := *st
	rng := newBCCDeterministicRNG("forge-z")
	bad2.Z = sampleUniformVec(rng, len(st.Z))
	if err := VerifyPartialProof(&bad2, proof); err == nil {
		t.Fatal("proof accepted against an unrelated z_i — soundness broken")
	}
}

// TestPartialProofBindingMutationsRejected: every Fiat–Shamir-bound field
// (session, nonce, party, challenge c, λ_i, commitments) must, when
// mutated at verification, reject the proof — the challenge re-derives
// differently, so the sigma equation no longer closes.
func TestPartialProofBindingMutationsRejected(t *testing.T) {
	st, w := partialFixture(t, ModeP65, "bind")
	proof := proveFixture(t, st, w, "bind")
	if err := VerifyPartialProof(st, proof); err != nil {
		t.Fatalf("baseline proof should verify: %v", err)
	}

	mutations := []struct {
		name string
		mut  func(s *PartialStatement)
	}{
		{"session", func(s *PartialStatement) { s.SessionID[0] ^= 1 }},
		{"nonce", func(s *PartialStatement) { s.NonceID[0] ^= 1 }},
		{"party", func(s *PartialStatement) { s.PartyID++ }},
		{"lambda", func(s *PartialStatement) { s.Lambda = (s.Lambda % (mldsaQ - 2)) + 1 }},
		{"challenge-c", func(s *PartialStatement) {
			c := s.C
			// flip one nonzero challenge coefficient to another value
			for j := 0; j < mldsaN; j++ {
				if c[j] != 0 {
					c[j] = (c[j] + 1) % mldsaQ
					break
				}
			}
			s.C = c
		}},
		{"dkg-commit", func(s *PartialStatement) { s.DKGCommitment = []byte("different-dkg") }},
		{"nonce-commit", func(s *PartialStatement) { s.NonceCommitment = []byte("different-nonce") }},
	}
	for _, m := range mutations {
		bad := *st
		// deep-copy Z so mutations to other fields don't share state
		bad.Z = append(polyVec(nil), st.Z...)
		m.mut(&bad)
		if err := VerifyPartialProof(&bad, proof); err == nil {
			t.Fatalf("binding mutation %q not detected — proof transfers across context", m.name)
		}
	}
}

// TestPartialProofZeroKnowledge: the serialized proof must NOT contain the
// witness y_i or s1_i. The sigma responses u = a + e·y are masked by
// uniform a; the proof bytes carry (T, u, v) only.
func TestPartialProofZeroKnowledge(t *testing.T) {
	st, w := partialFixture(t, ModeP65, "zk")
	proof := proveFixture(t, st, w, "zk")

	yBytes := packPolyVec(w.Y)
	s1Bytes := packPolyVec(w.S1)
	if bytes.Contains(proof, yBytes) {
		t.Fatal("partial-z proof leaks y_i (mask nonce share)")
	}
	if bytes.Contains(proof, s1Bytes) {
		t.Fatal("partial-z proof leaks s1_i (signing-key share)")
	}
	// Also: no single y_i[l] / s1_i[l] polynomial appears verbatim.
	for l := range w.Y {
		if bytes.Contains(proof, packPoly(&w.Y[l])) {
			t.Fatalf("partial-z proof leaks y_i[%d]", l)
		}
		if bytes.Contains(proof, packPoly(&w.S1[l])) {
			t.Fatalf("partial-z proof leaks s1_i[%d]", l)
		}
	}
}

// TestPartialProofMalformedRejected: structurally bad proofs are rejected
// without panic (truncated, padded, empty).
func TestPartialProofMalformedRejected(t *testing.T) {
	st, w := partialFixture(t, ModeP65, "malformed")
	proof := proveFixture(t, st, w, "malformed")

	for _, bad := range [][]byte{
		nil,
		{},
		proof[:len(proof)-1],
		append(append([]byte(nil), proof...), 0x00),
	} {
		if err := VerifyPartialProof(st, bad); err == nil {
			t.Fatal("malformed proof accepted")
		}
	}
}

// TestPartialProofZeroLambdaRejected: λ_i = 0 is degenerate (z ≡ 0) and
// must be rejected by both prover and verifier.
func TestPartialProofZeroLambdaRejected(t *testing.T) {
	st, w := partialFixture(t, ModeP65, "zerolambda")
	st.Lambda = 0
	if _, err := ProvePartial(st, w, newBCCDeterministicRNG("z")); err != ErrPartialZeroLambda {
		t.Fatalf("prover must reject lambda=0, got %v", err)
	}
	if err := VerifyPartialProof(st, make([]byte, 1)); err != ErrPartialZeroLambda {
		t.Fatalf("verifier must reject lambda=0, got %v", err)
	}
}

// TestSoundPartialZVerifierWiring: the sound verifier registered through
// the proof.go registry is exercised end-to-end via VerifyZPartial, and
// it lifts the fail-closed default (ProductionBCCSigningReady gating).
func TestSoundPartialZVerifierWiring(t *testing.T) {
	st, w := partialFixture(t, ModeP65, "wiring")
	proof := proveFixture(t, st, w, "wiring")

	old := registeredPartialZVerifier
	RegisterPartialZVerifier(SoundPartialZVerifier(st.Mode, st.Lambda, st.C, st.Z))
	defer func() { registeredPartialZVerifier = old }()

	p := &Partial{
		PartyID:   st.PartyID,
		SessionID: st.SessionID,
		NonceID:   st.NonceID,
		ZShare:    packPolyVec(st.Z),
		Proof:     proof,
	}
	in := PartialInput{
		PartyID:         st.PartyID,
		SessionID:       st.SessionID,
		NonceID:         st.NonceID,
		Challenge:       packPoly(&st.C),
		DKGCommitment:   st.DKGCommitment,
		NonceCommitment: st.NonceCommitment,
		ZShare:          packPolyVec(st.Z),
	}
	if err := VerifyZPartial(p, in); err != nil {
		t.Fatalf("sound verifier rejected a valid partial through VerifyZPartial: %v", err)
	}

	// Tamper the proof bytes → sound verifier must reject.
	p.Proof = append([]byte(nil), proof...)
	p.Proof[len(p.Proof)/2] ^= 0xFF
	if err := VerifyZPartial(p, in); err == nil {
		t.Fatal("sound verifier accepted a tampered proof through VerifyZPartial")
	}
}

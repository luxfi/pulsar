// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"testing"
)

// nonce_transcript_proof_test.go — soundness/ZK tests for the SOUND
// linear core of the NonceMPC transcript (nonce_transcript_proof.go), and
// fail-closed assertions for the novel non-linear parts.
//
// The sound identity is Σ_i λ_i·(A·y_i) − w0 = w1·α. We construct a
// real witness (random per-party masks y_i and Lagrange scalars λ_i),
// form w = Σ λ_i (A·y_i), set w1 = HighBits(w) and w0 = (w − w1·α) mod q,
// then prove/verify, mutate, and check ZK.

// nonceFixture builds a t-party (statement, witness) pair where the
// linear identity holds by construction. matrixA is the public A from a
// derived key (so it is a valid ExpandA matrix).
func nonceFixture(t *testing.T, mode Mode, parties int, seed string) (*NonceConsistencyStatement, *NonceConsistencyWitness) {
	t.Helper()
	K, L, _ := modeShape(mode)
	gamma2, _, _, _ := bccParams(mode)

	// Public A from a real key derivation.
	km, err := deriveKeyMaterial(mode, bccTestSeed(0x9E))
	if err != nil {
		t.Fatalf("deriveKeyMaterial: %v", err)
	}
	aHat := km.a

	rng := newBCCDeterministicRNG("PULSAR/Nonce/test/" + seed)

	ys := make([]polyVec, parties)
	lambdas := make([]uint32, parties)
	commits := make([][]byte, parties)
	// w = Σ λ_i (A·y_i)
	w := make(polyVec, K)
	for i := 0; i < parties; i++ {
		// small-ish masks so the aggregate w tends to land boundary-clear
		// often enough; use bounded mask like the BCC signer.
		var ySeed [64]byte
		_, _ = rng.Read(ySeed[:])
		y := make(polyVec, L)
		for l := 0; l < L; l++ {
			expandMaskPoly(&y[l], &ySeed, uint16(l), modeGamma1Bits(mode))
		}
		ys[i] = y

		var lam uint32
		var b [4]byte
		for {
			_, _ = rng.Read(b[:])
			v := (uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16) & 0x7FFFFF
			if v != 0 && v < mldsaQ {
				lam = v
				break
			}
		}
		lambdas[i] = lam
		commits[i] = []byte{byte('c'), byte(i)}

		// accumulate λ_i (A·y_i)
		yHat := make(polyVec, L)
		for l := 0; l < L; l++ {
			yHat[l] = y[l]
			yHat[l].reduceLe2Q()
			yHat[l].ntt()
		}
		for k := 0; k < K; k++ {
			var ay poly
			polyDotHat(&ay, aHat[k], yHat)
			ay.reduceLe2Q()
			ay.invNTT()
			ay.normalize()
			for j := 0; j < mldsaN; j++ {
				w[k][j] = uint32((uint64(w[k][j]) + (uint64(ay[j])*uint64(lam))%mldsaQ) % mldsaQ)
			}
		}
	}

	// w1 = HighBits(w); w0 = (w − w1·α) mod q. Identity exact by construction.
	w1 := highBitsVec(w, gamma2)
	alpha := uint64(2 * gamma2)
	w0 := make(polyVec, K)
	for k := 0; k < K; k++ {
		for j := 0; j < mldsaN; j++ {
			v := (int64(w[k][j]) - int64((uint64(w1[k][j])*alpha)%mldsaQ)) % mldsaQ
			if v < 0 {
				v += mldsaQ
			}
			w0[k][j] = uint32(v)
		}
	}

	st := &NonceConsistencyStatement{
		Mode:         mode,
		A:            aHat,
		Lambdas:      lambdas,
		W1:           w1,
		NonceID:      [32]byte{0x4E, 0x07},
		NonceCommits: commits,
	}
	wit := &NonceConsistencyWitness{Y: ys, W0: w0}
	return st, wit
}

// TestNonceConsistencyIdentityHolds is the statement-soundness gate: the
// constructed witness MUST satisfy Φ(y,w0) = w1·α.
func TestNonceConsistencyIdentityHolds(t *testing.T) {
	for _, mode := range []Mode{ModeP65, ModeP87} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			st, w := nonceFixture(t, mode, 4, "identity")
			got := nonceLinearMap(st.A, st.Lambdas, w.Y, w.W0)
			want := noncePublicImage(mode, st.W1)
			if !polyVecEqual(got, want) {
				t.Fatal("Σ λ_i (A·y_i) − w0 != w1·α — the nonce linear identity is wrong")
			}
		})
	}
}

// TestNonceConsistencyValidAccepted: a proof for the true witness verifies.
func TestNonceConsistencyValidAccepted(t *testing.T) {
	for _, mode := range []Mode{ModeP65, ModeP87} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			st, w := nonceFixture(t, mode, 4, "valid")
			proof, err := ProveNonceConsistency(st, w, newBCCDeterministicRNG("nonce/prove/"+mode.String()))
			if err != nil {
				t.Fatalf("ProveNonceConsistency: %v", err)
			}
			if err := VerifyNonceConsistency(st, proof); err != nil {
				t.Fatalf("valid nonce-consistency proof rejected: %v", err)
			}
		})
	}
}

// TestNonceConsistencySoundnessAndBinding: mutating w1, λ_i, the nonce id,
// or a commitment must reject the proof.
func TestNonceConsistencySoundnessAndBinding(t *testing.T) {
	st, w := nonceFixture(t, ModeP65, 4, "sound")
	proof, err := ProveNonceConsistency(st, w, newBCCDeterministicRNG("nonce/sound"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyNonceConsistency(st, proof); err != nil {
		t.Fatalf("baseline must verify: %v", err)
	}

	// Mutate w1 (changes the public image) → reject.
	badW1 := *st
	badW1.W1 = append(polyVec(nil), st.W1...)
	p0 := badW1.W1[0]
	p0[0] = (p0[0] + 1) % mldsaQ
	badW1.W1[0] = p0
	if err := VerifyNonceConsistency(&badW1, proof); err == nil {
		t.Fatal("proof accepted against mutated w1 — soundness broken")
	}

	// Mutate bindings (λ_i, nonce id, commitment) → FS re-derives → reject.
	for i, mut := range []func(s *NonceConsistencyStatement){
		func(s *NonceConsistencyStatement) {
			ls := append([]uint32(nil), s.Lambdas...)
			ls[0] = (ls[0] % (mldsaQ - 2)) + 1
			s.Lambdas = ls
		},
		func(s *NonceConsistencyStatement) { s.NonceID[0] ^= 1 },
		func(s *NonceConsistencyStatement) {
			cs := append([][]byte(nil), s.NonceCommits...)
			cs[0] = []byte("tampered")
			s.NonceCommits = cs
		},
	} {
		bad := *st
		mut(&bad)
		if err := VerifyNonceConsistency(&bad, proof); err == nil {
			t.Fatalf("binding mutation %d not detected", i)
		}
	}
}

// TestNonceConsistencyZeroKnowledge: the proof reveals no y_i or w0.
func TestNonceConsistencyZeroKnowledge(t *testing.T) {
	st, w := nonceFixture(t, ModeP65, 4, "zk")
	proof, err := ProveNonceConsistency(st, w, newBCCDeterministicRNG("nonce/zk"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(proof, packPolyVec(w.W0)) {
		t.Fatal("nonce-consistency proof leaks w0 (low part — correlates with residual)")
	}
	for i := range w.Y {
		if bytes.Contains(proof, packPolyVec(w.Y[i])) {
			t.Fatalf("nonce-consistency proof leaks y_%d (mask)", i)
		}
	}
}

// TestNonceW0MarginSelfCheck: the local self-check accepts a boundary-clear
// w0 and rejects an out-of-margin one. (Local invariant, not a ZK proof.)
func TestNonceW0MarginSelfCheck(t *testing.T) {
	gamma2, beta, _, _ := bccParams(ModeP65)
	bound := boundaryThreshold(gamma2, beta)
	K, _, _ := modeShape(ModeP65)

	// In-margin: all coefficients below the threshold.
	good := make(polyVec, K)
	for k := 0; k < K; k++ {
		for j := 0; j < mldsaN; j++ {
			good[k][j] = bound - 1
		}
	}
	if !nonceW0InMargin(ModeP65, good) {
		t.Fatal("in-margin w0 rejected by self-check")
	}
	// Out-of-margin: one coefficient at the threshold.
	bad := make(polyVec, K)
	copy(bad, good)
	p := bad[0]
	p[0] = bound
	bad[0] = p
	if nonceW0InMargin(ModeP65, bad) {
		t.Fatal("out-of-margin w0 accepted by self-check")
	}
}

// TestNonceBoundaryMPCFailsClosed: the novel HighBits/BoundaryClear-in-MPC
// predicate over secret-shared w is fail-closed (REVIEW), not faked.
func TestNonceBoundaryMPCFailsClosed(t *testing.T) {
	if NonceBoundaryMPCReady() {
		t.Fatal("HighBits/BoundaryClear-in-MPC must be fail-closed by default (novel MPC)")
	}
	if err := registeredNonceBoundaryVerifier.VerifyNonceBoundary(&NonceConsistencyStatement{}, nil); err != ErrNonceMPCBoundaryUnsound {
		t.Fatalf("boundary-MPC verifier must fail closed, got %v", err)
	}
}

// TestNonceProofMalformedRejected: structurally bad proofs rejected.
func TestNonceProofMalformedRejected(t *testing.T) {
	st, w := nonceFixture(t, ModeP65, 4, "mal")
	proof, err := ProveNonceConsistency(st, w, newBCCDeterministicRNG("nonce/mal"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, {}, proof[:len(proof)-1], append(append([]byte(nil), proof...), 0)} {
		if err := VerifyNonceConsistency(st, bad); err == nil {
			t.Fatal("malformed nonce proof accepted")
		}
	}
}

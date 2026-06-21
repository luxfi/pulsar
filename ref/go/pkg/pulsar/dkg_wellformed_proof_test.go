// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"reflect"
	"testing"
)

// dkg_wellformed_proof_test.go — soundness, ZK, and containment tests for
// the DKG linear-consistency proof (dkg_wellformed_proof.go).
//
// The load-bearing statement is A·s1 + s2 − t0 = t1·2^d. We build the
// witness from a real deriveKeyMaterial output, assert the relation holds
// in the package's own representation, then prove/verify, mutate, and
// check ZK + the no-T0-in-public-output containment.

// dkgFixtureFromSeed derives a key and packages the well-formedness
// statement + witness in normalized [0,q) form.
func dkgFixtureFromSeed(t *testing.T, mode Mode, seedByte byte) (*DKGWellFormedStatement, *DKGWellFormedWitness, *mldsaKeyMaterial) {
	t.Helper()
	seed := bccTestSeed(seedByte)
	km, err := deriveKeyMaterial(mode, seed)
	if err != nil {
		t.Fatalf("deriveKeyMaterial: %v", err)
	}
	normVec := func(src polyVec) polyVec {
		out := make(polyVec, len(src))
		for i := range src {
			out[i] = src[i]
			out[i].normalize()
		}
		return out
	}
	w := &DKGWellFormedWitness{
		S1: normVec(km.s1),
		S2: normVec(km.s2),
		T0: normVec(km.t0),
	}
	st := &DKGWellFormedStatement{
		Mode:            mode,
		A:               km.a, // NTT domain
		T1:              normVec(km.t1),
		PKEpoch:         1,
		Rho:             km.rho,
		ShareCommitRoot: [32]byte{0xDC, 0x01},
	}
	return st, w, km
}

// TestDKGRelationHoldsForRealKey is the statement-soundness gate: the
// linear relation Ψ(s1,s2,t0) = t1·2^d MUST hold for a genuine
// deriveKeyMaterial output. If it does not, every proof below would be
// proving the wrong statement.
func TestDKGRelationHoldsForRealKey(t *testing.T) {
	for _, mode := range []Mode{ModeP65, ModeP87} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			st, w, _ := dkgFixtureFromSeed(t, mode, 0x11)
			got := dkgLinearMap(st.A, w.S1, w.S2, w.T0)
			want := dkgPublicImage(st.T1)
			if !polyVecEqual(got, want) {
				t.Fatal("A·s1 + s2 − t0 != t1·2^d for a real key — the DKG " +
					"well-formedness statement does not match keygen algebra")
			}
		})
	}
}

// TestDKGWellFormedValidAccepted: a proof for the true witness verifies.
func TestDKGWellFormedValidAccepted(t *testing.T) {
	for _, mode := range []Mode{ModeP65, ModeP87} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			st, w, _ := dkgFixtureFromSeed(t, mode, 0x22)
			rng := newBCCDeterministicRNG("dkg/prove/" + mode.String())
			proof, err := ProveDKGWellFormed(st, w, rng)
			if err != nil {
				t.Fatalf("ProveDKGWellFormed: %v", err)
			}
			if err := VerifyDKGWellFormed(st, proof); err != nil {
				t.Fatalf("valid DKG well-formedness proof rejected: %v", err)
			}
		})
	}
}

// TestDKGWellFormedSoundness: a proof must not verify against a different
// public key (mutated t1) or a different binding context.
func TestDKGWellFormedSoundness(t *testing.T) {
	st, w, _ := dkgFixtureFromSeed(t, ModeP65, 0x33)
	proof, err := ProveDKGWellFormed(st, w, newBCCDeterministicRNG("dkg/sound"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDKGWellFormed(st, proof); err != nil {
		t.Fatalf("baseline must verify: %v", err)
	}

	// Mutate t1 (the public key high part): the public image changes, so
	// the sigma equation no longer closes.
	badT1 := *st
	badT1.T1 = append(polyVec(nil), st.T1...)
	p0 := badT1.T1[0]
	p0[0] = (p0[0] + 1) % mldsaQ
	badT1.T1[0] = p0
	if err := VerifyDKGWellFormed(&badT1, proof); err == nil {
		t.Fatal("proof accepted against a mutated t1 — soundness/binding broken")
	}

	// Mutate the binding context (epoch / ρ / share-commit root): the FS
	// challenge re-derives differently → reject.
	for i, mut := range []func(s *DKGWellFormedStatement){
		func(s *DKGWellFormedStatement) { s.PKEpoch++ },
		func(s *DKGWellFormedStatement) { s.Rho[0] ^= 1 },
		func(s *DKGWellFormedStatement) { s.ShareCommitRoot[0] ^= 1 },
	} {
		bad := *st
		mut(&bad)
		if err := VerifyDKGWellFormed(&bad, proof); err == nil {
			t.Fatalf("binding mutation %d not detected", i)
		}
	}
}

// TestDKGWellFormedZeroKnowledge: the serialized proof reveals no s1/s2/t0.
func TestDKGWellFormedZeroKnowledge(t *testing.T) {
	st, w, _ := dkgFixtureFromSeed(t, ModeP65, 0x44)
	proof, err := ProveDKGWellFormed(st, w, newBCCDeterministicRNG("dkg/zk"))
	if err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string][]byte{
		"s1": packPolyVec(w.S1),
		"s2": packPolyVec(w.S2),
		"t0": packPolyVec(w.T0),
	} {
		if bytes.Contains(proof, secret) {
			t.Fatalf("DKG well-formedness proof leaks %s", name)
		}
	}
	// Per-polynomial: t0 is the most sensitive (PULSAR-V13). Ensure no
	// t0[k] appears verbatim.
	for k := range w.T0 {
		if bytes.Contains(proof, packPoly(&w.T0[k])) {
			t.Fatalf("DKG proof leaks t0[%d] (long-term key material)", k)
		}
	}
}

// TestDKGPublicOutputHasNoT0 reflection-guards the DKG public output type:
// it must never carry t0, s2, the full t, or any master secret. (Mirrors
// the existing TestNoT0InProductionDKGTypes but anchored to the proof's
// own statement type too.)
func TestDKGPublicOutputHasNoT0(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(DKGPublicOutput{}),
		reflect.TypeOf(DKGShareCommitment{}),
		reflect.TypeOf(DKGWellFormedStatement{}),
	} {
		for _, f := range []string{"T0", "S2", "FullT", "MasterSecret", "S1Master", "T0Master", "T0Share", "S2Share"} {
			if hasFieldNamed(typ, f) {
				t.Fatalf("%s exposes forbidden secret field %q", typ.Name(), f)
			}
		}
	}
	// The witness type DOES carry S1/S2/T0 — that is correct (it is the
	// dealer's local secret input, never serialized). Confirm it is NOT in
	// the public-output set.
	for _, typ := range productionDKGTypes() {
		if typ == reflect.TypeOf(DKGWellFormedWitness{}) {
			t.Fatal("DKGWellFormedWitness must not be a production (public) DKG type")
		}
	}
}

// TestDKGWitnessInRange: the dealer's local self-check accepts a genuine
// small-norm witness and rejects an out-of-range one.
func TestDKGWitnessInRange(t *testing.T) {
	st, w, _ := dkgFixtureFromSeed(t, ModeP65, 0x55)
	_ = st
	if !dkgWitnessInRange(ModeP65, w) {
		t.Fatal("genuine key witness should be in small-norm range")
	}
	// Push one s1 coefficient out of [−η, η].
	bad := &DKGWellFormedWitness{
		S1: append(polyVec(nil), w.S1...),
		S2: w.S2,
		T0: w.T0,
	}
	p0 := bad.S1[0]
	p0[0] = mldsaQ / 2 // maximally far from 0 → out of range
	bad.S1[0] = p0
	if dkgWitnessInRange(ModeP65, bad) {
		t.Fatal("out-of-range witness should be rejected by the self-check")
	}
}

// TestDKGRangeProofFailsClosed: the tight small-norm range proof is
// fail-closed by default (it is novel, not a linear sigma).
func TestDKGRangeProofFailsClosed(t *testing.T) {
	if DKGRangeProofReady() {
		t.Fatal("DKG range proof must be fail-closed by default (novel lattice range proof)")
	}
	if err := registeredDKGRangeVerifier.VerifyDKGRange(&DKGWellFormedStatement{}, nil); err != ErrDKGRangeProofUnsound {
		t.Fatalf("range verifier must fail closed, got %v", err)
	}
}

// TestDKGProofMalformedRejected: structurally bad proofs rejected, no panic.
func TestDKGProofMalformedRejected(t *testing.T) {
	st, w, _ := dkgFixtureFromSeed(t, ModeP65, 0x66)
	proof, err := ProveDKGWellFormed(st, w, newBCCDeterministicRNG("dkg/mal"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, {}, proof[:len(proof)-1], append(append([]byte(nil), proof...), 0)} {
		if err := VerifyDKGWellFormed(st, bad); err == nil {
			t.Fatal("malformed DKG proof accepted")
		}
	}
}

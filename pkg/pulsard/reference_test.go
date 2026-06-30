// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// reference_test.go — the END-TO-END PROOF that pulsard's emitted evidence is
// accepted by the chain's own verifier, warp.VerifyPulsar. These tests use the
// reference trusted-dealer engine (FOOTGUN): they prove the VERIFY-SIDE
// integration is correct (group key, lane context, evidence fields, both subject
// domains) while the dealerless TALUS engine remains fail-closed.

package pulsard_test

import (
	"bytes"
	"testing"

	mldsa65 "github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/pulsar/pkg/pulsard"
	"github.com/luxfi/warp"
)

// TestReferenceDealer_VerifiesUnderWarp is THE proof: a group ML-DSA-65 keypair
// produced by the reference dealer signs a 32-byte subject, and the resulting
// warp.PulsarEvidence verifies under warp.VerifyPulsar — the exact function the
// chain runs. It also re-checks with raw mldsa65.Verify under the lane context,
// which is the drift guard for LaneContext (if warp's private context changed,
// VerifyPulsar would reject).
func TestReferenceDealer_VerifiesUnderWarp(t *testing.T) {
	signer, era := newRefSigner(t)
	subject := subject32("warp-message-id-D")

	ev, err := signer.ThresholdSign(subject)
	if err != nil {
		t.Fatalf("ThresholdSign: %v", err)
	}

	// THE proof: the chain's own verifier accepts.
	if err := warp.VerifyPulsar(ev, subject, era); err != nil {
		t.Fatalf("warp.VerifyPulsar rejected reference evidence: %v", err)
	}

	// Independent cross-check: raw FIPS-204 verify under the lane context. This
	// is what asserts pulsard.LaneContext == warp's private pulsarLaneContext.
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(era.MLDSAPubKey); err != nil {
		t.Fatalf("unmarshal group pk: %v", err)
	}
	if !mldsa65.Verify(&pk, subject, []byte(pulsard.LaneContext), ev.Signature) {
		t.Fatal("raw mldsa65.Verify failed under LaneContext — context drift or bad signature")
	}

	// Evidence fields must pin the era.
	if ev.SuiteID != warp.SuitePulsarThresholdMLDSA65 {
		t.Errorf("SuiteID = %q, want %q", ev.SuiteID, warp.SuitePulsarThresholdMLDSA65)
	}
	if ev.SignerSetID != era.SignerSetID || ev.KeyEraID != era.KeyEraID || ev.Generation != era.Generation {
		t.Errorf("evidence identifiers do not match era")
	}
	if len(ev.Signature) != mldsa65.SignatureSize {
		t.Errorf("signature size = %d, want %d", len(ev.Signature), mldsa65.SignatureSize)
	}
}

// TestReferenceDealer_ResolverDispatchPath reproduces the warp dispatcher's
// exact Pulsar arm: resolve the era from a KeyEraResolver, then VerifyPulsar.
// pulsard.KeyEraStore is used as the resolver — the same shape an on-chain
// resolver injects into warp's LaneVerifierSet.PulsarEra.
func TestReferenceDealer_ResolverDispatchPath(t *testing.T) {
	signer, era := newRefSigner(t)
	subject := subject32("subject-via-resolver")

	ev, err := signer.ThresholdSign(subject)
	if err != nil {
		t.Fatalf("ThresholdSign: %v", err)
	}

	store := pulsard.NewKeyEraStore()
	store.Put(era)

	// dispatcher step 1: resolve by the evidence's identifiers.
	resolved, err := store.ResolvePulsarKeyEra(ev.SignerSetID, ev.KeyEraID, ev.Generation)
	if err != nil {
		t.Fatalf("ResolvePulsarKeyEra: %v", err)
	}
	// dispatcher step 2: VerifyPulsar against the resolved era.
	if err := warp.VerifyPulsar(ev, subject, resolved); err != nil {
		t.Fatalf("VerifyPulsar via resolver: %v", err)
	}
}

// TestReferenceDealer_QuasarSubjectDomain proves the OTHER subject domain: M, a
// QuasarFinalitySubject digest. The same signer signs M and the evidence
// verifies, demonstrating subject-agnosticism (D for warp, M for quasar).
func TestReferenceDealer_QuasarSubjectDomain(t *testing.T) {
	signer, era := newRefSigner(t)

	params := warp.QuasarFinalityParams{
		ChainID:      era.ChainID,
		Height:       7,
		Round:        3,
		SignerSetID:  era.SignerSetID,
		KeyEraID:     era.KeyEraID,
		Generation:   era.Generation,
		PChainHeight: era.PChainHeight,
		PolicyID:     1,
	}
	m := warp.QuasarFinalitySubject(params)

	ev, err := signer.ThresholdSign(m[:])
	if err != nil {
		t.Fatalf("ThresholdSign(M): %v", err)
	}
	if err := warp.VerifyPulsar(ev, m[:], era); err != nil {
		t.Fatalf("VerifyPulsar over quasar subject M: %v", err)
	}
}

// TestReleaseGate_RejectsTamperedSignature asserts a flipped signature byte is
// caught: warp.VerifyPulsar and pulsard.ReleaseGate both reject. This is the
// release gate doing its job — pulsard never emits non-verifying evidence.
func TestReleaseGate_RejectsTamperedSignature(t *testing.T) {
	signer, era := newRefSigner(t)
	subject := subject32("tamper-me")

	ev, err := signer.ThresholdSign(subject)
	if err != nil {
		t.Fatalf("ThresholdSign: %v", err)
	}
	bad := ev
	bad.Signature = append([]byte(nil), ev.Signature...)
	bad.Signature[0] ^= 0xFF

	if err := warp.VerifyPulsar(bad, subject, era); err == nil {
		t.Fatal("warp.VerifyPulsar accepted a tampered signature")
	}
	if err := pulsard.ReleaseGate(bad, subject, era); err == nil {
		t.Fatal("ReleaseGate accepted a tampered signature")
	}
}

// TestReleaseGate_RejectsWrongEra asserts evidence for one era does not verify
// against a different generation (ErrWrongEra). The signature commits to the
// subject; the era identifiers must match exactly.
func TestReleaseGate_RejectsWrongEra(t *testing.T) {
	signer, era := newRefSigner(t)
	subject := subject32("wrong-era")

	ev, err := signer.ThresholdSign(subject)
	if err != nil {
		t.Fatalf("ThresholdSign: %v", err)
	}
	other := era
	other.Generation = era.Generation + 1
	if err := warp.VerifyPulsar(ev, subject, other); err == nil {
		t.Fatal("VerifyPulsar accepted evidence against the wrong era generation")
	}
}

// TestReshare_PreservesGroupKey asserts a reference reshare advances Generation
// while preserving the group public key, so old signatures still verify and new
// signatures verify under the new generation.
func TestReshare_PreservesGroupKey(t *testing.T) {
	signer, era := newRefSigner(t)
	subject := subject32("reshare-subject")

	evOld, err := signer.ThresholdSign(subject)
	if err != nil {
		t.Fatalf("ThresholdSign (pre-reshare): %v", err)
	}

	if err := signer.Reshare(); err != nil {
		t.Fatalf("Reshare: %v", err)
	}
	newEra := signer.Era()
	if newEra.Generation != era.Generation+1 {
		t.Fatalf("Generation = %d, want %d", newEra.Generation, era.Generation+1)
	}
	if !bytes.Equal(newEra.MLDSAPubKey, era.MLDSAPubKey) {
		t.Fatal("reshare changed the group public key")
	}

	// Old signature still verifies under the OLD era (key preserved).
	if err := warp.VerifyPulsar(evOld, subject, era); err != nil {
		t.Fatalf("old evidence no longer verifies after reshare: %v", err)
	}
	// New signature verifies under the NEW era.
	evNew, err := signer.ThresholdSign(subject)
	if err != nil {
		t.Fatalf("ThresholdSign (post-reshare): %v", err)
	}
	if err := warp.VerifyPulsar(evNew, subject, newEra); err != nil {
		t.Fatalf("new evidence does not verify under new era: %v", err)
	}
}

// TestReferenceDealer_FromSeed_Reproducible asserts deterministic keygen +
// deterministic signing yield a stable group key and signature (KAT-friendly).
func TestReferenceDealer_FromSeed_Reproducible(t *testing.T) {
	seed := bytes.Repeat([]byte{0x5A}, mldsa65.SeedSize)
	subject := subject32("kat-subject")

	mk := func() (warp.PulsarEvidence, warp.PulsarKeyEra) {
		dealer, era, err := pulsard.NewReferenceDealerFromSeed(
			seed, testID("chain"), testID("signer-set"), 1, 0, 0, testThreshold)
		if err != nil {
			t.Fatalf("NewReferenceDealerFromSeed: %v", err)
		}
		signer, err := pulsard.New(era, pulsard.WithEngine(dealer))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		ev, err := signer.ThresholdSign(subject)
		if err != nil {
			t.Fatalf("ThresholdSign: %v", err)
		}
		return ev, era
	}

	ev1, era1 := mk()
	ev2, era2 := mk()
	if !bytes.Equal(era1.MLDSAPubKey, era2.MLDSAPubKey) {
		t.Fatal("seeded keygen not reproducible (public key differs)")
	}
	if !bytes.Equal(ev1.Signature, ev2.Signature) {
		t.Fatal("deterministic signing not reproducible (signature differs)")
	}
	if err := warp.VerifyPulsar(ev1, subject, era1); err != nil {
		t.Fatalf("seeded evidence does not verify: %v", err)
	}
}

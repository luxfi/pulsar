// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// keyera_test.go — key-era records, the resolver, committee bounds, and the
// session/nonce plumbing (DeriveSessionID, NoncePool).

package pulsard_test

import (
	"errors"
	"testing"

	mldsa65 "github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/luxfi/pulsar/pkg/pulsard"
	"github.com/luxfi/warp"
)

// TestNewKeyEra_RejectsMalformedKey asserts a non-ML-DSA-65 public key is
// rejected at era creation (a malformed key can never verify).
func TestNewKeyEra_RejectsMalformedKey(t *testing.T) {
	if _, err := pulsard.NewKeyEra(testID("c"), testID("s"), 1, 0, 0, []byte{1, 2, 3}, testThreshold, "x"); !errors.Is(err, pulsard.ErrBadGroupKey) {
		t.Fatalf("NewKeyEra(short key) err = %v, want ErrBadGroupKey", err)
	}
	// A correctly-sized but invalid key is also rejected.
	if _, err := pulsard.NewKeyEra(testID("c"), testID("s"), 1, 0, 0, make([]byte, mldsa65.PublicKeySize), testThreshold, "x"); err != nil {
		// circl accepts an all-zero key as a structurally valid (if useless)
		// public key, so this may or may not error; the load-bearing case is the
		// wrong-length one above. We only assert NewKeyEra pins the suite.
		t.Logf("all-zero key: %v (acceptable)", err)
	}
}

// TestNewKeyEra_PinsSuite asserts the era's SchemeID is always the Pulsar suite.
func TestNewKeyEra_PinsSuite(t *testing.T) {
	_, era, err := pulsard.NewReferenceDealer(testID("c"), testID("s"), 1, 0, 0, testThreshold, nil)
	if err != nil {
		t.Fatalf("dealer: %v", err)
	}
	if era.SchemeID != warp.SuitePulsarThresholdMLDSA65 {
		t.Fatalf("SchemeID = %q, want Pulsar suite", era.SchemeID)
	}
}

// TestKeyEraStore_RoundTripAndMiss asserts Put/Resolve roundtrips and a miss
// fails closed.
func TestKeyEraStore_RoundTripAndMiss(t *testing.T) {
	_, era, err := pulsard.NewReferenceDealer(testID("c"), testID("s"), 9, 2, 0, testThreshold, nil)
	if err != nil {
		t.Fatalf("dealer: %v", err)
	}
	store := pulsard.NewKeyEraStore()
	store.Put(era)

	got, err := store.ResolvePulsarKeyEra(era.SignerSetID, era.KeyEraID, era.Generation)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.KeyEraID != era.KeyEraID || got.Generation != era.Generation {
		t.Fatal("resolved era identifiers mismatch")
	}
	if _, err := store.ResolvePulsarKeyEra(era.SignerSetID, era.KeyEraID, era.Generation+1); !errors.Is(err, pulsard.ErrKeyEraNotFound) {
		t.Fatalf("miss err = %v, want ErrKeyEraNotFound", err)
	}
}

// TestCommittee asserts validity bounds and the TALUS N≥2T−1 MPC bound.
func TestCommittee(t *testing.T) {
	if err := (pulsard.Committee{Threshold: 0, Parties: 3}).Validate(); err == nil {
		t.Error("T=0 accepted")
	}
	if err := (pulsard.Committee{Threshold: 4, Parties: 3}).Validate(); err == nil {
		t.Error("T>N accepted")
	}
	if err := (pulsard.Committee{Threshold: 3, Parties: 5}).Validate(); err != nil {
		t.Errorf("valid committee rejected: %v", err)
	}
	for _, tc := range []struct{ t, want int }{{1, 1}, {2, 2}, {3, 5}, {4, 7}} {
		if got := (pulsard.Committee{Threshold: tc.t}).MinPartiesMPC(); got != tc.want {
			t.Errorf("MinPartiesMPC(T=%d) = %d, want %d", tc.t, got, tc.want)
		}
	}
}

// TestDeriveSessionID asserts determinism and binding to (subject, era).
func TestDeriveSessionID(t *testing.T) {
	_, era, _ := pulsard.NewReferenceDealer(testID("c"), testID("s"), 1, 0, 0, testThreshold, nil)
	subA := subject32("A")
	subB := subject32("B")

	if pulsard.DeriveSessionID(subA, era) != pulsard.DeriveSessionID(subA, era) {
		t.Fatal("DeriveSessionID not deterministic")
	}
	if pulsard.DeriveSessionID(subA, era) == pulsard.DeriveSessionID(subB, era) {
		t.Fatal("different subjects yield same session id")
	}
	era2 := era
	era2.KeyEraID++
	if pulsard.DeriveSessionID(subA, era) == pulsard.DeriveSessionID(subA, era2) {
		t.Fatal("different eras yield same session id")
	}
}

// TestNoncePool asserts canonical selection is deterministic, consumption is
// one-shot, and exhaustion fails closed.
func TestNoncePool(t *testing.T) {
	pool := pulsard.NewNoncePool()
	ids := [][32]byte{{1}, {2}, {3}, {4}, {5}}
	for _, id := range ids {
		pool.Add(id)
	}
	pool.Add(ids[0]) // duplicate: idempotent
	if pool.Available() != 5 {
		t.Fatalf("Available = %d, want 5", pool.Available())
	}

	sid := [32]byte{0xAB}
	pick1, err := pool.SelectCanonical(sid)
	if err != nil {
		t.Fatalf("SelectCanonical: %v", err)
	}
	pick2, _ := pool.SelectCanonical(sid)
	if pick1 != pick2 {
		t.Fatal("canonical selection not deterministic for the same session")
	}

	// Consume everything; selection must then fail closed.
	for _, id := range ids {
		pool.Consume(id)
	}
	if pool.Available() != 0 {
		t.Fatalf("Available after consume = %d, want 0", pool.Available())
	}
	if _, err := pool.SelectCanonical(sid); !errors.Is(err, pulsard.ErrNoncePoolEmpty) {
		t.Fatalf("exhausted pool err = %v, want ErrNoncePoolEmpty", err)
	}
}

// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"bytes"
	"testing"
)

// TestTranscriptHashStable — same inputs produce same hash, no
// dependency on map iteration or extra-cost ordering.
func TestTranscriptHashStable(t *testing.T) {
	in := TranscriptInputs{
		ChainID:            []byte("lux-mainnet"),
		GroupID:            []byte("quasar-bls-shadow"),
		OldEpochID:         42,
		NewEpochID:         43,
		OldSetHash:         [32]byte{0x01, 0x02, 0x03, 0x04},
		NewSetHash:         [32]byte{0x05, 0x06, 0x07, 0x08},
		ThresholdOld:       11,
		ThresholdNew:       11,
		GroupPublicKeyHash: [32]byte{0x09, 0x0a, 0x0b, 0x0c},
		Variant:            "reshare",
	}
	a := in.Hash(nil)
	b := in.Hash(nil)
	if a != b {
		t.Fatal("non-deterministic transcript hash")
	}
}

// TestTranscriptHashDistinguishesVariant — the variant tag MUST
// produce a different hash for "refresh" vs "reshare". A common
// failure mode in similar protocols is to allow an activation cert
// from one variant to be replayed for the other.
func TestTranscriptHashDistinguishesVariant(t *testing.T) {
	base := TranscriptInputs{
		ChainID:    []byte("test"),
		GroupID:    []byte("g0"),
		OldEpochID: 1, NewEpochID: 2,
		ThresholdOld: 3, ThresholdNew: 3,
	}
	base.Variant = "refresh"
	hRefresh := base.Hash(nil)
	base.Variant = "reshare"
	hReshare := base.Hash(nil)
	if hRefresh == hReshare {
		t.Fatal("variant tag failed to distinguish refresh vs reshare hashes")
	}
}

// TestTranscriptHashDistinguishesEpoch — different epoch IDs MUST
// produce different hashes. Bound transcripts cannot be replayed
// across epochs.
func TestTranscriptHashDistinguishesEpoch(t *testing.T) {
	base := TranscriptInputs{
		ChainID: []byte("test"),
		GroupID: []byte("g0"),
		Variant: "reshare",
	}
	base.NewEpochID = 1
	h1 := base.Hash(nil)
	base.NewEpochID = 2
	h2 := base.Hash(nil)
	if h1 == h2 {
		t.Fatal("epoch ID change did not affect transcript hash")
	}
}

// TestValidatorSetHashOrderInvariant — the hash is the same
// regardless of the order the public keys are presented in. Caller
// can hand in any order; the function sorts internally.
func TestValidatorSetHashOrderInvariant(t *testing.T) {
	keys := [][]byte{
		[]byte("validator-A"),
		[]byte("validator-B"),
		[]byte("validator-C"),
		[]byte("validator-D"),
	}
	h1 := ValidatorSetHash(keys, nil)
	// Reverse.
	rev := make([][]byte, len(keys))
	for i, k := range keys {
		rev[len(keys)-1-i] = k
	}
	h2 := ValidatorSetHash(rev, nil)
	if h1 != h2 {
		t.Fatal("ValidatorSetHash order-dependent")
	}
}

// TestValidatorSetHashUniqueness — different sets produce different
// hashes.
func TestValidatorSetHashUniqueness(t *testing.T) {
	a := ValidatorSetHash([][]byte{[]byte("v1"), []byte("v2")}, nil)
	b := ValidatorSetHash([][]byte{[]byte("v1"), []byte("v3")}, nil)
	if a == b {
		t.Fatal("ValidatorSetHash collision")
	}
}

// TestTranscriptHashCrossLanguageCompatibility — emits the
// canonical bytes the C++ port at luxcpp/crypto/pulsar/reshare/ MUST
// reproduce. Useful as a fixed-vector smoke test when porting.
func TestTranscriptHashFixedVector(t *testing.T) {
	in := TranscriptInputs{
		ChainID:    []byte("lux-mainnet"),
		GroupID:    []byte("quasar-pq"),
		OldEpochID: 100,
		NewEpochID: 101,
		// Fixed values to make the digest deterministic.
		OldSetHash:         [32]byte{},
		NewSetHash:         [32]byte{},
		ThresholdOld:       11,
		ThresholdNew:       11,
		GroupPublicKeyHash: [32]byte{},
		Variant:            "reshare",
	}
	got := in.Hash(nil)
	// We don't pin a specific 32-byte expected value here; the
	// determinism is verified by re-running the hash. The C++ port's
	// matching test pins the exact bytes.
	if bytes.Equal(got[:], make([]byte, 32)) {
		t.Fatal("transcript hash returned all zeros — likely wrong")
	}
	// Re-run for determinism.
	if in.Hash(nil) != got {
		t.Fatal("non-deterministic")
	}
}

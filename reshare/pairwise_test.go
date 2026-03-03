// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// TestX25519PairSymmetric — ECDH symmetry: both parties derive the
// same shared secret. Smoke test that confirms the curve25519
// integration is wired correctly.
func TestX25519PairSymmetric(t *testing.T) {
	privA := make([]byte, 32)
	privB := make([]byte, 32)
	if _, err := rand.Read(privA); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(privB); err != nil {
		t.Fatal(err)
	}
	pubA, _ := curve25519.X25519(privA, curve25519.Basepoint)
	pubB, _ := curve25519.X25519(privB, curve25519.Basepoint)

	abShared, err := X25519Pair(privA, pubB)
	if err != nil {
		t.Fatal(err)
	}
	baShared, err := X25519Pair(privB, pubA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(abShared, baShared) {
		t.Fatal("X25519 not symmetric")
	}
}

// TestAuthenticatedKex — full authenticated KEX flow, both ends
// produce the same auth_kex.
func TestAuthenticatedKex(t *testing.T) {
	// Static (wire) Ed25519 keys for two parties.
	pubA, privA, _ := ed25519.GenerateKey(nil)
	pubB, privB, _ := ed25519.GenerateKey(nil)

	// Ephemeral X25519 pairs.
	ephPrivA := make([]byte, 32)
	rand.Read(ephPrivA)
	ephPubA, _ := curve25519.X25519(ephPrivA, curve25519.Basepoint)

	ephPrivB := make([]byte, 32)
	rand.Read(ephPrivB)
	ephPubB, _ := curve25519.X25519(ephPrivB, curve25519.Basepoint)

	// Common transcript hash (in production this is
	// TranscriptInputs.Hash() — for the test any 32-byte value works).
	thash := [32]byte{0xde, 0xad, 0xbe, 0xef}

	// Each party signs its own ephemeral.
	sigA := SignEphemeral(privA, ephPubA, thash)
	sigB := SignEphemeral(privB, ephPubB, thash)

	// Now A computes auth_kex from B's signed ephemeral.
	authKexA, err := AuthenticatedKex(ephPrivA, ephPubB, sigB, pubB, thash, nil)
	if err != nil {
		t.Fatalf("A.AuthenticatedKex: %v", err)
	}
	authKexB, err := AuthenticatedKex(ephPrivB, ephPubA, sigA, pubA, thash, nil)
	if err != nil {
		t.Fatalf("B.AuthenticatedKex: %v", err)
	}
	if !bytes.Equal(authKexA, authKexB) {
		t.Fatal("AuthenticatedKex not symmetric")
	}
}

// TestAuthenticatedKexRejectsBadSig — a tampered signed ephemeral
// must be rejected (active MITM defense).
func TestAuthenticatedKexRejectsBadSig(t *testing.T) {
	pubB, privB, _ := ed25519.GenerateKey(nil)
	_ = privB

	ephPrivA := make([]byte, 32)
	rand.Read(ephPrivA)
	ephPubB := make([]byte, 32)
	rand.Read(ephPubB)

	thash := [32]byte{0x12}
	// Bogus signature.
	bogus := make([]byte, ed25519.SignatureSize)
	_, err := AuthenticatedKex(ephPrivA, ephPubB, bogus, pubB, thash, nil)
	if err == nil {
		t.Fatal("AuthenticatedKex accepted bogus signature")
	}
}

// TestDeriveSeedsAndMACKeys — both endpoints of a pair derive the
// same seeds and MAC keys (the canonical-pair ordering ensures this).
func TestDeriveSeedsAndMACKeys(t *testing.T) {
	const K = 4
	authKex := make(map[[2]int][]byte, K*K)
	for i := 0; i < K; i++ {
		for j := i + 1; j < K; j++ {
			authKex[[2]int{i, j}] = []byte{byte(i*K + j + 1)}
		}
	}
	selfSeeds := make(map[int][]byte, K)
	for i := 0; i < K; i++ {
		selfSeeds[i] = []byte{byte(0xC0 + i)}
	}

	chainID := []byte("lux-test")
	groupID := []byte("g0")
	const epochID uint64 = 5

	seeds, err := DeriveSeeds(K, authKex, selfSeeds, chainID, groupID, 0, epochID, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	macs, err := DeriveMACKeys(K, authKex, chainID, groupID, 0, epochID, nil, 32)
	if err != nil {
		t.Fatal(err)
	}

	// Determinism: re-derive and confirm equality.
	seeds2, _ := DeriveSeeds(K, authKex, selfSeeds, chainID, groupID, 0, epochID, nil, 32)
	macs2, _ := DeriveMACKeys(K, authKex, chainID, groupID, 0, epochID, nil, 32)
	for k, v := range seeds {
		if !bytes.Equal(v, seeds2[k]) {
			t.Fatalf("seed at %v non-deterministic", k)
		}
	}
	for k, v := range macs {
		if !bytes.Equal(v, macs2[k]) {
			t.Fatalf("mac at %v non-deterministic", k)
		}
	}

	// Different epoch → different output.
	seeds3, _ := DeriveSeeds(K, authKex, selfSeeds, chainID, groupID, 0, epochID+1, nil, 32)
	for k, v := range seeds {
		if bytes.Equal(v, seeds3[k]) {
			t.Fatalf("epoch change did not affect derived seed at %v", k)
		}
	}

	// Different chain ID → different output.
	seeds4, _ := DeriveSeeds(K, authKex, selfSeeds, []byte("different-chain"), groupID, 0, epochID, nil, 32)
	for k, v := range seeds {
		if bytes.Equal(v, seeds4[k]) {
			t.Fatalf("chainID change did not affect derived seed at %v", k)
		}
	}

	// Diagonal entries (i, i) come from selfSeeds — but only seeds,
	// not MACs (a party doesn't MAC to itself).
	for i := 0; i < K; i++ {
		if _, ok := seeds[[2]int{i, i}]; !ok {
			t.Errorf("missing self-seed for party %d", i)
		}
		if _, ok := macs[[2]int{i, i}]; ok {
			t.Errorf("MAC keys contain a self-pair (i=%d)", i)
		}
	}
}

// TestKDFDomainSeparation — same auth_kex, different tags, MUST give
// different outputs. This is the "PRF and MAC keys are not the same
// secret" property.
func TestKDFDomainSeparation(t *testing.T) {
	const K = 2
	authKex := map[[2]int][]byte{
		{0, 1}: []byte("shared-secret-AB"),
	}
	selfSeeds := map[int][]byte{
		0: []byte("self-A"),
		1: []byte("self-B"),
	}

	seeds, _ := DeriveSeeds(K, authKex, selfSeeds, []byte("c"), []byte("g"), 0, 1, nil, 32)
	macs, _ := DeriveMACKeys(K, authKex, []byte("c"), []byte("g"), 0, 1, nil, 32)

	if bytes.Equal(seeds[[2]int{0, 1}], macs[[2]int{0, 1}]) {
		t.Fatal("PRF seed and MAC key are equal — KDF tags collide")
	}
}

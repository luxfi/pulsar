// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

// Pairwise authenticated key-exchange material for VSR.
//
// The Reshare and Refresh protocols require:
//
//  1. Authenticated, encrypted point-to-point channels OLD → NEW for
//     private share delivery. The authentication MUST be tied to each
//     party's wire-identity key (Ed25519 / ML-DSA-65) so a passive
//     observer cannot spoof a delivery.
//
//  2. Per-pair PRF seeds and MAC keys for the post-resharing signing
//     epoch. These derive from a Diffie-Hellman shared secret that
//     each pair establishes via authenticated KEX. After the share is
//     delivered, the PRF/MAC material is derived locally on each side
//     via DeriveSeeds / DeriveMACKeys.
//
// We use X25519 + Ed25519 here as the kernel KEX. The auth_kex_ij is
// derived via a transcript-bound mix of the X25519 output produced by
// the canonical Pulsar HashSuite (cSHAKE256 under Pulsar-SHA3, BLAKE3
// under the legacy suite). For the hybrid post-quantum mode, swap
// X25519 for ML-KEM-768 + X25519 — out of scope for this kernel.

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"github.com/luxfi/pulsar/hash"
)

// PairwiseKeyMaterial holds the X25519 keys + signed ephemerals that
// together produce auth_kex_ij. One instance per pair (canonicalized
// by the smaller party ID first).
type PairwiseKeyMaterial struct {
	PartyI         int
	PartyJ         int
	AuthKex        []byte
	TranscriptHash [32]byte
}

// X25519Pair runs an X25519 key exchange and returns the 32-byte
// shared secret. Returns an error if either point is the identity or
// otherwise produces a small-order shared secret.
func X25519Pair(privA, pubB []byte) ([]byte, error) {
	if len(privA) != 32 {
		return nil, fmt.Errorf("reshare: X25519 private key must be 32 bytes, got %d", len(privA))
	}
	if len(pubB) != 32 {
		return nil, fmt.Errorf("reshare: X25519 public key must be 32 bytes, got %d", len(pubB))
	}
	shared, err := curve25519.X25519(privA, pubB)
	if err != nil {
		return nil, fmt.Errorf("reshare: X25519 failed: %w", err)
	}
	allZero := true
	for _, b := range shared {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, errors.New("reshare: X25519 produced all-zero shared secret (low-order point)")
	}
	return shared, nil
}

// AuthenticatedKex runs the pairwise authenticated key exchange and
// returns the auth_kex_ij value. The signed ephemeral protects against
// active man-in-the-middle.
//
// suite=nil resolves to the production default (Pulsar-SHA3).
func AuthenticatedKex(
	privIEph []byte,
	pubJEph []byte,
	sigJEph []byte,
	jStaticKey ed25519.PublicKey,
	transcriptHash [32]byte,
	suite hash.HashSuite,
) ([]byte, error) {
	signedMsg := append([]byte("pulsar.reshare.kex-bind.v1"), transcriptHash[:]...)
	signedMsg = append(signedMsg, pubJEph...)
	if !ed25519.Verify(jStaticKey, signedMsg, sigJEph) {
		return nil, errors.New("reshare: peer ephemeral signature invalid")
	}

	shared, err := X25519Pair(privIEph, pubJEph)
	if err != nil {
		return nil, err
	}

	s := hash.Resolve(suite)
	out := s.TranscriptHash(
		[]byte("pulsar.reshare.auth-kex.v1"),
		transcriptHash[:],
		shared,
	)
	return out[:], nil
}

// SignEphemeral produces the signature j ships with its ephemeral
// public key.
func SignEphemeral(
	priv ed25519.PrivateKey,
	pubEph []byte,
	transcriptHash [32]byte,
) []byte {
	signedMsg := append([]byte("pulsar.reshare.kex-bind.v1"), transcriptHash[:]...)
	signedMsg = append(signedMsg, pubEph...)
	return ed25519.Sign(priv, signedMsg)
}

// DeriveSeeds populates the per-pair PRF seed map for a committee of
// size K. suite=nil resolves to the production default (Pulsar-SHA3).
//
// eraID and generation are passed through to the suite's DerivePairwise.
// For pre-Bucket-B callsites that only have a single epochID, fold it
// into generation and pass eraID=0.
func DeriveSeeds(
	K int,
	authKex map[[2]int][]byte,
	selfSeeds map[int][]byte,
	chainID, groupID []byte,
	eraID, generation uint64,
	suite hash.HashSuite,
	outLen int,
) (map[[2]int][]byte, error) {
	out := make(map[[2]int][]byte, K*K)
	for i := 0; i < K; i++ {
		for j := i; j < K; j++ {
			pair := [2]int{i, j}
			var keyMat []byte
			if i == j {
				keyMat = selfSeeds[i]
				if len(keyMat) == 0 {
					return nil, fmt.Errorf("reshare: missing self-seed for party %d", i)
				}
			} else {
				keyMat = authKex[pair]
				if len(keyMat) == 0 {
					return nil, fmt.Errorf("reshare: missing auth_kex for pair (%d, %d)", i, j)
				}
			}
			out[pair] = KDFOutput(
				suite,
				"pulsar.reshare.prf-seed.v1",
				keyMat,
				chainID, groupID,
				eraID, generation,
				i, j,
				outLen,
			)
		}
	}
	return out, nil
}

// DeriveMACKeys mirrors DeriveSeeds with the "pulsar.reshare.mac-key.v1"
// tag and only off-diagonal entries (a party never MACs to itself).
// suite=nil resolves to the production default.
func DeriveMACKeys(
	K int,
	authKex map[[2]int][]byte,
	chainID, groupID []byte,
	eraID, generation uint64,
	suite hash.HashSuite,
	outLen int,
) (map[[2]int][]byte, error) {
	out := make(map[[2]int][]byte, K*(K-1)/2)
	for i := 0; i < K; i++ {
		for j := i + 1; j < K; j++ {
			pair := [2]int{i, j}
			keyMat := authKex[pair]
			if len(keyMat) == 0 {
				return nil, fmt.Errorf("reshare: missing auth_kex for pair (%d, %d)", i, j)
			}
			out[pair] = KDFOutput(
				suite,
				"pulsar.reshare.mac-key.v1",
				keyMat,
				chainID, groupID,
				eraID, generation,
				i, j,
				outLen,
			)
		}
	}
	return out, nil
}

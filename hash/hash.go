// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package hash defines the canonical hashing profile used by every
// Pulsar reshare / activation / pairwise routine.
//
// Two profiles are shipped:
//
//   - Pulsar-SHA3   — the production profile. Built on cSHAKE256, KMAC256,
//     and TupleHash256 from FIPS 202 / NIST SP 800-185. KATs in the
//     reshare oracle are emitted under this profile.
//
//   - Pulsar-BLAKE3 — the legacy / non-normative profile. Preserved so
//     historical bytes can be reproduced for cross-checks. Marked NOT
//     for production.
//
// All operations bind a domain-separation tag through the cSHAKE
// customization parameter (or the equivalent BLAKE3 keyed personalization
// when the BLAKE3 suite is active). Tags are version-pinned: bumping a
// tag invalidates every transcript and every activation cert in flight,
// which is the correct behaviour when a breaking change ships.
//
// Suite contract:
//
//	Hc(t)              → 32 bytes, challenge sampler digest
//	Hu(t, L)           → L bytes, XOF stream (e.g. seeding a Gaussian)
//	TranscriptHash(...) → 32 bytes, length-prefixed binding of N parts
//	PRF(K, M, L)       → L bytes
//	MAC(K, M, L)       → L bytes
//	DerivePairwise(...) → outLen bytes, a single-call KDF over a pair
//
// Two suites with the same ID always produce the same bytes for the
// same inputs (KAT determinism). Two suites with different IDs MUST
// produce different bytes (cross-profile collision avoidance).
package hash

// HashSuite is the canonical hashing surface every Pulsar reshare,
// activation, and pairwise routine uses. Implementations are
// stateless, goroutine-safe, and deterministic.
type HashSuite interface {
	// ID returns the profile identifier, e.g. "Pulsar-SHA3" or
	// "Pulsar-BLAKE3". Bound into transcripts so two profiles can
	// never collide on the byte level.
	ID() string

	// Hc returns the 32-byte challenge digest of `transcript`. Used
	// where the protocol needs a single fixed-length sample (e.g. a
	// challenge seed before expansion to a ternary vector).
	Hc(transcript []byte) []byte

	// Hu returns `outLen` XOF bytes from `transcript`. Used where the
	// protocol needs a streaming source — Gaussian sampler seeds,
	// PRNG initialisers, etc.
	Hu(transcript []byte, outLen int) []byte

	// TranscriptHash returns a 32-byte binding over the ordered list
	// of byte-strings `parts`, with unambiguous length prefixing
	// (TupleHash for SHA3; length-prefixed BLAKE3 for the BLAKE3
	// suite).
	TranscriptHash(parts ...[]byte) [32]byte

	// PRF computes a pseudorandom output of `outLen` bytes keyed by
	// `key` over message `msg`. Domain separation is built in.
	PRF(key, msg []byte, outLen int) []byte

	// MAC computes a message-authentication code of `outLen` bytes
	// keyed by `key` over message `msg`. Distinct from PRF by
	// customization tag.
	MAC(key, msg []byte, outLen int) []byte

	// DerivePairwise derives `outLen` bytes for a pairwise PRF/MAC
	// from `kex` (the authenticated-KEX shared secret) under the
	// canonical (chain_id, group_id, era_id, generation, i, j)
	// labels. The (i, j) pair is canonicalized internally to the
	// smaller-id-first ordering.
	DerivePairwise(
		kex []byte,
		chainID, groupID []byte,
		eraID, generation uint64,
		i, j int,
		outLen int,
	) []byte
}

// Default returns the production hash suite: Pulsar-SHA3.
func Default() HashSuite { return defaultSuite }

// DefaultID is the string ID of the production suite.
const DefaultID = "Pulsar-SHA3"

// LegacyBLAKE3ID is the string ID of the non-normative legacy suite.
const LegacyBLAKE3ID = "Pulsar-BLAKE3"

// resolve picks the suite to use for a given call.
func resolve(s HashSuite) HashSuite {
	if s == nil {
		return defaultSuite
	}
	return s
}

// Resolve returns `s` if non-nil, otherwise the production default.
func Resolve(s HashSuite) HashSuite { return resolve(s) }

// defaultSuite is the package-level singleton for the production profile.
var defaultSuite HashSuite = NewPulsarSHA3()

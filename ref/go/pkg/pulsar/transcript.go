// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// transcript.go — Pulsar's transcript-binding layer over the shared
// SP 800-185 surface in github.com/luxfi/mlwe/transcript.
//
// The SP 800-185 IMPLEMENTATION (cSHAKE256, KMAC256, and the
// left_encode/right_encode/encode_string/bytepad encoders) lives
// exactly once, in mlwe/transcript. This file holds only what is
// Pulsar-specific:
//
//   - functionName: the cSHAKE function-name N pinned to "Pulsar".
//   - the customisation tag constants.
//   - cshake256: the Pulsar-bound cSHAKE256 entry point (pins N).
//   - transcriptHash / transcriptHash32: the Pulsar tuple framing.
//
// All hashing in Pulsar routes through this file (or, for streaming
// call sites, through sha3.NewCShake256 with functionName). Pure
// SP 800-185 encoders and KMAC256 are taken directly from
// mlwe/transcript at their call sites.
//
// All Pulsar customisation strings live in this file as named
// constants so that the audit footprint of the hash layer is one
// file. Rotating a tag invalidates every test vector pinned at that
// tag — bumping a tag is a deliberate, audited move.

import (
	"github.com/luxfi/mlwe/transcript"
)

// Customisation tags for cSHAKE256/KMAC256. These match
// pulsar.tex §3 table "purpose -> SP 800-185 customisation tag"
// byte-for-byte.
const (
	tagDKGCommit     = "PULSAR-DKG-COMMIT-V1"
	tagDKGTranscript = "PULSAR-DKG-TRANSCRIPT-V1"
	tagSignR1        = "PULSAR-SIGN-R1-V1"
	tagSignR1MAC     = "PULSAR-SIGN-R1-MAC-V1"
	// tagSignR2 = "PULSAR-SIGN-R2-V1" — RESERVED for a future
	// Round-2 MAC envelope as defense-in-depth (see
	// docs/threat-model.md "Round-2 integrity"). The v0.1
	// design relies on commit-bind (Round-1's D_i digest
	// equals cSHAKE256(mask||masked||τ_1) — tampered Round-2
	// reveals fail commit re-derivation in Combine and are
	// rejected, verified by TestThresholdSwap_RejectedByCommitBind
	// in threshold_test.go). The MAC tag is intentionally left
	// undefined here so a stale rebase reusing the name catches
	// the inconsistency at compile time.
	// tagSignMask: per-attempt Round-1 mask derivation. Mixes the
	// raw RNG output with (sid || attempt || NodeID) so a caller
	// who accidentally reuses the same deterministic RNG across
	// two attempts (or two parallel sessions) gets DISTINCT masks
	// per (sid, attempt, NodeID). Closes the cross-attempt mask
	// reuse window flagged by the cryptographer review (H2).
	tagSignMask      = "PULSAR-SIGN-MASK-V1"
	tagReshareCommit = "PULSAR-RESHARE-COMMIT-V1"
	tagReshareTrans  = "PULSAR-RESHARE-TRANSCRIPT-V1"
	tagReshareBeacon = "PULSAR-RESHARE-BEACON-V1"
	tagExpandB       = "PULSAR-EXPANDB-V1"
	tagComplaint     = "PULSAR-COMPLAINT-V1"
	tagSeedShare     = "PULSAR-SEED-SHARE-V1"
)

// functionName is the SP 800-185 cSHAKE function-name parameter.
// All Pulsar cSHAKE calls pin N to "Pulsar" so that an integrator
// who mistakenly fed Pulsar cSHAKE bytes into a non-Pulsar cSHAKE
// engine would get a deterministic mismatch.
const functionName = "Pulsar"

// cshake256 returns the first outLen bytes of cSHAKE256(input, N,
// customisation) per SP 800-185 §3, with the function-name N pinned to
// the Pulsar domain tag (functionName). This is Pulsar's bound entry
// point into the shared cSHAKE256 in mlwe/transcript: the SP 800-185
// implementation lives there exactly once; the "Pulsar" binding lives
// here exactly once.
func cshake256(input []byte, outLen int, customisation string) []byte {
	return transcript.CShake256(functionName, customisation, input, outLen)
}

// transcriptHash binds an ordered tuple of byte-strings into a single
// 48-byte digest under the named customisation tag. The 48-byte width
// matches FIPS 204's commitment-hash length (CTildeSize); this lets us
// re-use the digest as a chain-pinning value without re-hashing.
//
// Encoding is SP 800-185 TupleHash256-style: for each part, prepend
// left_encode(bit_len(part)) so the boundary between parts is
// unambiguous regardless of part lengths. This matches
// pulsar/hash/sp800_185.go: TranscriptHash on the Pulsar-SHA3 suite.
func transcriptHash(customisation string, parts ...[]byte) [48]byte {
	buf := make([]byte, 0, 64+len(parts)*40)
	buf = append(buf, transcript.LeftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		buf = append(buf, transcript.EncodeString(p)...)
	}
	out := cshake256(buf, 48, customisation)
	var ret [48]byte
	copy(ret[:], out)
	return ret
}

// transcriptHash32 is the 32-byte counterpart used where a shorter
// digest is sufficient (commit digests, MAC tags).
func transcriptHash32(customisation string, parts ...[]byte) [32]byte {
	buf := make([]byte, 0, 64+len(parts)*40)
	buf = append(buf, transcript.LeftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		buf = append(buf, transcript.EncodeString(p)...)
	}
	out := cshake256(buf, 32, customisation)
	var ret [32]byte
	copy(ret[:], out)
	return ret
}

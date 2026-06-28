// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// transcript.go — Pulsar's FIPS 202 / SP 800-185 transcript surface.
//
// The SP 800-185 primitives themselves (cSHAKE256, KMAC256, and the
// LeftEncode / RightEncode / EncodeString / BytePad string encoders)
// live in exactly ONE place across the Lux Module-LWE stack:
// github.com/luxfi/mlwe/transcript. Pulsar and Corona both route through
// it, so there is a single audited implementation of every construction
// and the byte encodings cannot drift between protocols.
//
// This file owns only what is genuinely Pulsar-specific:
//
//   - the customisation tags (the protocol's domain separation),
//   - the cSHAKE function-name N = "Pulsar",
//   - the Pulsar hash entry points cshake256 / kmac256, which bind those
//     two above so the audit footprint of "which hash, which tag" stays
//     one file (matching the prior contract), and
//   - transcriptHash / transcriptHash32, Pulsar's own length-prefixed
//     multi-part digest. This is NOT SP 800-185 TupleHash256 (it prepends
//     left_encode(nParts) and omits the trailing right_encode(L), under
//     N = "Pulsar"), so it cannot be the shared TupleHash256 — it is
//     re-expressed over the shared CShake256 + encoders and kept here.
//
// All Pulsar customisation strings live in this file as named constants
// so that rotating a tag is a single, deliberate, audited edit: bumping a
// tag invalidates every test vector pinned at that tag.

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
// customisation) per SP 800-185 §3, with N pinned to functionName. The
// byte encoding is the shared mlwe/transcript implementation — this is
// only the Pulsar-named entry that binds N = "Pulsar".
func cshake256(input []byte, outLen int, customisation string) []byte {
	return transcript.CShake256(functionName, customisation, input, outLen)
}

// kmac256 returns KMAC256(key, msg, outLen, customisation) per
// SP 800-185 §4. The construction is the shared mlwe/transcript
// implementation; this is the Pulsar-named MAC entry so all of Pulsar's
// keyed hashing stays addressable from one file.
func kmac256(key, msg []byte, outLen int, customisation string) []byte {
	return transcript.KMAC256(key, msg, outLen, customisation)
}

// transcriptHash binds an ordered tuple of byte-strings into a single
// 48-byte digest under the named customisation tag. The 48-byte width
// matches FIPS 204's commitment-hash length (CTildeSize); this lets us
// re-use the digest as a chain-pinning value without re-hashing.
//
// Encoding: left_encode(nParts) followed by encode_string(part) for each
// part, hashed with cSHAKE256 under N = "Pulsar". The per-part
// encode_string makes the boundary between parts unambiguous. This is a
// Pulsar-specific construction — it is deliberately NOT SP 800-185
// TupleHash256 (which omits the nParts prefix, appends right_encode(L),
// and fixes N = "TupleHash") — so it routes through the shared encoders
// rather than the shared TupleHash256.
func transcriptHash(customisation string, parts ...[]byte) [48]byte {
	buf := transcript.LeftEncode(uint64(len(parts)))
	for _, p := range parts {
		buf = append(buf, transcript.EncodeString(p)...)
	}
	out := transcript.CShake256(functionName, customisation, buf, 48)
	var ret [48]byte
	copy(ret[:], out)
	return ret
}

// transcriptHash32 is the 32-byte counterpart used where a shorter
// digest is sufficient (commit digests, MAC tags).
func transcriptHash32(customisation string, parts ...[]byte) [32]byte {
	buf := transcript.LeftEncode(uint64(len(parts)))
	for _, p := range parts {
		buf = append(buf, transcript.EncodeString(p)...)
	}
	out := transcript.CShake256(functionName, customisation, buf, 32)
	var ret [32]byte
	copy(ret[:], out)
	return ret
}

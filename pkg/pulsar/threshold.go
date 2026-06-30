// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// threshold.go — shared threshold-signing transcript machinery.
//
// The v0.1 reconstruction-aggregator instantiation (ThresholdSigner /
// Round1 / Round2 / Combine) once lived here. It Lagrange-reconstructed
// the master seed in aggregator memory and called FIPS 204 SignTo once
// — i.e. a quorum's full ML-DSA signing key materialised in a single
// process. That reconstruct-then-sign ceremony was the H-1 footgun and
// has been removed in its entirety. The one and only threshold-signing
// path is now the v0.3 algebraic ceremony (threshold_v03.go +
// orchestrate.go), whose Lagrange-linearity-of-z aggregation produces
// the FIPS 204 signature WITHOUT ever reconstructing the secret in any
// party's memory.
//
// What remains in this file is the transcript / committee-root /
// constant-time machinery and the shared error set still consumed by
// the v0.3 path, the wide-committee GF(q) path (large_threshold.go),
// and the DKG (large_dkg.go).

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/mlwe/transcript"
)

// Errors returned by threshold signing. Shared across the v0.3
// algebraic path, the GF(q) wide-committee path, and the DKG.
var (
	ErrEmptyQuorum      = errors.New("pulsar: empty signing quorum")
	ErrInsufficientQuor = errors.New("pulsar: quorum smaller than threshold")
	ErrRound1MACBad     = errors.New("pulsar: Round-1 MAC verification failed")
	ErrRound2CommitBad  = errors.New("pulsar: Round-2 reveal does not match Round-1 commit")
	ErrSessionMismatch  = errors.New("pulsar: round messages from different sessions")
	ErrAttemptMismatch  = errors.New("pulsar: round messages from different rejection-restart attempts")
	ErrNotInQuorum      = errors.New("pulsar: party not in quorum")
	ErrPubkeyMismatch   = errors.New("pulsar: KeyShare public-key does not match")
)

// transcriptTau1Bytes builds the Round-1 transcript τ_1 = (sid, κ, T,
// sender, pk, μ). τ_1 is bound into every commit and MAC so a cross-
// session replay of the commit-and-reveal pair becomes a transcript
// mismatch. Sender-dependent: each party's commit binds its own NodeID
// (preventing share-equivocation across parties).
func transcriptTau1Bytes(sid [16]byte, attempt uint32, quorum []NodeID, sender NodeID, pk *PublicKey, message []byte) []byte {
	var attemptBE [4]byte
	binary.BigEndian.PutUint32(attemptBE[:], attempt)
	parts := make([][]byte, 0, 3+len(quorum)+2)
	parts = append(parts, sid[:], attemptBE[:])
	for _, q := range quorum {
		parts = append(parts, q[:])
	}
	parts = append(parts, sender[:])
	if pk != nil {
		parts = append(parts, pk.Bytes)
	}
	parts = append(parts, message)
	// SP 800-185 encode_string framing so commit boundaries are unambiguous.
	out := append([]byte{}, transcript.LeftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		out = append(out, transcript.EncodeString(p)...)
	}
	return out
}

// committeeRootFromShares reconstructs the DKG committee root from a
// directory of KeyShares. The committee root is the canonical
// 32-byte digest of the sorted committee that DKG installed.
func committeeRootFromShares(shares []*KeyShare) [32]byte {
	ids := make([]NodeID, 0, len(shares))
	for _, s := range shares {
		ids = append(ids, s.NodeID)
	}
	// Sort canonically.
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && nodeIDLess(ids[j], ids[j-1]); j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
	parts := make([][]byte, 0, len(ids)+1)
	parts = append(parts, []byte("PULSAR-COMMITTEE-V1"))
	for _, id := range ids {
		parts = append(parts, id[:])
	}
	return transcriptHash32(tagDKGCommit, parts...)
}

// ctEqualSlice is a constant-time byte-slice equality check. Returns
// false if lengths differ; otherwise scans every byte regardless of
// where the first mismatch occurs.
func ctEqualSlice(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

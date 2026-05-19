// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// large_types.go -- wire types for the GF(q) protocol stack, the
// parallel of types.go's KeyShare / Round1Message / Round2Message for
// the small-committee GF(257) path.
//
// Wire-format note (CR-6/7/8 closure, 2026-05-18). The GF(q) path now
// shares the canonical DKGShareEnvelope wire type with the GF(257)
// path: identity-stage seal/open is width-agnostic over the inner
// share slice (64 bytes for GF(257), 128 bytes for GF(q)). The vestigial
// per-dealer Commits field on Round-1 broadcasts was removed alongside
// dropping it on the small path (BLOCKERS.md CR-6 path A); binding
// comes from Round-2 digest agreement over the ordered envelope set.
//
// Cap. Every Large* type and constructor refuses committee sizes
// above TargetCommitteeSize = 1 111 111. This is the canonical
// extreme committee size for Lux's continental-scale validator set
// roadmap; the underlying GF(q) field supports up to q - 1 =
// 8 380 416 parties but pulsar's reference implementation pins
// the cap an order of magnitude below for over-provisioning,
// joining-without-reshare slack, and grow-without-fork.
//
// Architectural note. Production Lux consensus does NOT run one
// Pulsar ceremony over 1.1 M parties. It runs the small-committee
// GF(257) Pulsar at (T, N) = (2, 3) per sortitioned group, with
// ~366k groups in parallel and a Z-Chain Groth16 roll-up. See
// spec/system-model.tex section "Committee selection and rollup".
// The Large* types in this file are for the alternative deployment
// pattern: a single large committee that operates without a
// sortition layer (e.g. permissioned consortium or audit-attestation
// scenarios). Both deployment patterns produce a single FIPS 204
// ML-DSA signature; the verifier is unchanged.

import "errors"

// Errors specific to the Large* protocol surface.
var (
	ErrCommitteeAboveCap = errors.New("pulsar: committee larger than TargetCommitteeSize=1,111,111")
)

// LargeKeyShare is the GF(q) counterpart of KeyShare. Each lane is
// a uint32 evaluation of the per-byte Shamir polynomial over GF(q);
// the wire footprint is exactly twice that of the GF(257) variant.
type LargeKeyShare struct {
	NodeID    NodeID
	EvalPoint uint32               // Shamir x-coordinate in [1, TargetCommitteeSize]
	Share     [shareWireSizeQ]byte // 32 × uint32 big-endian GF(q) lanes
	Pub       *PublicKey
	Mode      Mode
}

// LargeDKGRound1Msg is the GF(q) Round-1 broadcast. Mirrors
// DKGRound1Msg: per-recipient envelopes are KEM-wrapped against the
// recipient's long-term ML-KEM-768 identity public key. No separate
// commit field (CR-6 path A); binding comes from Round-2 digest
// agreement over the ordered envelope set.
type LargeDKGRound1Msg struct {
	NodeID    NodeID
	Envelopes map[NodeID]DKGShareEnvelope
}

// LargeDKGRound2Msg is the GF(q) Round-2 broadcast. The digest is
// the same 32-byte cSHAKE256 output as the small-committee variant
// -- only the per-envelope payload widths change.
type LargeDKGRound2Msg struct {
	NodeID NodeID
	Digest [32]byte
}

// LargeDKGOutput is the result of a successful GF(q) DKG.
type LargeDKGOutput struct {
	GroupPubkey    *PublicKey
	SecretShare    *LargeKeyShare
	TranscriptHash [48]byte
	AbortEvidence  *AbortEvidence
}

// LargeRound1Message is the GF(q) threshold-sign Round-1 broadcast.
type LargeRound1Message struct {
	NodeID    NodeID
	SessionID [16]byte
	Attempt   uint32
	Commit    [32]byte
	MACs      map[NodeID][32]byte
}

// LargeRound2Message is the GF(q) threshold-sign Round-2 broadcast.
// PartialSig is 256 bytes (128-byte mask || 128-byte masked share).
type LargeRound2Message struct {
	NodeID     NodeID
	SessionID  [16]byte
	Attempt    uint32
	W1         []byte
	PartialSig []byte
}

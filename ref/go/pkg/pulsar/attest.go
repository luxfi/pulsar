// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// attest.go — canonical TBS bytes for binding a validator's TEE
// quote to its Round-1 commit in a public-permissionless Pulsar
// quorum (PULSAR-V12-TEE-BIND from AUDIT-2026-06.md).
//
// Pulsar's public-permissionless v0.3 path requires no TEE for
// safety: AlgebraicAggregate produces a byte-identical FIPS 204
// ML-DSA-65 signature without materialising the master sk at any
// quorum party. The CUSTODY-mode TEE path lives outside this
// package at github.com/luxfi/threshold/protocols/mldsa-tee.
//
// Some host chains nonetheless want to GATE participation in the
// permissionless quorum on attestation presence — i.e. only validators
// running an attested binary in an attested TEE may join the quorum,
// even though the protocol itself is safe without it. The host
// chain's attestation-policy module needs ONE canonical TBS recipe
// that the validator's TEE quote binds to. This file provides that
// recipe.
//
// DECOMPLECTING NOTE
//
// This file deliberately does NOT touch AlgebraicRound1Message,
// AlgebraicRound2Message, or any other wire shape. The attestation
// binding lives ALONGSIDE the threshold protocol, not INSIDE it. The
// host chain's consensus envelope carries (commit, quote) as a single
// validator broadcast; the chain's attestation-policy verifier
// consumes (commit, AttestationContext(commit), quote) to decide
// whether to admit the commit into the quorum.
//
// Wire stability invariant: bytes-on-wire for AlgebraicRound1Message,
// AlgebraicRound2Message, Signature, GroupKey, and AbortEvidence are
// UNCHANGED by this file's existence.

// AttestationContextTag is the customisation string for the SP 800-185
// TupleHash binding the validator's TEE quote to its Round-1 commit.
// The tag is unique-per-pulsar to keep the attestation TBS bytes
// distinct from any other Pulsar transcript hash (Round-1 commit
// transcript, MAC keys, signature challenge), preventing cross-context
// collisions.
const AttestationContextTag = "pulsar-att-v1"

// AttestationContext returns the canonical 32-byte TBS digest a
// validator's TEE quote should bind to when participating in a
// public-permissionless Pulsar quorum that the host chain gates by
// attestation presence.
//
// The digest is computed via the SP 800-185 TupleHash primitive
// shared with the rest of the pulsar transcript layer (see
// transcript.go: transcriptHash32). The tuple is the ordered
// concatenation of:
//
//	tag      = "pulsar-att-v1"           (customisation string)
//	parts[0] = sessionID                 (16 bytes)
//	parts[1] = attempt                   (big-endian 4 bytes)
//	parts[2] = groupPubBytes             (FIPS 204 pk-encoding bytes)
//	parts[3] = nodeID                    (32 bytes)
//	parts[4] = commit                    (32 bytes)
//
// Each part is framed by left_encode(bit_len) per SP 800-185 §2.3.1.
// Any field change shifts the digest unambiguously.
//
// The 32-byte output is the value the validator's TEE quote nonce
// (or report-data field, per vendor convention) MUST be set to. The
// host chain's attestation-policy verifier then:
//
//  1. Calls AttestationContext(setup, msg) to reconstruct the bound
//     value from the (setup, msg) pair it received with the quote.
//  2. Calls the vendor's attestation verifier (mpc/cc/attest.Dispatch)
//     to verify the quote against the policy-pinned root, asserting
//     quote.Nonce == AttestationContext.
//  3. Admits the commit into the quorum iff both pass.
//
// Wire impact: NONE. This is a pure function over already-
// transmitted Round-1 inputs. The attestation envelope is the host
// chain's consensus-envelope concern, not pulsar's.
//
// Panic safety: returns the zero [32]byte for nil setup or nil msg
// rather than panicking, matching the rest of the package's no-panic
// boundary (per pulsar.tex §6.1 DD-007).
func AttestationContext(setup *AlgebraicSetup, msg *AlgebraicRound1Message) [32]byte {
	if setup == nil || msg == nil || setup.Pub == nil {
		var zero [32]byte
		return zero
	}
	var attemptBytes [4]byte
	attemptBytes[0] = byte(msg.Attempt >> 24)
	attemptBytes[1] = byte(msg.Attempt >> 16)
	attemptBytes[2] = byte(msg.Attempt >> 8)
	attemptBytes[3] = byte(msg.Attempt)
	return transcriptHash32(
		AttestationContextTag,
		msg.SessionID[:],
		attemptBytes[:],
		setup.Pub.Bytes,
		msg.NodeID[:],
		msg.Commit[:],
	)
}

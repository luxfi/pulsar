// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// types.go — public data types used across the Pulsar reference
// implementation. The wire layout of every wire-bound type freezes at
// the encoding-freeze gate (DD-008); until then, on-the-wire bytes are
// stable per-test-vector but not stable across patch releases.

// NodeID is the canonical party identifier used in all Pulsar
// protocols. The 32-byte width matches the Lux validator-ID format and
// is wide enough to host an arbitrary external identifier (for example
// a Hanzo IAM subject hash). Index 0 is forbidden because the Shamir
// evaluation point at x=0 holds the master secret; any party with
// nominal index 0 is rejected by params validation.
type NodeID [32]byte

// Field identifies which Shamir base field a Pulsar instance uses.
// The choice is committee-size driven: GF(257) (FieldGF257) has the
// smallest wire footprint and is preferred for committees of at most
// 256 parties; GF(q) (FieldGFq) supports committees up to q − 1 =
// 8 380 416 and is mandatory for any committee with more than 256
// parties.
//
// The verifier (Class N1 manifesto) is unaffected by this choice:
// the output FIPS 204 signature is byte-identical in both cases.
type Field uint8

const (
	// FieldDefault asks the constructor to pick the narrowest field
	// that fits the committee size: GF(257) when n ≤ 256, else GF(q).
	FieldDefault Field = 0

	// FieldGF257 forces byte-wise Shamir over the prime 257. Wire
	// share size: 64 bytes. Cap: 256 parties.
	FieldGF257 Field = 1

	// FieldGFq forces byte-wise Shamir over the FIPS 204 prime
	// q = 8 380 417. Wire share size: 128 bytes. Cap: q − 1 parties.
	FieldGFq Field = 2
)

// String returns the canonical name for use in transcripts.
func (f Field) String() string {
	switch f {
	case FieldGF257:
		return "GF(257)"
	case FieldGFq:
		return "GF(q)"
	default:
		return "default"
	}
}

// resolveField picks the concrete field for a committee of size n.
// Callers that pass FieldDefault get the narrowest field that fits;
// callers that pin a field get that field even if it is wider than
// strictly necessary (useful for cross-implementation KAT replay).
func resolveField(want Field, n int) (Field, error) {
	switch want {
	case FieldGF257:
		if n > LargeCommitteeThreshold {
			return 0, ErrCommitteeTooLarge
		}
		return FieldGF257, nil
	case FieldGFq:
		if uint64(n) > uint64(MaxCommitteeQ) {
			return 0, ErrCommitteeTooLargeQ
		}
		return FieldGFq, nil
	default:
		if n <= LargeCommitteeThreshold {
			return FieldGF257, nil
		}
		if uint64(n) > uint64(MaxCommitteeQ) {
			return 0, ErrCommitteeTooLargeQ
		}
		return FieldGFq, nil
	}
}

// PublicKey wraps a FIPS 204 ML-DSA public key. The byte layout is
// exactly what cloudflare/circl's mldsa{44,65,87}.PublicKey.Pack emits
// — i.e. a single contiguous (ρ, t1) concatenation per FIPS 204 §5.1.
//
// The headline Class N1 claim of Pulsar is that a Pulsar
// signature against this PublicKey verifies under unmodified
// FIPS 204 ML-DSA.Verify (see Verify in verify.go).
type PublicKey struct {
	Mode  Mode
	Bytes []byte
}

// PrivateKey wraps a FIPS 204 ML-DSA private key. Only the trusted
// dealer in keygen.go holds the full PrivateKey; threshold deployments
// hold KeyShare values produced by DKG instead.
//
// PrivateKey carries the seed it was derived from so that determinism
// across re-load is preserved; the seed is the Shamir-shared quantity
// in the threshold model.
type PrivateKey struct {
	Mode  Mode
	Bytes []byte
	Seed  [32]byte
	Pub   *PublicKey
}

// KeyShare is one party's portion of a threshold-DKG output. Each
// share is a (NodeID, scalar-byte-vector) tuple where the scalar
// vector is the Shamir share of the underlying 32-byte ML-DSA seed
// at the party's Shamir evaluation point.
//
// The evaluation point is derived deterministically from the party's
// committee position (1-indexed). It must be non-zero and distinct
// across the committee.
//
// Share carries 32 × uint16 lanes (big-endian), giving the Shamir
// share value in GF(257) at every byte position of the underlying
// seed. The 64-byte wire layout is independent of the FIPS 204
// parameter set.
type KeyShare struct {
	NodeID    NodeID
	EvalPoint uint32   // Shamir x-coordinate in [1, 257); distinct per party
	Share     [64]byte // 32 × uint16 big-endian GF(257) share values
	Pub       *PublicKey
	Mode      Mode
}

// Signature is a FIPS 204 ML-DSA signature in its standard byte
// layout. The triple (c̃, z, h) is concatenated exactly per
// FIPS 204 §7.2 (Algorithm 28 sigEncode); no Pulsar envelope is
// applied. A relying party that can verify ML-DSA can verify a
// Pulsar Signature with no code change.
//
// Two signing paths today:
//
//   - Combine (threshold.go): reveal-and-aggregate. The aggregator
//     briefly reconstructs the master ML-DSA seed via Lagrange
//     interpolation over byte-wise GF(257) shares before calling
//     FIPS 204 sign. TEE-attestation is required on funds-bearing
//     networks; the aggregator process is in the TCB for the sign
//     call. LargeCombine (large_threshold.go) is the large-committee
//     variant.
//
//   - BCC/CEF (bcc_sign.go): the no-leak path. It never forms c·s2,
//     c·t0, r0, or full w — the hint is recovered from public data
//     via FindHint, so no aggregator ever holds the master key. The
//     threshold orchestration is gated fail-closed behind the ZK
//     verifiers in proof.go (ML-DSA-65/87 only).
//
// Combine is suitable for: M-Chain bridge custody (TEE in aggregator
// TCB), A-Chain confidential compute, single-operator deployments
// where the aggregator host is already trusted.
//
// Combine is NOT suitable for public adversarial deployments where
// the aggregator host is not in the TCB — use the BCC/CEF no-leak
// path there instead.
//
// Callers that wish to additionally TEE-bind the aggregator wire
// TEE attestation at THEIR layer using
// github.com/luxfi/ai/pkg/attestation — Pulsar itself stays TEE-
// agnostic so the same protocol works on the public chain (no
// TEE) and on a confidential-compute chain (with TEE), without
// bifurcating the wire format.
type Signature struct {
	Mode  Mode
	Bytes []byte
}

// DKGRound1Msg is the broadcast emitted by DKGSession.Round1.
//
// Protocol shape (CR-6 path A — Shamir+sum, no commit-and-open):
// the dealer broadcasts one KEM-wrapped envelope per recipient that
// carries the recipient's Shamir share of the dealer's contribution
// to the joint seed (BLOCKERS.md CR-6). There is no separate
// "commit-then-open" round: binding comes from Round-2 digest
// agreement over the ordered envelope set. The unkeyed v0.1
// `myCommit = cSHAKE(c_i || blind_i)` field was broadcast but never
// transmitted alongside an opening, so it bound to nothing the
// protocol verified; that field is gone and the protocol is
// documented as Shamir+sum-with-equivocation-digest.
//
// Per-recipient envelopes are KEM-wrapped under ML-KEM-768 against
// the recipient's long-term identity public key (BLOCKERS.md CR-8).
// A passive network observer who reads the broadcast learns only the
// ciphertext; no Shamir share leaks to anyone outside the committee.
type DKGRound1Msg struct {
	NodeID NodeID
	// Envelopes carries the per-recipient ML-KEM-768-wrapped envelope.
	// Recipient decrypts with their long-term identity secret key
	// (DKGSession.identityKey.KEMPriv) at Round 2.
	Envelopes map[NodeID]DKGShareEnvelope
}

// DKGShareEnvelope is the ML-KEM-768-wrapped envelope carrying one
// recipient's per-byte Shamir share of the dealer's secret seed
// contribution AND the full dealer contribution. Sealing is
// per-recipient with the recipient's long-term ML-KEM-768 identity
// public key (BLOCKERS.md CR-8).
//
// Wire layout:
//   - KEMCiphertext: ML-KEM-768 ciphertext encapsulating a per-pair
//     shared secret to the recipient (1088 bytes for ML-KEM-768).
//   - Sealed: stream-cipher-encrypted (Share || Contribution || Tag)
//     under HKDF-SHA3-256(shared_secret). The plaintext under Sealed
//     is 64 bytes Shamir share + 32 bytes dealer contribution + 32
//     bytes authentication tag = 128 bytes total.
//
// The dealer contribution c_i is duplicated into every envelope so
// that each committee member, after decrypting their own envelope,
// learns the full contribution from this dealer. Combining N such
// per-dealer contributions at Round 3 lets each party compute the
// joint master public key locally — without needing to read other
// recipients' envelopes (which they cannot under CR-8).
//
// This preserves the v0.1 reconstruction-aggregator trust model
// (every committee member learns the master secret) while closing
// CR-8 against passive network observers (envelopes are unreadable
// outside the committee). A v0.2 instantiation that gives true
// threshold secrecy lives behind the algebraic Lagrange-linearity
// path of pulsar.tex §4.2.
//
// The authentication tag binds the share+contribution to the
// (dealer, recipient, committee_root) tuple so a relayed envelope
// from a different dealer cannot replay as the recipient's share —
// even after KEM decap.
type DKGShareEnvelope struct {
	// KEMCiphertext is the ML-KEM-768 ciphertext (1088 bytes).
	KEMCiphertext []byte
	// Sealed is the AEAD-style sealed payload (128 bytes total).
	Sealed []byte
}

// DKGRound2Msg is the broadcast emitted by DKGSession.Round2: the
// per-party Pedersen-commit digest (the Round-1.5 cross-party
// equivocation gate of pulsar.tex §4.1).
type DKGRound2Msg struct {
	NodeID NodeID
	Digest [32]byte // cSHAKE256(commits) per PULSAR-DKG-COMMIT-V1
}

// DKGOutput is the result of a successful DKG.
//
// On success, GroupPubkey is the joint FIPS 204 ML-DSA public key,
// SecretShare is the calling party's Shamir share of the group seed,
// TranscriptHash is the 48-byte transcript digest that the chain can
// pin in its validator-set commitment, and AbortEvidence is nil.
//
// On failure, GroupPubkey and SecretShare are zero-valued and
// AbortEvidence carries the signed complaint identifying the
// misbehaving party.
type DKGOutput struct {
	GroupPubkey    *PublicKey
	SecretShare    *KeyShare
	TranscriptHash [48]byte
	AbortEvidence  *AbortEvidence
}

// AbortEvidence is a signed complaint emitted by an honest party when
// it detects deviation. The Pulsar protocol family commits to
// identifiable abort: every detected deviation produces verifiable
// evidence suitable for slashing. See pulsar.tex §4.5 for the
// taxonomy of complaints.
type AbortEvidence struct {
	Kind     ComplaintKind
	Accuser  NodeID
	Accused  NodeID
	Epoch    uint64
	Evidence []byte // kind-specific evidence blob
	// Signature is over (kind, accuser, accused, epoch, evidence) under
	// the accuser's long-term identity key (Ed25519 in production, opaque
	// here so consumers can wire their own identity layer).
	Signature []byte
}

// ComplaintKind is the taxonomy of identifiable-abort complaint types.
// Values are wire-stable (do not renumber).
type ComplaintKind uint8

const (
	// ComplaintEquivocation: a dealer broadcast distinct commit vectors
	// to distinct recipients. Evidence: two commits and the signed
	// broadcasts from the accused. See pulsar.tex §4.5.
	ComplaintEquivocation ComplaintKind = 1

	// ComplaintBadDelivery: the private (share, blind) delivered to the
	// accuser fails the Pedersen-identity check against the broadcast
	// commits. Evidence: the (share, blind, commits) tuple.
	ComplaintBadDelivery ComplaintKind = 2

	// ComplaintMACFailure: a MAC from the accused failed verification.
	// Evidence: the failing MAC and the recipient's key.
	ComplaintMACFailure ComplaintKind = 3

	// ComplaintRangeFailure: the accused's contribution would have
	// caused the aggregated signature to fail the FIPS 204 norm checks
	// by an amount inconsistent with honest behaviour. Evidence: the
	// per-party transcript line.
	ComplaintRangeFailure ComplaintKind = 4
)

// String returns the canonical name of the complaint kind.
func (k ComplaintKind) String() string {
	switch k {
	case ComplaintEquivocation:
		return "equivocation"
	case ComplaintBadDelivery:
		return "bad-delivery"
	case ComplaintMACFailure:
		return "mac-failure"
	case ComplaintRangeFailure:
		return "range-failure"
	default:
		return "unknown"
	}
}

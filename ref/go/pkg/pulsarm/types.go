// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

// types.go — public data types used across the Pulsar-M reference
// implementation. The wire layout of every wire-bound type freezes at
// the encoding-freeze gate (DD-008); until then, on-the-wire bytes are
// stable per-test-vector but not stable across patch releases.

// NodeID is the canonical party identifier used in all Pulsar-M
// protocols. The 32-byte width matches the Lux validator-ID format and
// is wide enough to host an arbitrary external identifier (for example
// a Hanzo IAM subject hash). Index 0 is forbidden because the Shamir
// evaluation point at x=0 holds the master secret; any party with
// nominal index 0 is rejected by params validation.
type NodeID [32]byte

// PublicKey wraps a FIPS 204 ML-DSA public key. The byte layout is
// exactly what cloudflare/circl's mldsa{44,65,87}.PublicKey.Pack emits
// — i.e. a single contiguous (ρ, t1) concatenation per FIPS 204 §5.1.
//
// The headline Class N1 claim of Pulsar-M is that a Pulsar-M
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
// FIPS 204 §7.2 (Algorithm 28 sigEncode); no Pulsar-M envelope is
// applied. A relying party that can verify ML-DSA can verify a
// Pulsar-M Signature with no code change.
type Signature struct {
	Mode  Mode
	Bytes []byte
}

// Round1Message is the broadcast emitted by ThresholdSigner.Round1.
//
// The protocol structure follows pulsar-m.tex §4.2 Algorithm "Sign
// Round 1": commit + MAC the per-party w̄_i. The full bar-w is sent
// alongside the digest at round 2 — the digest's role is binding under
// MAC, not concealment. See pulsar-m.tex §4.2 Remark "Round-1
// commit-digest binding".
type Round1Message struct {
	NodeID    NodeID
	SessionID [16]byte // sid uniqueness; see pulsar-m.tex §6.2
	Attempt   uint32   // rejection-restart counter κ
	Commit    [32]byte // D_i = cSHAKE(w̄_i || τ_1) per pulsar-m.tex §4.2
	MACs      map[NodeID][32]byte // KMAC256(K_{i,j}, D_i || τ_1)
}

// Round2Message is the broadcast emitted by ThresholdSigner.Round2.
//
// Carries the party's plaintext mask contribution (so peers can
// re-derive D_i and compare against the Round-1 commit), the per-party
// response contribution, and the per-party blinding-share term used by
// the aggregator to recompute c·s_2.
type Round2Message struct {
	NodeID    NodeID
	SessionID [16]byte
	Attempt   uint32

	// W1 is the per-party w̄_i in HighBits form. The aggregator sums
	// the per-party W1 values to recover the aggregate w̄ used to
	// compute the FIPS 204 challenge c̃.
	W1 []byte

	// PartialSig is this party's contribution toward the FIPS 204
	// signature. In the v0.1 reconstruction-aggregator instantiation
	// (see docs/known-limitations.md), this is the Shamir share of
	// the seed encrypted under the round transcript hash; the
	// aggregator collects t shares, reconstructs the seed, and emits
	// a single FIPS 204 signature. The Lagrange-linearity path of
	// pulsar-m.tex §4.2 Algorithm "Sign Round 2" produces (z_i, r_i)
	// here directly; it is on the v0.2 critical path.
	PartialSig []byte
}

// DKGRound1Msg is the broadcast emitted by DKGSession.Round1: the
// per-party Pedersen commits to the polynomial coefficients of f_i(X),
// along with the encrypted private envelope carrying f_i(j) and
// g_i(j) for each recipient j.
type DKGRound1Msg struct {
	NodeID  NodeID
	Commits [][]byte // C_{i,k} for k = 0..t-1; each is a serialized R_q^k vector
	// Envelopes carries the per-recipient sealed share (f_i(j), g_i(j)).
	// Sealed under the recipient's long-term DH key — in v0.1 we expose
	// the plain payload; v0.2 wraps with a noise-or-equivalent KEM.
	Envelopes map[NodeID]DKGShareEnvelope
}

// DKGShareEnvelope is the (share, blinding) pair sent from a Round-1
// dealer to a Round-1 recipient. v0.1 transmits these in the clear
// under the DKG transcript hash; v0.2 will seal each envelope under
// the recipient's identity-key Curve25519 DH (a noise-style framing).
//
// Share is 32 × uint16 big-endian GF(257) lanes carrying the
// per-byte Shamir share of the dealer's secret contribution at the
// recipient's evaluation point. Blind is the matching Pedersen
// blinding share at the same point (used for v0.2 binding; in v0.1
// the binding is by RO-collision of the cSHAKE256 commit).
type DKGShareEnvelope struct {
	Share [64]byte // f_i(j) — Shamir share of party i's secret seed contribution at j
	Blind [64]byte // g_i(j) — Pedersen blinding share at j
}

// DKGRound2Msg is the broadcast emitted by DKGSession.Round2: the
// per-party Pedersen-commit digest (the Round-1.5 cross-party
// equivocation gate of pulsar-m.tex §4.1).
type DKGRound2Msg struct {
	NodeID NodeID
	Digest [32]byte // cSHAKE256(commits) per PULSAR-M-DKG-COMMIT-V1
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
// it detects deviation. The Pulsar-M protocol family commits to
// identifiable abort: every detected deviation produces verifiable
// evidence suitable for slashing. See pulsar-m.tex §4.5 for the
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
	// broadcasts from the accused. See pulsar-m.tex §4.5.
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

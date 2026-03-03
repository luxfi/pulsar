// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dkg2

// Complaint workflow and disqualification logic for the Pedersen DKG.
//
// The Pedersen DKG has identifiable abort: any malformed contribution
// (Round 1 commit / Round 1.5 digest / Round 2 share-blind pair) names
// the offending sender. Each detection produces a signed Complaint that
// any honest validator can independently re-check without trusting the
// complainer.
//
// Failure modes (mirrors reshare.ComplaintReason):
//
//  (a) ComplaintBadDelivery — sender i shipped (share_{i→j}, blind_{i→j})
//      that does not satisfy A·NTT(share) + B·NTT(blind) =
//      Σ_k (j+1)^k · C_{i,k}. Evidence: the (share, blind, commits)
//      triple. Re-check via VerifyShareAgainstCommits.
//
//  (b) ComplaintEquivocation — sender i broadcast different commit
//      vectors to different recipients. Detected via Round 1.5 digest
//      cross-check: when recipient j observes that sender i delivered
//      digest h_i^{(j)} but other recipients k report h_i^{(k)} ≠
//      h_i^{(j)}, j emits this complaint. Evidence: two signed digest
//      broadcasts under sender i's wire identity that disagree.
//
//  (c) ComplaintMissing — sender i failed to deliver Round 1 by the
//      cohort deadline. Evidence is the absence; a separate liveness
//      round timestamps the deadline.
//
//  (d) ComplaintMalformedCommit — sender i's commit vector has the
//      wrong length, the wrong dimension, or fails Round 2 sanity
//      checks. Evidence: the malformed commit vector. Re-check via
//      VerifyShareAgainstCommits returning ErrMalformedCommit.
//
// Disqualification rule (deterministic, identical on every honest party):
//
//   - Complaints from the same complainer about the same sender are
//     deduplicated by (sender, complainer) tuple.
//   - A sender i is disqualified iff at least DisqualificationThreshold
//     distinct complainers signed valid complaints against i. The
//     default threshold is t-1 (so at most t-1 colluding adversaries
//     cannot disqualify an honest sender).
//   - After the Round 2 deadline every honest party computes the same
//     set Q' = Q \ disqualified. If |Q'| < t the DKG aborts and the
//     activation cert binds the abort transcript so the chain stays at
//     the previous epoch.
//
// Slashing evidence: every signed Complaint, plus the equivocation pair
// (commits_a, commits_b) where applicable, is admissible at the Quasar
// layer. Wire format mirrors reshare/quasar_integration.go to keep one
// adjudication path for both protocols.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/pulsar/hash"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// ComplaintReason enumerates the failure modes that justify a complaint.
type ComplaintReason uint8

const (
	// ComplaintBadDelivery — share_{i→j} fails the Pedersen identity.
	ComplaintBadDelivery ComplaintReason = 1

	// ComplaintEquivocation — sender i broadcast disagreeing commit
	// digests to different recipients.
	ComplaintEquivocation ComplaintReason = 2

	// ComplaintMissing — sender i failed to deliver share_{i→j} by
	// the round-1 deadline.
	ComplaintMissing ComplaintReason = 3

	// ComplaintMalformedCommit — sender i's commit vector has wrong
	// length / wrong dimension / nil entries.
	ComplaintMalformedCommit ComplaintReason = 4
)

// String returns a human-readable name for the reason.
func (r ComplaintReason) String() string {
	switch r {
	case ComplaintBadDelivery:
		return "bad-delivery"
	case ComplaintEquivocation:
		return "equivocation"
	case ComplaintMissing:
		return "missing"
	case ComplaintMalformedCommit:
		return "malformed-commit"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

// Complaint is a signed assertion that party SenderID misbehaved during
// the Pedersen DKG protocol. The structure mirrors reshare.Complaint to
// keep one adjudication path for both protocols.
//
// SenderID is the misbehaving party (the dealer in dkg2 parlance).
// ComplainerID is the recipient that observed the failure and signs.
//
// TranscriptHash binds the complaint to a specific dkg2 invocation
// (n, t, sessionID, suiteID). A complaint with a stale transcript hash
// is rejected.
//
// Evidence carries the protocol-specific data needed to re-check the
// claim without trusting the complainer:
//
//   - ComplaintBadDelivery: serialize(share, blind, commits) for the
//     (sender, recipient) pair. Any honest party can re-run
//     VerifyShareAgainstCommits and confirm the mismatch.
//   - ComplaintEquivocation: two signed commit-digest broadcasts from
//     SenderID with disagreeing digests.
//   - ComplaintMissing: empty (the absence is the evidence; a separate
//     liveness round timestamps the deadline).
//   - ComplaintMalformedCommit: serialize(commits) showing the
//     malformed structure.
type Complaint struct {
	TranscriptHash [32]byte
	SenderID       int    // 0-indexed party ID of the misbehaving dealer
	ComplainerID   int    // 0-indexed party ID of the complainer
	Reason         ComplaintReason
	Evidence       []byte // canonical-serialized evidence (see above)
	Signature      []byte // Ed25519 signature over Bytes() under ComplainerID's wire key
	ComplainerKey  ed25519.PublicKey
}

// Bytes returns the canonical signed payload for a complaint. The
// Signature field is excluded (it is computed OVER these bytes).
//
// Format:
//
//	"pulsar.dkg2.complaint.v1" || transcript || sender_id_be32 ||
//	complainer_id_be32 || reason_u8 || evidence_len_be32 || evidence
func (c *Complaint) Bytes() []byte {
	var buf bytes.Buffer
	buf.WriteString("pulsar.dkg2.complaint.v1")
	buf.Write(c.TranscriptHash[:])
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(c.SenderID))
	buf.Write(b4[:])
	binary.BigEndian.PutUint32(b4[:], uint32(c.ComplainerID))
	buf.Write(b4[:])
	buf.WriteByte(byte(c.Reason))
	binary.BigEndian.PutUint32(b4[:], uint32(len(c.Evidence)))
	buf.Write(b4[:])
	buf.Write(c.Evidence)
	return buf.Bytes()
}

// Sign produces a complaint signature using the provided Ed25519 private
// key. Callers MUST use the wire-identity key associated with
// ComplainerID — using a different key produces a complaint that other
// validators reject.
func (c *Complaint) Sign(priv ed25519.PrivateKey) {
	c.Signature = ed25519.Sign(priv, c.Bytes())
	c.ComplainerKey = priv.Public().(ed25519.PublicKey)
}

// Verify checks the Ed25519 signature against ComplainerKey. Returns nil
// iff the signature is valid. Note: this does NOT verify that the
// reason actually holds (e.g. for ComplaintBadDelivery the evidence must
// be re-checked separately) — only that the complaint was signed by the
// claimed complainer.
func (c *Complaint) Verify() error {
	if c == nil || len(c.Signature) == 0 || len(c.ComplainerKey) == 0 {
		return errors.New("dkg2: complaint missing signature or key")
	}
	if !ed25519.Verify(c.ComplainerKey, c.Bytes(), c.Signature) {
		return errors.New("dkg2: complaint signature invalid")
	}
	return nil
}

// ComplaintHash returns a 32-byte digest over the complaint's canonical
// bytes (signature included), bound under the active HashSuite. Used to
// commit to the SET of complaints in the Round 2 transcript and the
// activation message.
//
// Pass nil for the production default (Pulsar-SHA3).
func ComplaintHash(suite hash.HashSuite, c *Complaint) [32]byte {
	s := hash.Resolve(suite)
	return s.TranscriptHash([]byte("pulsar.dkg2.complaint-hash.v1"), c.Bytes(), c.Signature)
}

// DisqualificationThreshold returns the minimum number of distinct,
// validly-signed complaints needed to disqualify a sender.
//
// Default: t-1. Rationale: any single Byzantine validator can emit one
// false complaint to slow the protocol, but to disqualify an honest
// sender the adversary needs t-1 collaborators — which exceeds the
// static-corruption threshold of t-1 by exactly one.
func DisqualificationThreshold(threshold int) int {
	if threshold <= 1 {
		return 1
	}
	return threshold - 1
}

// ComputeDisqualifiedSet takes a slice of validated complaints and
// returns the set of sender IDs that meet the disqualification
// threshold. Every honest party that processes the same complaint set
// returns the same disqualified set.
//
// "Validated" means: the complaint's signature has been verified, the
// complaint's transcript hash matches the local view, and (for
// ComplaintBadDelivery / ComplaintEquivocation / ComplaintMalformedCommit)
// the evidence has been re-checked. This function does NOT re-verify
// the underlying claim — the caller is responsible (see VerifyComplaint).
//
// Complaints are deduplicated by (sender, complainer) tuple; if the same
// complainer signs two complaints against the same sender (e.g. for
// different reasons), only one counts toward the threshold.
func ComputeDisqualifiedSet(complaints []*Complaint, threshold int) map[int]struct{} {
	cap := DisqualificationThreshold(threshold)
	seen := make(map[[2]int]bool)
	count := make(map[int]int)
	for _, c := range complaints {
		key := [2]int{c.SenderID, c.ComplainerID}
		if seen[key] {
			continue
		}
		seen[key] = true
		count[c.SenderID]++
	}
	out := make(map[int]struct{})
	for sender, n := range count {
		if n >= cap {
			out[sender] = struct{}{}
		}
	}
	return out
}

// FilterQualifiedQuorum returns the survivor set of party IDs after
// removing disqualified senders. Returns ErrInsufficientQuorum if too
// many parties were disqualified for the protocol to recover.
//
// Sorted ascending for determinism — every honest party that processes
// the same disqualified set computes the same surviving slice.
func FilterQualifiedQuorum(originalQuorum []int, disqualified map[int]struct{}, threshold int) ([]int, error) {
	out := make([]int, 0, len(originalQuorum))
	for _, id := range originalQuorum {
		if _, dq := disqualified[id]; dq {
			continue
		}
		out = append(out, id)
	}
	if len(out) < threshold {
		return nil, fmt.Errorf("%w: %d survivors < threshold %d",
			ErrInsufficientQuorum, len(out), threshold)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out, nil
}

// ErrInsufficientQuorum signals that too many parties were disqualified
// for the DKG to recover. The activation cert binds the abort transcript
// and the chain stays at the previous epoch.
var ErrInsufficientQuorum = errors.New("dkg2: qualified quorum below threshold after disqualification")

// NewBadDeliveryComplaint constructs an unsigned ComplaintBadDelivery
// against sender for the (share, blind, commits) triple that
// VerifyShareAgainstCommits rejected. The caller signs with their wire
// identity key via Complaint.Sign before broadcasting.
//
// transcriptHash binds the complaint to the active dkg2 invocation;
// pass the result of TranscriptHash on the canonical session inputs.
func NewBadDeliveryComplaint(
	transcriptHash [32]byte,
	senderID, complainerID int,
	share, blind structs.Vector[ring.Poly],
	commits []structs.Vector[ring.Poly],
) (*Complaint, error) {
	evidence, err := serializeBadDeliveryEvidence(share, blind, commits)
	if err != nil {
		return nil, err
	}
	return &Complaint{
		TranscriptHash: transcriptHash,
		SenderID:       senderID,
		ComplainerID:   complainerID,
		Reason:         ComplaintBadDelivery,
		Evidence:       evidence,
	}, nil
}

// NewEquivocationComplaint constructs an unsigned ComplaintEquivocation
// against sender. evidenceA and evidenceB are two distinct, independently
// signed commit-digest broadcasts under sender's wire identity that
// disagree (Round 1.5 cross-party check).
func NewEquivocationComplaint(
	transcriptHash [32]byte,
	senderID, complainerID int,
	evidenceA, evidenceB []byte,
) *Complaint {
	var buf bytes.Buffer
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(len(evidenceA)))
	buf.Write(b4[:])
	buf.Write(evidenceA)
	binary.BigEndian.PutUint32(b4[:], uint32(len(evidenceB)))
	buf.Write(b4[:])
	buf.Write(evidenceB)
	return &Complaint{
		TranscriptHash: transcriptHash,
		SenderID:       senderID,
		ComplainerID:   complainerID,
		Reason:         ComplaintEquivocation,
		Evidence:       buf.Bytes(),
	}
}

// NewMissingComplaint constructs an unsigned ComplaintMissing against
// sender. Evidence is empty by design — the absence of a Round 1
// delivery before the cohort deadline is the evidence; a separate
// liveness round timestamps the deadline.
func NewMissingComplaint(
	transcriptHash [32]byte,
	senderID, complainerID int,
) *Complaint {
	return &Complaint{
		TranscriptHash: transcriptHash,
		SenderID:       senderID,
		ComplainerID:   complainerID,
		Reason:         ComplaintMissing,
		Evidence:       nil,
	}
}

// NewMalformedCommitComplaint constructs an unsigned
// ComplaintMalformedCommit against sender carrying the malformed commit
// vector as evidence.
func NewMalformedCommitComplaint(
	transcriptHash [32]byte,
	senderID, complainerID int,
	commits []structs.Vector[ring.Poly],
) (*Complaint, error) {
	evidence, err := serializeCommitsEvidence(commits)
	if err != nil {
		return nil, err
	}
	return &Complaint{
		TranscriptHash: transcriptHash,
		SenderID:       senderID,
		ComplainerID:   complainerID,
		Reason:         ComplaintMalformedCommit,
		Evidence:       evidence,
	}, nil
}

// serializeBadDeliveryEvidence packs (share, blind, commits) into the
// canonical evidence wire format consumed by VerifyComplaint.
//
// Format:
//
//	share_bytes_len_be32 || share_bytes ||
//	blind_bytes_len_be32 || blind_bytes ||
//	t_be32 || (commits[k]_bytes_len_be32 || commits[k]_bytes) × t
func serializeBadDeliveryEvidence(
	share, blind structs.Vector[ring.Poly],
	commits []structs.Vector[ring.Poly],
) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeVector(&buf, share); err != nil {
		return nil, err
	}
	if err := writeVector(&buf, blind); err != nil {
		return nil, err
	}
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(len(commits)))
	buf.Write(b4[:])
	for _, v := range commits {
		if err := writeVector(&buf, v); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// serializeCommitsEvidence packs a commits vector into evidence bytes
// for ComplaintMalformedCommit. Format:
//
//	t_be32 || (commits[k]_bytes_len_be32 || commits[k]_bytes) × t
func serializeCommitsEvidence(commits []structs.Vector[ring.Poly]) ([]byte, error) {
	var buf bytes.Buffer
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(len(commits)))
	buf.Write(b4[:])
	for _, v := range commits {
		if err := writeVector(&buf, v); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// writeVector emits a length-prefixed serialization of one
// structs.Vector[ring.Poly] using the lattigo WriteTo wire format.
func writeVector(buf *bytes.Buffer, v structs.Vector[ring.Poly]) error {
	var inner bytes.Buffer
	if _, err := v.WriteTo(&inner); err != nil {
		return fmt.Errorf("%w: %v", ErrSerialization, err)
	}
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(inner.Len()))
	buf.Write(b4[:])
	buf.Write(inner.Bytes())
	return nil
}

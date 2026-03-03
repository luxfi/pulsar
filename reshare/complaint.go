// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

// Complaint workflow and disqualification logic for VSR.
//
// During Round 1, every old (or refresh-participating) party i broadcasts
// its commitment vector C_i and privately delivers (share_{i→j},
// blind_{i→j}) to every recipient j. In Round 1.5, every recipient j
// independently runs VerifyShareAgainstCommits — if any check fails, j
// emits a signed Complaint naming sender i and the failing slot.
//
// The complaint workflow exists for three failure modes:
//
//  (a) Bad delivery — sender i ships a (share, blind) pair that does
//      not satisfy the commitment equation. Either i mis-computed,
//      or i deliberately ships a poisoned share (mobile-adversary
//      strategy: coerce a recipient to recompute the secret with
//      offset to leak it later).
//
//  (b) Cross-recipient equivocation — sender i ships commits C_a to
//      recipient a and a different C_b to recipient b. Detected via
//      the CommitDigest broadcast in Round 1.5: if a's digest from i
//      ≠ b's digest from i (after cross-broadcast), i has equivocated.
//
//  (c) Silence — sender i fails to deliver to recipient j by the
//      Round 1 deadline. Detected by absence in j's view; j broadcasts
//      a "missing share" complaint.
//
// Disqualification rule (deterministic, identical on every honest party):
//
//  - Complaints from the same complainer about the same sender are
//    deduplicated by (sender, complainer) tuple.
//  - A sender i is DISQUALIFIED iff at least DisqualificationThreshold
//    distinct complainers signed valid complaints against i. The
//    default threshold is t_old - 1 (so that an honest majority of
//    the qualified set always achieves disqualification of a
//    sufficiently misbehaving sender).
//  - After the Round 2 deadline, every honest party computes the
//    SAME set Q' = Q \ {disqualified senders} and uses it as the new
//    quorum. Lagrange coefficients λ^{Q'}_i are recomputed against
//    Q', not Q.
//  - If |Q'| < t_old, the resharing FAILS and the chain stays at the
//    old epoch. The activation circuit-breaker (activation.go)
//    enforces this.
//
// Slashing evidence: every signed Complaint against a misbehaving
// sender, plus the equivocation pair (commits_a, commits_b) where
// applicable, is admissible as slashing evidence at the Quasar layer
// (see quasar_integration.go for the wire format).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/zeebo/blake3"
)

// ComplaintReason enumerates the failure modes that justify a complaint.
type ComplaintReason uint8

const (
	// ComplaintBadDelivery — share_{i→j} fails the commitment check.
	ComplaintBadDelivery ComplaintReason = 1

	// ComplaintEquivocation — sender i shipped different commits to
	// different recipients (detected via Round 1.5 digest cross-check).
	ComplaintEquivocation ComplaintReason = 2

	// ComplaintMissing — sender i failed to deliver share_{i→j} by
	// the round-1 deadline.
	ComplaintMissing ComplaintReason = 3

	// ComplaintMalformedCommit — sender i's commit vector has the
	// wrong length, has nil entries, or fails internal sanity checks.
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

// Complaint is a signed assertion that sender PartyID misbehaved
// during the resharing protocol.
//
// SenderID is the misbehaving old-committee party (the dealer).
// ComplainerID is the new-committee party that observed the failure
// and signs the complaint.
//
// TranscriptHash binds the complaint to a specific reshare invocation
// (see transcript.go). A complaint with a stale or wrong transcript
// hash is rejected.
//
// Evidence carries the protocol-specific data the chain needs to
// adjudicate the complaint:
//
//   - For ComplaintBadDelivery: the (share, blind) pair received by
//     ComplainerID, plus the SenderID's commit vector. Any honest
//     party can re-run VerifyShareAgainstCommits and confirm the
//     mismatch.
//   - For ComplaintEquivocation: two commit-digest signed broadcasts
//     from SenderID with different digests. Both signed under
//     SenderID's wire identity key; the contradiction is self-
//     evident.
//   - For ComplaintMissing: empty (the absence is the evidence).
//     A separate liveness round provides timing context.
//   - For ComplaintMalformedCommit: the malformed commit vector.
type Complaint struct {
	TranscriptHash [32]byte
	SenderID       int             // 1-indexed party ID of the misbehaving dealer
	ComplainerID   int             // 1-indexed party ID of the complainer
	Reason         ComplaintReason
	Evidence       []byte          // canonical-serialized evidence (see above)
	Signature      []byte          // Ed25519 signature over Bytes() under ComplainerID's wire key
	ComplainerKey  ed25519.PublicKey // public key for verification
}

// Bytes returns the canonical signed payload for a complaint. The
// Signature field is excluded (it is computed OVER these bytes).
//
// Format:
//
//	"pulsar.reshare.complaint.v1" || transcript || sender_id_be32 ||
//	complainer_id_be32 || reason_u8 || evidence_len_be32 || evidence
func (c *Complaint) Bytes() []byte {
	var buf bytes.Buffer
	buf.WriteString("pulsar.reshare.complaint.v1")
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

// Sign produces a complaint signature using the provided Ed25519
// private key. Callers MUST use the wire-identity key associated with
// ComplainerID — using a different key produces a complaint that
// other validators reject.
func (c *Complaint) Sign(priv ed25519.PrivateKey) {
	c.Signature = ed25519.Sign(priv, c.Bytes())
	c.ComplainerKey = priv.Public().(ed25519.PublicKey)
}

// Verify checks the Ed25519 signature against ComplainerKey. Returns
// nil iff the signature is valid. Note: this does NOT verify that the
// complaint's reason actually holds (e.g. for ComplaintBadDelivery
// the evidence must be re-checked separately) — only that the
// complaint was signed by the claimed complainer.
func (c *Complaint) Verify() error {
	if c == nil || len(c.Signature) == 0 || len(c.ComplainerKey) == 0 {
		return errors.New("reshare: complaint missing signature or key")
	}
	if !ed25519.Verify(c.ComplainerKey, c.Bytes(), c.Signature) {
		return errors.New("reshare: complaint signature invalid")
	}
	return nil
}

// ComplaintHash returns BLAKE3 over the complaint's canonical bytes
// (signature included). Used by the resharing transcript to commit
// to the SET of complaints and the activation message to bind to the
// final disqualification result.
func ComplaintHash(c *Complaint) [32]byte {
	h := blake3.New()
	_, _ = h.Write([]byte("pulsar.reshare.complaint-hash.v1"))
	_, _ = h.Write(c.Bytes())
	_, _ = h.Write(c.Signature)
	var out [32]byte
	copy(out[:], h.Sum(nil)[:32])
	return out
}

// DisqualificationThreshold returns the minimum number of distinct,
// validly-signed complaints needed to disqualify a sender.
//
// Default: t_old - 1. Rationale: any single Byzantine validator can
// emit one false complaint to slow the protocol, but to disqualify
// an honest sender the adversary needs t_old - 1 collaborators —
// exceeding the static-corruption threshold of t_old - 1 by exactly
// one. So no honest sender can be disqualified by a maximally
// adversarial complainer set.
//
// For Refresh, the threshold is t - 1 (same logic: t parties form
// the quorum; t-1 is the corruption bound).
func DisqualificationThreshold(thresholdOld int) int {
	if thresholdOld <= 1 {
		return 1
	}
	return thresholdOld - 1
}

// ComputeDisqualifiedSet takes a slice of validated complaints and
// returns the set of sender IDs that meet the disqualification
// threshold. Every honest party that processes the same complaint set
// returns the same disqualified set — this determinism is essential
// for the new committee to compute a consistent quorum Q'.
//
// "Validated" means: the complaint's signature has been verified, the
// complaint's transcript hash matches the local view, and (for
// ComplaintBadDelivery / ComplaintEquivocation) the evidence has been
// re-checked and confirms the misbehaviour. This function does NOT
// re-verify the underlying claim — that is the caller's job (see
// VerifyComplaint helpers in the integration layer).
//
// Complaints are deduplicated by (sender, complainer) tuple; if the
// same complainer signs two complaints against the same sender (e.g.
// for different reasons), only one counts toward the threshold.
func ComputeDisqualifiedSet(
	complaints []*Complaint,
	thresholdOld int,
) map[int]struct{} {
	threshold := DisqualificationThreshold(thresholdOld)
	// (sender, complainer) → seen
	seen := make(map[[2]int]bool)
	// sender → number of distinct complainers
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
		if n >= threshold {
			out[sender] = struct{}{}
		}
	}
	return out
}

// FilterQualifiedQuorum returns the survivor set Q' = Q \ disqualified.
// Returns ErrInsufficientQuorum if |Q'| < tOld. Otherwise returns
// the (deterministic) sorted slice of surviving party IDs.
//
// This is the exact set the new committee uses to compute Lagrange
// coefficients for the re-shared shares — an inconsistency here
// produces shares that interpolate to a DIFFERENT secret on different
// new validators, which immediately fails the activation cert.
func FilterQualifiedQuorum(
	originalQuorum []int,
	disqualified map[int]struct{},
	tOld int,
) ([]int, error) {
	out := make([]int, 0, len(originalQuorum))
	for _, id := range originalQuorum {
		if _, dq := disqualified[id]; dq {
			continue
		}
		out = append(out, id)
	}
	if len(out) < tOld {
		return nil, fmt.Errorf("%w: %d survivors < threshold %d",
			ErrInsufficientQuorum, len(out), tOld)
	}
	// Sort ascending for determinism.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out, nil
}

// ErrInsufficientQuorum signals that too many resharing parties were
// disqualified for the protocol to recover. The chain MUST stay at
// the old epoch when this error is returned (see activation.go).
var ErrInsufficientQuorum = errors.New("reshare: qualified quorum below t_old after disqualification")

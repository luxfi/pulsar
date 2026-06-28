// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// blame.go — SIGN-path identifiable abort: attribute a deviating partial to
// its PartyID instead of silently dropping it (RED MEDIUM, identifiable-abort).
//
// AggregateBCC previously `continue`d past a malformed, duplicate, or
// invalid-proof partial — the round could die with no record of WHO caused it
// (unattributable DoS), and a duplicate PartyID could even satisfy the
// threshold with fewer than t DISTINCT signers (CanonicalSignerSet does not
// dedupe). The blame layer below makes every detected sign-time deviation
// produce an attributed PartialBlame; the signer (which holds the quorum →
// NodeID mapping) elevates it to a signed-complaint AbortEvidence for the
// slashing layer.
//
// SCOPE. This attributes deviations the verifier can DETECT today: malformed
// encoding, duplicate / out-of-range PartyID, session/nonce mismatch, and a
// FAILED sigma proof. It does NOT yet attribute a VALID-sigma WRONG-z partial —
// that requires the BDLOP dealt-share binding (share_commit.go, Residual A);
// until then a valid-sigma wrong-z is a liveness fault (never a forgery/leak),
// flagged by ErrIdentifiableAbortResidual.

import "encoding/binary"

// BlameReason enumerates the detectable sign-time deviations.
type BlameReason uint8

const (
	// BlameMalformed: the partial's ZShare/Proof did not parse for the mode.
	BlameMalformed BlameReason = iota + 1
	// BlameDuplicatePartyID: a second partial carrying an already-seen PartyID.
	BlameDuplicatePartyID
	// BlameUnknownParty: PartyID outside the signing quorum's eval-point range.
	BlameUnknownParty
	// BlameSessionMismatch: SessionID/NonceID did not match the round.
	BlameSessionMismatch
	// BlameProofInvalid: the partial-z sigma proof failed verification.
	BlameProofInvalid
)

// String returns the canonical reason name.
func (r BlameReason) String() string {
	switch r {
	case BlameMalformed:
		return "malformed-partial"
	case BlameDuplicatePartyID:
		return "duplicate-party-id"
	case BlameUnknownParty:
		return "unknown-party"
	case BlameSessionMismatch:
		return "session-mismatch"
	case BlameProofInvalid:
		return "proof-invalid"
	default:
		return "unknown"
	}
}

// PartialBlame attributes one detected deviation to a PartyID. AggregateBCC's
// no-NodeID-context layer reports these; the signer maps PartyID → NodeID to
// build a signed AbortEvidence.
type PartialBlame struct {
	PartyID uint32
	Reason  BlameReason
	// SessionID / NonceID identify the round the deviation occurred in.
	SessionID [32]byte
	NonceID   [32]byte
}

// badPartialFieldCount: (partyid_reason, sessionid, nonceid) — 3 TLV fields.
const badPartialFieldCount = 3

// badPartialField0MinLen: 4-byte PartyID (BE) + 1-byte reason.
const badPartialField0MinLen = 5

// marshalBadPartialEvidence encodes a PartialBlame into the AbortEvidence TLV
// blob: field0 = PartyID(BE u32)‖reason(u8); field1 = sessionID; field2 = nonceID.
func marshalBadPartialEvidence(b PartialBlame) []byte {
	field0 := make([]byte, 5)
	binary.BigEndian.PutUint32(field0[:4], b.PartyID)
	field0[4] = byte(b.Reason)
	out := make([]byte, 0, 4+5+4+32+4+32)
	appendField := func(f []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		out = append(out, l[:]...)
		out = append(out, f...)
	}
	appendField(field0)
	appendField(b.SessionID[:])
	appendField(b.NonceID[:])
	return out
}

// validateBadPartialEvidence: 3 fields, field0 ≥ 5 bytes, sessionID/nonceID 32.
func validateBadPartialEvidence(blob []byte) error {
	fields, err := parseEvidenceFields(blob)
	if err != nil {
		return err
	}
	if len(fields) != badPartialFieldCount {
		return ErrEvidenceFieldCount
	}
	if len(fields[0]) < badPartialField0MinLen {
		return ErrEvidenceFieldLen
	}
	if len(fields[1]) < 32 || len(fields[2]) < 32 {
		return ErrEvidenceFieldLen
	}
	return nil
}

// BadPartialEvidence builds a signed-complaint-ready AbortEvidence for a sign
// deviation. accuser is the aggregator/observer; accused is the deviating
// party's NodeID. The Signature field is left empty for the caller's identity
// layer to fill (TranscriptForComplaint gives the to-be-signed bytes).
func BadPartialEvidence(accuser, accused NodeID, epoch uint64, b PartialBlame) AbortEvidence {
	return AbortEvidence{
		Kind:     ComplaintBadPartial,
		Accuser:  accuser,
		Accused:  accused,
		Epoch:    epoch,
		Evidence: marshalBadPartialEvidence(b),
	}
}

// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// abort.go — identifiable-abort complaints.
//
// Every detected deviation in DKG, Sign, or Reshare produces a signed
// AbortEvidence. The system-model slashing layer consumes these
// complaints; a quorum of distinct accusers against the same accused
// is a disqualification event.
//
// pulsar.tex §4.5 enumerates the complaint taxonomy. This file
// gives the canonical wire format and the verification routines that
// any third party (chain validator, audit observer, slashing module)
// uses to check a complaint is well-formed.

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Errors returned by abort-evidence verification.
var (
	ErrInvalidComplaint   = errors.New("pulsar: complaint structure invalid")
	ErrComplaintSelfAcc   = errors.New("pulsar: complaint accuser equals accused")
	ErrComplaintNoSig     = errors.New("pulsar: complaint missing accuser signature")
	ErrComplaintKind      = errors.New("pulsar: complaint kind out of range")
	ErrComplaintNoEv      = errors.New("pulsar: complaint missing evidence blob")
	ErrEvidenceFieldCount = errors.New("pulsar: evidence field count mismatch for kind")
	ErrEvidenceFieldLen   = errors.New("pulsar: evidence field length below FIPS 204 minimum")
	ErrEvidenceTrailing   = errors.New("pulsar: trailing bytes after last evidence field")
	ErrEvidenceTruncated  = errors.New("pulsar: evidence field truncated")
	ErrEvidenceDuplicate  = errors.New("pulsar: duplicate field where uniqueness required")
)

// Per-kind evidence-field counts (matches types.go:235-254 schema).
//
//	Equivocation = (commit1, commit2, broadcast_sig1, broadcast_sig2)  — 4 fields
//	BadDelivery  = (share, blind, commits)                             — 3 fields
//	MACFailure   = (mac, key)                                          — 2 fields
//	RangeFailure = (transcript_line)                                   — 1 field
const (
	equivocationFieldCount = 4
	badDeliveryFieldCount  = 3
	macFailureFieldCount   = 2
	rangeFailureFieldCount = 1
)

// Per-field minimum byte lengths. Set conservatively against the
// FIPS 204 ML-DSA-65 + Pulsar Pedersen primitives.
//
//	commit  : 32 bytes (SHAKE-256-truncated Pedersen commit)
//	sig     : 64 bytes  (FIPS 204 §3.7 minimum across schemes —
//	                     Ed25519 = 64; opaque to this package)
//	share   : 32 bytes  (per-party ML-DSA share digest)
//	blind   : 32 bytes  (Pedersen blinding seed)
//	mac     : 32 bytes  (SHAKE-256-truncated MAC)
//	key     : 32 bytes  (recipient identity / MAC key)
//	t-line  : 1 byte    (transcript line is variable; require at
//	                     least one byte so empty doesn't pass)
const (
	commitMinLen     = 32
	sigMinLen        = 64
	shareMinLen      = 32
	blindMinLen      = 32
	commitListMinLen = 32 // at least one commit
	macMinLen        = 32
	keyMinLen        = 32
	transcriptMinLen = 1
)

// parseEvidenceFields parses an evidence blob in TLV form:
//
//	field = 4 bytes (BE u32 length) || N bytes payload
//	blob  = field || field || ... || field
//
// Returns the parsed payloads (without their length prefixes). A
// trailing-bytes overflow or truncated length-prefix yields a
// distinct error so callers can distinguish framing errors from
// length-bound errors.
func parseEvidenceFields(blob []byte) ([][]byte, error) {
	fields := make([][]byte, 0, 4)
	off := 0
	for off < len(blob) {
		if len(blob)-off < 4 {
			return nil, ErrEvidenceTruncated
		}
		l := binary.BigEndian.Uint32(blob[off : off+4])
		off += 4
		if uint64(off)+uint64(l) > uint64(len(blob)) {
			return nil, ErrEvidenceTruncated
		}
		fields = append(fields, blob[off:off+int(l)])
		off += int(l)
	}
	return fields, nil
}

// validateEquivocationEvidence: 4 fields (commit1, commit2, sig1, sig2).
//
// Adversarial test: commit1 == commit2 means no equivocation; reject
// with ErrEvidenceDuplicate (the package can do this structural check
// even though it can't validate the broadcast signatures themselves).
func validateEquivocationEvidence(blob []byte) error {
	fields, err := parseEvidenceFields(blob)
	if err != nil {
		return err
	}
	if len(fields) != equivocationFieldCount {
		return ErrEvidenceFieldCount
	}
	commit1, commit2, sig1, sig2 := fields[0], fields[1], fields[2], fields[3]
	if len(commit1) < commitMinLen || len(commit2) < commitMinLen {
		return ErrEvidenceFieldLen
	}
	if len(sig1) < sigMinLen || len(sig2) < sigMinLen {
		return ErrEvidenceFieldLen
	}
	if bytes.Equal(commit1, commit2) {
		return ErrEvidenceDuplicate
	}
	return nil
}

// validateBadDeliveryEvidence: 3 fields (share, blind, commits).
func validateBadDeliveryEvidence(blob []byte) error {
	fields, err := parseEvidenceFields(blob)
	if err != nil {
		return err
	}
	if len(fields) != badDeliveryFieldCount {
		return ErrEvidenceFieldCount
	}
	share, blind, commits := fields[0], fields[1], fields[2]
	if len(share) < shareMinLen {
		return ErrEvidenceFieldLen
	}
	if len(blind) < blindMinLen {
		return ErrEvidenceFieldLen
	}
	if len(commits) < commitListMinLen {
		return ErrEvidenceFieldLen
	}
	return nil
}

// validateMACFailureEvidence: 2 fields (mac, key).
func validateMACFailureEvidence(blob []byte) error {
	fields, err := parseEvidenceFields(blob)
	if err != nil {
		return err
	}
	if len(fields) != macFailureFieldCount {
		return ErrEvidenceFieldCount
	}
	mac, key := fields[0], fields[1]
	if len(mac) < macMinLen {
		return ErrEvidenceFieldLen
	}
	if len(key) < keyMinLen {
		return ErrEvidenceFieldLen
	}
	return nil
}

// validateRangeFailureEvidence: 1 field (transcript_line).
func validateRangeFailureEvidence(blob []byte) error {
	fields, err := parseEvidenceFields(blob)
	if err != nil {
		return err
	}
	if len(fields) != rangeFailureFieldCount {
		return ErrEvidenceFieldCount
	}
	transcript := fields[0]
	if len(transcript) < transcriptMinLen {
		return ErrEvidenceFieldLen
	}
	return nil
}

// ValidateAbortEvidence dispatches per-kind structural validation
// of the evidence blob (followup C closure). The package-level
// generic VerifyAbortEvidenceForm calls this internally; consumers
// can call it directly if they want only kind-specific blob shape
// checks without the surrounding form check.
//
// Returns ErrComplaintKind for an unknown kind, or the per-kind
// validator's error for shape violations.
func ValidateAbortEvidence(e *AbortEvidence) error {
	if e == nil {
		return ErrInvalidComplaint
	}
	switch e.Kind {
	case ComplaintEquivocation:
		return validateEquivocationEvidence(e.Evidence)
	case ComplaintBadDelivery:
		return validateBadDeliveryEvidence(e.Evidence)
	case ComplaintMACFailure:
		return validateMACFailureEvidence(e.Evidence)
	case ComplaintRangeFailure:
		return validateRangeFailureEvidence(e.Evidence)
	case ComplaintBadPartial:
		return validateBadPartialEvidence(e.Evidence)
	default:
		return ErrComplaintKind
	}
}

// AbortSignatureVerifier is the pluggable identity-layer signature
// verifier. Third parties (chain validators, audit observers, slashing
// modules) call VerifyAbortEvidence with an instance that wraps their
// production identity-key scheme (Ed25519, hybrid PQ, BLS, etc.).
//
// `transcript` is the canonical to-be-signed bytes returned by
// TranscriptForComplaint(e). `signature` is e.Signature. `accuser` is
// e.Accuser — the verifier looks up the accuser's public identity key
// in its own validator-set record and runs the underlying scheme's
// verify.
//
// Return true iff the signature is valid AND the accuser's identity is
// known to the verifier (i.e., the accuser is a registered party at
// the complained-about epoch). A nil verifier check is rejected by
// VerifyAbortEvidence via ErrComplaintNoSig — there is no implicit
// "skip signature verification" path.
type AbortSignatureVerifier interface {
	VerifyAbortSignature(accuser NodeID, transcript, signature []byte) bool
}

// MarshalAbortEvidence serialises an AbortEvidence to its canonical
// wire form. Layout:
//
//	1 byte    kind
//	32 bytes  accuser NodeID
//	32 bytes  accused NodeID
//	8 bytes   epoch (big-endian uint64)
//	4 bytes   evidence length (big-endian uint32)
//	N bytes   evidence
//	4 bytes   signature length (big-endian uint32)
//	M bytes   signature
//
// Wire-stable across versions; new ComplaintKind values append to
// the kind table but do not shift existing field offsets.
func MarshalAbortEvidence(e *AbortEvidence) ([]byte, error) {
	if e == nil {
		return nil, ErrInvalidComplaint
	}
	if e.Accuser == e.Accused {
		return nil, ErrComplaintSelfAcc
	}
	buf := make([]byte, 0, 1+32+32+8+4+len(e.Evidence)+4+len(e.Signature))
	buf = append(buf, byte(e.Kind))
	buf = append(buf, e.Accuser[:]...)
	buf = append(buf, e.Accused[:]...)
	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], e.Epoch)
	buf = append(buf, epochBuf[:]...)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(e.Evidence)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, e.Evidence...)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(e.Signature)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, e.Signature...)
	return buf, nil
}

// UnmarshalAbortEvidence parses canonical wire bytes into an
// AbortEvidence. Returns ErrInvalidComplaint on any structural
// failure (truncated buffer, oversize length fields).
func UnmarshalAbortEvidence(buf []byte) (*AbortEvidence, error) {
	if len(buf) < 1+32+32+8+4+0+4 {
		return nil, ErrInvalidComplaint
	}
	e := &AbortEvidence{}
	off := 0
	e.Kind = ComplaintKind(buf[off])
	off += 1
	copy(e.Accuser[:], buf[off:off+32])
	off += 32
	copy(e.Accused[:], buf[off:off+32])
	off += 32
	e.Epoch = binary.BigEndian.Uint64(buf[off : off+8])
	off += 8
	evLen := binary.BigEndian.Uint32(buf[off : off+4])
	off += 4
	if int(evLen) > len(buf)-off-4 {
		return nil, ErrInvalidComplaint
	}
	e.Evidence = append([]byte{}, buf[off:off+int(evLen)]...)
	off += int(evLen)
	sigLen := binary.BigEndian.Uint32(buf[off : off+4])
	off += 4
	if int(sigLen) > len(buf)-off {
		return nil, ErrInvalidComplaint
	}
	e.Signature = append([]byte{}, buf[off:off+int(sigLen)]...)
	if e.Accuser == e.Accused {
		return nil, ErrComplaintSelfAcc
	}
	return e, nil
}

// TranscriptForComplaint returns the canonical to-be-signed bytes
// of an AbortEvidence. The accuser's long-term identity key signs
// these bytes; the chain's slashing module verifies the signature
// against the accuser's published identity key in the validator-set
// record. Callers constructing a complaint outside this package
// pre-compute these bytes to feed their identity-key signer.
func TranscriptForComplaint(e *AbortEvidence) []byte {
	parts := [][]byte{
		{byte(e.Kind)},
		e.Accuser[:],
		e.Accused[:],
	}
	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], e.Epoch)
	parts = append(parts, epochBuf[:])
	parts = append(parts, e.Evidence)
	out := append([]byte{}, leftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		out = append(out, encodeString(p)...)
	}
	return out
}

// VerifyAbortEvidenceForm performs the third-party-verifiable
// STRUCTURAL well-formedness check on an AbortEvidence (Agent 4 H1
// + followup C closure). Independent of any signature scheme.
//
// Checks (in order):
//   - e is non-nil.
//   - accuser != accused.
//   - kind is in the registered ComplaintKind range.
//   - signature is non-empty.
//   - evidence blob is non-empty AND passes the kind-specific
//     ValidateAbortEvidence shape check (field count, per-field min
//     length, no trailing bytes, kind-specific uniqueness checks).
//
// Returns the first matching error, or nil if all structural checks
// pass. Third-party verifiers should call this BEFORE attempting
// signature verification — a well-formed transcript depends on the
// form being valid first.
//
// followup C key adversarial property: a blob valid for kind A will
// NOT validate under kind B, because the field counts differ
// (4/3/2/1) and ValidateAbortEvidence rejects mismatched counts via
// ErrEvidenceFieldCount.
func VerifyAbortEvidenceForm(e *AbortEvidence) error {
	if e == nil {
		return ErrInvalidComplaint
	}
	if e.Accuser == e.Accused {
		return ErrComplaintSelfAcc
	}
	switch e.Kind {
	case ComplaintEquivocation, ComplaintBadDelivery,
		ComplaintMACFailure, ComplaintRangeFailure, ComplaintBadPartial:
		// known kind
	default:
		return ErrComplaintKind
	}
	if len(e.Signature) == 0 {
		return ErrComplaintNoSig
	}
	if len(e.Evidence) == 0 {
		return ErrComplaintNoEv
	}
	if err := ValidateAbortEvidence(e); err != nil {
		return err
	}
	return nil
}

// VerifyAbortEvidence performs the FULL third-party verification of an
// AbortEvidence (Agent 4 H1 closure):
//
//  1. Structural well-formedness via VerifyAbortEvidenceForm.
//  2. Identity-layer signature check via the supplied verifier.
//
// The verifier MUST be non-nil — the package does not provide a
// default "skip signature" path. Returns ErrComplaintNoSig if the
// supplied verifier rejects the signature (i.e., the accuser's
// identity is not on file or the signature is forged).
//
// Pure form validation is available standalone via
// VerifyAbortEvidenceForm.
func VerifyAbortEvidence(e *AbortEvidence, v AbortSignatureVerifier) error {
	if err := VerifyAbortEvidenceForm(e); err != nil {
		return err
	}
	if v == nil {
		return ErrComplaintNoSig
	}
	if !v.VerifyAbortSignature(e.Accuser, TranscriptForComplaint(e), e.Signature) {
		return ErrComplaintNoSig
	}
	return nil
}

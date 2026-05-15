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
	"encoding/binary"
	"errors"
)

// Errors returned by abort-evidence verification.
var (
	ErrInvalidComplaint   = errors.New("pulsar: complaint structure invalid")
	ErrComplaintSelfAcc   = errors.New("pulsar: complaint accuser equals accused")
	ErrComplaintNoSig     = errors.New("pulsar: complaint missing accuser signature")
)

// MarshalAbortEvidence serialises an AbortEvidence to its canonical
// wire form. Layout:
//
//   1 byte    kind
//   32 bytes  accuser NodeID
//   32 bytes  accused NodeID
//   8 bytes   epoch (big-endian uint64)
//   4 bytes   evidence length (big-endian uint32)
//   N bytes   evidence
//   4 bytes   signature length (big-endian uint32)
//   M bytes   signature
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

// transcriptForComplaint returns the canonical transcript hash that
// the accuser's long-term identity key signs over. The accuser's
// signature is what makes the complaint a slashing-eligible artifact.
//
// transcriptForComplaint is the byte string passed to the identity-
// key signer (e.g. Ed25519); the chain's slashing module verifies the
// signature against the accuser's published identity key in the
// validator-set record.
func transcriptForComplaint(e *AbortEvidence) []byte {
	parts := [][]byte{
		[]byte{byte(e.Kind)},
		e.Accuser[:],
		e.Accused[:],
	}
	var epochBuf [8]byte
	binary.BigEndian.PutUint64(epochBuf[:], e.Epoch)
	parts = append(parts, epochBuf[:])
	parts = append(parts, e.Evidence)
	out := []byte{}
	out = append(out, leftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		out = append(out, encodeString(p)...)
	}
	return out
}

// TranscriptForComplaint is the public counterpart to
// transcriptForComplaint, exposed so that callers can pre-compute the
// to-be-signed bytes when constructing a complaint outside this
// package (the package does not sign — identity-key signing happens
// in the consumer's chain-specific identity layer).
func TranscriptForComplaint(e *AbortEvidence) []byte {
	return transcriptForComplaint(e)
}

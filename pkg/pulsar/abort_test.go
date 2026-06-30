// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// makeTLV builds a length-prefixed evidence blob for tests.
// Each field is encoded as 4-byte BE u32 length || N bytes payload.
func makeTLV(fields ...[]byte) []byte {
	out := make([]byte, 0)
	var lenBuf [4]byte
	for _, f := range fields {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(f)))
		out = append(out, lenBuf[:]...)
		out = append(out, f...)
	}
	return out
}

// rep returns a length-n byte slice filled with byte v. Used to
// build evidence fields of the per-field minimum byte lengths.
func rep(v byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

// validEvidenceFor returns a TLV-encoded evidence blob that passes
// the per-kind structural validator for the given kind.
func validEvidenceFor(kind ComplaintKind) []byte {
	switch kind {
	case ComplaintEquivocation:
		// 4 fields: commit1, commit2, sig1, sig2 (commits must differ)
		return makeTLV(rep(0xA1, 32), rep(0xA2, 32), rep(0xB1, 64), rep(0xB2, 64))
	case ComplaintBadDelivery:
		// 3 fields: share, blind, commits
		return makeTLV(rep(0x11, 32), rep(0x22, 32), rep(0x33, 32))
	case ComplaintMACFailure:
		// 2 fields: mac, key
		return makeTLV(rep(0x55, 32), rep(0x66, 32))
	case ComplaintRangeFailure:
		// 1 field: transcript_line
		return makeTLV([]byte("transcript-line-payload"))
	default:
		return nil
	}
}

func TestAbortEvidence_RoundTrip(t *testing.T) {
	original := &AbortEvidence{
		Kind:      ComplaintEquivocation,
		Accuser:   NodeID{1, 2, 3},
		Accused:   NodeID{4, 5, 6},
		Epoch:     42,
		Evidence:  validEvidenceFor(ComplaintEquivocation),
		Signature: []byte("identity-key-signature"),
	}
	wire, err := MarshalAbortEvidence(original)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalAbortEvidence(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != original.Kind {
		t.Fatalf("Kind mismatch")
	}
	if got.Accuser != original.Accuser {
		t.Fatalf("Accuser mismatch")
	}
	if got.Accused != original.Accused {
		t.Fatalf("Accused mismatch")
	}
	if got.Epoch != original.Epoch {
		t.Fatalf("Epoch mismatch")
	}
	if !bytes.Equal(got.Evidence, original.Evidence) {
		t.Fatalf("Evidence mismatch")
	}
	if !bytes.Equal(got.Signature, original.Signature) {
		t.Fatalf("Signature mismatch")
	}
}

func TestAbortEvidence_RejectsSelfAccusation(t *testing.T) {
	e := &AbortEvidence{
		Kind:    ComplaintEquivocation,
		Accuser: NodeID{1},
		Accused: NodeID{1},
	}
	if _, err := MarshalAbortEvidence(e); err != ErrComplaintSelfAcc {
		t.Fatalf("self-accusation not rejected: %v", err)
	}
}

func TestAbortEvidence_RejectsTruncated(t *testing.T) {
	if _, err := UnmarshalAbortEvidence([]byte{0x01}); err != ErrInvalidComplaint {
		t.Fatalf("truncated bytes not rejected: %v", err)
	}
}

func TestAbortEvidence_Nil(t *testing.T) {
	if _, err := MarshalAbortEvidence(nil); err != ErrInvalidComplaint {
		t.Fatalf("nil evidence not rejected: %v", err)
	}
}

func TestAbortEvidence_TranscriptStable(t *testing.T) {
	e := &AbortEvidence{
		Kind:     ComplaintBadDelivery,
		Accuser:  NodeID{1},
		Accused:  NodeID{2},
		Epoch:    7,
		Evidence: []byte("evidence"),
	}
	t1 := TranscriptForComplaint(e)
	t2 := TranscriptForComplaint(e)
	if !bytes.Equal(t1, t2) {
		t.Fatalf("transcript not deterministic")
	}
	if len(t1) == 0 {
		t.Fatalf("empty transcript")
	}
}

// stubVerifier is a deterministic AbortSignatureVerifier for tests:
// it accepts iff the signature equals a fixed prefix of the transcript.
type stubVerifier struct {
	acceptPrefix []byte
}

func (s *stubVerifier) VerifyAbortSignature(_ NodeID, transcript, signature []byte) bool {
	if len(signature) > len(transcript) {
		return false
	}
	if !bytes.HasPrefix(transcript, signature) {
		return false
	}
	if !bytes.Equal(signature[:len(s.acceptPrefix)], s.acceptPrefix) {
		return false
	}
	return true
}

func TestVerifyAbortEvidenceForm_HappyPath(t *testing.T) {
	e := &AbortEvidence{
		Kind:      ComplaintBadDelivery,
		Accuser:   NodeID{1},
		Accused:   NodeID{2},
		Epoch:     1,
		Evidence:  validEvidenceFor(ComplaintBadDelivery),
		Signature: []byte("sig"),
	}
	if err := VerifyAbortEvidenceForm(e); err != nil {
		t.Fatalf("form check rejected valid evidence: %v", err)
	}
}

func TestVerifyAbortEvidenceForm_RejectsNil(t *testing.T) {
	if err := VerifyAbortEvidenceForm(nil); err != ErrInvalidComplaint {
		t.Fatalf("nil not rejected: %v", err)
	}
}

func TestVerifyAbortEvidenceForm_RejectsSelfAcc(t *testing.T) {
	e := &AbortEvidence{Kind: ComplaintEquivocation, Accuser: NodeID{1}, Accused: NodeID{1},
		Evidence: []byte("x"), Signature: []byte("y")}
	if err := VerifyAbortEvidenceForm(e); err != ErrComplaintSelfAcc {
		t.Fatalf("self-acc not rejected: %v", err)
	}
}

func TestVerifyAbortEvidenceForm_RejectsBadKind(t *testing.T) {
	e := &AbortEvidence{Kind: ComplaintKind(99), Accuser: NodeID{1}, Accused: NodeID{2},
		Evidence: []byte("x"), Signature: []byte("y")}
	if err := VerifyAbortEvidenceForm(e); err != ErrComplaintKind {
		t.Fatalf("bad kind not rejected: %v", err)
	}
}

func TestVerifyAbortEvidenceForm_RejectsNoEvidence(t *testing.T) {
	e := &AbortEvidence{Kind: ComplaintEquivocation, Accuser: NodeID{1}, Accused: NodeID{2},
		Signature: []byte("sig")}
	if err := VerifyAbortEvidenceForm(e); err != ErrComplaintNoEv {
		t.Fatalf("empty evidence not rejected: %v", err)
	}
}

func TestVerifyAbortEvidenceForm_RejectsNoSignature(t *testing.T) {
	e := &AbortEvidence{Kind: ComplaintEquivocation, Accuser: NodeID{1}, Accused: NodeID{2},
		Evidence: validEvidenceFor(ComplaintEquivocation)}
	if err := VerifyAbortEvidenceForm(e); err != ErrComplaintNoSig {
		t.Fatalf("empty signature not rejected: %v", err)
	}
}

// TestAbortEvidence_PerKindValidators — every kind's structurally
// valid evidence blob passes its own validator, every kind's
// structurally invalid blob (bare bytes, no TLV framing) fails.
func TestAbortEvidence_PerKindValidators(t *testing.T) {
	cases := []struct {
		name string
		kind ComplaintKind
	}{
		{"equivocation", ComplaintEquivocation},
		{"bad-delivery", ComplaintBadDelivery},
		{"mac-failure", ComplaintMACFailure},
		{"range-failure", ComplaintRangeFailure},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			good := &AbortEvidence{Kind: c.kind, Accuser: NodeID{1}, Accused: NodeID{2},
				Evidence: validEvidenceFor(c.kind), Signature: []byte("sig")}
			if err := ValidateAbortEvidence(good); err != nil {
				t.Fatalf("valid evidence rejected: %v", err)
			}
			// Bare bytes (no TLV framing) — either truncated or wrong count.
			bad := &AbortEvidence{Kind: c.kind, Accuser: NodeID{1}, Accused: NodeID{2},
				Evidence: []byte("bare-bytes-no-tlv"), Signature: []byte("sig")}
			if err := ValidateAbortEvidence(bad); err == nil {
				t.Fatalf("bare-bytes evidence accepted under %s", c.name)
			}
		})
	}
}

// TestAbortEvidence_RejectsWrongKindShape — the adversarial property:
// a blob valid for kind A must not validate under kind B (different
// field counts: 4/3/2/1).
func TestAbortEvidence_RejectsWrongKindShape(t *testing.T) {
	all := []ComplaintKind{
		ComplaintEquivocation, ComplaintBadDelivery,
		ComplaintMACFailure, ComplaintRangeFailure,
	}
	for _, blobKind := range all {
		blob := validEvidenceFor(blobKind)
		for _, checkKind := range all {
			if blobKind == checkKind {
				continue
			}
			e := &AbortEvidence{Kind: checkKind, Accuser: NodeID{1}, Accused: NodeID{2},
				Evidence: blob, Signature: []byte("sig")}
			err := ValidateAbortEvidence(e)
			if err == nil {
				t.Fatalf("blob valid for %s accepted under %s — field-count cross-talk",
					blobKind, checkKind)
			}
		}
	}
}

func TestAbortEvidence_RejectsTrailingBytes(t *testing.T) {
	blob := validEvidenceFor(ComplaintMACFailure)
	blob = append(blob, 0xFF, 0xFE) // trailing bytes (incomplete length prefix)
	e := &AbortEvidence{Kind: ComplaintMACFailure, Accuser: NodeID{1}, Accused: NodeID{2},
		Evidence: blob, Signature: []byte("sig")}
	if err := ValidateAbortEvidence(e); err != ErrEvidenceTruncated {
		t.Fatalf("trailing bytes not rejected as truncated: %v", err)
	}
}

func TestAbortEvidence_RejectsEquivocationDuplicateCommits(t *testing.T) {
	// Equivocation with commit1 == commit2 means no actual equivocation.
	dup := rep(0xA1, 32)
	blob := makeTLV(dup, dup, rep(0xB1, 64), rep(0xB2, 64))
	e := &AbortEvidence{Kind: ComplaintEquivocation, Accuser: NodeID{1}, Accused: NodeID{2},
		Evidence: blob, Signature: []byte("sig")}
	if err := ValidateAbortEvidence(e); err != ErrEvidenceDuplicate {
		t.Fatalf("duplicate-commit equivocation not rejected: %v", err)
	}
}

func TestAbortEvidence_RejectsShortFields(t *testing.T) {
	// MACFailure with mac/key of 16 bytes — below 32-byte minimum.
	blob := makeTLV(rep(0x55, 16), rep(0x66, 16))
	e := &AbortEvidence{Kind: ComplaintMACFailure, Accuser: NodeID{1}, Accused: NodeID{2},
		Evidence: blob, Signature: []byte("sig")}
	if err := ValidateAbortEvidence(e); err != ErrEvidenceFieldLen {
		t.Fatalf("short fields not rejected: %v", err)
	}
}

func TestValidateAbortEvidence_RejectsNil(t *testing.T) {
	if err := ValidateAbortEvidence(nil); err != ErrInvalidComplaint {
		t.Fatalf("nil not rejected: %v", err)
	}
}

func TestValidateAbortEvidence_RejectsUnknownKind(t *testing.T) {
	e := &AbortEvidence{Kind: ComplaintKind(99), Evidence: validEvidenceFor(ComplaintMACFailure)}
	if err := ValidateAbortEvidence(e); err != ErrComplaintKind {
		t.Fatalf("unknown kind not rejected: %v", err)
	}
}

func TestVerifyAbortEvidence_HappyPath(t *testing.T) {
	e := &AbortEvidence{
		Kind:     ComplaintBadDelivery,
		Accuser:  NodeID{1},
		Accused:  NodeID{2},
		Epoch:    1,
		Evidence: validEvidenceFor(ComplaintBadDelivery),
	}
	// sign := first 4 bytes of transcript
	transcript := TranscriptForComplaint(e)
	e.Signature = append([]byte{}, transcript[:4]...)
	v := &stubVerifier{acceptPrefix: transcript[:4]}
	if err := VerifyAbortEvidence(e, v); err != nil {
		t.Fatalf("verify rejected valid: %v", err)
	}
}

func TestVerifyAbortEvidence_RejectsBadSignature(t *testing.T) {
	e := &AbortEvidence{
		Kind:      ComplaintBadDelivery,
		Accuser:   NodeID{1},
		Accused:   NodeID{2},
		Epoch:     1,
		Evidence:  validEvidenceFor(ComplaintBadDelivery),
		Signature: []byte("forged"),
	}
	transcript := TranscriptForComplaint(e)
	// stub accepts only signatures that PREFIX the transcript;
	// "forged" does not match transcript[:6] in general
	v := &stubVerifier{acceptPrefix: transcript[:1]}
	err := VerifyAbortEvidence(e, v)
	if err != ErrComplaintNoSig {
		t.Fatalf("forged signature not rejected: %v", err)
	}
}

func TestVerifyAbortEvidence_RejectsNilVerifier(t *testing.T) {
	e := &AbortEvidence{
		Kind:      ComplaintBadDelivery,
		Accuser:   NodeID{1},
		Accused:   NodeID{2},
		Epoch:     1,
		Evidence:  validEvidenceFor(ComplaintBadDelivery),
		Signature: []byte("sig"),
	}
	if err := VerifyAbortEvidence(e, nil); err != ErrComplaintNoSig {
		t.Fatalf("nil verifier not rejected: %v", err)
	}
}

func TestComplaintKind_String(t *testing.T) {
	for _, tc := range []struct {
		k    ComplaintKind
		want string
	}{
		{ComplaintEquivocation, "equivocation"},
		{ComplaintBadDelivery, "bad-delivery"},
		{ComplaintMACFailure, "mac-failure"},
		{ComplaintRangeFailure, "range-failure"},
		{ComplaintKind(99), "unknown"},
	} {
		if got := tc.k.String(); got != tc.want {
			t.Fatalf("kind %d: got %q want %q", tc.k, got, tc.want)
		}
	}
}

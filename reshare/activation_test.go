// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"bytes"
	"errors"
	"testing"
)

// TestActivationMessageDeterministic — same inputs → same signable
// bytes.
func TestActivationMessageSignableBytesStable(t *testing.T) {
	a := ActivationMessage{
		Transcript: TranscriptInputs{
			ChainID: []byte("test"),
			GroupID: []byte("g"),
			Variant: "reshare",
		},
		ReshareTranscript: ReshareTranscript{
			CommitDigests:       map[int][32]byte{1: {0xaa}, 2: {0xbb}},
			ComplaintHashes:     [][32]byte{{0xcc}},
			DisqualifiedSenders: []int{4},
			QualifiedQuorum:     []int{1, 2, 3},
		},
	}
	b1 := a.SignableBytes(nil)
	b2 := a.SignableBytes(nil)
	if !bytes.Equal(b1, b2) {
		t.Fatal("SignableBytes non-deterministic")
	}
	// Format: 25-byte personalization prefix + 32 + 32 = 89 bytes.
	const wantLen = len("QUASAR-PULSAR-ACTIVATE-v1") + 32 + 32
	if len(b1) != wantLen {
		t.Fatalf("unexpected SignableBytes length: %d (want %d)", len(b1), wantLen)
	}
}

// TestReshareTranscriptHashStable — committed digest of an exchange
// is reproducible regardless of the order Caller inserted the
// CommitDigests map keys.
func TestReshareTranscriptHashStable(t *testing.T) {
	rt := ReshareTranscript{
		CommitDigests: map[int][32]byte{
			3: {0x33},
			1: {0x11},
			5: {0x55},
		},
		ComplaintHashes: [][32]byte{{0x99}, {0x88}},
		DisqualifiedSenders: []int{4, 2},
		QualifiedQuorum:     []int{1, 3, 5},
	}
	a := rt.Hash(nil)
	b := rt.Hash(nil)
	if a != b {
		t.Fatal("non-deterministic hash")
	}
}

// TestVerifyActivationHappyPath — activation cert verified with a
// fake verify callback that returns true succeeds.
func TestVerifyActivationHappyPath(t *testing.T) {
	a := &ActivationCert{
		Message: ActivationMessage{
			Transcript: TranscriptInputs{
				ChainID: []byte("c"), GroupID: []byte("g"), Variant: "reshare",
			},
			ReshareTranscript: ReshareTranscript{
				QualifiedQuorum: []int{1, 2, 3},
			},
		},
		Signature: []byte("opaque-threshold-sig"),
	}
	tHash := a.Message.Transcript.Hash(nil)
	rtHash := a.Message.ReshareTranscript.Hash(nil)
	verify := func(message, sig []byte) bool {
		// Sanity: caller passed the canonical bytes for SignableBytes.
		if !bytes.Equal(message, a.Message.SignableBytes(nil)) {
			return false
		}
		return bytes.Equal(sig, []byte("opaque-threshold-sig"))
	}
	if err := VerifyActivation(a, tHash, rtHash, nil, verify); err != nil {
		t.Fatalf("happy path failed: %v", err)
	}
}

// TestVerifyActivationRejectsBadSig — verify callback returning false
// produces ErrActivationFailed.
func TestVerifyActivationRejectsBadSig(t *testing.T) {
	a := &ActivationCert{
		Message: ActivationMessage{
			Transcript: TranscriptInputs{Variant: "reshare"},
		},
		Signature: []byte("forged-sig"),
	}
	tHash := a.Message.Transcript.Hash(nil)
	rtHash := a.Message.ReshareTranscript.Hash(nil)
	verify := func(message, sig []byte) bool { return false }
	err := VerifyActivation(a, tHash, rtHash, nil, verify)
	if err == nil || !errors.Is(err, ErrActivationFailed) {
		t.Fatalf("expected ErrActivationFailed, got %v", err)
	}
}

// TestVerifyActivationRejectsTranscriptMismatch — local transcript
// hash differs from cert's view → ErrTranscriptMismatch.
func TestVerifyActivationRejectsTranscriptMismatch(t *testing.T) {
	a := &ActivationCert{
		Message: ActivationMessage{
			Transcript: TranscriptInputs{Variant: "reshare", ChainID: []byte("a")},
		},
		Signature: []byte("sig"),
	}
	rtHash := a.Message.ReshareTranscript.Hash(nil)
	wrong := [32]byte{0xff, 0xff}
	verify := func(message, sig []byte) bool { return true } // would have passed
	err := VerifyActivation(a, wrong, rtHash, nil, verify)
	if err == nil || !errors.Is(err, ErrTranscriptMismatch) {
		t.Fatalf("expected ErrTranscriptMismatch, got %v", err)
	}
}

// TestVerifyActivationRejectsExchangeMismatch — local exchange hash
// differs → ErrTranscriptMismatch.
func TestVerifyActivationRejectsExchangeMismatch(t *testing.T) {
	a := &ActivationCert{
		Message: ActivationMessage{
			Transcript: TranscriptInputs{Variant: "reshare"},
		},
		Signature: []byte("sig"),
	}
	tHash := a.Message.Transcript.Hash(nil)
	wrong := [32]byte{0xee}
	verify := func(message, sig []byte) bool { return true }
	err := VerifyActivation(a, tHash, wrong, nil, verify)
	if err == nil || !errors.Is(err, ErrTranscriptMismatch) {
		t.Fatalf("expected ErrTranscriptMismatch, got %v", err)
	}
}

// TestVerifyActivationRejectsNilCert — defensive nil check.
func TestVerifyActivationRejectsNilCert(t *testing.T) {
	err := VerifyActivation(nil, [32]byte{}, [32]byte{}, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil cert")
	}
}

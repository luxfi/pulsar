// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSignVerify_RoundTrip_AllModes(t *testing.T) {
	for _, mode := range []Mode{ModeP44, ModeP65, ModeP87} {
		t.Run(mode.String(), func(t *testing.T) {
			params := MustParamsFor(mode)
			sk, err := GenerateKey(params, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("Pulsar-M round-trip test message — Class N1 sanity")
			sig, err := Sign(params, sk, msg, nil, true, rand.Reader)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(sig.Bytes) != params.SignatureSize {
				t.Fatalf("sig size %d want %d", len(sig.Bytes), params.SignatureSize)
			}
			if err := Verify(params, sk.Pub, msg, sig); err != nil {
				t.Fatalf("Verify failed for honestly-produced sig: %v", err)
			}
		})
	}
}

func TestSignVerify_BadSig_Rejected(t *testing.T) {
	params := MustParamsFor(ModeP65)
	sk, _ := GenerateKey(params, rand.Reader)
	msg := []byte("test")
	sig, _ := Sign(params, sk, msg, nil, true, rand.Reader)
	// Flip a byte.
	sig.Bytes[10] ^= 0x01
	if err := Verify(params, sk.Pub, msg, sig); err == nil {
		t.Fatalf("tampered sig should fail Verify")
	}
}

func TestSignVerify_WrongMessage_Rejected(t *testing.T) {
	params := MustParamsFor(ModeP65)
	sk, _ := GenerateKey(params, rand.Reader)
	sig, _ := Sign(params, sk, []byte("alpha"), nil, true, rand.Reader)
	if err := Verify(params, sk.Pub, []byte("beta"), sig); err == nil {
		t.Fatalf("wrong-message sig should fail Verify")
	}
}

func TestSignVerify_WrongPubkey_Rejected(t *testing.T) {
	params := MustParamsFor(ModeP65)
	sk1, _ := GenerateKey(params, rand.Reader)
	sk2, _ := GenerateKey(params, rand.Reader)
	msg := []byte("test")
	sig, _ := Sign(params, sk1, msg, nil, true, rand.Reader)
	if err := Verify(params, sk2.Pub, msg, sig); err == nil {
		t.Fatalf("wrong-pubkey verify should fail")
	}
}

func TestVerify_NilArgs(t *testing.T) {
	params := MustParamsFor(ModeP65)
	if err := Verify(params, nil, nil, nil); err != ErrNilPublicKey {
		t.Fatalf("nil pubkey not detected, got %v", err)
	}
	sk, _ := GenerateKey(params, rand.Reader)
	if err := Verify(params, sk.Pub, nil, nil); err != ErrNilSignature {
		t.Fatalf("nil sig not detected, got %v", err)
	}
}

func TestVerify_WrongMode(t *testing.T) {
	params65 := MustParamsFor(ModeP65)
	params44 := MustParamsFor(ModeP44)
	sk, _ := GenerateKey(params44, rand.Reader)
	sig, _ := Sign(params44, sk, []byte("m"), nil, true, rand.Reader)
	if err := Verify(params65, sk.Pub, []byte("m"), sig); err == nil {
		t.Fatalf("wrong-mode verify should fail")
	}
}

func TestVerify_WrongSigSize(t *testing.T) {
	params := MustParamsFor(ModeP65)
	sk, _ := GenerateKey(params, rand.Reader)
	bad := &Signature{Mode: ModeP65, Bytes: []byte{0x00}}
	if err := Verify(params, sk.Pub, []byte("m"), bad); err != ErrSignatureWrongSize {
		t.Fatalf("wrong sig size not detected, got %v", err)
	}
}

func TestSign_DeterministicSeed_Reproducible(t *testing.T) {
	params := MustParamsFor(ModeP65)
	seed := [SeedSize]byte{0xaa, 0xbb, 0xcc, 0xdd}
	sk, _ := KeyFromSeed(params, seed)
	msg := []byte("kat-replay")
	// randomized=false uses deterministic FIPS 204 signing — same input → same sig.
	sig1, err := Sign(params, sk, msg, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := Sign(params, sk, msg, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig1.Bytes, sig2.Bytes) {
		t.Fatalf("deterministic sig should be reproducible")
	}
	// And it verifies.
	if err := Verify(params, sk.Pub, msg, sig1); err != nil {
		t.Fatalf("deterministic sig fails Verify: %v", err)
	}
}

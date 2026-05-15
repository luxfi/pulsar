// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGenerateKey_AllModes(t *testing.T) {
	for _, mode := range []Mode{ModeP44, ModeP65, ModeP87} {
		t.Run(mode.String(), func(t *testing.T) {
			params := MustParamsFor(mode)
			sk, err := GenerateKey(params, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if sk.Pub == nil {
				t.Fatalf("nil pub")
			}
			if len(sk.Pub.Bytes) != params.PublicKeySize {
				t.Fatalf("pub size %d want %d", len(sk.Pub.Bytes), params.PublicKeySize)
			}
			if len(sk.Bytes) != params.PrivateKeySize {
				t.Fatalf("priv size %d want %d", len(sk.Bytes), params.PrivateKeySize)
			}
		})
	}
}

func TestKeyFromSeed_Deterministic(t *testing.T) {
	for _, mode := range []Mode{ModeP44, ModeP65, ModeP87} {
		t.Run(mode.String(), func(t *testing.T) {
			params := MustParamsFor(mode)
			seed := [SeedSize]byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
			}
			a, err := KeyFromSeed(params, seed)
			if err != nil {
				t.Fatal(err)
			}
			b, err := KeyFromSeed(params, seed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a.Bytes, b.Bytes) {
				t.Fatalf("priv bytes differ across seeds")
			}
			if !bytes.Equal(a.Pub.Bytes, b.Pub.Bytes) {
				t.Fatalf("pub bytes differ across seeds")
			}
		})
	}
}

func TestPublicKey_Equal(t *testing.T) {
	params := MustParamsFor(ModeP65)
	a, _ := GenerateKey(params, rand.Reader)
	b, _ := GenerateKey(params, rand.Reader)
	if a.Pub.Equal(b.Pub) {
		t.Fatalf("two fresh keys should not be equal")
	}
	if !a.Pub.Equal(a.Pub) {
		t.Fatalf("key not equal to itself")
	}
}

func TestParams_Validate(t *testing.T) {
	if err := ParamsP65.Validate(); err != nil {
		t.Fatalf("Validate canonical: %v", err)
	}
	tampered := *ParamsP65
	tampered.K = 99
	if err := tampered.Validate(); err == nil {
		t.Fatalf("tampered params should fail Validate")
	}
	if err := (*Params)(nil).Validate(); err == nil {
		t.Fatalf("nil params should fail Validate")
	}
}

func TestParamsFor_UnknownMode(t *testing.T) {
	if _, err := ParamsFor(Mode(255)); err == nil {
		t.Fatalf("unknown mode should error")
	}
}

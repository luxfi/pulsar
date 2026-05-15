// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

import (
	"crypto/rand"
	"errors"
	"testing"
)

// TestVerifyBatch_AllValid_MultiMode generates N signatures across
// ModeP44/65/87 by mixing single-party FIPS 204 signatures and
// confirms VerifyBatch reports all valid. Mixed modes within a single
// batch are NOT supported (params is shared); we instead loop modes
// and check each batch separately.
func TestVerifyBatch_AllValid_MultiMode(t *testing.T) {
	for _, mode := range []Mode{ModeP44, ModeP65, ModeP87} {
		params := MustParamsFor(mode)
		const n = 8

		gps := make([]*PublicKey, n)
		msgs := make([][]byte, n)
		sigs := make([]*Signature, n)

		for i := 0; i < n; i++ {
			sk, err := GenerateKey(params, rand.Reader)
			if err != nil {
				t.Fatalf("[mode=%v] GenerateKey i=%d: %v", mode, i, err)
			}
			msg := []byte("verify_batch test message " + string(rune('A'+i)))
			sig, err := Sign(params, sk, msg, nil, false, rand.Reader)
			if err != nil {
				t.Fatalf("[mode=%v] Sign i=%d: %v", mode, i, err)
			}
			gps[i] = sk.Public()
			msgs[i] = msg
			sigs[i] = sig
		}

		results, err := VerifyBatch(params, gps, msgs, sigs)
		if err != nil {
			t.Fatalf("[mode=%v] VerifyBatch returned err=%v", mode, err)
		}
		if len(results) != n {
			t.Fatalf("[mode=%v] results len=%d, want %d", mode, len(results), n)
		}
		for i, r := range results {
			if r != nil {
				t.Errorf("[mode=%v] result[%d] = %v, want nil", mode, i, r)
			}
		}

		ok, err := VerifyBatchAll(params, gps, msgs, sigs)
		if err != nil || !ok {
			t.Errorf("[mode=%v] VerifyBatchAll ok=%v err=%v, want (true, nil)", mode, ok, err)
		}
	}
}

// TestVerifyBatch_OneCorrupt asserts a single-entry corruption is
// localised: results[i] = ErrInvalidSignature for the corrupt entry,
// nil for all the rest, and VerifyBatchAll returns false.
func TestVerifyBatch_OneCorrupt(t *testing.T) {
	params := MustParamsFor(ModeP65)
	const n = 10
	const badIdx = 4

	gps := make([]*PublicKey, n)
	msgs := make([][]byte, n)
	sigs := make([]*Signature, n)

	for i := 0; i < n; i++ {
		sk, err := GenerateKey(params, rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey i=%d: %v", i, err)
		}
		msg := []byte{byte(i), 'm', 's', 'g'}
		sig, err := Sign(params, sk, msg, nil, false, rand.Reader)
		if err != nil {
			t.Fatalf("Sign i=%d: %v", i, err)
		}
		gps[i] = sk.Public()
		msgs[i] = msg
		sigs[i] = sig
	}
	// Flip a byte in the bad entry's signature so FIPS 204 verify rejects it.
	sigs[badIdx].Bytes[10] ^= 0xFF

	results, err := VerifyBatch(params, gps, msgs, sigs)
	if err != nil {
		t.Fatalf("VerifyBatch err=%v", err)
	}
	for i, r := range results {
		if i == badIdx {
			if !errors.Is(r, ErrInvalidSignature) {
				t.Errorf("result[%d] = %v, want ErrInvalidSignature", i, r)
			}
		} else if r != nil {
			t.Errorf("result[%d] = %v, want nil", i, r)
		}
	}

	ok, err := VerifyBatchAll(params, gps, msgs, sigs)
	if err != nil {
		t.Fatalf("VerifyBatchAll err=%v", err)
	}
	if ok {
		t.Error("VerifyBatchAll = true, want false")
	}
}

// TestVerifyBatch_StructuralMismatch asserts length-mismatched slices
// surface as ErrBatchSizeMismatch with a nil results slice.
func TestVerifyBatch_StructuralMismatch(t *testing.T) {
	params := MustParamsFor(ModeP65)

	gps := []*PublicKey{nil, nil}
	msgs := [][]byte{{1}, {2}, {3}}
	sigs := []*Signature{nil, nil}

	results, err := VerifyBatch(params, gps, msgs, sigs)
	if !errors.Is(err, ErrBatchSizeMismatch) {
		t.Errorf("err = %v, want ErrBatchSizeMismatch", err)
	}
	if results != nil {
		t.Errorf("results = %v, want nil", results)
	}
}

// TestVerifyBatch_Empty asserts an empty batch is (nil, nil).
func TestVerifyBatch_Empty(t *testing.T) {
	params := MustParamsFor(ModeP65)
	results, err := VerifyBatch(params, nil, nil, nil)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if results != nil {
		t.Errorf("results = %v, want nil", results)
	}
}

// BenchmarkVerifyBatch_P65_N32 measures parallel throughput at the
// most common consensus committee size.
func BenchmarkVerifyBatch_P65_N32(b *testing.B) {
	params := MustParamsFor(ModeP65)
	const n = 32

	gps := make([]*PublicKey, n)
	msgs := make([][]byte, n)
	sigs := make([]*Signature, n)
	for i := 0; i < n; i++ {
		sk, _ := GenerateKey(params, rand.Reader)
		msg := []byte{byte(i), 'b', 'e', 'n', 'c', 'h'}
		sig, _ := Sign(params, sk, msg, nil, false, rand.Reader)
		gps[i] = sk.Public()
		msgs[i] = msg
		sigs[i] = sig
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyBatch(params, gps, msgs, sigs)
	}
}

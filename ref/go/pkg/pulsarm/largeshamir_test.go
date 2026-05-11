// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestLargeShamir_EvalAtTargetCommitteeSize is the canonical "extreme
// committee" smoke test: deal exactly TargetCommitteeSize = 1 111 111
// virtual parties via the per-party EvalAt path (so we never have to
// materialise all 1.1M shares), reconstruct from a t-size quorum
// sampled across the index range including the endpoint x = N, and
// assert byte-equality against the original secret.
func TestLargeShamir_EvalAtTargetCommitteeSize(t *testing.T) {
	const N = TargetCommitteeSize
	const thresh = 5

	var secret [SeedSize]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	stream := bytes.Repeat([]byte{0xa5, 0x5a, 0xc3, 0x3c}, 64)

	ls := LargeShamir{Field: FieldGFq}

	xs := []uint32{1, 7, uint32(N / 3), uint32(N - 1), uint32(N)}
	wires := make([]LargeShareWire, len(xs))
	for i, x := range xs {
		w, err := ls.EvalAt(secret, x, thresh, stream)
		if err != nil {
			t.Fatalf("EvalAt x=%d failed: %v", x, err)
		}
		wires[i] = w
	}
	rec, err := ls.Reconstruct(xs, wires)
	if err != nil {
		t.Fatalf("Reconstruct at N=%d failed: %v", N, err)
	}
	if rec != secret {
		t.Fatalf("Reconstruct mismatch at N=%d: got %x want %x", N, rec, secret)
	}
}

// TestLargeShamir_RoundTrip_Small confirms the public surface
// works identically to the internal shamirShareQ helpers at small N.
func TestLargeShamir_RoundTrip_Small(t *testing.T) {
	const N = 16
	const thresh = 9
	var secret [SeedSize]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	stream := bytes.Repeat([]byte{0x77}, (thresh-1)*SeedSize*4+8)

	ls := LargeShamir{Field: FieldGFq}
	xs, wires, err := ls.Deal(secret, N, thresh, stream)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := ls.Reconstruct(xs[:thresh], wires[:thresh])
	if err != nil {
		t.Fatal(err)
	}
	if rec != secret {
		t.Fatalf("round-trip mismatch")
	}
}

// TestResolveField verifies the auto-selection logic between
// FieldGF257 and FieldGFq based on the committee size.
func TestResolveField(t *testing.T) {
	type row struct {
		want Field
		n    int
		exp  Field
		err  bool
	}
	cases := []row{
		{FieldDefault, 1, FieldGF257, false},
		{FieldDefault, 256, FieldGF257, false},
		{FieldDefault, 257, FieldGFq, false},
		{FieldDefault, 1_111_111, FieldGFq, false},
		{FieldDefault, int(MaxCommitteeQ), FieldGFq, false},
		{FieldGF257, 256, FieldGF257, false},
		{FieldGF257, 257, 0, true},
		{FieldGFq, 1, FieldGFq, false},
		{FieldGFq, int(MaxCommitteeQ), FieldGFq, false},
	}
	for _, c := range cases {
		got, err := resolveField(c.want, c.n)
		if c.err {
			if err == nil {
				t.Fatalf("want=%v n=%d expected error", c.want, c.n)
			}
			continue
		}
		if err != nil {
			t.Fatalf("want=%v n=%d unexpected error: %v", c.want, c.n, err)
		}
		if got != c.exp {
			t.Fatalf("want=%v n=%d got=%v exp=%v", c.want, c.n, got, c.exp)
		}
	}
}

// TestLargeShamir_FullCeremony_10001 runs a full Deal + Reconstruct
// round-trip at N = 10 001 -- the smallest committee at which the
// problem statement's "N > 10 000" requirement applies. Allocates
// 1.28 MB for the share table; fast on every CI machine.
func TestLargeShamir_FullCeremony_10001(t *testing.T) {
	const N = 10_001
	const thresh = 7
	var secret [SeedSize]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	stream := bytes.Repeat([]byte{0xe7}, (thresh-1)*SeedSize*4+8)
	ls := LargeShamir{Field: FieldGFq}
	xs, wires, err := ls.Deal(secret, N, thresh, stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(xs) != N {
		t.Fatalf("got %d shares, want %d", len(xs), N)
	}
	// Pick a non-trivial quorum (skip indices 0..2 to test offset).
	rec, err := ls.Reconstruct(xs[2:2+thresh], wires[2:2+thresh])
	if err != nil {
		t.Fatal(err)
	}
	if rec != secret {
		t.Fatalf("N=%d Reconstruct mismatch", N)
	}
}

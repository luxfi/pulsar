// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestShamirQ_DealAndReconstruct_Small(t *testing.T) {
	for _, tc := range []struct {
		name string
		n, t int
	}{
		{"3of2", 3, 2},
		{"5of3", 5, 3},
		{"7of4", 7, 4},
		{"16of11", 16, 11},
		{"500of51", 500, 51},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			secret := [SeedSize]byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
			}
			stream := bytes.Repeat([]byte{0xaa}, (tc.t-1)*SeedSize*4+8)
			shares, err := shamirDealRandomQ(secret, tc.n, tc.t, stream)
			if err != nil {
				t.Fatal(err)
			}
			if len(shares) != tc.n {
				t.Fatalf("got %d shares, want %d", len(shares), tc.n)
			}
			recovered, err := shamirReconstructQ(shares[:tc.t])
			if err != nil {
				t.Fatal(err)
			}
			if recovered != secret {
				t.Fatalf("reconstructed %x want %x", recovered, secret)
			}
		})
	}
}

// TestShamirQ_LargeN_Extreme exercises the canonical extreme committee
// size TargetCommitteeSize = 1 111 111. We do not materialise all
// 1.111M shares -- that would burn ~140 MB just for the per-byte
// uint32 lanes -- instead we deal at a small t over a committee of
// exactly TargetCommitteeSize and reconstruct from t arbitrary
// shares spread across the index range, including indices near 1
// and near TargetCommitteeSize so the Lagrange path is exercised on
// the extreme positions.
func TestShamirQ_LargeN_Extreme(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1.111M-committee test in -short mode")
	}
	const n = TargetCommitteeSize
	const thresh = 5

	var secret [SeedSize]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}

	// We avoid allocating n shares; instead recompute t specific shares
	// directly from the polynomial. That's the production-realistic
	// path for very large committees -- only the participating quorum
	// materialises shares; non-participants hold theirs in escrow on
	// chain or in HSM.
	stream := bytes.Repeat([]byte{0xc3}, (thresh-1)*SeedSize*4+8)
	// Deal at every interesting index in one pass by giving
	// shamirDealRandomQ a small committee that covers the corners.
	// We synthesise the polynomial by dealing across the full small
	// committee and then re-evaluating coefficients at the large
	// indices via a direct evaluation helper.
	//
	// Concretely: the dealer's polynomial coefficients are derived
	// deterministically from (secret, stream); we recompute them and
	// evaluate at the four extreme indices below.

	// Recompute coefficients exactly as shamirDealRandomQ does.
	coeffs := make([][SeedSize]uint32, thresh)
	for b := 0; b < SeedSize; b++ {
		coeffs[0][b] = uint32(secret[b])
	}
	off := 0
	for d := 1; d < thresh; d++ {
		for b := 0; b < SeedSize; b++ {
			r := uint32(stream[off])<<24 | uint32(stream[off+1])<<16 | uint32(stream[off+2])<<8 | uint32(stream[off+3])
			off += 4
			coeffs[d][b] = uint32(uint64(r) % shamirPrimeQ)
		}
	}
	evalAt := func(x uint32) shamirShareQ {
		var s shamirShareQ
		s.X = x
		xu := uint64(x)
		for b := 0; b < SeedSize; b++ {
			acc := uint64(coeffs[thresh-1][b])
			for d := thresh - 2; d >= 0; d-- {
				acc = (acc*xu + uint64(coeffs[d][b])) % shamirPrimeQ
			}
			s.Y[b] = uint32(acc)
		}
		return s
	}

	// Pick 5 evaluation points: 1, 2, mid, n-1, n.
	xs := []uint32{1, 2, uint32(n / 2), uint32(n - 1), uint32(n)}
	if int(xs[len(xs)-1]) != n {
		t.Fatalf("test setup bad: xs last = %d, want %d", xs[len(xs)-1], n)
	}
	shares := make([]shamirShareQ, len(xs))
	for i, x := range xs {
		shares[i] = evalAt(x)
	}

	rec, err := shamirReconstructQ(shares)
	if err != nil {
		t.Fatalf("reconstruct at N=%d failed: %v", n, err)
	}
	if rec != secret {
		t.Fatalf("N=%d reconstruction mismatch: got %x want %x", n, rec, secret)
	}
}

// TestShamirQ_LargeN_BoundaryCommittees walks a range of large
// committee sizes including N = 10 001 (just past the 10k bar), N =
// 100 000, N = 1 000 000, and N = TargetCommitteeSize. Each run does
// a single dealer at the requested N with a small threshold,
// reconstructs from t boundary shares, and asserts equality.
func TestShamirQ_LargeN_BoundaryCommittees(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping boundary-committee scan in -short mode")
	}
	for _, n := range []int{10_001, 100_000, 1_000_000, TargetCommitteeSize} {
		n := n
		t.Run("", func(t *testing.T) {
			const thresh = 4
			var secret [SeedSize]byte
			if _, err := rand.Read(secret[:]); err != nil {
				t.Fatal(err)
			}
			stream := bytes.Repeat([]byte{0xbe}, (thresh-1)*SeedSize*4+8)
			coeffs := make([][SeedSize]uint32, thresh)
			for b := 0; b < SeedSize; b++ {
				coeffs[0][b] = uint32(secret[b])
			}
			off := 0
			for d := 1; d < thresh; d++ {
				for b := 0; b < SeedSize; b++ {
					r := uint32(stream[off])<<24 | uint32(stream[off+1])<<16 | uint32(stream[off+2])<<8 | uint32(stream[off+3])
					off += 4
					coeffs[d][b] = uint32(uint64(r) % shamirPrimeQ)
				}
			}
			evalAt := func(x uint32) shamirShareQ {
				var s shamirShareQ
				s.X = x
				xu := uint64(x)
				for b := 0; b < SeedSize; b++ {
					acc := uint64(coeffs[thresh-1][b])
					for d := thresh - 2; d >= 0; d-- {
						acc = (acc*xu + uint64(coeffs[d][b])) % shamirPrimeQ
					}
					s.Y[b] = uint32(acc)
				}
				return s
			}
			xs := []uint32{1, 2, uint32(n - 1), uint32(n)}
			shares := make([]shamirShareQ, len(xs))
			for i, x := range xs {
				shares[i] = evalAt(x)
			}
			rec, err := shamirReconstructQ(shares)
			if err != nil {
				t.Fatalf("reconstruct at N=%d failed: %v", n, err)
			}
			if rec != secret {
				t.Fatalf("N=%d reconstruction mismatch: got %x want %x", n, rec, secret)
			}
		})
	}
}

func TestShamirQ_RejectsAbsurdN(t *testing.T) {
	var secret [SeedSize]byte
	// q − 1 is the maximum supported; q is one too many.
	if _, err := shamirDealRandomQ(secret, int(shamirPrimeQ), 2, nil); err != ErrCommitteeTooLargeQ {
		t.Fatalf("n=q not rejected: %v", err)
	}
}

func TestShamirQ_DuplicateEvalPoint(t *testing.T) {
	secret := [SeedSize]byte{0x42}
	shares, _ := shamirDealRandomQ(secret, 5, 3, bytes.Repeat([]byte{0xab}, 1024))
	shares[1].X = shares[0].X
	if _, err := shamirReconstructQ(shares[:3]); err != ErrDuplicateEvalPoint {
		t.Fatalf("duplicate eval points not detected, got %v", err)
	}
}

func TestShamirQ_ZeroEvalPoint(t *testing.T) {
	secret := [SeedSize]byte{0x42}
	shares, _ := shamirDealRandomQ(secret, 5, 3, bytes.Repeat([]byte{0xab}, 1024))
	shares[0].X = 0
	if _, err := shamirReconstructQ(shares[:3]); err != ErrZeroEvalPoint {
		t.Fatalf("zero eval point not detected, got %v", err)
	}
}

func TestShamirQ_ShareWireRoundTrip(t *testing.T) {
	share := shamirShareQ{X: 1_111_111, Y: [SeedSize]uint32{1, 2, 8_380_416, 100, 200}}
	wire := shareToBytesQ(share)
	rec := shareFromBytesQ(share.X, wire)
	if rec.X != share.X {
		t.Fatalf("X mismatch")
	}
	for i := range share.Y {
		if rec.Y[i] != share.Y[i] {
			t.Fatalf("Y[%d] mismatch: %d vs %d", i, rec.Y[i], share.Y[i])
		}
	}
}

func TestModInvQ_Correctness(t *testing.T) {
	for _, a := range []uint64{1, 2, 3, 7, 257, 1024, 8_380_415, 8_380_416} {
		inv := modInvQ(a)
		if (a*inv)%shamirPrimeQ != 1 {
			t.Fatalf("modInvQ wrong for a=%d (inv=%d, product=%d)", a, inv, (a*inv)%shamirPrimeQ)
		}
	}
}

func TestLagrangeAtZeroQ_AgreesWithReconstruction(t *testing.T) {
	const thresh = 3
	secret := [SeedSize]byte{0x55, 0xaa}
	stream := bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 256)
	shares, _ := shamirDealRandomQ(secret, thresh+2, thresh, stream)
	quorum := shares[:thresh]
	xs := []uint32{quorum[0].X, quorum[1].X, quorum[2].X}

	// Direct Lagrange combination at x=0 using LagrangeAtZeroQ.
	for b := 0; b < SeedSize; b++ {
		var acc uint64
		for i := 0; i < thresh; i++ {
			lam := uint64(LagrangeAtZeroQ(xs[i], xs))
			acc = (acc + lam*uint64(quorum[i].Y[b])) % shamirPrimeQ
		}
		if uint64(secret[b]) != acc {
			t.Fatalf("byte %d: secret=%d, lagrange=%d", b, secret[b], acc)
		}
	}
}

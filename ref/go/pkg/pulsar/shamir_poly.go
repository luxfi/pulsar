// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// shamir_poly.go — polynomial-coefficient-wise Shamir secret sharing
// over GF(q) where q = 8380417 is the FIPS 204 prime.
//
// The v0.2 algebraic threshold signer (threshold_v02.go) needs each
// party to hold a polynomial-vector share of the master (s1, s2, t0)
// such that the global polynomial equals the Lagrange combination of
// per-party shares evaluated at x=0. Since polynomial operations in
// the FIPS 204 ring are linear in each coefficient, Shamir-sharing
// coefficient-wise over GF(q) preserves the algebraic structure: a
// quorum can compute z = y + c·s without any party reconstructing s
// at any point in time.
//
// Domain separation: this file shares POLY-VECTOR secrets and reuses
// shamir_gfq.go's shamirPrimeQ. The byte-wise GF(q) sharing in that
// file is used by v0.1; the polynomial sharing here is the v0.2
// primitive.

import (
	"encoding/binary"
	"io"
)

// shamirPolyShare carries one party's share of a polynomial-vector
// secret. Each polynomial in Polys is the per-coefficient Shamir share
// at evaluation point X.
type shamirPolyShare struct {
	X     uint32  // evaluation point in [1, q); 1-indexed
	Polys polyVec // per-polynomial share value at X (each coeff in [0,q))
}

// shamirPolyDealRandom shares a polynomial vector across n parties
// with reconstruction threshold t. Each coefficient of each polynomial
// is independently Shamir-shared over GF(q) using a degree-(t-1)
// polynomial whose constant term is the secret coefficient.
//
// The per-share randomness is drawn from rng via rejection sampling
// of uint32 values mod q. Returns one shamirPolyShare per party with
// evaluation point i+1 (1-indexed).
func shamirPolyDealRandom(secret polyVec, n, t int, rng io.Reader) ([]shamirPolyShare, error) {
	if t < 1 || n < t {
		return nil, ErrInvalidThreshold
	}
	if uint64(n) > uint64(MaxCommitteeQ) {
		return nil, ErrCommitteeTooLargeQ
	}

	L := len(secret)
	// coeffs[d][li] = degree-d coefficient for the li-th poly in the secret.
	// coeffs[0][li] = secret[li] (normalised mod q).
	coeffs := make([][]poly, t)
	for d := 0; d < t; d++ {
		coeffs[d] = make([]poly, L)
	}
	for li := 0; li < L; li++ {
		coeffs[0][li] = secret[li]
		for ci := 0; ci < mldsaN; ci++ {
			coeffs[0][li][ci] = modQ(coeffs[0][li][ci])
		}
	}
	var buf [4]byte
	for d := 1; d < t; d++ {
		for li := 0; li < L; li++ {
			for ci := 0; ci < mldsaN; ci++ {
				for {
					if _, err := io.ReadFull(rng, buf[:]); err != nil {
						return nil, ErrShortRand
					}
					v := binary.LittleEndian.Uint32(buf[:]) & 0x7FFFFFFF
					if uint64(v) < shamirPrimeQ {
						coeffs[d][li][ci] = v
						break
					}
				}
			}
		}
	}

	shares := make([]shamirPolyShare, n)
	for i := 0; i < n; i++ {
		shares[i].X = uint32(i + 1)
		shares[i].Polys = make(polyVec, L)
		x := uint64(i + 1)
		for li := 0; li < L; li++ {
			for ci := 0; ci < mldsaN; ci++ {
				acc := uint64(coeffs[t-1][li][ci])
				for d := t - 2; d >= 0; d-- {
					acc = (acc*x + uint64(coeffs[d][li][ci])) % shamirPrimeQ
				}
				shares[i].Polys[li][ci] = uint32(acc)
			}
		}
	}

	// Zeroize the coefficient table — the higher-degree coefficients
	// embed the master secret-sharing polynomial.
	for d := range coeffs {
		for li := range coeffs[d] {
			for ci := range coeffs[d][li] {
				coeffs[d][li][ci] = 0
			}
		}
	}

	return shares, nil
}

// shamirPolyLambda computes the Lagrange coefficient λ_i at x=0 for
// the i-th party in the quorum, given the quorum's evaluation points.
//
//   λ_i(0) = Π_{j ≠ i}  (-x_j) / (x_i - x_j)  mod q
//
// Returns the value in [0, q).
func shamirPolyLambda(xs []uint32, i int) uint32 {
	num := uint64(1)
	den := uint64(1)
	for j := range xs {
		if j == i {
			continue
		}
		negXj := (shamirPrimeQ - uint64(xs[j])%shamirPrimeQ) % shamirPrimeQ
		num = (num * negXj) % shamirPrimeQ
		diff := (shamirPrimeQ + uint64(xs[i]) - uint64(xs[j])) % shamirPrimeQ
		den = (den * diff) % shamirPrimeQ
	}
	denInv := modInvQ(den)
	return uint32((num * denInv) % shamirPrimeQ)
}

// zeroizePolyShare overwrites every coefficient of every polynomial
// in the share.
func zeroizePolyShare(s *shamirPolyShare) {
	if s == nil {
		return
	}
	for i := range s.Polys {
		for j := range s.Polys[i] {
			s.Polys[i][j] = 0
		}
	}
}

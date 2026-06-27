// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// talus_mpc.go — the honest-majority MPC substrate the TALUS-MPC CarryCompare
// (CSCP) is built on: BGW secure multiplication over GF(q) Shamir shares and a
// shared-random-bit generator. These are REAL, SOUND, semi-honest honest-
// majority primitives (BGW, "Completeness Theorems for Non-Cryptographic
// Fault-Tolerant Distributed Computation", STOC 1988), TESTED for correctness,
// and they concretely enforce TALUS Theorem 10.1's N ≥ 2T−1 barrier: the
// product of two degree-(T−1) Shamir polynomials has degree 2(T−1), so its
// degree-reduction re-sharing is only sound when N ≥ 2T−1 (bgwMulShares refuses
// otherwise).
//
// SCOPE. This substrate is the multiplication/randomness layer a full CSCP
// secure-comparison circuit (bit-decomposition + prefix carry, or a DCF for the
// T=2 case) composes from. talus_cef.go documents exactly which CSCP step the
// secure comparison fills and computes the obstruction; this file provides the
// sound multiplication gate that step would call. The MALICIOUS-secure /
// identifiable-abort hardening (Feldman/Pedersen-committed shares + verified
// openings, TALUS Phase B) is the orthogonal residual; the arithmetic here is
// the honest, complete substrate.

import (
	"errors"
	"io"
)

var (
	// ErrBGWNotEnoughParties is returned when a degree-reducing multiplication
	// is attempted with N < 2T−1 parties — the degree-2(T−1) product cannot be
	// interpolated, so privacy/correctness fail (TALUS Theorem 10.1).
	ErrBGWNotEnoughParties = errors.New(
		"pulsar: BGW multiplication needs N ≥ 2T−1 (honest majority) — the " +
			"degree-2(T−1) product of two degree-(T−1) sharings is otherwise " +
			"unreconstructable (TALUS Theorem 10.1)")
	// ErrBGWShape rejects mismatched share/eval-point lengths.
	ErrBGWShape = errors.New("pulsar: BGW share/eval-point shape mismatch")
)

// shamirShareScalarGFq deals a scalar secret ∈ [0,q) across the parties at
// evalPoints with a fresh degree-(threshold−1) GF(q) polynomial whose constant
// term is the secret. Returns shares[p] = f(evalPoints[p]). Σ_p λ_p·shares[p] =
// secret by Lagrange at 0.
func shamirShareScalarGFq(secret uint32, evalPoints []uint32, threshold int, rng io.Reader) ([]uint32, error) {
	if threshold < 1 {
		return nil, ErrInvalidThreshold
	}
	coeffs := make([]uint32, threshold-1)
	for d := 0; d < threshold-1; d++ {
		v, err := randGFq(rng)
		if err != nil {
			return nil, err
		}
		coeffs[d] = v
	}
	out := make([]uint32, len(evalPoints))
	a0 := uint64(secret % mldsaQ)
	for p, xp := range evalPoints {
		x := uint64(xp)
		var acc uint64
		for d := threshold - 2; d >= 0; d-- {
			acc = (acc*x + uint64(coeffs[d])) % shamirPrimeQ
		}
		acc = (acc*x + a0) % shamirPrimeQ
		out[p] = uint32(acc)
	}
	return out, nil
}

// reconstructScalarGFq Lagrange-interpolates a parallel (evalPoints, shares)
// pair at X = 0. The caller is responsible for supplying ≥ degree+1 points; for
// a degree-(T−1) sharing that is any T points.
func reconstructScalarGFq(evalPoints, shares []uint32) (uint32, error) {
	if len(evalPoints) != len(shares) || len(shares) == 0 {
		return 0, ErrBGWShape
	}
	var acc uint64
	for i := range shares {
		lambda := LagrangeAtZeroQ(evalPoints[i], evalPoints)
		acc = (acc + uint64(lambda)*uint64(shares[i])) % shamirPrimeQ
	}
	return uint32(acc), nil
}

// bgwMulShares performs one BGW secure multiplication: given degree-(T−1)
// Shamir shares of X and Y at the same evalPoints (xShares[i], yShares[i] held
// by party i), it returns degree-(T−1) Shamir shares of X·Y at those same
// points — WITHOUT any party learning X, Y, or X·Y.
//
// Method (the standard BGW degree reduction):
//
//  1. Local product: party i computes p_i = xShares[i]·yShares[i]. The p_i lie
//     on the degree-2(T−1) polynomial f_X·f_Y, so {(x_i, p_i)} is a (non-fresh,
//     too-high-degree) sharing of X·Y.
//  2. Re-share: party i deals a FRESH degree-(T−1) Shamir sharing q_i of p_i.
//  3. Recombine: zShares[k] = Σ_i r_i·q_i[k], where r_i is the degree-2(T−1)
//     Lagrange-at-0 coefficient over ALL N points. Then Σ_i r_i·p_i = X·Y, so
//     {zShares[k]} is a fresh degree-(T−1) sharing of X·Y.
//
// Requires N ≥ 2T−1 (else step 3's interpolation of the degree-2(T−1) product
// is underdetermined). rng supplies the fresh re-sharing randomness.
func bgwMulShares(xShares, yShares, evalPoints []uint32, threshold int, rng io.Reader) ([]uint32, error) {
	n := len(evalPoints)
	if len(xShares) != n || len(yShares) != n {
		return nil, ErrBGWShape
	}
	if n < 2*threshold-1 {
		return nil, ErrBGWNotEnoughParties
	}
	// 1+2. Local products, each re-shared at degree T−1.
	reshares := make([][]uint32, n) // reshares[i][k] = q_i(x_k)
	for i := 0; i < n; i++ {
		p := uint32((uint64(xShares[i]) * uint64(yShares[i])) % shamirPrimeQ)
		q, err := shamirShareScalarGFq(p, evalPoints, threshold, rng)
		if err != nil {
			return nil, err
		}
		reshares[i] = q
	}
	// 3. Degree-reduction recombination via the degree-2(T−1) Lagrange weights.
	r := make([]uint32, n)
	for i := 0; i < n; i++ {
		r[i] = LagrangeAtZeroQ(evalPoints[i], evalPoints) // over all N points
	}
	zShares := make([]uint32, n)
	for k := 0; k < n; k++ {
		var acc uint64
		for i := 0; i < n; i++ {
			acc = (acc + uint64(r[i])*uint64(reshares[i][k])) % shamirPrimeQ
		}
		zShares[k] = uint32(acc)
	}
	return zShares, nil
}

// bgwAddShares is the free, local share addition (degree-preserving). Provided
// for symmetry with bgwMulShares so the CSCP circuit reads uniformly.
func bgwAddShares(xShares, yShares []uint32) ([]uint32, error) {
	if len(xShares) != len(yShares) {
		return nil, ErrBGWShape
	}
	out := make([]uint32, len(xShares))
	for i := range xShares {
		out[i] = uint32((uint64(xShares[i]) + uint64(yShares[i])) % shamirPrimeQ)
	}
	return out, nil
}

// bgwScalarMulShares multiplies a sharing by a PUBLIC scalar (local, free).
func bgwScalarMulShares(scalar uint32, xShares []uint32) []uint32 {
	out := make([]uint32, len(xShares))
	for i := range xShares {
		out[i] = uint32((uint64(xShares[i]) * uint64(scalar)) % shamirPrimeQ)
	}
	return out
}

// SharedRandomBit generates a degree-(threshold−1) Shamir sharing of a uniform
// bit b ∈ {0,1} held jointly by the parties, via XOR-folding of per-party
// private bits: b = b_0 ⊕ b_1 ⊕ ... ⊕ b_{N−1}, where each XOR
// u ⊕ v = u + v − 2uv is one BGW multiplication. The result is uniform as long
// as at least one party's bit is uniform and private (honest-majority). It is
// sqrt-free (avoids Tonelli–Shanks over q ≡ 1 mod 4) and exercises the
// multiplication substrate exactly as the CSCP carry circuit would. partyBits
// are the parties' private input bits (one per party).
func SharedRandomBit(evalPoints []uint32, threshold int, partyBits []bool, rng io.Reader) ([]uint32, error) {
	n := len(evalPoints)
	if len(partyBits) != n {
		return nil, ErrBGWShape
	}
	if n < 2*threshold-1 {
		return nil, ErrBGWNotEnoughParties
	}
	// Share each party's private bit (the party knows it; sharing is trivial).
	bitShares := make([][]uint32, n)
	for h := 0; h < n; h++ {
		var bit uint32
		if partyBits[h] {
			bit = 1
		}
		sh, err := shamirShareScalarGFq(bit, evalPoints, threshold, rng)
		if err != nil {
			return nil, err
		}
		bitShares[h] = sh
	}
	// XOR-fold: acc ⊕ b_h = acc + b_h − 2·acc·b_h.
	acc := bitShares[0]
	for h := 1; h < n; h++ {
		prod, err := bgwMulShares(acc, bitShares[h], evalPoints, threshold, rng)
		if err != nil {
			return nil, err
		}
		sum, err := bgwAddShares(acc, bitShares[h])
		if err != nil {
			return nil, err
		}
		twoProd := bgwScalarMulShares(2, prod)
		out := make([]uint32, n)
		for i := 0; i < n; i++ {
			// sum − 2·prod  (mod q)
			out[i] = uint32((uint64(sum[i]) + (shamirPrimeQ - uint64(twoProd[i]))) % shamirPrimeQ)
		}
		acc = out
	}
	return acc, nil
}

// randBitFromReader draws one uniform bit from rng (helper for tests/usage that
// supply per-party private bits to SharedRandomBit).
func randBitFromReader(rng io.Reader) (bool, error) {
	var b [1]byte
	if _, err := io.ReadFull(rng, b[:]); err != nil {
		return false, err
	}
	return b[0]&1 == 1, nil
}

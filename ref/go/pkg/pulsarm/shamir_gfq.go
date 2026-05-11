// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

// shamir_gfq.go -- byte-wise Shamir secret sharing over GF(q) where
// q = 8380417 is the FIPS 204 ML-DSA prime. This is the wide-field
// counterpart to shamir.go's GF(257) and unlocks committee sizes up
// to q-1 = 8 380 416 parties, with comfortable margin for the N >
// 10 000 large-committee regime documented in spec/pulsar-m.tex
// section "Large committees (N > 256)".
//
// Layout choice. Each per-byte share value is a uniform draw in
// [0, q). 23 bits fit in a uint32; we pack 4 bytes (big-endian) per
// share lane on the wire, giving 32 * 4 = 128 bytes per share Y.
// The wire layout is intentionally simple: every lane is a fixed-
// width uint32, eliminating bit-packing edge cases that the GF(257)
// path was carrying.
//
// Correctness. The reconstructed value at X = 0 is the original byte
// in [0, 256). To prove a value is a valid byte we range-check post
// reconstruction; the wide field tolerates the 8-bit secret without
// any modular folding.
//
// Security. Shamir over GF(q) with degree-(t-1) polynomial provides
// the same (t-1)-out-of-n information-theoretic privacy as the GF(257)
// path. The choice of q matches the ring modulus, which removes one
// distinct prime from the audit footprint: every modular arithmetic
// operation in Pulsar-M is now mod q.

import (
	"encoding/binary"
	"errors"
)

// shamirPrimeQ is the FIPS 204 prime q = 2^23 - 2^13 + 1.
const shamirPrimeQ uint64 = 8380417

// shamirShareQ contains one party's per-byte Shamir share over GF(q).
// X and each Y[b] are values in [0, q), stored in uint32 lanes.
type shamirShareQ struct {
	X uint32
	Y [SeedSize]uint32
}

// shareWireSizeQ is the byte length of a single shamirShareQ's Y in
// wire form (32 * uint32, big-endian).
const shareWireSizeQ = SeedSize * 4

// MaxCommitteeQ is the largest committee supported by GF(q) Shamir.
// We cap at q - 1 to keep eval points in [1, q). Production deploy-
// ments will typically be bounded by their consensus layer's own
// validator-count cap (a few thousand) long before this limit binds.
const MaxCommitteeQ = uint32(shamirPrimeQ - 1)

// LargeCommitteeThreshold is the committee size at which dkg.go,
// threshold.go, and reshare.go automatically switch from GF(257) to
// GF(q). Below this threshold the GF(257) path is preferred because
// its wire footprint (64 bytes/share vs 128 bytes/share) is half.
const LargeCommitteeThreshold = 256

// Errors specific to the GF(q) Shamir path.
var (
	ErrCommitteeTooLargeQ = errors.New("pulsarm: committee larger than GF(q) supports (n > q-1)")
)

// shamirDealRandomQ is the GF(q) counterpart of shamirDealRandom.
// Shares a 32-byte secret across n parties with reconstruction
// threshold t over GF(q). Each party 1..n gets a share at evaluation
// point i. The (t-1) polynomial coefficients per slot are pulled
// from coeffStream (which is stretched via cSHAKE256 if short).
func shamirDealRandomQ(secret [SeedSize]byte, n, t int, coeffStream []byte) ([]shamirShareQ, error) {
	if t < 1 || n < t {
		return nil, ErrInvalidThreshold
	}
	if uint64(n) > uint64(MaxCommitteeQ) {
		return nil, ErrCommitteeTooLargeQ
	}

	// Per-coefficient we need 4 bytes of stream (uint32 reduced mod q).
	needed := (t - 1) * SeedSize * 4
	if needed < 4 {
		needed = 4
	}
	if len(coeffStream) < needed {
		coeffStream = cshake256(coeffStream, needed, tagSeedShare)
	}

	// coeffs[d][b]: degree-d coefficient for byte-slot b.
	coeffs := make([][SeedSize]uint32, t)
	for b := 0; b < SeedSize; b++ {
		coeffs[0][b] = uint32(secret[b])
	}
	off := 0
	for d := 1; d < t; d++ {
		for b := 0; b < SeedSize; b++ {
			r := binary.BigEndian.Uint32(coeffStream[off : off+4])
			off += 4
			coeffs[d][b] = uint32(uint64(r) % shamirPrimeQ)
		}
	}

	shares := make([]shamirShareQ, n)
	for i := 1; i <= n; i++ {
		shares[i-1].X = uint32(i)
		x := uint64(i)
		for b := 0; b < SeedSize; b++ {
			// Horner: acc = (((c_{t-1} * x) + c_{t-2}) * x + ...) + c_0
			acc := uint64(coeffs[t-1][b])
			for d := t - 2; d >= 0; d-- {
				acc = (acc*x + uint64(coeffs[d][b])) % shamirPrimeQ
			}
			shares[i-1].Y[b] = uint32(acc)
		}
	}
	return shares, nil
}

// shamirReconstructQ Lagrange-interpolates a quorum of shamirShareQ
// at X = 0 to recover the original 32-byte secret. Returns an error
// if any reconstructed slot does not lie in [0, 256) -- which can
// only happen if at least one share was tampered with (an honest
// dealer always sets the constant term to a byte value).
func shamirReconstructQ(shares []shamirShareQ) ([SeedSize]byte, error) {
	gf, err := shamirReconstructGFQ(shares)
	if err != nil {
		return [SeedSize]byte{}, err
	}
	var out [SeedSize]byte
	for b := 0; b < SeedSize; b++ {
		if gf[b] >= 256 {
			return out, ErrInvalidShare
		}
		out[b] = byte(gf[b])
	}
	return out, nil
}

// shamirReconstructGFQ returns the raw GF(q) constant-term vector.
// Used by aggregation paths that re-mix the byte-sum through cSHAKE256
// before treating it as a seed.
func shamirReconstructGFQ(shares []shamirShareQ) ([SeedSize]uint32, error) {
	var out [SeedSize]uint32
	if len(shares) < 1 {
		return out, ErrNotEnoughShares
	}
	seen := make(map[uint32]struct{}, len(shares))
	for _, s := range shares {
		if s.X == 0 {
			return out, ErrZeroEvalPoint
		}
		if _, dup := seen[s.X]; dup {
			return out, ErrDuplicateEvalPoint
		}
		seen[s.X] = struct{}{}
	}

	t := len(shares)
	lambdas := make([]uint32, t)
	for i := 0; i < t; i++ {
		num := uint64(1)
		den := uint64(1)
		for j := 0; j < t; j++ {
			if i == j {
				continue
			}
			// num *= (-x_j) mod q
			negXj := (shamirPrimeQ - uint64(shares[j].X)) % shamirPrimeQ
			num = (num * negXj) % shamirPrimeQ
			// den *= (x_i - x_j) mod q
			diff := (shamirPrimeQ + uint64(shares[i].X) - uint64(shares[j].X)) % shamirPrimeQ
			den = (den * diff) % shamirPrimeQ
		}
		denInv := modInvQ(den)
		lambdas[i] = uint32((num * denInv) % shamirPrimeQ)
	}

	for b := 0; b < SeedSize; b++ {
		var acc uint64
		for i := 0; i < t; i++ {
			acc = (acc + uint64(lambdas[i])*uint64(shares[i].Y[b])) % shamirPrimeQ
		}
		out[b] = uint32(acc)
	}
	return out, nil
}

// modInvQ computes a^-1 mod q via Fermat's little theorem (q is prime).
// Constant-time in the bit pattern of a but not in q-2; q is a fixed
// compile-time constant so this is acceptable. Used only on
// non-secret Lagrange denominators.
func modInvQ(a uint64) uint64 {
	return modPowQ(a, shamirPrimeQ-2)
}

// modPowQ computes base^exp mod q via square-and-multiply.
func modPowQ(base, exp uint64) uint64 {
	result := uint64(1)
	b := base % shamirPrimeQ
	for exp > 0 {
		if exp&1 == 1 {
			result = (result * b) % shamirPrimeQ
		}
		b = (b * b) % shamirPrimeQ
		exp >>= 1
	}
	return result
}

// shareToBytesQ serialises a shamirShareQ's Y component to wire form
// (big-endian uint32 per byte position).
func shareToBytesQ(s shamirShareQ) [shareWireSizeQ]byte {
	var out [shareWireSizeQ]byte
	for b := 0; b < SeedSize; b++ {
		binary.BigEndian.PutUint32(out[4*b:4*b+4], s.Y[b])
	}
	return out
}

// shareFromBytesQ deserialises a wire-form Y component over GF(q).
func shareFromBytesQ(x uint32, buf [shareWireSizeQ]byte) shamirShareQ {
	var s shamirShareQ
	s.X = x
	for b := 0; b < SeedSize; b++ {
		s.Y[b] = binary.BigEndian.Uint32(buf[4*b : 4*b+4])
	}
	return s
}

// EvalPointFromIDQ derives a deterministic non-zero GF(q) Shamir
// evaluation point from a NodeID. The output lies in [1, q). Used
// by DKG / Reshare instances configured for the large-committee
// regime.
func EvalPointFromIDQ(id NodeID) uint32 {
	digest := cshake256(id[:], 4, tagSeedShare)
	v := binary.BigEndian.Uint32(digest)
	r := uint64(v) % (shamirPrimeQ - 1)
	return uint32(r + 1)
}

// LagrangeAtZeroQ returns the Lagrange coefficient at X = 0 for the
// party at evaluation point myX in the quorum allEvals over GF(q).
// Exposed for reshare contributions that need to pre-multiply old
// shares by their old-quorum Lagrange coefficient.
func LagrangeAtZeroQ(myX uint32, allEvals []uint32) uint32 {
	num := uint64(1)
	den := uint64(1)
	for _, xj := range allEvals {
		if xj == myX {
			continue
		}
		negXj := (shamirPrimeQ - uint64(xj)) % shamirPrimeQ
		num = (num * negXj) % shamirPrimeQ
		diff := (shamirPrimeQ + uint64(myX) - uint64(xj)) % shamirPrimeQ
		den = (den * diff) % shamirPrimeQ
	}
	return uint32((num * modInvQ(den)) % shamirPrimeQ)
}

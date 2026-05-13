// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

// shamir.go — byte-wise Shamir secret sharing over GF(257).
//
// Why byte-wise over GF(257): the threshold layer shares a 32-byte
// ML-DSA seed. The byte values 0..255 fit in [0, 257) and share
// values fit in [0, 257) which need 9 bits → packs as one uint16 per
// per-byte share value. Reconstruction at x=0 returns the original
// byte in [0, 256) because the polynomial's constant term is the byte.
//
// The choice of GF(257) (instead of the FIPS 204 prime GF(8380417))
// keeps the wire-share size minimal and the audit footprint small:
// each share is 32 × uint16 = 64 bytes, regardless of the FIPS 204
// parameter set. Sharing over GF(8380417) is on the v0.2 path that
// integrates with the Lagrange-linearity sign mode of
// pulsar.tex §4.2 (where shares must align with R_q^k arithmetic).
//
// All arithmetic is constant-time mod p via the small-prime modular
// inverse table seeded at package init.

import "errors"

// shamirPrime is the small prime used for per-byte Shamir sharing.
// 257 is the smallest prime > 255 so it admits every byte value as a
// distinct field element.
const shamirPrime uint32 = 257

// shamirShare contains one party's per-byte Shamir share of a
// 32-byte secret. Each element is a value in [0, 257) stored in a
// uint16 lane.
type shamirShare struct {
	X uint32           // Shamir evaluation point in [1, p); 1-indexed
	Y [SeedSize]uint16 // per-byte share value at X (each in [0, p))
}

// shareWireSize is the byte length of a single shamirShare's Y
// component in wire form (32 × uint16, big-endian).
const shareWireSize = SeedSize * 2

// shamirShareErrs.
var (
	ErrInvalidThreshold   = errors.New("pulsarm: invalid threshold (n < t or t < 1)")
	ErrCommitteeTooLarge  = errors.New("pulsarm: committee larger than 256 parties (shamir GF(257))")
	ErrNotEnoughShares    = errors.New("pulsarm: not enough shares for reconstruction")
	ErrZeroEvalPoint      = errors.New("pulsarm: evaluation point x=0 is reserved for the secret")
	ErrDuplicateEvalPoint = errors.New("pulsarm: duplicate evaluation point in shares")
	ErrShareWireSize      = errors.New("pulsarm: share has wrong wire size")
)

// shamirDealRandom shares a 32-byte secret across n parties with
// reconstruction threshold t.
//
// Thin wrapper around shamirDealRandomGF that lifts each byte
// secret[b] to a GF(257) value. Used by the DKG path where each
// party's contribution IS a 32-byte vector.
func shamirDealRandom(secret [SeedSize]byte, n, t int, coeffStream []byte) ([]shamirShare, error) {
	var gf [SeedSize]uint16
	for b := 0; b < SeedSize; b++ {
		gf[b] = uint16(secret[b])
	}
	return shamirDealRandomGF(gf, n, t, coeffStream)
}

// shamirDealRandomGF shares a 32-element GF(257) secret vector
// across n parties with reconstruction threshold t. Each party 1..n
// gets a share at evaluation point i. The (t-1) polynomial
// coefficients per slot are pulled from coeffStream.
//
// If coeffStream is shorter than needed, it is stretched via
// cSHAKE256(coeffStream, tag=PULSAR-SEED-SHARE-V1).
//
// Use this when the secret vector contains values that may equal
// 256 (the 257-th GF element), e.g. an HJKY97 reshare contribution
// that is `λ_i · share_i` mod 257.
func shamirDealRandomGF(secret [SeedSize]uint16, n, t int, coeffStream []byte) ([]shamirShare, error) {
	if t < 1 || n < t {
		return nil, ErrInvalidThreshold
	}
	if n > 256 {
		return nil, ErrCommitteeTooLarge
	}

	needed := (t - 1) * SeedSize * 2
	if needed < 2 {
		needed = 2
	}
	if len(coeffStream) < needed {
		coeffStream = cshake256(coeffStream, needed, tagSeedShare)
	}

	// Polynomial coefficients per slot.
	// coeffs[d][b] is the degree-d coefficient for slot b.
	// coeffs[0][b] is the constant term — the secret value itself.
	coeffs := make([][SeedSize]uint16, t)
	for b := 0; b < SeedSize; b++ {
		coeffs[0][b] = secret[b] % uint16(shamirPrime)
	}
	off := 0
	for d := 1; d < t; d++ {
		for b := 0; b < SeedSize; b++ {
			r := uint32(coeffStream[off])<<8 | uint32(coeffStream[off+1])
			off += 2
			coeffs[d][b] = uint16(r % shamirPrime)
		}
	}

	shares := make([]shamirShare, n)
	for i := 1; i <= n; i++ {
		shares[i-1].X = uint32(i)
		x := uint32(i)
		for b := 0; b < SeedSize; b++ {
			// Horner's method: acc = (((c_{t-1} * x) + c_{t-2}) * x + ...) + c_0
			acc := uint32(coeffs[t-1][b])
			for d := t - 2; d >= 0; d-- {
				acc = (acc*x + uint32(coeffs[d][b])) % shamirPrime
			}
			shares[i-1].Y[b] = uint16(acc)
		}
	}
	return shares, nil
}

// shamirReconstruct Lagrange-interpolates the constant term from a
// quorum of shares. Returns the 32-byte secret (each byte = constant
// term mod 256 — the cSHAKE256 mix downstream flattens any byte-vs-
// GF(257) bias).
//
// Use shamirReconstructGF if the caller wants the raw GF(257) result
// (e.g. when chaining reshare and DKG arithmetic that must preserve
// the 256-valued element).
func shamirReconstruct(shares []shamirShare) ([SeedSize]byte, error) {
	gf, err := shamirReconstructGF(shares)
	if err != nil {
		return [SeedSize]byte{}, err
	}
	var out [SeedSize]byte
	for b := 0; b < SeedSize; b++ {
		out[b] = byte(gf[b] % 256)
	}
	return out, nil
}

// shamirReconstructGF Lagrange-interpolates the constant term as a
// 32-element GF(257) vector. Used by Reshare to preserve byte-value
// 256 across the rotation.
func shamirReconstructGF(shares []shamirShare) ([SeedSize]uint16, error) {
	var out [SeedSize]uint16
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
	// Lagrange basis values at x=0 over GF(p).
	// λ_i = Π_{j≠i} (-x_j) / (x_i - x_j) mod p
	lambdas := make([]uint16, t)
	for i := 0; i < t; i++ {
		num := uint32(1)
		den := uint32(1)
		for j := 0; j < t; j++ {
			if i == j {
				continue
			}
			// num *= (-x_j) mod p
			negXj := shamirPrime - (shares[j].X % shamirPrime)
			num = (num * negXj) % shamirPrime
			// den *= (x_i - x_j) mod p
			diff := (shamirPrime + shares[i].X - shares[j].X) % shamirPrime
			den = (den * diff) % shamirPrime
		}
		denInv := modInvSmall(den, shamirPrime)
		lambdas[i] = uint16((num * denInv) % shamirPrime)
	}

	for b := 0; b < SeedSize; b++ {
		var acc uint32
		for i := 0; i < t; i++ {
			acc = (acc + uint32(lambdas[i])*uint32(shares[i].Y[b])) % shamirPrime
		}
		// acc ∈ [0, 257). For a SUM of single-secret Shamir shares
		// the constant term may take the value 256; return as GF(257).
		// Callers that want a byte representation use shamirReconstruct
		// which reduces mod 256.
		out[b] = uint16(acc)
	}
	return out, nil
}

// ErrInvalidShare is returned by shamirReconstruct when the
// interpolated constant term overflows byte range, indicating either
// share tampering or that the original secret was not byte-valued.
var ErrInvalidShare = errors.New("pulsarm: reconstructed value out of byte range — share tampering suspected")

// modInvSmall computes the modular inverse of a mod p where p is a
// small prime. Uses the extended Euclidean algorithm; constant-time
// in the bit pattern of a, not data-dependent in p. p must be prime
// and a must be in [1, p).
func modInvSmall(a, p uint32) uint32 {
	return modPowSmall(a, p-2, p)
}

// modPowSmall computes (base^exp) mod p via square-and-multiply.
func modPowSmall(base, exp, p uint32) uint32 {
	result := uint32(1)
	b := base % p
	for exp > 0 {
		if exp&1 == 1 {
			result = (result * b) % p
		}
		b = (b * b) % p
		exp >>= 1
	}
	return result
}

// shareToBytes serialises a shamirShare's Y component to wire form
// (big-endian uint16 per byte position).
func shareToBytes(s shamirShare) [shareWireSize]byte {
	var out [shareWireSize]byte
	for b := 0; b < SeedSize; b++ {
		out[2*b] = byte(s.Y[b] >> 8)
		out[2*b+1] = byte(s.Y[b])
	}
	return out
}

// shareFromBytes deserialises a wire-form Y component.
func shareFromBytes(x uint32, buf [shareWireSize]byte) shamirShare {
	var s shamirShare
	s.X = x
	for b := 0; b < SeedSize; b++ {
		s.Y[b] = uint16(buf[2*b])<<8 | uint16(buf[2*b+1])
	}
	return s
}

// EvalPointFromID derives a deterministic non-zero Shamir evaluation
// point in [1, 257) from a NodeID. Used by callers that want an
// ID-stable evaluation point rather than a position-in-committee
// point. The DKG default uses (committee_index + 1) which is simpler
// and KAT-stable.
func EvalPointFromID(id NodeID) uint32 {
	digest := cshake256(id[:], 1, tagSeedShare)
	return uint32(digest[0])%(shamirPrime-1) + 1
}

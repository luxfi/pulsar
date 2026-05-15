// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// largeshamir.go -- the public, large-committee Shamir surface.
//
// At committee sizes above GF(257)'s cap (n > 256), the Pulsar
// reference implementation switches to byte-wise Shamir over the
// FIPS 204 prime q = 8 380 417. This file exposes a clean Field-
// agnostic surface, so a chain integrator can drive Pulsar at
// committees ranging from 2 parties (a multisig) all the way to
// TargetCommitteeSize = 1 111 111 (the canonical "extreme committee"
// target for Lux's continental-scale validator set roadmap) with a
// single API.
//
// Wire compatibility. Below LargeCommitteeThreshold (256), the
// existing GF(257) KAT vectors are unchanged. At and above the
// threshold, share wire bytes are 128-byte (GF(q)) entries. The
// final FIPS 204 signature is byte-identical in either path -- the
// field choice never leaks past the DKG / Sign quorum boundary.

import "errors"

// LargeShareWire is the public wire form of one large-committee
// Pulsar share. Bytes are the big-endian uint32 lanes of the
// per-byte share, identical to shamirShareQ.Y.
type LargeShareWire [shareWireSizeQ]byte

// LargeShamir is the public Shamir API used by the large-committee
// DKG, threshold sign, and reshare paths. It hides the
// shamirShareQ / shamirShare split behind a Field-tagged value type.
type LargeShamir struct {
	Field Field
}

// Errors specific to the public LargeShamir surface.
var (
	ErrFieldMismatch = errors.New("pulsar: share field mismatch with deal context")
)

// Deal shares a secret across n parties with reconstruction threshold
// t. Each returned share carries its evaluation point and the per-
// byte Shamir lanes. The dealer's polynomial coefficients are pulled
// from coeffStream (cSHAKE-extended if short).
//
// Range: n ≤ MaxCommitteeQ (8 380 416). t ∈ [1, n]. Wire share size:
// shareWireSizeQ = 128 bytes.
func (LargeShamir) Deal(secret [SeedSize]byte, n, t int, coeffStream []byte) ([]uint32, []LargeShareWire, error) {
	shares, err := shamirDealRandomQ(secret, n, t, coeffStream)
	if err != nil {
		return nil, nil, err
	}
	xs := make([]uint32, n)
	wires := make([]LargeShareWire, n)
	for i := 0; i < n; i++ {
		xs[i] = shares[i].X
		w := shareToBytesQ(shares[i])
		wires[i] = LargeShareWire(w)
	}
	return xs, wires, nil
}

// Reconstruct Lagrange-interpolates a quorum's shares at X = 0 to
// recover the 32-byte secret. Returns ErrInvalidShare if any
// reconstructed slot exceeds 255 (i.e. at least one share was
// tampered with — an honest dealer always sets constant terms to
// byte values).
func (LargeShamir) Reconstruct(xs []uint32, wires []LargeShareWire) ([SeedSize]byte, error) {
	if len(xs) != len(wires) {
		return [SeedSize]byte{}, errors.New("pulsar: LargeShamir.Reconstruct: len(xs) != len(wires)")
	}
	shares := make([]shamirShareQ, len(xs))
	for i := range xs {
		shares[i] = shareFromBytesQ(xs[i], [shareWireSizeQ]byte(wires[i]))
	}
	return shamirReconstructQ(shares)
}

// ReconstructGF returns the raw GF(q) constant-term vector, used by
// aggregation paths that re-mix the byte-sum through cSHAKE256
// before treating it as a seed (mirroring the small-committee path
// in dkg.go).
func (LargeShamir) ReconstructGF(xs []uint32, wires []LargeShareWire) ([SeedSize]uint32, error) {
	if len(xs) != len(wires) {
		return [SeedSize]uint32{}, errors.New("pulsar: LargeShamir.ReconstructGF: len(xs) != len(wires)")
	}
	shares := make([]shamirShareQ, len(xs))
	for i := range xs {
		shares[i] = shareFromBytesQ(xs[i], [shareWireSizeQ]byte(wires[i]))
	}
	return shamirReconstructGFQ(shares)
}

// EvalAt returns the polynomial-derived share at evaluation point x
// for a polynomial whose coefficients are derived from (secret,
// coeffStream) the same way Deal would derive them. This is the
// "deal a single share without materialising all n" path used by
// production deployments at very large N where only the
// participating quorum needs concrete shares (non-participants hold
// theirs in escrow on chain or in an HSM and only materialise on
// demand).
//
// The cost is O(t * SeedSize) per share, independent of N.
func (LargeShamir) EvalAt(secret [SeedSize]byte, x uint32, t int, coeffStream []byte) (LargeShareWire, error) {
	if t < 1 {
		return LargeShareWire{}, ErrInvalidThreshold
	}
	if x == 0 {
		return LargeShareWire{}, ErrZeroEvalPoint
	}
	if uint64(x) >= shamirPrimeQ {
		return LargeShareWire{}, ErrCommitteeTooLargeQ
	}
	needed := (t - 1) * SeedSize * 4
	if needed < 4 {
		needed = 4
	}
	if len(coeffStream) < needed {
		coeffStream = cshake256(coeffStream, needed, tagSeedShare)
	}
	coeffs := make([][SeedSize]uint32, t)
	for b := 0; b < SeedSize; b++ {
		coeffs[0][b] = uint32(secret[b])
	}
	off := 0
	for d := 1; d < t; d++ {
		for b := 0; b < SeedSize; b++ {
			r := uint32(coeffStream[off])<<24 | uint32(coeffStream[off+1])<<16 | uint32(coeffStream[off+2])<<8 | uint32(coeffStream[off+3])
			off += 4
			coeffs[d][b] = uint32(uint64(r) % shamirPrimeQ)
		}
	}
	var s shamirShareQ
	s.X = x
	xu := uint64(x)
	for b := 0; b < SeedSize; b++ {
		acc := uint64(coeffs[t-1][b])
		for d := t - 2; d >= 0; d-- {
			acc = (acc*xu + uint64(coeffs[d][b])) % shamirPrimeQ
		}
		s.Y[b] = uint32(acc)
	}
	w := shareToBytesQ(s)
	return LargeShareWire(w), nil
}

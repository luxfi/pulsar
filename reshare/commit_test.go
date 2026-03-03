// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/luxfi/pulsar/sign"
	"github.com/luxfi/pulsar/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// TestCommitToPolyAndVerify — end-to-end commit/verify flow.
//
// 1. Build a t-degree polynomial (secret c_0..c_{t-1}, blind r_0..r_{t-1}).
// 2. Commit via CommitToPoly.
// 3. Evaluate (share, blind) at recipient β.
// 4. Verify via VerifyShareAgainstCommits.
//
// Should accept the honest share and reject a tampered share.
func TestCommitToPolyAndVerify(t *testing.T) {
	params, err := NewCommitParams(nil)
	if err != nil {
		t.Fatal(err)
	}
	const tThr = 3

	// Sample (c_k, r_k) for k = 0..t-1 from a Gaussian PRNG. We use
	// the same Gaussian as Pulsar secrets.
	prng, _ := sampling.NewKeyedPRNG([]byte("commit-test-prng"))
	gauss := ring.NewGaussianSampler(prng, params.R,
		ring.DiscreteGaussian{Sigma: sign.SigmaE, Bound: sign.BoundE}, false)

	secretCoeffs := make([]structs.Vector[ring.Poly], tThr)
	blindCoeffs := make([]structs.Vector[ring.Poly], tThr)
	for k := 0; k < tThr; k++ {
		secretCoeffs[k] = utils.SamplePolyVector(params.R, sign.N, gauss, false, false)
		blindCoeffs[k] = utils.SamplePolyVector(params.R, sign.N, gauss, false, false)
	}

	commits, err := CommitToPoly(params, secretCoeffs, blindCoeffs)
	if err != nil {
		t.Fatalf("CommitToPoly: %v", err)
	}
	if len(commits) != tThr {
		t.Fatalf("expected %d commits, got %d", tThr, len(commits))
	}

	// Evaluate (share, blind) at recipient β = 7.
	const beta = 7
	q := new(big.Int).SetUint64(sign.Q)
	share := hornerEvalVector(params.R, secretCoeffs, beta, q)
	blind := hornerEvalVector(params.R, blindCoeffs, beta, q)

	// Honest share should verify.
	if err := VerifyShareAgainstCommits(params, share, blind, commits, beta); err != nil {
		t.Fatalf("honest share rejected: %v", err)
	}

	// Tamper: flip one coefficient.
	tampered := cloneVectorPlain(params.R, share)
	tampered[0].Coeffs[0][0] ^= 1
	if err := VerifyShareAgainstCommits(params, tampered, blind, commits, beta); err == nil {
		t.Fatal("tampered share accepted (commitment is unsound)")
	} else if !errors.Is(err, ErrCommitMismatch) {
		t.Fatalf("expected ErrCommitMismatch, got %v", err)
	}

	// Wrong recipient β rejects honest share for the OTHER recipient.
	if err := VerifyShareAgainstCommits(params, share, blind, commits, beta+1); err == nil {
		t.Fatal("wrong recipient β accepted")
	}
}

// TestCommitDigestStable — same commits produce same digest.
func TestCommitDigestStable(t *testing.T) {
	params, _ := NewCommitParams(nil)
	prng, _ := sampling.NewKeyedPRNG([]byte("commit-digest-prng"))
	gauss := ring.NewGaussianSampler(prng, params.R,
		ring.DiscreteGaussian{Sigma: sign.SigmaE, Bound: sign.BoundE}, false)
	secretCoeffs := []structs.Vector[ring.Poly]{
		utils.SamplePolyVector(params.R, sign.N, gauss, false, false),
		utils.SamplePolyVector(params.R, sign.N, gauss, false, false),
	}
	blindCoeffs := []structs.Vector[ring.Poly]{
		utils.SamplePolyVector(params.R, sign.N, gauss, false, false),
		utils.SamplePolyVector(params.R, sign.N, gauss, false, false),
	}
	c, err := CommitToPoly(params, secretCoeffs, blindCoeffs)
	if err != nil {
		t.Fatal(err)
	}
	a := CommitDigest(c, nil)
	b := CommitDigest(c, nil)
	if a != b {
		t.Fatal("CommitDigest non-deterministic")
	}
	if bytes.Equal(a[:], make([]byte, 32)) {
		t.Fatal("CommitDigest is all zero")
	}
}

// hornerEvalVector evaluates Σ_k coeffs[k] * x^k in standard form.
// This mirrors the dealer-side Horner used in the reshare protocol.
func hornerEvalVector(r *ring.Ring, coeffs []structs.Vector[ring.Poly], x int, q *big.Int) structs.Vector[ring.Poly] {
	tThr := len(coeffs)
	N := r.N()
	out := make(structs.Vector[ring.Poly], sign.N)
	for vi := 0; vi < sign.N; vi++ {
		out[vi] = r.NewPoly()
	}
	bigX := big.NewInt(int64(x))
	for vi := 0; vi < sign.N; vi++ {
		for k := 0; k < N; k++ {
			acc := new(big.Int).SetUint64(coeffs[tThr-1][vi].Coeffs[0][k])
			for d := tThr - 2; d >= 0; d-- {
				acc.Mul(acc, bigX)
				acc.Add(acc, new(big.Int).SetUint64(coeffs[d][vi].Coeffs[0][k]))
				acc.Mod(acc, q)
			}
			out[vi].Coeffs[0][k] = acc.Uint64()
		}
	}
	return out
}

// cloneVectorPlain deep-copies a Share so test mutations don't bleed.
func cloneVectorPlain(r *ring.Ring, in structs.Vector[ring.Poly]) structs.Vector[ring.Poly] {
	_ = r
	out := make(structs.Vector[ring.Poly], len(in))
	for i, p := range in {
		out[i] = *p.CopyNew()
	}
	return out
}

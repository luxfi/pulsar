// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// mldsa_sample.go — Pulsar consumes the FIPS 204 SHAKE samplers (ExpandA,
// ExpandS, ExpandMask, SampleInBall) from the canonical
// github.com/luxfi/mlwe/sample/shake copy. That package was lifted
// verbatim, at the value level, from this package's former hand-rolled
// samplers, so routing through it is byte-identical BY CONSTRUCTION: a
// public key or signature produced via these adapters is the exact same
// bytes as before the de-dup.
//
// This file is the only Pulsar<->mlwe sampler bridge: it holds the
// uint64<->uint32 poly converter and the four FIPS 204 sampler entry
// points in Pulsar's own poly/polyVec shapes. ExpandA and ExpandS are
// consumed in their natural matrix/vector form (the nonce schedule
// i<<8|j and i / i+L is internal to mlwe). ExpandMask and SampleInBall
// keep per-poly Pulsar-named entries because callers — and the no-leak /
// transcript tests — invoke them per polynomial; the single-poly mask is
// recovered from the vector sampler with an L=1 profile and kappa=nonce,
// which samples exactly poly index nonce.

import (
	"github.com/luxfi/mlwe"
	"github.com/luxfi/mlwe/sample/shake"
)

// fromMLWE narrows an mlwe.Poly (uint64 coefficients) into Pulsar's
// [256]uint32 core. Every sampler output is < 2q < 2^32, so the cast is
// lossless.
func fromMLWE(m mlwe.Poly) poly {
	var out poly
	for i := 0; i < mldsaN; i++ {
		out[i] = uint32(m.Coeffs[i])
	}
	return out
}

// expandAPulsar derives Pulsar's public matrix A = ExpandA(rho)
// (FIPS 204 §3.5): K×L polynomials sampled directly in the NTT
// (evaluation) domain, byte-identical to circl's stored pk.A and to
// deriveKeyMaterial's km.a. The FIPS 204 nonce schedule i<<8|j is
// internal to mlwe.ExpandA.
func expandAPulsar(rho [32]byte, K, L int) []polyVec {
	am := shake.ExpandA(mlwe.Profile{N: mldsaN, Q: mldsaQ, K: K, L: L}, rho)
	a := make([]polyVec, K)
	for i := 0; i < K; i++ {
		a[i] = make(polyVec, L)
		for j := 0; j < L; j++ {
			a[i][j] = fromMLWE(am[i][j])
		}
	}
	return a
}

// expandSPulsar samples the secret vectors s1 (length L) and s2 (length
// K) from a 64-byte seed via the FIPS 204 centered-binomial sampler
// (ExpandS), with coefficients in the χ_η representation [q-η, q+η]. The
// nonce schedule (i for s1, i+L for s2) is internal to mlwe.ExpandS.
func expandSPulsar(rhoPrime [64]byte, K, L, eta int) (s1, s2 polyVec) {
	s1m, s2m := shake.ExpandS(mlwe.Profile{N: mldsaN, Q: mldsaQ, K: K, L: L, Eta: eta}, rhoPrime)
	s1 = make(polyVec, len(s1m))
	for i := range s1m {
		s1[i] = fromMLWE(s1m[i])
	}
	s2 = make(polyVec, len(s2m))
	for i := range s2m {
		s2[i] = fromMLWE(s2m[i])
	}
	return s1, s2
}

// expandMaskPoly fills p with one FIPS 204 ExpandMask polynomial —
// coefficients uniform in (-γ1, γ1], drawn from SHAKE-256(seed || nonce)
// — via the canonical mlwe sampler. mlwe exposes ExpandMask per vector;
// the single-poly form is recovered with an L=1 profile and kappa=nonce,
// which samples exactly poly index nonce. nonce is the per-poly index l
// (the per-attempt seed carries the round entropy, so no global κ).
func expandMaskPoly(p *poly, seed *[64]byte, nonce uint16, gamma1Bits uint32) {
	y := shake.ExpandMask(mlwe.Profile{N: mldsaN, Q: mldsaQ, L: 1, Gamma1: uint32(1) << gamma1Bits}, *seed, nonce)
	*p = fromMLWE(y[0])
}

// polyDeriveUniformBall fills p with the FIPS 204 SampleInBall challenge
// (τ nonzero ±1 coefficients, -1 stored as q-1) for seed, via the
// canonical mlwe sampler. SampleInBall is naturally per-poly, so this is
// a 1:1 adapter.
func polyDeriveUniformBall(p *poly, seed []byte, tau int) {
	*p = fromMLWE(shake.SampleInBall(mlwe.Profile{N: mldsaN, Q: mldsaQ, Tau: tau}, seed))
}

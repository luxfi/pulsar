// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// mldsa_lattice.go — FIPS 204 lattice primitives used by the threshold
// path (threshold.go) and the single-key BCC signer (bcc_sign.go).
//
// This file is a self-contained re-implementation of the polynomial-
// ring arithmetic needed for FIPS 204 ML-DSA signing. It mirrors the
// cloudflare/circl implementation byte-for-byte at the value level so
// that the threshold signer can produce signatures byte-identical to
// single-party mldsa{44,65,87}.SignTo. The reference for these
// constructions is FIPS 204 (NIST PQC Round 4 ML-DSA spec).
//
// Why re-implement instead of importing circl/internal/dilithium: the
// circl internal package is intentionally not exported. The threshold
// signer needs to operate on polynomial shares directly — the circl
// public API only exposes seed-derived signing, which is exactly what
// the threshold path must avoid. Re-implementing the primitives here
// gives us a single auditable surface within the pulsar package.
//
// All primitives in this file are package-private; the public signing
// surface lives in threshold.go and bcc_sign.go.
//
// The FIPS 204 SHAKE samplers (ExpandA/ExpandS/ExpandMask/SampleInBall)
// that formerly lived here are now consumed from the canonical
// github.com/luxfi/mlwe/sample/shake copy via the adapters in
// mldsa_sample.go, and the NTT/INTT/MulNTT ring core (and its zeta
// tables) from github.com/luxfi/mlwe/ring/mldsa via pulsarRing below —
// both byte-identical, since mlwe/ring/mldsa was lifted from this file.
// The remaining primitives here (raw add/sub, the reduceLe2Q/modQ
// reductions, Decompose/Power2Round in the a₀+q wire representation, the
// FIPS 204 bit-packers) stay Pulsar-side: mlwe exposes them only through
// the normalized [0,q) Ring/RoundingRing interface, a different byte
// representation than the wire frame and FindHint (boundary.go) require.

import (
	"github.com/luxfi/mlwe"
	mldsaring "github.com/luxfi/mlwe/ring/mldsa"
)

// pulsarRing is the canonical FIPS 204 ML-DSA ring core. NTT, INTT and
// MulNTT are parameter-set-independent (they touch only N, q and the
// zeta tables), so a single instance serves Pulsar-44/65/87.
var pulsarRing = mldsaring.MustNew(mldsaring.Profile65)

// Ring parameters per FIPS 204 §4. These are fixed across all three
// parameter sets (Pulsar-44, Pulsar-65, Pulsar-87).
const (
	mldsaN            = 256     // ring degree
	mldsaQ            = 8380417 // 2²³ - 2¹³ + 1
	mldsaD            = 13      // dropped low bits
	mldsaTRSize       = 64      // FIPS 204 ML-DSA SHAKE-256 hash of pk
	mldsaCTildeSize   = 48      // ML-DSA-65 c̃ length (λ=192 ⇒ λ/4)
	mldsaCTildeSize44 = 32      // ML-DSA-44 c̃ length (λ=128 ⇒ λ/4)
	mldsaCTildeSize87 = 64      // ML-DSA-87 c̃ length (λ=256 ⇒ λ/4)
	mldsaGamma2P65    = 261888  // (q-1)/32 for ML-DSA-65/87
	mldsaGamma2P44    = 95232   // (q-1)/88 for ML-DSA-44
)

// poly is the ML-DSA polynomial in R_q = Z_q[X]/(X^256 + 1). Coefficients
// are stored mod q (or mod 2q in transient states); per-coefficient
// arithmetic is performed in either Montgomery form (during NTT-domain
// work) or standard form.
type poly [mldsaN]uint32

// vecK and vecL hold the FIPS 204 module vectors of length K and L for
// each parameter set. Sized via slices since K and L vary by mode.
type polyVec []poly

// reduceLe2Q computes y < 2q with y ≡ x (mod q).
//
// Identical to circl's ReduceLe2Q. Constant-time (no data-dependent
// branches; the shift-and-add operates on the full machine word).
func reduceLe2Q(x uint32) uint32 {
	x1 := x >> 23
	x2 := x & 0x7FFFFF
	return x2 + (x1 << 13) - x1
}

// le2qModQ computes x mod q for 0 ≤ x < 2q.
func le2qModQ(x uint32) uint32 {
	x -= mldsaQ
	mask := uint32(int32(x) >> 31)
	return x + (mask & mldsaQ)
}

// modQ computes x mod q. Two-step reduction.
func modQ(x uint32) uint32 { return le2qModQ(reduceLe2Q(x)) }

// toMLWE widens Pulsar's [256]uint32 core into an mlwe.Poly for the
// ring-core delegations (ntt/invNTT/mulHat) below. fromMLWE
// (mldsa_sample.go) narrows back; both casts are lossless (< 2q < 2³²).
func (p *poly) toMLWE() mlwe.Poly {
	c := make([]uint64, mldsaN)
	for i := 0; i < mldsaN; i++ {
		c[i] = uint64(p[i])
	}
	return mlwe.Poly{Coeffs: c}
}

// power2round returns a₀ + q and a₁ with a = a₁·2^D + a₀ and -2^(D-1)
// < a₀ ≤ 2^(D-1). Used for the FIPS 204 Power2Round step in keygen.
func power2round(a uint32) (a0plusQ, a1 uint32) {
	a0 := a & ((1 << mldsaD) - 1)
	a0 -= (1 << (mldsaD - 1)) + 1
	a0 += uint32(int32(a0)>>31) & (1 << mldsaD)
	a0 -= (1 << (mldsaD - 1)) - 1
	a0plusQ = mldsaQ + a0
	a1 = (a - a0) >> mldsaD
	return
}

// Decompose splits 0 ≤ a < q into a₀, a₁ with a = a₁α + a₀ for α = 2γ₂.
//
// For Pulsar-65/87 (γ₂ = (q-1)/32 = 261888, α = 523776, a₁ ∈ [0, 16)).
// For Pulsar-44 (γ₂ = (q-1)/88 = 95232, α = 190464, a₁ ∈ [0, 44)).
//
// Returns a₀ + q (always in [1, q) for normalized input) and a₁.
func decompose(a uint32, gamma2 uint32) (a0plusQ, a1 uint32) {
	a1 = (a + 127) >> 7
	if gamma2 == mldsaGamma2P65 {
		// α = 523776 = (q-1)/16 · 2, a₁ ∈ [0,16)
		a1 = (a1*1025 + (1 << 21)) >> 22
		a1 &= 15
	} else if gamma2 == mldsaGamma2P44 {
		a1 = (a1*11275 + (1 << 23)) >> 24
		a1 ^= uint32(int32(43-a1)>>31) & a1
	} else {
		// Unsupported γ₂ — caller's responsibility to gate.
		return 0, 0
	}
	alpha := 2 * gamma2
	a0plusQ = a - a1*alpha
	a0plusQ += uint32(int32(a0plusQ-(mldsaQ-1)/2)>>31) & mldsaQ
	return
}

// polyReduceLe2Q normalises all coefficients of p to < 2q in place.
func (p *poly) reduceLe2Q() {
	for i := 0; i < mldsaN; i++ {
		p[i] = reduceLe2Q(p[i])
	}
}

// polyNormalize reduces each coefficient to [0, q).
func (p *poly) normalize() {
	for i := 0; i < mldsaN; i++ {
		p[i] = modQ(p[i])
	}
}

// polyAdd sets p = a + b (per-coefficient, no reduction).
func (p *poly) add(a, b *poly) {
	for i := 0; i < mldsaN; i++ {
		p[i] = a[i] + b[i]
	}
}

// polySub sets p = a - b mod 2q assuming coefficients of b are < 2q.
func (p *poly) sub(a, b *poly) {
	for i := 0; i < mldsaN; i++ {
		p[i] = a[i] + (2*mldsaQ - b[i])
	}
}

// mulHat sets p = a ∘ b, the NTT-domain pointwise Montgomery product,
// via the canonical ring core (mlwe MulNTT). The CT Montgomery
// convention is preserved exactly, so the multiply round-trip
// INTT(MulNTT(NTT(a),NTT(b))) == a·b holds (see invNTT).
func (p *poly) mulHat(a, b *poly) {
	out := pulsarRing.NewPoly()
	pulsarRing.MulNTT(out, a.toMLWE(), b.toMLWE())
	*p = fromMLWE(out)
}

// polyExceeds reports whether the "supnorm" of p (max central-rep
// absolute coefficient value) is ≥ bound. Assumes p is normalised.
// Constant-time over WHICH coefficient breaks (the FIPS 204 spec
// explicitly allows leaking position-of-break under rejection
// sampling, but not the value).
func (p *poly) exceeds(bound uint32) bool {
	for i := 0; i < mldsaN; i++ {
		x := int32((mldsaQ-1)/2) - int32(p[i])
		x ^= x >> 31
		x = int32((mldsaQ-1)/2) - x
		if uint32(x) >= bound {
			return true
		}
	}
	return false
}

// polyMulBy2toD sets p = 2^D · q. Caller must ensure coefficients fit
// in 32 bits after shift (i.e. < 2^(32-D)).
func (p *poly) mulBy2toD(q *poly) {
	for i := 0; i < mldsaN; i++ {
		p[i] = q[i] << mldsaD
	}
}

// polyPower2Round splits p into p0PlusQ and p1 per FIPS 204
// Power2Round. Requires p normalised.
func (p *poly) power2Round(p0PlusQ, p1 *poly) {
	for i := 0; i < mldsaN; i++ {
		p0PlusQ[i], p1[i] = power2round(p[i])
	}
}

// polyDotHat sets p = Σ_i a[i] · b[i] pointwise in Montgomery form.
// Coefficients of result bounded by 2|a|·q.
func polyDotHat(p *poly, a, b polyVec) {
	if len(a) != len(b) {
		// caller's contract — panic acceptable at this internal call site
		panic("pulsar: polyDotHat length mismatch")
	}
	var t poly
	*p = poly{}
	for i := range a {
		t.mulHat(&a[i], &b[i])
		p.add(&t, p)
	}
}

// ntt executes the in-place forward NTT on p via the canonical ring core
// (mlwe NTT). Output coefficients are left unreduced (< 18q), exactly as
// the verbatim core, for the multiply chain (mulHat, invNTT) to consume.
func (p *poly) ntt() {
	mp := p.toMLWE()
	pulsarRing.NTT(mp)
	*p = fromMLWE(mp)
}

// invNTT executes the inverse NTT on p via the canonical ring core (mlwe
// INTT): it reduces to < 2q first and normalizes into [0, q) after, per
// the mlwe RoundingRing contract. CT Montgomery convention — the bare
// round-trip INTT(NTT(p)) == R·p (R = 2³² mod q), NOT p; the real
// contract is the multiply round-trip INTT(MulNTT(NTT(a),NTT(b))) == a·b.
// Every Pulsar caller already normalizes after invNTT (only
// congruence-preserving add/sub intervene), so the bundled reduce/
// normalize is byte-identical to the former hand-reduced sequence.
func (p *poly) invNTT() {
	mp := p.toMLWE()
	pulsarRing.INTT(mp)
	*p = fromMLWE(mp)
}

// polyPackLeGamma1 packs p (coefficients in (-γ₁, γ₁]) into buf using
// gamma1Bits+1 bits per coefficient.
func polyPackLeGamma1(p *poly, buf []byte, gamma1Bits uint32) {
	gamma1 := uint32(1) << gamma1Bits
	if gamma1Bits == 17 {
		j := 0
		size := 18 * mldsaN / 8
		for i := 0; i+9 <= size; i += 9 {
			p0 := gamma1 - p[j]
			p0 += uint32(int32(p0)>>31) & mldsaQ
			p1 := gamma1 - p[j+1]
			p1 += uint32(int32(p1)>>31) & mldsaQ
			p2 := gamma1 - p[j+2]
			p2 += uint32(int32(p2)>>31) & mldsaQ
			p3 := gamma1 - p[j+3]
			p3 += uint32(int32(p3)>>31) & mldsaQ
			buf[i+0] = byte(p0)
			buf[i+1] = byte(p0 >> 8)
			buf[i+2] = byte(p0>>16) | byte(p1<<2)
			buf[i+3] = byte(p1 >> 6)
			buf[i+4] = byte(p1>>14) | byte(p2<<4)
			buf[i+5] = byte(p2 >> 4)
			buf[i+6] = byte(p2>>12) | byte(p3<<6)
			buf[i+7] = byte(p3 >> 2)
			buf[i+8] = byte(p3 >> 10)
			j += 4
		}
	} else if gamma1Bits == 19 {
		j := 0
		size := 20 * mldsaN / 8
		for i := 0; i+5 <= size; i += 5 {
			p0 := gamma1 - p[j]
			p0 += uint32(int32(p0)>>31) & mldsaQ
			p1 := gamma1 - p[j+1]
			p1 += uint32(int32(p1)>>31) & mldsaQ
			buf[i+0] = byte(p0)
			buf[i+1] = byte(p0 >> 8)
			buf[i+2] = byte(p0>>16) | byte(p1<<4)
			buf[i+3] = byte(p1 >> 4)
			buf[i+4] = byte(p1 >> 12)
			j += 2
		}
	}
}

// polyPackT1 packs p (coefficients ≤ 2^(QBits-D) = 2^10) into buf at
// 10 bits per coefficient. PolyT1Size = N · (QBits-D) / 8 = N · 10/8 = 320.
func polyPackT1(p *poly, buf []byte) {
	for i := 0; i < mldsaN/4; i++ {
		buf[5*i+0] = byte(p[4*i+0])
		buf[5*i+1] = byte(p[4*i+0]>>8) | byte(p[4*i+1]<<2)
		buf[5*i+2] = byte(p[4*i+1]>>6) | byte(p[4*i+2]<<4)
		buf[5*i+3] = byte(p[4*i+2]>>4) | byte(p[4*i+3]<<6)
		buf[5*i+4] = byte(p[4*i+3] >> 2)
	}
}

// polyPackT0 packs p (centred-rep coefficients in (-2^(D-1), 2^(D-1)])
// into buf at D=13 bits per coefficient. PolyT0Size = N · D / 8 = 416.
func polyPackT0(p *poly, buf []byte) {
	const halfD = 1 << (mldsaD - 1)
	for i := 0; i < mldsaN/8; i++ {
		var t [8]uint32
		for j := 0; j < 8; j++ {
			t[j] = halfD - p[8*i+j] + mldsaQ
			t[j] = ((t[j] >> 31) & mldsaQ) + t[j]
			// Now t[j] is in [0, 2^D)
		}
		buf[13*i+0] = byte(t[0])
		buf[13*i+1] = byte(t[0]>>8) | byte(t[1]<<5)
		buf[13*i+2] = byte(t[1] >> 3)
		buf[13*i+3] = byte(t[1]>>11) | byte(t[2]<<2)
		buf[13*i+4] = byte(t[2]>>6) | byte(t[3]<<7)
		buf[13*i+5] = byte(t[3] >> 1)
		buf[13*i+6] = byte(t[3]>>9) | byte(t[4]<<4)
		buf[13*i+7] = byte(t[4] >> 4)
		buf[13*i+8] = byte(t[4]>>12) | byte(t[5]<<1)
		buf[13*i+9] = byte(t[5]>>7) | byte(t[6]<<6)
		buf[13*i+10] = byte(t[6] >> 2)
		buf[13*i+11] = byte(t[6]>>10) | byte(t[7]<<3)
		buf[13*i+12] = byte(t[7] >> 5)
	}
}

// polyPackW1 packs the high-bits polynomial p into buf for the
// challenge hash. The packing width depends on γ₂.
//
//	γ₂ = 261888: 4-bit packing (PolyW1Size = N/2 = 128 bytes/poly).
//	γ₂ =  95232: 6-bit packing (PolyW1Size = N · 6 / 8 = 192).
func polyPackW1(p *poly, buf []byte, gamma2 uint32) {
	if gamma2 == mldsaGamma2P65 {
		for i := 0; i < mldsaN/2; i++ {
			buf[i] = byte(p[2*i]) | byte(p[2*i+1]<<4)
		}
	} else if gamma2 == mldsaGamma2P44 {
		for i := 0; i < mldsaN/4; i++ {
			buf[3*i+0] = byte(p[4*i+0]) | byte(p[4*i+1]<<6)
			buf[3*i+1] = byte(p[4*i+1]>>2) | byte(p[4*i+2]<<4)
			buf[3*i+2] = byte(p[4*i+2]>>4) | byte(p[4*i+3]<<2)
		}
	}
}

// polyVecPackHint packs the K-vector hint into buf of length omega+K.
func polyVecPackHint(v polyVec, buf []byte, omega int) {
	off := uint8(0)
	for i := range v {
		for j := uint16(0); j < mldsaN; j++ {
			if v[i][j] != 0 {
				buf[off] = uint8(j)
				off++
			}
		}
		buf[omega+i] = off
	}
	for ; off < uint8(omega); off++ {
		buf[off] = 0
	}
}

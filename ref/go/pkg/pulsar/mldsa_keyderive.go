// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// mldsa_keyderive.go — FIPS 204 ML-DSA KeyGen from a 32-byte seed.
//
// This file is used by the v0.2 algebraic threshold signer
// (threshold_v02.go) to derive the (s1, s2, t0, A, tr, key, ρ) tuple
// from the master seed during a TRUSTED setup. The output (s1, s2, t0)
// is then polynomial-Shamir-shared across the committee via
// shamir_poly.go. The master seed is destroyed before any signing.
//
// Byte-for-byte compatible with cloudflare/circl's NewKeyFromSeed: any
// signature produced by the v0.2 threshold path against the resulting
// (ρ, t1) public key verifies under unmodified mldsa{44,65,87}.Verify.

import (
	"golang.org/x/crypto/sha3"
)

// mldsaKeyMaterial is the full FIPS 204 ML-DSA private key state
// expanded from a 32-byte seed. After expansion, the seed itself is
// no longer needed; the v0.2 threshold protocol shares (s1, s2, t0)
// over the committee and the (ρ, key, tr) tuple is broadcast as
// public per-party data so every party can derive the matrix A and
// the message-binding hash μ identically.
//
// All polynomial fields are stored in STANDARD (un-NTT'd) coefficient
// form. NTT-domain copies are computed locally at sign time.
type mldsaKeyMaterial struct {
	rho [32]byte  // ρ — public matrix seed
	key [32]byte  // K — signing key seed (FIPS 204 sk-binding)
	tr  [64]byte  // tr = SHAKE-256(pk, 64)
	s1  polyVec   // length L, coefficients in [q-η, q+η]
	s2  polyVec   // length K, coefficients in [q-η, q+η]
	t0  polyVec   // length K, centred-rep low bits, un-normalised
	t1  polyVec   // length K, high bits in [0, 2^10)
	a   []polyVec // K × L public matrix derived from ρ (NTT-domain)
	pub []byte    // packed public key per FIPS 204 §5.1
	prv []byte    // packed private key (full FIPS 204 sk encoding)
}

// modeShape returns (K, L, η) for the given Mode.
func modeShape(mode Mode) (k, l int, eta uint32) {
	switch mode {
	case ModeP44:
		return 4, 4, 2
	case ModeP65:
		return 6, 5, 4
	case ModeP87:
		return 8, 7, 2
	}
	return 0, 0, 0
}

// modeTauOmega returns (τ, ω, γ₁Bits, γ₂) for the given Mode.
func modeTauOmega(mode Mode) (tau, omega int, gamma1Bits, gamma2 uint32) {
	switch mode {
	case ModeP44:
		return 39, 80, 17, mldsaGamma2P44
	case ModeP65:
		return 49, 55, 19, mldsaGamma2P65
	case ModeP87:
		return 60, 75, 19, mldsaGamma2P65
	}
	return 0, 0, 0, 0
}

// modeCTildeSize returns the FIPS 204 challenge-hash length for mode.
func modeCTildeSize(mode Mode) int {
	switch mode {
	case ModeP44:
		return mldsaCTildeSize44
	case ModeP65, ModeP87:
		return mldsaCTildeSize
	}
	return 0
}

// deriveKeyMaterial expands a 32-byte seed into the full FIPS 204
// ML-DSA private key state for the given mode. Byte-identical to
// circl's NewKeyFromSeed; runs once per (seed, mode) pair during the
// trusted DKG ceremony tail.
//
// This function is the ONLY place v0.2 touches the master seed.
// Callers MUST zeroize the seed argument and the returned key material
// once polynomial shares are derived and distributed.
func deriveKeyMaterial(mode Mode, seed *[SeedSize]byte) (*mldsaKeyMaterial, error) {
	K, L, eta := modeShape(mode)
	if K == 0 {
		return nil, ErrUnknownMode
	}
	var km mldsaKeyMaterial
	km.s1 = make(polyVec, L)
	km.s2 = make(polyVec, K)
	km.t0 = make(polyVec, K)
	km.t1 = make(polyVec, K)
	km.a = make([]polyVec, K)
	for i := range km.a {
		km.a[i] = make(polyVec, L)
	}

	// FIPS 204: SHAKE-256(seed || K_byte || L_byte) → eSeed[128].
	var eSeed [128]byte
	var sSeed [64]byte
	h := sha3.NewShake256()
	_, _ = h.Write(seed[:])
	_, _ = h.Write([]byte{byte(K), byte(L)})
	_, _ = h.Read(eSeed[:])

	copy(km.rho[:], eSeed[:32])
	copy(sSeed[:], eSeed[32:96])
	copy(km.key[:], eSeed[96:128])

	// Derive A from ρ: K × L block of polynomials.
	for i := 0; i < K; i++ {
		for j := 0; j < L; j++ {
			polyDeriveUniform(&km.a[i][j], &km.rho, uint16(i)<<8|uint16(j))
		}
	}

	// Sample s1 (length L) and s2 (length K).
	for i := 0; i < L; i++ {
		polyDeriveUniformLeqEta(&km.s1[i], &sSeed, uint16(i), eta)
	}
	for i := 0; i < K; i++ {
		polyDeriveUniformLeqEta(&km.s2[i], &sSeed, uint16(i+L), eta)
	}

	// Compute t = A · s1 + s2 (NTT-domain mul, then InvNTT).
	s1Hat := make(polyVec, L)
	for i := 0; i < L; i++ {
		s1Hat[i] = km.s1[i]
		s1Hat[i].ntt()
	}
	t := make(polyVec, K)
	for i := 0; i < K; i++ {
		polyDotHat(&t[i], km.a[i], s1Hat)
		t[i].reduceLe2Q()
		t[i].invNTT()
	}
	for i := 0; i < K; i++ {
		// t = t + s2 (s2 unnormalised in [q-η, q+η]).
		t[i].add(&t[i], &km.s2[i])
	}
	for i := 0; i < K; i++ {
		t[i].normalize()
	}

	// Power2Round: t = t1 · 2^D + t0, with t0 ∈ (-2^(D-1), 2^(D-1)].
	for i := 0; i < K; i++ {
		t[i].power2Round(&km.t0[i], &km.t1[i])
	}

	// Pack public key (ρ || PackT1(t1)).
	pubKeySize := 32 + 320*K
	km.pub = make([]byte, pubKeySize)
	copy(km.pub[:32], km.rho[:])
	for i := 0; i < K; i++ {
		polyPackT1(&km.t1[i], km.pub[32+320*i:32+320*(i+1)])
	}

	// tr = SHAKE-256(pk, 64).
	h.Reset()
	_, _ = h.Write(km.pub[:])
	_, _ = h.Read(km.tr[:])

	// Pack private key. The pulsar v0.2 path does NOT need the packed
	// sk wire form, but compute it for cross-check + key-equality tests.
	polyLeqEtaSize := (mldsaN * 4) / 8 // matches Eta-2 and Eta-4 (DoubleEtaBits=3 or 4)
	if eta == 2 {
		polyLeqEtaSize = (mldsaN * 3) / 8
	}
	privKeySize := 32 + 32 + 64 + polyLeqEtaSize*(L+K) + 416*K
	km.prv = make([]byte, privKeySize)
	copy(km.prv[:32], km.rho[:])
	copy(km.prv[32:64], km.key[:])
	copy(km.prv[64:128], km.tr[:])
	off := 128
	for i := 0; i < L; i++ {
		polyPackLeqEta(&km.s1[i], km.prv[off:off+polyLeqEtaSize], eta)
		off += polyLeqEtaSize
	}
	for i := 0; i < K; i++ {
		polyPackLeqEta(&km.s2[i], km.prv[off:off+polyLeqEtaSize], eta)
		off += polyLeqEtaSize
	}
	for i := 0; i < K; i++ {
		polyPackT0(&km.t0[i], km.prv[off:off+416])
		off += 416
	}

	// NOTE: km.a is already in NTT-domain. PolyDeriveUniform is FIPS 204
	// §3.5 ExpandA, which samples coefficients DIRECTLY into the NTT
	// representation — no forward NTT step is required. Confirmed by
	// byte-equal comparison against cloudflare/circl's pk.A field
	// (PolyDeriveUniform output == circl's stored A matrix).
	//
	// A previous version of this file NTT'd km.a once more here; that
	// produced double-NTT'd values which caused v0.3 AlgebraicAggregate
	// signatures to fail mldsa{44,65,87}.Verify even though keygen pub
	// was byte-equal (because keygen uses A correctly while signing
	// consumed setup.A = km.a in its double-NTT'd form). See
	// PULSAR-V03-1 in BLOCKERS.md. Guarded by
	// TestAMatrix_IsAlreadyInNTTDomain (compares km.a vs circl.pk.A at
	// [0][0] and [K-1][L-1] byte-for-byte).

	return &km, nil
}

// polyPackLeqEta packs p (un-normalised in [q-η, q+η]) into buf using
// the FIPS 204 PolyEta packing.
func polyPackLeqEta(p *poly, buf []byte, eta uint32) {
	if eta == 4 {
		// 4 bits per coefficient — DoubleEtaBits = 4.
		j := 0
		size := mldsaN * 4 / 8
		for i := 0; i < size; i++ {
			buf[i] = byte(mldsaQ+eta-p[j]) | (byte(mldsaQ+eta-p[j+1]) << 4)
			j += 2
		}
	} else if eta == 2 {
		// 3 bits per coefficient — DoubleEtaBits = 3.
		j := 0
		size := mldsaN * 3 / 8
		for i := 0; i < size; i += 3 {
			buf[i] = byte(mldsaQ+eta-p[j]) |
				(byte(mldsaQ+eta-p[j+1]) << 3) |
				(byte(mldsaQ+eta-p[j+2]) << 6)
			buf[i+1] = (byte(mldsaQ+eta-p[j+2]) >> 2) |
				(byte(mldsaQ+eta-p[j+3]) << 1) |
				(byte(mldsaQ+eta-p[j+4]) << 4) |
				(byte(mldsaQ+eta-p[j+5]) << 7)
			buf[i+2] = (byte(mldsaQ+eta-p[j+5]) >> 1) |
				(byte(mldsaQ+eta-p[j+6]) << 2) |
				(byte(mldsaQ+eta-p[j+7]) << 5)
			j += 8
		}
	}
}

// zeroizeKeyMaterial overwrites every secret-bearing field of km.
// Public fields (rho, t1, pub, A) are not touched — they are not
// secret-bearing.
func zeroizeKeyMaterial(km *mldsaKeyMaterial) {
	if km == nil {
		return
	}
	for i := range km.key {
		km.key[i] = 0
	}
	for i := range km.s1 {
		for j := range km.s1[i] {
			km.s1[i][j] = 0
		}
	}
	for i := range km.s2 {
		for j := range km.s2[i] {
			km.s2[i][j] = 0
		}
	}
	for i := range km.t0 {
		for j := range km.t0[i] {
			km.t0[i][j] = 0
		}
	}
	if km.prv != nil {
		for i := range km.prv {
			km.prv[i] = 0
		}
	}
}

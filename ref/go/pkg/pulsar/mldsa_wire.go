// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// mldsa_wire.go — shared FIPS 204 wire-format helpers for the v0.3
// algebraic-aggregate threshold path (threshold_v03.go) and the wire
// codec in wire.go. These primitives are pure mathematics over the
// FIPS 204 ring; they hold no protocol-version semantics.
//
// Single source of truth. The same helpers were previously co-located
// with the v0.2 transitional code; v0.2 has been retired from pulsar
// core (the TEE-only variant lives at luxfi/threshold/protocols/mldsa-tee/).
// Splitting them here documents that these are version-agnostic ring
// primitives, not part of any single protocol round.

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// modeGamma1Bits returns the FIPS 204 γ_1 bit-width for the given mode.
func modeGamma1Bits(mode Mode) uint32 {
	switch mode {
	case ModeP44:
		return 17
	case ModeP65, ModeP87:
		return 19
	}
	return 0
}

// packPolyVec packs a polynomial vector into a flat byte buffer
// (4 bytes per coefficient, little-endian, un-NTT'd, normalised in
// [0, q)). Used by the v0.3 Round-2 wire payload (W / Z / CS2 / CT0).
func packPolyVec(v polyVec) []byte {
	out := make([]byte, 4*mldsaN*len(v))
	off := 0
	for i := range v {
		for j := 0; j < mldsaN; j++ {
			binary.LittleEndian.PutUint32(out[off:off+4], v[i][j])
			off += 4
		}
	}
	return out
}

// unpackPolyVec is the inverse of packPolyVec for an n-polynomial
// vector. Returns a fresh polyVec.
func unpackPolyVec(buf []byte, n int) polyVec {
	v := make(polyVec, n)
	off := 0
	for i := 0; i < n; i++ {
		for j := 0; j < mldsaN; j++ {
			v[i][j] = binary.LittleEndian.Uint32(buf[off : off+4])
			off += 4
		}
	}
	return v
}

// decomposeVec applies polyDecompose to every polynomial in v, returning
// (a1, a0PlusQ) per FIPS 204 §4.5.
func decomposeVec(v polyVec, gamma2 uint32) (high, lowPlusQ polyVec) {
	K := len(v)
	high = make(polyVec, K)
	lowPlusQ = make(polyVec, K)
	for i := 0; i < K; i++ {
		v[i].decompose(&lowPlusQ[i], &high[i], gamma2)
	}
	return high, lowPlusQ
}

// packW1Vec packs the high-bits vector for the FIPS 204 challenge hash.
func packW1Vec(w1 polyVec, gamma2 uint32, K int) []byte {
	var polyW1Size int
	if gamma2 == mldsaGamma2P65 {
		polyW1Size = mldsaN / 2
	} else {
		polyW1Size = mldsaN * 6 / 8
	}
	out := make([]byte, polyW1Size*K)
	for i := 0; i < K; i++ {
		polyPackW1(&w1[i], out[polyW1Size*i:polyW1Size*(i+1)], gamma2)
	}
	return out
}

// polyDeriveUniformBounded samples p with coefficients uniform in
// (-bound, bound] from a SHAKE-256(seed ‖ nonce) byte-stream via
// rejection sampling. Output coefficients are stored normalised in
// [0, q) — positive values map to themselves; negative values are
// stored as q + r where r is the centred value.
//
// Per FROST-for-FSwA, the per-party y_i is sampled with bound =
// (γ_1 - 2β) / t so the quorum sum lies in (-γ_1 + 2β, γ_1 - 2β]
// with probability 1 (worst case bounds are exact), leaving headroom
// for the c · s_1 contribution to keep z within the FIPS 204 envelope.
//
// Rejection sampling rate: ≈ (2·bound + 1) / 2^32, which is well
// above 50% for bound ≥ 2^15; the expected number of trials per
// coefficient is < 2.
func polyDeriveUniformBounded(p *poly, seed *[64]byte, nonce uint16, bound uint32) {
	var iv [66]byte
	copy(iv[:64], seed[:])
	iv[64] = byte(nonce)
	iv[65] = byte(nonce >> 8)
	h := sha3.NewShake256()
	_, _ = h.Write(iv[:])
	var buf [4]byte
	span := uint64(bound)*2 + 1
	threshold := uint64(0x100000000) - (uint64(0x100000000) % span)
	for i := 0; i < mldsaN; i++ {
		for {
			_, _ = h.Read(buf[:])
			v := uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24
			if v >= threshold {
				continue
			}
			r := v % span
			centered := int64(r) - int64(bound)
			if centered < 0 {
				p[i] = uint32(int64(mldsaQ) + centered)
			} else {
				p[i] = uint32(centered)
			}
			break
		}
	}
}

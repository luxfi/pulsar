// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// mldsa_wire.go — shared FIPS 204 wire-format helpers used by the
// threshold path (threshold.go), the single-key BCC signer
// (bcc_sign.go), and the wire codec in wire.go. These primitives are
// pure mathematics over the FIPS 204 ring; they are version-agnostic
// and hold no protocol-round semantics.

import (
	"encoding/binary"
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
// [0, q)). Used wherever a polynomial vector is serialized for the
// wire (packed z-shares, HighBits commitments).
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
// vector. Returns a fresh polyVec. The caller MUST have validated the
// length (4·N·n) — use unpackPolyVecChecked for UNTRUSTED input (a short
// buffer panics here).
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

// unpackPolyVecChecked is the length-validating unpack for UNTRUSTED bytes
// (e.g. an attacker-supplied Partial.ZShare). It returns ErrWireLengthMismatch
// instead of panicking on a truncated/oversized buffer — closing a malformed-
// share DoS in the aggregation path.
func unpackPolyVecChecked(buf []byte, n int) (polyVec, error) {
	if len(buf) != 4*mldsaN*n {
		return nil, ErrWireLengthMismatch
	}
	return unpackPolyVec(buf, n), nil
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

// unpackW1Vec is the exact inverse of packW1Vec: it recovers the K-vector
// of HighBits polynomials from the canonical packed bytes a NonceCert
// carries. The no-reconstruct aggregator needs w1 in polynomial form to run
// FindHint(w', w1); because w1 is the PUBLIC challenge target, any verifier
// reconstructs it from the cert alone. Round-trips byte-for-byte with
// polyPackW1 over the in-range HighBits values.
//
// For the BCC-proven scope (ML-DSA-65/87, γ2 = (q−1)/32) the packing is two
// 4-bit nibbles per byte; ML-DSA-44 (6-bit) is handled for completeness but
// is out of the BCC scope. Returns ErrWireLengthMismatch on a short buffer.
func unpackW1Vec(buf []byte, gamma2 uint32, K int) (polyVec, error) {
	var polyW1Size int
	if gamma2 == mldsaGamma2P65 {
		polyW1Size = mldsaN / 2
	} else {
		polyW1Size = mldsaN * 6 / 8
	}
	if len(buf) != polyW1Size*K {
		return nil, ErrWireLengthMismatch
	}
	w1 := make(polyVec, K)
	for i := 0; i < K; i++ {
		polyUnpackW1(&w1[i], buf[polyW1Size*i:polyW1Size*(i+1)], gamma2)
	}
	return w1, nil
}

// polyUnpackW1 is the inverse of polyPackW1 for one polynomial.
func polyUnpackW1(p *poly, buf []byte, gamma2 uint32) {
	if gamma2 == mldsaGamma2P65 {
		// 4-bit packing: buf[i] = p[2i] | (p[2i+1] << 4).
		for i := 0; i < mldsaN/2; i++ {
			p[2*i] = uint32(buf[i] & 0x0F)
			p[2*i+1] = uint32(buf[i] >> 4)
		}
		return
	}
	if gamma2 == mldsaGamma2P44 {
		// 6-bit packing (out of BCC scope; provided for completeness).
		for i := 0; i < mldsaN/4; i++ {
			p[4*i+0] = uint32(buf[3*i+0] & 0x3F)
			p[4*i+1] = uint32(buf[3*i+0]>>6) | uint32(buf[3*i+1]&0x0F)<<2
			p[4*i+2] = uint32(buf[3*i+1]>>4) | uint32(buf[3*i+2]&0x03)<<4
			p[4*i+3] = uint32(buf[3*i+2] >> 2)
		}
	}
}

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

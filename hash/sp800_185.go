// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hash

// FIPS 202 / NIST SP 800-185 helpers — left_encode, right_encode,
// bytepad, encode_string — and the TupleHash / KMAC constructions
// they enable. Vendored here because Go's golang.org/x/crypto/sha3
// ships cSHAKE128/256 but not TupleHash or KMAC. The implementation
// is fully covered by the published NIST test vectors (see hash_test.go).
//
// All encoders match SP 800-185 §2.3 byte-for-byte. left_encode and
// right_encode operate on the BIT length, not the byte length.

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// leftEncode returns the SP 800-185 left_encode(x) byte string.
func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x01, 0x00}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], x)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	out := make([]byte, 0, 9-i)
	out = append(out, byte(8-i))
	out = append(out, buf[i:]...)
	return out
}

// rightEncode returns the SP 800-185 right_encode(x) byte string.
func rightEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x00, 0x01}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], x)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	out := make([]byte, 0, 9-i)
	out = append(out, buf[i:]...)
	out = append(out, byte(8-i))
	return out
}

// encodeString returns left_encode(bit_len(s)) || s.
func encodeString(s []byte) []byte {
	out := leftEncode(uint64(len(s)) * 8)
	out = append(out, s...)
	return out
}

// bytepad pads x with zeros so the result is a multiple of w bytes,
// prefixed by left_encode(w).
func bytepad(x []byte, w int) []byte {
	prefix := leftEncode(uint64(w))
	out := make([]byte, 0, len(prefix)+len(x)+w)
	out = append(out, prefix...)
	out = append(out, x...)
	for len(out)%w != 0 {
		out = append(out, 0x00)
	}
	return out
}

// kmac256 returns KMAC256(K, X, outLen, S) per SP 800-185 §4.
func kmac256(key, msg []byte, outLen int, customization string) []byte {
	x := bytepad(encodeString(key), 136)
	x = append(x, msg...)
	x = append(x, rightEncode(uint64(outLen)*8)...)

	h := sha3.NewCShake256([]byte("KMAC"), []byte(customization))
	_, _ = h.Write(x)
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out
}

// tupleHash256 returns TupleHash256(parts, outLen, S) per SP 800-185 §5.
func tupleHash256(parts [][]byte, outLen int, customization string) []byte {
	var x []byte
	for _, p := range parts {
		x = append(x, encodeString(p)...)
	}
	x = append(x, rightEncode(uint64(outLen)*8)...)

	h := sha3.NewCShake256([]byte("TupleHash"), []byte(customization))
	_, _ = h.Write(x)
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out
}

// cshake256Stream is the bare cSHAKE256 XOF: customization S is the
// only label; N is empty.
func cshake256Stream(customization string, transcript []byte, outLen int) []byte {
	h := sha3.NewCShake256(nil, []byte(customization))
	_, _ = h.Write(transcript)
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out
}

// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// transcript.go — FIPS 202 / SP 800-185 transcript primitives used by
// every Pulsar protocol round.
//
// All hashing in Pulsar routes through this file. Direct use of
// stdlib hashes anywhere else in the package is a CI failure per
// pulsar.tex §6.1 (DD-002 hash family) and CONTRIBUTING.md.
//
// The two primitives we vend are:
//
//   - cSHAKE256(K, X, L, S)         — FIPS 202 §6.3 + SP 800-185 §3
//   - KMAC256  (K, X, L, S)         — SP 800-185 §4
//
// All Pulsar customisation strings live in this file as named
// constants so that the audit footprint of the hash layer is one
// file. Rotating a tag invalidates every test vector pinned at that
// tag — bumping a tag is a deliberate, audited move.

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// Customisation tags for cSHAKE256/KMAC256. These match
// pulsar.tex §3 table "purpose -> SP 800-185 customisation tag"
// byte-for-byte.
const (
	tagDKGCommit     = "PULSAR-DKG-COMMIT-V1"
	tagDKGTranscript = "PULSAR-DKG-TRANSCRIPT-V1"
	tagSignR1        = "PULSAR-SIGN-R1-V1"
	tagSignR1MAC     = "PULSAR-SIGN-R1-MAC-V1"
	tagSignR2        = "PULSAR-SIGN-R2-V1"
	tagSignPRNG      = "PULSAR-SIGN-PRNG-V1"
	tagSignPRNGKey   = "PULSAR-SIGN-PRNGKEY-V1"
	tagSignPRF       = "PULSAR-SIGN-PRF-V1"
	tagReshareCommit = "PULSAR-RESHARE-COMMIT-V1"
	tagReshareTrans  = "PULSAR-RESHARE-TRANSCRIPT-V1"
	tagReshareBeacon = "PULSAR-RESHARE-BEACON-V1"
	tagExpandB       = "PULSAR-EXPANDB-V1"
	tagComplaint     = "PULSAR-COMPLAINT-V1"
	tagSeedShare     = "PULSAR-SEED-SHARE-V1"
)

// functionName is the SP 800-185 cSHAKE function-name parameter.
// All Pulsar cSHAKE calls pin N to "Pulsar" so that an integrator
// who mistakenly fed Pulsar cSHAKE bytes into a non-Pulsar cSHAKE
// engine would get a deterministic mismatch.
const functionName = "Pulsar"

// cshake256 returns the first outLen bytes of cSHAKE256(input, N,
// customisation) per SP 800-185 §3. Implemented over Go's
// golang.org/x/crypto/sha3.NewCShake256, which is the FIPS 202 +
// SP 800-185 reference engine we already depend on.
func cshake256(input []byte, outLen int, customisation string) []byte {
	h := sha3.NewCShake256([]byte(functionName), []byte(customisation))
	_, _ = h.Write(input)
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out
}

// kmac256 returns KMAC256(key, msg, outLen, customisation) per
// SP 800-185 §4.
//
// SP 800-185 §4 specifies the construction as:
//
//	KMAC256(K, X, L, S) :=
//	  cSHAKE256(newX, L, "KMAC", S),
//	  where newX = bytepad(encode_string(K), 136) || X || right_encode(L)
//
// 136 = SHA-3-256 rate / 8 = (1600 - 2*256) / 8.
func kmac256(key, msg []byte, outLen int, customisation string) []byte {
	preamble := bytepad(encodeString(key), 136)
	body := append(append([]byte{}, preamble...), msg...)
	body = append(body, rightEncode(uint64(outLen)*8)...)
	// KMAC's function-name is fixed to "KMAC" per SP 800-185 §4.
	h := sha3.NewCShake256([]byte("KMAC"), []byte(customisation))
	_, _ = h.Write(body)
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out
}

// SP 800-185 §2.3 encoders.

// leftEncode returns left_encode(x) per SP 800-185 §2.3.1. Operates on
// the BIT length: input must be the value to be encoded, callers
// pre-multiply by 8 when encoding a byte-length.
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

// rightEncode returns right_encode(x) per SP 800-185 §2.3.1.
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

// encodeString returns encode_string(s) = left_encode(bit_len(s)) || s
// per SP 800-185 §2.3.2.
func encodeString(s []byte) []byte {
	out := leftEncode(uint64(len(s)) * 8)
	out = append(out, s...)
	return out
}

// bytepad returns bytepad(x, w) = left_encode(w) || x || pad-to-w-bytes
// per SP 800-185 §2.3.3.
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

// transcriptHash binds an ordered tuple of byte-strings into a single
// 48-byte digest under the named customisation tag. The 48-byte width
// matches FIPS 204's commitment-hash length (CTildeSize); this lets us
// re-use the digest as a chain-pinning value without re-hashing.
//
// Encoding is SP 800-185 TupleHash256-style: for each part, prepend
// left_encode(bit_len(part)) so the boundary between parts is
// unambiguous regardless of part lengths. This matches
// pulsar/hash/sp800_185.go: TranscriptHash on the Pulsar-SHA3 suite.
func transcriptHash(customisation string, parts ...[]byte) [48]byte {
	buf := make([]byte, 0, 64+len(parts)*40)
	buf = append(buf, leftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		buf = append(buf, encodeString(p)...)
	}
	out := cshake256(buf, 48, customisation)
	var ret [48]byte
	copy(ret[:], out)
	return ret
}

// transcriptHash32 is the 32-byte counterpart used where a shorter
// digest is sufficient (commit digests, MAC tags).
func transcriptHash32(customisation string, parts ...[]byte) [32]byte {
	buf := make([]byte, 0, 64+len(parts)*40)
	buf = append(buf, leftEncode(uint64(len(parts)))...)
	for _, p := range parts {
		buf = append(buf, encodeString(p)...)
	}
	out := cshake256(buf, 32, customisation)
	var ret [32]byte
	copy(ret[:], out)
	return ret
}

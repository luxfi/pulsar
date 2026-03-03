// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// transcripts_byte_oracle — emits byte-only KATs for the BLAKE3 transcript
// primitives in github.com/luxfi/pulsar/primitives/hash.go.
//
// The byte-only paths are the parts of each transcript function that do NOT
// require structs.{Vector,Matrix}[ring.Poly] serialization (i.e. M1). They
// validate the C++ port at luxcpp/crypto/ringtail/cpp/transcripts.{hpp,cpp}
// before M1 lands.
//
// Each entry in the emitted JSON has:
//   - name        : function name (PRNGKey, Hash, GenerateMAC, ...)
//   - input_desc  : short text description
//   - input_hex   : the exact concatenated bytes that the function feeds to
//                   BLAKE3 (so the C++ side can hand-construct or assert)
//   - output_hex  : the 32-byte BLAKE3 digest, hex-encoded
//
// To regenerate:
//   go run ./cmd/transcripts_byte_oracle/ > /Users/z/work/luxcpp/crypto/ringtail/test/kat/transcripts_byte_only.json
//
// Determinism: pure functions of the input bytes; no random seeds.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/zeebo/blake3"
)

type Entry struct {
	Name      string `json:"name"`
	InputDesc string `json:"input_desc"`
	InputHex  string `json:"input_hex"`
	OutputHex string `json:"output_hex"`
}

type Output struct {
	Description string  `json:"description"`
	Entries     []Entry `json:"entries"`
}

func b3(buf []byte) []byte {
	h := blake3.New()
	if _, err := h.Write(buf); err != nil {
		panic(err)
	}
	d := h.Sum(nil)
	return d[:32]
}

func writeBE[T any](buf *bytes.Buffer, v T) {
	if err := binary.Write(buf, binary.BigEndian, v); err != nil {
		panic(err)
	}
}

// PRNGKey: blake3 of input bytes truncated to 32. With the default 32-byte
// digest, "truncate" is a no-op.
func katPRNGKey(skSerialized []byte) Entry {
	out := b3(skSerialized)
	return Entry{
		Name:      "PRNGKey",
		InputDesc: fmt.Sprintf("len(sk_serialized)=%d", len(skSerialized)),
		InputHex:  hex.EncodeToString(skSerialized),
		OutputHex: hex.EncodeToString(out),
	}
}

// Hash: A_bytes || b_bytes || int64-BE(sid) || int32-BE(|T|) ||
// int32-BE(T[i])... || D_concat.
func katHash(a, b []byte, sid int64, T []int32, dConcat []byte) Entry {
	buf := new(bytes.Buffer)
	buf.Write(a)
	buf.Write(b)
	writeBE(buf, sid)
	writeBE(buf, int32(len(T)))
	for _, t := range T {
		writeBE(buf, t)
	}
	buf.Write(dConcat)
	out := b3(buf.Bytes())
	return Entry{
		Name:      "Hash",
		InputDesc: fmt.Sprintf("|A|=%d, |b|=%d, sid=%d, |T|=%d, |D|=%d", len(a), len(b), sid, len(T), len(dConcat)),
		InputHex:  hex.EncodeToString(buf.Bytes()),
		OutputHex: hex.EncodeToString(out),
	}
}

// GenerateMAC: int64-BE(verify ? otherParty : partyID) || MACKey ||
// tildeD_bytes || int64-BE(sid) || int32-BE(|T|) || int32-BE(T[i])...
func katGenerateMAC(partyID, otherParty int64, verify bool, macKey [32]byte, tildeD []byte, sid int64, T []int32) Entry {
	buf := new(bytes.Buffer)
	if verify {
		writeBE(buf, otherParty)
	} else {
		writeBE(buf, partyID)
	}
	buf.Write(macKey[:])
	buf.Write(tildeD)
	writeBE(buf, sid)
	writeBE(buf, int32(len(T)))
	for _, t := range T {
		writeBE(buf, t)
	}
	out := b3(buf.Bytes())
	return Entry{
		Name:      "GenerateMAC",
		InputDesc: fmt.Sprintf("party=%d other=%d verify=%t |tildeD|=%d sid=%d |T|=%d", partyID, otherParty, verify, len(tildeD), sid, len(T)),
		InputHex:  hex.EncodeToString(buf.Bytes()),
		OutputHex: hex.EncodeToString(out),
	}
}

// LowNormHash: A_bytes || b_bytes || h_bytes || mu_bytes  (digest only)
func katLowNormHash(a, b, h, mu []byte) Entry {
	buf := new(bytes.Buffer)
	buf.Write(a)
	buf.Write(b)
	buf.Write(h)
	buf.Write(mu)
	out := b3(buf.Bytes())
	return Entry{
		Name:      "LowNormHashDigest",
		InputDesc: fmt.Sprintf("|A|=%d |b|=%d |h|=%d mu=%q", len(a), len(b), len(h), string(mu)),
		InputHex:  hex.EncodeToString(buf.Bytes()),
		OutputHex: hex.EncodeToString(out),
	}
}

// GaussianHash digest: hash_input || mu_bytes
func katGaussianHash(hashInput, mu []byte) Entry {
	buf := new(bytes.Buffer)
	buf.Write(hashInput)
	buf.Write(mu)
	out := b3(buf.Bytes())
	return Entry{
		Name:      "GaussianHashDigest",
		InputDesc: fmt.Sprintf("|hash|=%d mu=%q", len(hashInput), string(mu)),
		InputHex:  hex.EncodeToString(buf.Bytes()),
		OutputHex: hex.EncodeToString(out),
	}
}

// PRF digest: PRFKey || sd_ij || hash || mu
func katPRF(prfKey [32]byte, sdIj, hash, mu []byte) Entry {
	buf := new(bytes.Buffer)
	buf.Write(prfKey[:])
	buf.Write(sdIj)
	buf.Write(hash)
	buf.Write(mu)
	out := b3(buf.Bytes())
	return Entry{
		Name:      "PRFDigest",
		InputDesc: fmt.Sprintf("|sd_ij|=%d |hash|=%d mu=%q", len(sdIj), len(hash), string(mu)),
		InputHex:  hex.EncodeToString(buf.Bytes()),
		OutputHex: hex.EncodeToString(out),
	}
}

func main() {
	out := Output{
		Description: "Byte-only KATs for ringtail BLAKE3 transcripts. Validates buffer construction + BLAKE3 wiring without depending on M1 (lattice_ring + structs.Matrix). Each entry pins the exact concatenated input bytes and the resulting 32-byte digest.",
	}

	// 1. PRNGKey
	out.Entries = append(out.Entries,
		katPRNGKey([]byte{}),
		katPRNGKey([]byte("hello world")),
		katPRNGKey(bytes.Repeat([]byte{0xAA}, 256)),
	)

	// 2. Hash
	out.Entries = append(out.Entries,
		katHash(nil, nil, 0, nil, nil),
		katHash([]byte("A"), []byte("b"), 1, []int32{0}, []byte("D")),
		katHash(
			bytes.Repeat([]byte{0x01}, 64),
			bytes.Repeat([]byte{0x02}, 32),
			42,
			[]int32{1, 2, 3},
			bytes.Repeat([]byte{0x03}, 96),
		),
	)

	// 3. GenerateMAC
	var macKey [32]byte
	for i := range macKey {
		macKey[i] = byte(i)
	}
	out.Entries = append(out.Entries,
		katGenerateMAC(0, 0, false, [32]byte{}, nil, 0, nil),
		katGenerateMAC(7, 0, false, macKey, []byte("tildeD"), 5, []int32{1, 2, 3, 4}),
		katGenerateMAC(7, 11, true, macKey, []byte("tildeD"), 5, []int32{1, 2, 3, 4}),
	)

	// 4. LowNormHashDigest
	out.Entries = append(out.Entries,
		katLowNormHash(nil, nil, nil, []byte("")),
		katLowNormHash([]byte("A"), []byte("b"), []byte("h"), []byte("mu-00")),
		katLowNormHash(bytes.Repeat([]byte{0x10}, 32), bytes.Repeat([]byte{0x20}, 32), bytes.Repeat([]byte{0x30}, 32), []byte("msg-99")),
	)

	// 5. GaussianHashDigest
	out.Entries = append(out.Entries,
		katGaussianHash(nil, nil),
		katGaussianHash([]byte("hash"), []byte("mu")),
		katGaussianHash(bytes.Repeat([]byte{0xCC}, 32), []byte("ringtail-mu-77")),
	)

	// 6. PRFDigest
	var prfKey [32]byte
	for i := range prfKey {
		prfKey[i] = byte(0xFF - i)
	}
	out.Entries = append(out.Entries,
		katPRF([32]byte{}, nil, nil, nil),
		katPRF(prfKey, []byte("sd_ij"), []byte("hash"), []byte("mu")),
		katPRF(prfKey, bytes.Repeat([]byte{0x77}, 64), bytes.Repeat([]byte{0x88}, 32), []byte("ringtail-prf")),
	)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

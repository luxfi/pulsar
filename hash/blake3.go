// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hash

// PulsarBLAKE3 is a NON-NORMATIVE legacy suite kept for byte-equality
// checks against transcripts produced before the Pulsar-SHA3 profile
// was pinned as canonical. NEW deployments MUST use Pulsar-SHA3.

import (
	"encoding/binary"

	"github.com/zeebo/blake3"
)

// pulsarBLAKE3 implements HashSuite using BLAKE3 primitives.
type pulsarBLAKE3 struct{}

// NewPulsarBLAKE3 returns the legacy BLAKE3 suite. NOT for production.
func NewPulsarBLAKE3() HashSuite { return pulsarBLAKE3{} }

func (pulsarBLAKE3) ID() string { return "Pulsar-BLAKE3" }

func (pulsarBLAKE3) Hc(transcript []byte) []byte {
	h := blake3.New()
	_, _ = h.Write([]byte(tagHC))
	_, _ = h.Write(transcript)
	return h.Sum(nil)[:32]
}

func (pulsarBLAKE3) Hu(transcript []byte, outLen int) []byte {
	h := blake3.New()
	_, _ = h.Write([]byte(tagHU))
	_, _ = h.Write(transcript)
	out := make([]byte, outLen)
	_, _ = h.Digest().Read(out)
	return out
}

func (pulsarBLAKE3) TranscriptHash(parts ...[]byte) [32]byte {
	h := blake3.New()
	_, _ = h.Write([]byte(tagTranscript))
	for _, p := range parts {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(p)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil)[:32])
	return out
}

func (pulsarBLAKE3) PRF(key, msg []byte, outLen int) []byte {
	keyArr := blake3SizedKey(key)
	h, _ := blake3.NewKeyed(keyArr[:])
	_, _ = h.Write([]byte(tagPRF))
	_, _ = h.Write(msg)
	out := make([]byte, outLen)
	_, _ = h.Digest().Read(out)
	return out
}

func (pulsarBLAKE3) MAC(key, msg []byte, outLen int) []byte {
	keyArr := blake3SizedKey(key)
	h, _ := blake3.NewKeyed(keyArr[:])
	_, _ = h.Write([]byte(tagMAC))
	_, _ = h.Write(msg)
	out := make([]byte, outLen)
	_, _ = h.Digest().Read(out)
	return out
}

func (pulsarBLAKE3) DerivePairwise(
	kex []byte,
	chainID, groupID []byte,
	eraID, generation uint64,
	i, j int,
	outLen int,
) []byte {
	a, b := i, j
	if a > b {
		a, b = b, a
	}
	keyArr := blake3SizedKey(kex)
	h, _ := blake3.NewKeyed(keyArr[:])
	_, _ = h.Write([]byte(tagPairwise))
	writeLen(h, chainID)
	writeLen(h, groupID)
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], eraID)
	_, _ = h.Write(u8[:])
	binary.BigEndian.PutUint64(u8[:], generation)
	_, _ = h.Write(u8[:])
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], uint32(a))
	_, _ = h.Write(u4[:])
	binary.BigEndian.PutUint32(u4[:], uint32(b))
	_, _ = h.Write(u4[:])
	out := make([]byte, outLen)
	_, _ = h.Digest().Read(out)
	return out
}

// blake3SizedKey compresses an arbitrary keying material into the
// 32-byte key BLAKE3.NewKeyed requires.
func blake3SizedKey(kex []byte) [32]byte {
	if len(kex) == 32 {
		var out [32]byte
		copy(out[:], kex)
		return out
	}
	h := blake3.New()
	_, _ = h.Write([]byte("PULSAR-KDF-KEY-v1"))
	_, _ = h.Write(kex)
	var out [32]byte
	copy(out[:], h.Sum(nil)[:32])
	return out
}

// writeLen writes a length-prefixed byte slice to the hash writer.
func writeLen(h interface{ Write(p []byte) (int, error) }, data []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(data)
}

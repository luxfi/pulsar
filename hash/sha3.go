// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hash

// PulsarSHA3 is the production hash suite for Pulsar. Built on
// cSHAKE256 / KMAC256 / TupleHash256 from FIPS 202 and NIST SP 800-185.
//
// Customization tags pin every operation to the Pulsar protocol:
//
//	Hc                "PULSAR-HC-v1"
//	Hu                "PULSAR-HU-v1"
//	TranscriptHash    "PULSAR-TRANSCRIPT-v1"
//	PRF               "PULSAR-PRF-v1"     (KMAC256)
//	MAC               "PULSAR-MAC-v1"     (KMAC256)
//	DerivePairwise    "PULSAR-PAIRWISE-v1" (KMAC256)
//
// Distinct customization strings are essential — same primitive +
// different tag = independent oracle. Bumping any tag invalidates
// every transcript / activation cert / pairwise material in flight.
//
// All operations are stateless and goroutine-safe.

import (
	"encoding/binary"
)

const (
	tagHC         = "PULSAR-HC-v1"
	tagHU         = "PULSAR-HU-v1"
	tagTranscript = "PULSAR-TRANSCRIPT-v1"
	tagPRF        = "PULSAR-PRF-v1"
	tagMAC        = "PULSAR-MAC-v1"
	tagPairwise   = "PULSAR-PAIRWISE-v1"
)

// pulsarSHA3 implements HashSuite using the SP 800-185 primitives.
type pulsarSHA3 struct{}

// NewPulsarSHA3 returns the production hash suite.
func NewPulsarSHA3() HashSuite { return pulsarSHA3{} }

func (pulsarSHA3) ID() string { return "Pulsar-SHA3" }

func (pulsarSHA3) Hc(transcript []byte) []byte {
	return cshake256Stream(tagHC, transcript, 32)
}

func (pulsarSHA3) Hu(transcript []byte, outLen int) []byte {
	return cshake256Stream(tagHU, transcript, outLen)
}

func (pulsarSHA3) TranscriptHash(parts ...[]byte) [32]byte {
	out := tupleHash256(parts, 32, tagTranscript)
	var fixed [32]byte
	copy(fixed[:], out)
	return fixed
}

func (pulsarSHA3) PRF(key, msg []byte, outLen int) []byte {
	return kmac256(key, msg, outLen, tagPRF)
}

func (pulsarSHA3) MAC(key, msg []byte, outLen int) []byte {
	return kmac256(key, msg, outLen, tagMAC)
}

func (pulsarSHA3) DerivePairwise(
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
	var msg []byte
	msg = append(msg, encodeString(chainID)...)
	msg = append(msg, encodeString(groupID)...)
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], eraID)
	msg = append(msg, encodeString(u8[:])...)
	binary.BigEndian.PutUint64(u8[:], generation)
	msg = append(msg, encodeString(u8[:])...)
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], uint32(a))
	msg = append(msg, encodeString(u4[:])...)
	binary.BigEndian.PutUint32(u4[:], uint32(b))
	msg = append(msg, encodeString(u4[:])...)

	return kmac256(kex, msg, outLen, tagPairwise)
}

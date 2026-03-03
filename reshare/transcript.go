// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

// Transcript binding for Verifiable Secret Resharing.
//
// Every resharing message — Round 1 commits + private share deliveries,
// Round 1.5 commit-digest broadcasts, Round 2 complaints, and the final
// activation certificate — is bound to a transcript hash that commits
// to the (chain_id, network_id, group_id, era, generations, epochs,
// sets, thresholds, group_pk_hash, nebula_root, hash_suite_id,
// implementation_version) tuple. The transcript hash is a single point
// of equality the new committee uses when it threshold-signs the
// activation message under the unchanged GroupKey: the chain accepts
// the new epoch only when the activation signature verifies against
// this hash.
//
// Domain separation. Every input field is unambiguously length-prefixed
// (TupleHash framing under Pulsar-SHA3, hand-rolled length prefixes
// under the legacy Pulsar-BLAKE3 suite). The customization tag is
// "PULSAR-TRANSCRIPT-v1" — distinct from any DKG transcript tag (e.g.
// "pulsar.dkg2.commit.v1") and from any Pulsar Sign transcript tag.

import (
	"bytes"
	"encoding/binary"

	"github.com/luxfi/pulsar/hash"
)

// TranscriptPersonalization is the legacy BLAKE3 personalization
// string. Kept as an exported symbol because some external consumers
// (cross-language KAT loaders) reference it; the canonical transcript
// binding is now produced via the HashSuite layer.
const TranscriptPersonalization = "pulsar.reshare.transcript.v1"

// TranscriptInputs holds the public binding fields for one resharing
// invocation. All fields are mandatory; the transcript hash is well-
// defined only when every byte below is fixed.
type TranscriptInputs struct {
	ChainID               []byte
	NetworkID             []byte
	GroupID               []byte
	KeyEraID              uint64
	OldGeneration         uint64
	NewGeneration         uint64
	OldEpochID            uint64
	NewEpochID            uint64
	OldSetHash            [32]byte
	NewSetHash            [32]byte
	ThresholdOld          uint32
	ThresholdNew          uint32
	GroupPublicKeyHash    [32]byte
	NebulaRoot            [32]byte
	HashSuiteID           string
	ImplementationVersion string
	Variant               string
}

// Hash returns the canonical 32-byte transcript binding for the inputs
// under the supplied HashSuite. nil resolves to the production default
// (Pulsar-SHA3); pass hash.NewPulsarBLAKE3() to reproduce legacy bytes.
func (t *TranscriptInputs) Hash(suite hash.HashSuite) [32]byte {
	s := hash.Resolve(suite)
	parts := buildTranscriptParts(t)
	return s.TranscriptHash(parts...)
}

// buildTranscriptParts canonicalizes a TranscriptInputs into the
// ordered byte-string list that drives TranscriptHash.
func buildTranscriptParts(t *TranscriptInputs) [][]byte {
	enc64 := func(v uint64) []byte {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		return b[:]
	}
	enc32 := func(v uint32) []byte {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		return b[:]
	}
	return [][]byte{
		[]byte("variant"), []byte(t.Variant),
		[]byte("chain_id"), t.ChainID,
		[]byte("network_id"), t.NetworkID,
		[]byte("group_id"), t.GroupID,
		[]byte("key_era_id"), enc64(t.KeyEraID),
		[]byte("old_generation"), enc64(t.OldGeneration),
		[]byte("new_generation"), enc64(t.NewGeneration),
		[]byte("old_epoch_id"), enc64(t.OldEpochID),
		[]byte("new_epoch_id"), enc64(t.NewEpochID),
		[]byte("old_set_hash"), t.OldSetHash[:],
		[]byte("new_set_hash"), t.NewSetHash[:],
		[]byte("threshold_old"), enc32(t.ThresholdOld),
		[]byte("threshold_new"), enc32(t.ThresholdNew),
		[]byte("group_public_key_hash"), t.GroupPublicKeyHash[:],
		[]byte("nebula_root"), t.NebulaRoot[:],
		[]byte("hash_suite_id"), []byte(t.HashSuiteID),
		[]byte("implementation_version"), []byte(t.ImplementationVersion),
	}
}

// ValidatorSetHash returns the canonical hash of a validator set.
// suite=nil resolves to the production default (Pulsar-SHA3).
func ValidatorSetHash(publicKeys [][]byte, suite hash.HashSuite) [32]byte {
	s := hash.Resolve(suite)
	sorted := make([][]byte, len(publicKeys))
	copy(sorted, publicKeys)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && bytes.Compare(sorted[j-1], sorted[j]) > 0; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	parts := make([][]byte, 0, 2+len(sorted))
	parts = append(parts, []byte("pulsar.reshare.validator-set.v1"))
	var nBuf [4]byte
	binary.BigEndian.PutUint32(nBuf[:], uint32(len(sorted)))
	parts = append(parts, nBuf[:])
	for _, pk := range sorted {
		if len(pk) > 0xFFFF {
			panic("reshare: validator public key longer than 65535 bytes")
		}
		parts = append(parts, pk)
	}
	return s.TranscriptHash(parts...)
}

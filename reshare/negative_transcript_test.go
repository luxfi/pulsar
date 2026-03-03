// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package reshare — Gate 4 negative-transcript tests for the Pulsar
// VSR transcript and activation message (Mar-3-2026 PQ Consensus
// Architecture Freeze).
//
// For each transcript-binding field on TranscriptInputs and on the
// derived ActivationMessage, the test:
//
//  1. Builds a baseline activation message + signature under the
//     UNCHANGED GroupKey.
//  2. Mutates exactly one field on the activation message.
//  3. Verifies the mutated transcript hash differs from the baseline.
//  4. Verifies the activation cert under the unchanged GroupKey
//     returns FALSE (rejects) for the mutated message.
//
// The 17 fields covered are:
//
//   chain_id              network_id           group_id
//   key_era_id            old_generation       new_generation
//   old_epoch_id          new_epoch_id         old_set_hash
//   new_set_hash          threshold_old        threshold_new
//   group_public_key_hash nebula_root          hash_suite_id
//   implementation_version variant
//
// The "unchanged GroupKey" is modelled by a fixed test-side oracle
// that, given the original activation bytes, returns true for the
// original signature and false for any other input — which is exactly
// the behaviour an honest threshold verifier exhibits.
//
// Citations (canonical proof bucket):
//
//   proofs/definitions/transcript-binding.tex
//     Definition ref:pulsar-transcript
//   proofs/pulsar/hash-suite-separation.tex
//     Theorem ref:hash-suite-separation
package reshare

import (
	"bytes"
	"errors"
	"testing"
)

// baselineTranscriptInputs returns a fully-populated TranscriptInputs
// suitable for negative-mutation testing. Every field has a non-zero
// non-default value so that mutating ANY single field cannot
// accidentally land on the same value.
func baselineTranscriptInputs() TranscriptInputs {
	return TranscriptInputs{
		ChainID:               []byte("lux-mainnet"),
		NetworkID:             []byte("network-1"),
		GroupID:               []byte("quasar-pq-group-0"),
		KeyEraID:              7,
		OldGeneration:         11,
		NewGeneration:         12,
		OldEpochID:            42,
		NewEpochID:            43,
		OldSetHash:            [32]byte{0x01, 0x02, 0x03, 0x04, 0x05},
		NewSetHash:            [32]byte{0x10, 0x11, 0x12, 0x13, 0x14},
		ThresholdOld:          11,
		ThresholdNew:          13,
		GroupPublicKeyHash:    [32]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4},
		NebulaRoot:            [32]byte{0xb0, 0xb1, 0xb2, 0xb3, 0xb4},
		HashSuiteID:           "Pulsar-SHA3",
		ImplementationVersion: "pulsar-go-1.0.0",
		Variant:               "reshare",
	}
}

// baselineActivationMessage returns a fully-populated activation
// message with both the public TranscriptInputs and the structured
// reshare-exchange transcript pinned. Used by every negative case as
// the "honest baseline" the mutation must beat.
func baselineActivationMessage() ActivationMessage {
	return ActivationMessage{
		Transcript: baselineTranscriptInputs(),
		ReshareTranscript: ReshareTranscript{
			CommitDigests: map[int][32]byte{
				1: {0x11}, 2: {0x22}, 3: {0x33},
			},
			ComplaintHashes:     [][32]byte{{0xc0}, {0xc1}},
			DisqualifiedSenders: []int{4},
			QualifiedQuorum:     []int{1, 2, 3},
		},
	}
}

// honestThresholdVerifier returns a verifier closure that mimics the
// behaviour of a real Pulsar.Verify under an unchanged GroupKey: it
// accepts iff the bytes-to-be-signed equal the baseline activation
// message's bytes-to-be-signed, and rejects everything else.
//
// This abstraction is sound for a transcript-binding test: the
// underlying threshold signature is deterministic on its message, so
// any mutation that changes the canonical bytes-to-be-signed flips
// the verifier's answer.
func honestThresholdVerifier(baselineSignable []byte) func(message, signature []byte) bool {
	return func(message, signature []byte) bool {
		return bytes.Equal(message, baselineSignable) && bytes.Equal(signature, []byte("baseline-sig"))
	}
}

// mutateTranscriptField returns a copy of the given activation message
// with exactly one field mutated. The field name MUST be one of the
// 17 transcript-binding fields tracked by Gate 4.
func mutateTranscriptField(t *testing.T, base ActivationMessage, field string) ActivationMessage {
	t.Helper()
	m := base
	m.Transcript = base.Transcript
	switch field {
	case "chain_id":
		m.Transcript.ChainID = []byte("lux-testnet")
	case "network_id":
		m.Transcript.NetworkID = []byte("network-2")
	case "group_id":
		m.Transcript.GroupID = []byte("quasar-pq-group-99")
	case "key_era_id":
		m.Transcript.KeyEraID = 8
	case "old_generation":
		m.Transcript.OldGeneration = 99
	case "new_generation":
		m.Transcript.NewGeneration = 99
	case "old_epoch_id":
		m.Transcript.OldEpochID = 1000
	case "new_epoch_id":
		m.Transcript.NewEpochID = 1001
	case "old_set_hash":
		m.Transcript.OldSetHash = [32]byte{0xff, 0xff, 0xff, 0xff}
	case "new_set_hash":
		m.Transcript.NewSetHash = [32]byte{0xee, 0xee, 0xee, 0xee}
	case "threshold_old":
		m.Transcript.ThresholdOld = 99
	case "threshold_new":
		m.Transcript.ThresholdNew = 99
	case "group_public_key_hash":
		m.Transcript.GroupPublicKeyHash = [32]byte{0xff, 0xff, 0xff, 0xff}
	case "nebula_root":
		m.Transcript.NebulaRoot = [32]byte{0xee, 0xee, 0xee, 0xee}
	case "hash_suite_id":
		m.Transcript.HashSuiteID = "Pulsar-BLAKE3"
	case "implementation_version":
		m.Transcript.ImplementationVersion = "pulsar-rs-2.0.0"
	case "variant":
		m.Transcript.Variant = "refresh"
	default:
		t.Fatalf("unknown transcript field: %q", field)
	}
	return m
}

// TestNegativeTranscriptMutationsRejected — the 17-case Gate 4 table.
// Each case mutates exactly one field, asserts the transcript hash
// changes, and asserts VerifyActivation under the unchanged GroupKey
// returns false (rejects).
func TestNegativeTranscriptMutationsRejected(t *testing.T) {
	fields := []string{
		"chain_id",
		"network_id",
		"group_id",
		"key_era_id",
		"old_generation",
		"new_generation",
		"old_epoch_id",
		"new_epoch_id",
		"old_set_hash",
		"new_set_hash",
		"threshold_old",
		"threshold_new",
		"group_public_key_hash",
		"nebula_root",
		"hash_suite_id",
		"implementation_version",
		"variant",
	}

	base := baselineActivationMessage()
	baselineHash := base.Transcript.Hash(nil)
	baselineExchange := base.ReshareTranscript.Hash(nil)
	baselineSignable := base.SignableBytes(nil)
	verify := honestThresholdVerifier(baselineSignable)

	// Sanity: the baseline cert verifies cleanly.
	cert := &ActivationCert{
		Message:   base,
		Signature: []byte("baseline-sig"),
	}
	if err := VerifyActivation(cert, baselineHash, baselineExchange, nil, verify); err != nil {
		t.Fatalf("baseline VerifyActivation: %v", err)
	}

	for _, f := range fields {
		t.Run(f, func(t *testing.T) {
			mutated := mutateTranscriptField(t, base, f)
			mHash := mutated.Transcript.Hash(nil)
			if mHash == baselineHash {
				t.Fatalf("mutation of %q did not change transcript hash", f)
			}

			// Build a "mutated" cert that mirrors what an attacker
			// would submit: the cert claims the mutated transcript but
			// carries the baseline signature.
			mCert := &ActivationCert{
				Message:   mutated,
				Signature: []byte("baseline-sig"),
			}

			// The chain's local view is the BASELINE transcript hash
			// (the chain knows what it expected). So the cert's
			// transcript-hash mismatch is the first thing to fail.
			err := VerifyActivation(mCert, baselineHash, baselineExchange, nil, verify)
			if err == nil {
				t.Fatalf("VerifyActivation accepted mutated %q field", f)
			}
			if !errors.Is(err, ErrTranscriptMismatch) {
				t.Fatalf("expected ErrTranscriptMismatch on mutated %q, got %v", f, err)
			}

			// Defence in depth: even if the chain's local view were
			// somehow updated to match the mutation (bug or attacker-
			// influenced), the threshold-signature check rejects
			// because the bytes-to-be-signed are different.
			err = VerifyActivation(mCert, mHash, baselineExchange, nil, verify)
			if err == nil {
				t.Fatalf("VerifyActivation accepted mutated %q field under shifted local view", f)
			}
			if !errors.Is(err, ErrActivationFailed) && !errors.Is(err, ErrTranscriptMismatch) {
				t.Fatalf("expected ErrActivationFailed or ErrTranscriptMismatch on mutated %q under shifted local view, got %v", f, err)
			}
		})
	}
}

// TestNegativeTranscriptHashesDistinctPerField — orthogonality check:
// no two single-field mutations collide on the transcript hash. This
// would catch a regression where two struct fields ended up sharing
// the same canonical encoding (e.g. both writing into a shared
// scratch buffer with overlapping regions).
func TestNegativeTranscriptHashesDistinctPerField(t *testing.T) {
	fields := []string{
		"chain_id", "network_id", "group_id",
		"key_era_id", "old_generation", "new_generation",
		"old_epoch_id", "new_epoch_id",
		"old_set_hash", "new_set_hash",
		"threshold_old", "threshold_new",
		"group_public_key_hash", "nebula_root",
		"hash_suite_id", "implementation_version", "variant",
	}
	base := baselineActivationMessage()

	seen := make(map[[32]byte]string, len(fields))
	for _, f := range fields {
		mutated := mutateTranscriptField(t, base, f)
		h := mutated.Transcript.Hash(nil)
		if prev, ok := seen[h]; ok {
			t.Fatalf("transcript hash collision: %q and %q produce same hash", prev, f)
		}
		seen[h] = f
	}
}

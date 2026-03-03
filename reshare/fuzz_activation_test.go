// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package reshare fuzz harness for activation-message signable bytes.
//
// Property anchor: proofs/pulsar/activation-safety.tex.
// The activation cert is the post-reshare circuit-breaker; it must be
// produced over a deterministic byte stream that uniquely binds the
// resharing transcript hash and the protocol-domain prefix
// "QUASAR-PULSAR-ACTIVATE-v1". This harness exercises the
// SignableBytes encoder against arbitrary mutated inputs.

package reshare

import (
	"bytes"
	"testing"
)

// FuzzActivationMessageSignableBytes exercises the canonical signable
// bytes against mutated TranscriptInputs / ReshareTranscript values.
//
// Properties:
//
//  1. SignableBytes never panics on arbitrary inputs.
//  2. Output is deterministic: same struct → same bytes across calls.
//  3. The output begins with the canonical protocol prefix
//     "QUASAR-PULSAR-ACTIVATE-v1".
//  4. The output length is exactly len(prefix) + 32 + 32 = 89 bytes,
//     irrespective of how large the input fields are.
func FuzzActivationMessageSignableBytes(f *testing.F) {
	// Seed corpus: representative shapes from the activation_oracle
	// KAT generator.
	f.Add(seedActivationBytes("lux-mainnet", "quasar-pq", 100, 101, "reshare", 3, 2, 0))
	f.Add(seedActivationBytes("lux-testnet", "g0", 1, 2, "refresh", 5, 0, 1))
	f.Add(seedActivationBytes("", "", 0, 0, "", 0, 0, 0))

	prefix := []byte("QUASAR-PULSAR-ACTIVATE-v1")
	const wantLen = len("QUASAR-PULSAR-ACTIVATE-v1") + 32 + 32

	f.Fuzz(func(t *testing.T, raw []byte) {
		msg := decodeFuzzActivation(raw)

		b1 := msg.SignableBytes(nil)
		b2 := msg.SignableBytes(nil)

		if !bytes.Equal(b1, b2) {
			t.Fatalf("non-deterministic SignableBytes")
		}
		if !bytes.HasPrefix(b1, prefix) {
			t.Fatalf("missing canonical prefix")
		}
		if len(b1) != wantLen {
			t.Fatalf("unexpected SignableBytes length: %d (want %d)", len(b1), wantLen)
		}

		// Mutating any field that flows into the transcript hash MUST
		// change the SignableBytes output.
		msg2 := msg
		msg2.Transcript.Variant = msg.Transcript.Variant + "x"
		b3 := msg2.SignableBytes(nil)
		if bytes.Equal(b1, b3) {
			t.Fatalf("variant mutation did not change SignableBytes")
		}
	})
}

// TestFuzzCorpus_ActivationReplay re-runs the seed corpus
// deterministically for CI replay.
func TestFuzzCorpus_ActivationReplay(t *testing.T) {
	prefix := []byte("QUASAR-PULSAR-ACTIVATE-v1")
	seeds := [][]byte{
		seedActivationBytes("lux-mainnet", "quasar-pq", 100, 101, "reshare", 3, 2, 0),
		seedActivationBytes("lux-testnet", "g0", 1, 2, "refresh", 5, 0, 1),
		seedActivationBytes("", "", 0, 0, "", 0, 0, 0),
	}
	for i, s := range seeds {
		msg := decodeFuzzActivation(s)
		b := msg.SignableBytes(nil)
		if !bytes.HasPrefix(b, prefix) {
			t.Fatalf("seed %d: missing prefix", i)
		}
		if msg.SignableBytes(nil) == nil || !bytes.Equal(b, msg.SignableBytes(nil)) {
			t.Fatalf("seed %d: non-deterministic", i)
		}
	}
}

// seedActivationBytes builds a flat byte stream the fuzz harness
// decodes into an ActivationMessage. Like the transcript fuzz harness,
// this encoding is internal to the test binary.
func seedActivationBytes(
	chain, group string,
	oldEpoch, newEpoch uint64,
	variant string,
	commits, complaints, dq int,
) []byte {
	var b []byte
	b = appendString(b, chain)
	b = appendString(b, group)
	b = appendU64(b, oldEpoch)
	b = appendU64(b, newEpoch)
	b = appendString(b, variant)
	b = appendU32(b, uint32(commits))
	b = appendU32(b, uint32(complaints))
	b = appendU32(b, uint32(dq))
	return b
}

// decodeFuzzActivation pulls fields out of an arbitrary byte stream
// and constructs an ActivationMessage.
func decodeFuzzActivation(raw []byte) ActivationMessage {
	r := &fuzzReader{buf: raw}
	chain := r.readBytes()
	group := r.readBytes()
	oldEpoch := r.readU64()
	newEpoch := r.readU64()
	variant := r.readString()
	commits := r.readU32()
	complaints := r.readU32()
	dq := r.readU32()

	// Cap the structural sizes so the fuzzer cannot allocate arbitrary
	// amounts of memory; the harness goal is to exercise byte paths,
	// not to OOM the test process.
	const maxStructural = 64
	if commits > maxStructural {
		commits = maxStructural
	}
	if complaints > maxStructural {
		complaints = maxStructural
	}
	if dq > maxStructural {
		dq = maxStructural
	}

	rt := ReshareTranscript{
		CommitDigests:       make(map[int][32]byte, commits),
		ComplaintHashes:     make([][32]byte, complaints),
		DisqualifiedSenders: make([]int, dq),
		QualifiedQuorum:     []int{},
	}
	for i := uint32(0); i < commits; i++ {
		var d [32]byte
		copy(d[:], r.readN(32))
		rt.CommitDigests[int(i)] = d
	}
	for i := uint32(0); i < complaints; i++ {
		var d [32]byte
		copy(d[:], r.readN(32))
		rt.ComplaintHashes[i] = d
	}
	for i := uint32(0); i < dq; i++ {
		rt.DisqualifiedSenders[i] = int(r.readU32())
	}

	return ActivationMessage{
		Transcript: TranscriptInputs{
			ChainID:    chain,
			GroupID:    group,
			OldEpochID: oldEpoch,
			NewEpochID: newEpoch,
			Variant:    variant,
		},
		ReshareTranscript: rt,
	}
}

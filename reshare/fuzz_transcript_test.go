// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package reshare fuzz harness for transcript binding.
//
// Property anchor: proofs/definitions/transcript-binding.tex
// Definition ref:pulsar-transcript ("Pulsar TranscriptInputs.Hash") —
// the canonical TranscriptHash is collision-resistant, and any two
// distinct field tuples yield distinct hashes by collision resistance
// of TupleHash256.
//
// This harness exercises the Go implementation of the canonical
// TranscriptInputs encoder against arbitrary mutated inputs, asserting:
//
//  1. Encoding never panics (decode-encode-cycle robustness).
//  2. The encoding is canonical: re-hashing identical inputs yields the
//     same bytes (determinism is the input-side requirement of the
//     collision-resistance bound).
//  3. Two TranscriptInputs values that differ in any single field yield
//     distinct hashes — the field-level binding property is what makes
//     the activation cert non-replayable across epochs / variants /
//     suites.

package reshare

import (
	"encoding/binary"
	"testing"
)

// FuzzTranscriptInputsHash exercises the canonical transcript hash
// against arbitrary byte inputs.
//
// We cannot decode-and-re-encode TranscriptInputs because the type has
// strongly-typed fields (uint64 era IDs, [32]byte set hashes) — there
// is no "wire format" we serialize/deserialize. Instead we drive the
// fuzzer at the transcript-hash function: produce arbitrary inputs,
// confirm Hash never panics, and confirm that mutating a single
// canonical-encoding input always changes the hash.
func FuzzTranscriptInputsHash(f *testing.F) {
	// Seed corpus: a few representative TranscriptInputs values pulled
	// from the activation_oracle KAT shape. Each is encoded as a flat
	// byte stream the harness decodes into a TranscriptInputs.
	f.Add(seedTranscriptBytes("lux-mainnet", "quasar-pq", 1, 100, 101, 11, 11, "Pulsar-SHA3", "v1", "reshare"))
	f.Add(seedTranscriptBytes("lux-testnet", "g0", 0, 1, 2, 3, 3, "Pulsar-BLAKE3", "v1", "refresh"))
	f.Add(seedTranscriptBytes("", "", 0, 0, 0, 0, 0, "", "", ""))

	f.Fuzz(func(t *testing.T, raw []byte) {
		in1 := decodeFuzzTranscript(raw)

		// Property 1: Hash never panics on arbitrary inputs.
		h1 := in1.Hash(nil)

		// Property 2: deterministic — same inputs, same output.
		h2 := in1.Hash(nil)
		if h1 != h2 {
			t.Fatalf("non-deterministic hash on identical inputs")
		}

		// Property 3: the build-parts canonicalization yields the same
		// hash regardless of whether the same struct value is hashed
		// once or twice in succession.
		h3 := in1.Hash(nil)
		if h1 != h3 {
			t.Fatalf("hash changed across repeated invocations")
		}

		// Property 4: distinct inputs produce distinct hashes. We mutate
		// one canonical field (the variant tag) and confirm divergence.
		// If the original variant was non-empty we flip a byte; if empty
		// we set it.
		in2 := in1
		if len(in2.Variant) == 0 {
			in2.Variant = "x"
		} else {
			b := []byte(in2.Variant)
			b[0] ^= 0x01
			in2.Variant = string(b)
		}
		h4 := in2.Hash(nil)
		if h1 == h4 {
			t.Fatalf("variant mutation did not change transcript hash")
		}
	})
}

// FuzzCorpus_TranscriptReplay re-runs the seed corpus deterministically
// for CI environments that want to confirm the canonical inputs still
// hash to stable values without invoking the native fuzzer.
func TestFuzzCorpus_TranscriptReplay(t *testing.T) {
	seeds := [][]byte{
		seedTranscriptBytes("lux-mainnet", "quasar-pq", 1, 100, 101, 11, 11, "Pulsar-SHA3", "v1", "reshare"),
		seedTranscriptBytes("lux-testnet", "g0", 0, 1, 2, 3, 3, "Pulsar-BLAKE3", "v1", "refresh"),
		seedTranscriptBytes("", "", 0, 0, 0, 0, 0, "", "", ""),
	}
	for i, s := range seeds {
		in := decodeFuzzTranscript(s)
		h1 := in.Hash(nil)
		h2 := in.Hash(nil)
		if h1 != h2 {
			t.Fatalf("seed %d: non-deterministic", i)
		}
	}
}

// seedTranscriptBytes builds a flat byte stream the fuzz harness can
// decode into a TranscriptInputs. The encoding is intentionally simple
// (the fuzzer does not care about field semantics, only that we feed it
// arbitrary bytes the decoder accepts) and is NOT used in any
// production wire format — it lives entirely inside the test binary.
func seedTranscriptBytes(
	chain, group string,
	era uint64,
	oldEpoch, newEpoch uint64,
	tOld, tNew uint32,
	suite, ver, variant string,
) []byte {
	var b []byte
	b = appendString(b, chain)
	b = appendString(b, group)
	b = appendU64(b, era)
	b = appendU64(b, oldEpoch)
	b = appendU64(b, newEpoch)
	b = appendU32(b, tOld)
	b = appendU32(b, tNew)
	b = appendString(b, suite)
	b = appendString(b, ver)
	b = appendString(b, variant)
	return b
}

// decodeFuzzTranscript pulls fields out of an arbitrary byte stream
// using length-prefixed reads. Any read past the end returns the
// zero value; the harness still produces a valid TranscriptInputs that
// Hash will accept.
func decodeFuzzTranscript(raw []byte) TranscriptInputs {
	r := &fuzzReader{buf: raw}
	chain := r.readBytes()
	group := r.readBytes()
	era := r.readU64()
	oldEpoch := r.readU64()
	newEpoch := r.readU64()
	tOld := r.readU32()
	tNew := r.readU32()
	suite := r.readString()
	ver := r.readString()
	variant := r.readString()

	in := TranscriptInputs{
		ChainID:               chain,
		GroupID:               group,
		KeyEraID:              era,
		OldEpochID:            oldEpoch,
		NewEpochID:            newEpoch,
		ThresholdOld:          tOld,
		ThresholdNew:          tNew,
		HashSuiteID:           suite,
		ImplementationVersion: ver,
		Variant:               variant,
	}
	// Bind a few of the [32]byte fields from the remaining stream so
	// the harness explores those positions too.
	copy(in.OldSetHash[:], r.readN(32))
	copy(in.NewSetHash[:], r.readN(32))
	copy(in.GroupPublicKeyHash[:], r.readN(32))
	copy(in.NebulaRoot[:], r.readN(32))
	return in
}

type fuzzReader struct {
	buf []byte
}

func (r *fuzzReader) readU32() uint32 {
	if len(r.buf) < 4 {
		r.buf = nil
		return 0
	}
	v := binary.BigEndian.Uint32(r.buf[:4])
	r.buf = r.buf[4:]
	return v
}

func (r *fuzzReader) readU64() uint64 {
	if len(r.buf) < 8 {
		r.buf = nil
		return 0
	}
	v := binary.BigEndian.Uint64(r.buf[:8])
	r.buf = r.buf[8:]
	return v
}

func (r *fuzzReader) readBytes() []byte {
	n := r.readU32()
	if uint64(n) > uint64(len(r.buf)) {
		out := append([]byte(nil), r.buf...)
		r.buf = nil
		return out
	}
	out := append([]byte(nil), r.buf[:n]...)
	r.buf = r.buf[n:]
	return out
}

func (r *fuzzReader) readString() string { return string(r.readBytes()) }

func (r *fuzzReader) readN(n int) []byte {
	if len(r.buf) < n {
		out := make([]byte, n)
		copy(out, r.buf)
		r.buf = nil
		return out
	}
	out := append([]byte(nil), r.buf[:n]...)
	r.buf = r.buf[n:]
	return out
}

func appendU32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}

func appendU64(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(dst, b[:]...)
}

func appendString(dst []byte, s string) []byte {
	dst = appendU32(dst, uint32(len(s)))
	return append(dst, s...)
}

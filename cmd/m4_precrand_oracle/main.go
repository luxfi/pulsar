// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// m4_precrand_oracle — emits byte-equal KATs for the PrecomputedRandomness
// state machine from luxfi/ringtail/utils/utils.go.
//
// Algorithm:
//
//	hasher := blake3.New()
//	hasher.Write(key)
//	digest := hasher.Digest()
//	buf := make([]byte, size)
//	digest.Read(buf)              // XOF: pulls `size` bytes
//	GetRandomBytes(n) returns buf[ix : ix+n], advances ix.
//
// This is the production seed buffer used by sign.Gen to derive MAC keys,
// PRF seeds, and the (n-1) random ints per coordinate consumed by
// ShamirSecretSharing. Every byte emitted in this exact order is part of
// the KAT-binding chain.
//
// This oracle re-implements the primitive in-line (no ringtail/utils
// import) because the surrounding workspace has a checksum-mismatch on
// luxfi/lattice. The algorithm is small (<10 lines) and matches utils.go
// byte-for-byte; any future drift in utils.PrecomputeRandomness must update
// both the in-line copy here AND the C++ port together.
//
// Each entry pins (key_hex, sequence of (n_i) reads, captured outputs).
// Replaying with the same key bytes and the same sequence of get_random_bytes
// calls must produce byte-equal output streams.
//
// Output: <luxcpp/crypto>/ringtail/test/kat/precrand.json (12 entries
// covering: short keys, 32-byte seeds, single read, sequential reads,
// reads larger than 64 (BLAKE3 block size), reads spanning chunk
// boundaries, an oversized buffer with sparse reads).

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zeebo/blake3"
)

// ReadOp is one (n) read from the precomputed buffer; the captured bytes
// are the expected output.
type ReadOp struct {
	N      int    `json:"n"`        // number of bytes pulled
	OutHex string `json:"out_hex"`  // 2*n hex chars
}

type Entry struct {
	Name        string   `json:"name"`
	KeyHex      string   `json:"key_hex"`       // BLAKE3 input bytes
	BufferSize  int      `json:"buffer_size"`   // total precomputed bytes
	BufferHex   string   `json:"buffer_hex"`    // full buffer (sanity-check)
	Reads       []ReadOp `json:"reads"`
	FinalIndex  int      `json:"final_index"`   // sum of all n_i (must == buffer cursor at end)
}

type OracleOut struct {
	Description string  `json:"description"`
	Entries     []Entry `json:"entries"`
}

// precomputeRandomness mirrors utils.PrecomputeRandomness exactly.
// Returns the precomputed buffer.
func precomputeRandomness(size int, key []byte) []byte {
	h := blake3.New()
	_, _ = h.Write(key)
	d := h.Digest()
	out := make([]byte, size)
	if _, err := d.Read(out); err != nil {
		panic(err)
	}
	return out
}

// Streaming state mirroring the package-global PrecomputedRandomness +
// RandomnessIndex pair.
type prState struct {
	buf []byte
	ix  int
}

func (s *prState) GetRandomBytes(n int) []byte {
	out := make([]byte, n)
	copy(out, s.buf[s.ix:s.ix+n])
	s.ix += n
	return out
}

// deriveKey makes a label-keyed bytes buffer of `keyLen` bytes via
// SHA-256 counter mode. Independent of BLAKE3 so different entries can
// use distinct keys without aliasing.
func deriveKey(label string, keyLen int) []byte {
	out := make([]byte, keyLen)
	idx := 0
	ctr := uint64(0)
	seed := sha256.Sum256([]byte("m4-precrand-key:" + label))
	var buf [40]byte
	copy(buf[0:32], seed[:])
	for idx < keyLen {
		binary.BigEndian.PutUint64(buf[32:40], ctr)
		ctr++
		h := sha256.Sum256(buf[:])
		take := keyLen - idx
		if take > 32 {
			take = 32
		}
		copy(out[idx:idx+take], h[:take])
		idx += take
	}
	return out
}

func main() {
	type readPlan struct {
		n int
	}
	type entrySpec struct {
		name       string
		keyLen     int
		bufferSize int
		reads      []readPlan
	}

	// 12 entries covering the byte-stream surface that production sign.Gen
	// exercises:
	//   * varying key lengths (16, 32, 64, 128 bytes)
	//   * single small reads
	//   * many sequential small reads
	//   * reads ≥ 64 (single BLAKE3 block)
	//   * reads ≥ 1024 (BLAKE3 chunk boundary)
	//   * mixed-size reads
	specs := []entrySpec{
		{
			name:       "single_small_read",
			keyLen:     32,
			bufferSize: 64,
			reads:      []readPlan{{n: 7}},
		},
		{
			name:       "exact_buffer_one_read",
			keyLen:     32,
			bufferSize: 64,
			reads:      []readPlan{{n: 64}},
		},
		{
			name:       "sequential_7byte_reads",
			keyLen:     32,
			bufferSize: 256,
			reads: []readPlan{
				{n: 7}, {n: 7}, {n: 7}, {n: 7},
				{n: 7}, {n: 7}, {n: 7}, {n: 7},
			},
		},
		{
			name:       "short_key_16",
			keyLen:     16,
			bufferSize: 256,
			reads:      []readPlan{{n: 32}, {n: 32}, {n: 32}},
		},
		{
			name:       "long_key_64",
			keyLen:     64,
			bufferSize: 256,
			reads:      []readPlan{{n: 16}, {n: 48}, {n: 64}},
		},
		{
			name:       "very_long_key_128",
			keyLen:     128,
			bufferSize: 1024,
			reads:      []readPlan{{n: 64}, {n: 128}, {n: 256}},
		},
		{
			name:       "spans_block_boundary",
			keyLen:     32,
			bufferSize: 1024,
			reads: []readPlan{
				{n: 60}, {n: 8}, {n: 128}, {n: 256},
			},
		},
		{
			name:       "spans_chunk_boundary_1024",
			keyLen:     32,
			bufferSize: 4096,
			reads: []readPlan{
				{n: 1000}, {n: 100}, {n: 2000},
			},
		},
		{
			name:       "many_one_byte_reads",
			keyLen:     32,
			bufferSize: 128,
			reads: []readPlan{
				{n: 1}, {n: 1}, {n: 1}, {n: 1}, {n: 1}, {n: 1}, {n: 1}, {n: 1},
				{n: 1}, {n: 1}, {n: 1}, {n: 1}, {n: 1}, {n: 1}, {n: 1}, {n: 1},
			},
		},
		{
			name:       "mixed_sizes",
			keyLen:     32,
			bufferSize: 1024,
			reads: []readPlan{
				{n: 3}, {n: 17}, {n: 64}, {n: 7}, {n: 200}, {n: 1},
			},
		},
		{
			name:       "shamir_tk_n7_workload",
			keyLen:     32,
			bufferSize: 32 * 1024,
			// Mimics ShamirSecretSharing for n=7, N=256: per coord
			// (n-1)=6 reads of 7 bytes = 42 bytes/coord × 256 = 10752 B.
			reads: func() []readPlan {
				out := make([]readPlan, 256*6)
				for i := range out {
					out[i] = readPlan{n: 7}
				}
				return out
			}(),
		},
		{
			name:       "consume_exact_buffer",
			keyLen:     32,
			bufferSize: 256,
			reads: []readPlan{
				{n: 100}, {n: 100}, {n: 56},
			},
		},
	}

	out := OracleOut{
		Description: "PrecomputedRandomness state machine. " +
			"buffer = BLAKE3.XOF(key)[:buffer_size]; GetRandomBytes(n) returns " +
			"the next n bytes from the buffer in order. Each entry pins key, " +
			"buffer_size, the full precomputed buffer (for sanity), and a " +
			"sequence of (n, captured_bytes) reads that the C++ port must " +
			"reproduce byte-for-byte.",
	}

	for _, sp := range specs {
		key := deriveKey(sp.name, sp.keyLen)
		buf := precomputeRandomness(sp.bufferSize, key)

		// Sanity: total reads must not exceed buffer.
		totalN := 0
		for _, r := range sp.reads {
			totalN += r.n
		}
		if totalN > sp.bufferSize {
			fmt.Fprintf(os.Stderr, "spec %q: total reads %d > buffer_size %d\n",
				sp.name, totalN, sp.bufferSize)
			os.Exit(1)
		}

		state := &prState{buf: buf, ix: 0}
		reads := make([]ReadOp, 0, len(sp.reads))
		for _, r := range sp.reads {
			b := state.GetRandomBytes(r.n)
			reads = append(reads, ReadOp{
				N:      r.n,
				OutHex: hex.EncodeToString(b),
			})
		}

		entry := Entry{
			Name:       sp.name,
			KeyHex:     hex.EncodeToString(key),
			BufferSize: sp.bufferSize,
			BufferHex:  hex.EncodeToString(buf),
			Reads:      reads,
			FinalIndex: state.ix,
		}
		out.Entries = append(out.Entries, entry)
	}

	outPath := filepath.Join("/Users/z/work/lux/cpp/crypto/ringtail/test/kat", "precrand.json")
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote precrand.json (%d entries)\n", len(out.Entries))
}

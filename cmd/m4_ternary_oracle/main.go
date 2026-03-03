// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// m4_ternary_oracle — emits byte-equal KATs for the SPARSE branch of
// ring.TernarySampler (lattice/ring/sampler_ternary.go:sampleSparse).
//
// Algorithm (Ternary{H: hw}, montgomery=false):
//
//   randomBytes := make([]byte, ceil(hw/8))
//   prng.Read(randomBytes)                     // one initial fill
//   index := [0..N-1]                          // mutable, shrinks
//   pointer := uint8(0)
//   for i := 0; i < hw; i++ {
//       mask = (1 << bits.Len64(N-i)) - 1
//       j = randInt32(prng, mask)              // 4 BE bytes & mask
//       for j >= N-i { j = randInt32(prng, mask) }   // rejection
//       coeff = (randomBytes[0] >> (i & 7)) & 1      // sign bit
//       idxj = index[j]
//       coeffs[idxj] = m[coeff+1]              // montgomery=false:
//                                              //   m[1]=1, m[2]=q-1
//       index[j] = index[len(index)-1]
//       index = index[:len(index)-1]
//       pointer++
//       if pointer == 8 { randomBytes = randomBytes[1:]; pointer = 0 }
//   }
//   zero out remaining index[] positions
//
// randInt32 reads 4 PRNG bytes BIG-ENDIAN (sampler_uniform.go:131) — note
// this is *different* from the prompt's mention of LE, but the Go source
// is BE and we mirror it byte-for-byte.
//
// LowNormHash uses kappa = sign.Kappa = 23. To exercise edge cases we vary
// (seed, hw, num_polys). For each entry: a fresh KeyedPRNG is seeded, then
// TernarySampler.ReadNew is called num_polys times. polys_hex is BE-encoded
// uint64 coefficients per poly (matches the m4_uniform_oracle wire format).
//
// Output: <luxcpp>/crypto/ringtail/test/kat/ternary_sampler.json

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
)

const (
	Q    uint64 = 0x1000000004A01
	LogN        = 8 // N = 256
)

type Entry struct {
	Name     string   `json:"name"`
	SeedHex  string   `json:"seed_hex"`
	HW       int      `json:"hw"`
	NumPolys int      `json:"num_polys"`
	PolysHex []string `json:"polys_hex"`
}

type OracleOut struct {
	Description string  `json:"description"`
	Q           uint64  `json:"q"`
	N           int     `json:"n"`
	Entries     []Entry `json:"entries"`
}

func uint64SliceToHex(c []uint64) string {
	buf := make([]byte, 8*len(c))
	for i, v := range c {
		binary.BigEndian.PutUint64(buf[i*8:], v)
	}
	return hex.EncodeToString(buf)
}

func deriveSeed(label string) []byte {
	h := sha256.Sum256([]byte("m4-ternary-oracle:" + label))
	return h[:]
}

func main() {
	r, err := ring.NewRing(1<<LogN, []uint64{Q})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	out := OracleOut{
		Description: "ring.TernarySampler sparse branch (Ternary{H: hw}, montgomery=false) " +
			"over R_q (Q=0x1000000004A01, N=256). Each entry: reset KeyedPRNG with " +
			"seed_hex, instantiate TernarySampler with H=hw, then call ReadNew num_polys " +
			"times. polys_hex is BE-encoded uint64 coeffs per poly (zeros where unset, " +
			"1 or q-1 at the H non-zero positions).",
		Q: Q,
		N: r.N(),
	}

	cases := []struct {
		name     string
		seedTag  string
		hw       int
		numPolys int
	}{
		// LowNormHash canonical: kappa = sign.Kappa = 23
		{"low_norm_hash_kappa23_alpha", "lnh_alpha", 23, 1},
		{"low_norm_hash_kappa23_beta", "lnh_beta", 23, 1},
		{"low_norm_hash_kappa23_gamma_3polys", "lnh_gamma", 23, 3},
		{"low_norm_hash_kappa23_delta_5polys", "lnh_delta", 23, 5},
		// Edge: hw=1 (smallest non-zero, single bit in randomBytes[0])
		{"hw1_singleton", "hw1", 1, 2},
		// Edge: hw=8 (exact byte boundary — no randomBytes shrink mid-poly)
		{"hw8_byte_boundary", "hw8", 8, 2},
		// Edge: hw=9 (one over byte boundary — exercises shrink)
		{"hw9_post_shrink", "hw9", 9, 2},
		// Larger hw to exercise rejection sampling at small N-i values
		{"hw32_rejection_heavy", "hw32", 32, 2},
		// Largest practical hw < N
		{"hw128_half_sparse", "hw128", 128, 1},
		// hw == N (all coefficients become ±1, no zeros remain)
		{"hw_eq_N_full_dense", "hwN", 256, 1},
	}

	for _, c := range cases {
		seed := deriveSeed(c.seedTag)
		prng, err := sampling.NewKeyedPRNG(seed)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		ts, err := ring.NewTernarySampler(prng, r, ring.Ternary{H: c.hw}, false)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		polysHex := make([]string, 0, c.numPolys)
		for i := 0; i < c.numPolys; i++ {
			p := ts.ReadNew()
			polysHex = append(polysHex, uint64SliceToHex(p.Coeffs[0]))
		}
		out.Entries = append(out.Entries, Entry{
			Name:     c.name,
			SeedHex:  hex.EncodeToString(seed),
			HW:       c.hw,
			NumPolys: c.numPolys,
			PolysHex: polysHex,
		})
	}

	outPath := filepath.Join("/Users/z/work/luxcpp/crypto/ringtail/test/kat", "ternary_sampler.json")
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
	fmt.Fprintf(os.Stderr, "wrote ternary_sampler.json (%d entries)\n", len(out.Entries))
}

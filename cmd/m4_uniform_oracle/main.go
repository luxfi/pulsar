// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// m4_uniform_oracle — emits byte-equal KATs for ring.UniformSampler.
//
// Algorithm (lattice/ring/sampler_uniform.go): refill 1024-byte buffer
// from KeyedPRNG, then for each coefficient read 8 bytes BIG-ENDIAN, AND
// with mask = (1 << bits.Len64(Q-1)) - 1, accept if < Q else retry next
// 8-byte chunk. Buffer refills mid-poly when ptr hits 1024.
//
// For Q = 0x1000000004A01 (49-bit), mask = 0x1FFFFFFFFFFFF.
//
// Each entry pins (seed, num_polys, polys_hex). Replaying a fresh
// KeyedPRNG with the same seed and consuming the same number of polys
// must produce byte-equal coefficients.

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
	Name      string   `json:"name"`
	SeedHex   string   `json:"seed_hex"`
	NumPolys  int      `json:"num_polys"`
	PolysHex  []string `json:"polys_hex"`
}

type OracleOut struct {
	Description string  `json:"description"`
	Q           uint64  `json:"q"`
	N           int     `json:"n"`
	Mask        uint64  `json:"mask"`
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
	h := sha256.Sum256([]byte("m4-uniform-oracle:" + label))
	return h[:]
}

func main() {
	r, err := ring.NewRing(1<<LogN, []uint64{Q})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	out := OracleOut{
		Description: "ring.UniformSampler over R_q (Q=0x1000000004A01, N=256). Each entry: " +
			"reset KeyedPRNG with seed_hex, then call UniformSampler.ReadNew num_polys times. " +
			"polys_hex is the BE-encoded coeff list per poly, in order of sampling.",
		Q:    Q,
		N:    r.N(),
		Mask: r.SubRings[0].Mask,
	}

	cases := []struct {
		name     string
		seedTag  string
		numPolys int
	}{
		{"single_poly_alpha", "alpha", 1},
		{"single_poly_beta", "beta", 1},
		{"two_polys_a", "two_a", 2},
		{"two_polys_b", "two_b", 2},
		{"five_polys", "five", 5},        // exercises buffer refill (5 * 256 * 8 = 10240B > 1024B buffer)
		{"eight_polys", "eight", 8},
		{"thirteen_polys", "thirteen", 13}, // larger refill count
		{"matrix_7x8", "matrix_7x8", 56},  // M*N_vec scale
	}

	for _, c := range cases {
		seed := deriveSeed(c.seedTag)
		prng, _ := sampling.NewKeyedPRNG(seed)
		us := ring.NewUniformSampler(prng, r)

		polysHex := make([]string, 0, c.numPolys)
		for i := 0; i < c.numPolys; i++ {
			p := us.ReadNew()
			polysHex = append(polysHex, uint64SliceToHex(p.Coeffs[0]))
		}
		out.Entries = append(out.Entries, Entry{
			Name:     c.name,
			SeedHex:  hex.EncodeToString(seed),
			NumPolys: c.numPolys,
			PolysHex: polysHex,
		})
	}

	outPath := filepath.Join("/Users/z/work/luxcpp/crypto/ringtail/test/kat", "uniform_sampler.json")
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
	fmt.Fprintln(os.Stderr, "wrote uniform_sampler.json")
}

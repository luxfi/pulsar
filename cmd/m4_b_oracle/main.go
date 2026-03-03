// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// m4_b_oracle — emits byte-equal KATs for two M4 primitives in the
// LP-073 canonical Ringtail port:
//
//   1. CheckL2Norm  — sum of centered squares vs Bsquare bound
//   2. FullRankCheck — Gaussian elimination mod Q over a coefficient sub-matrix
//
// Independent of Lattigo Poly types — uses raw uint64 / *big.Int math
// to mirror exactly what the C++ port consumes (raw u64 arrays).
//
// Q = 0x1000000004A01 (LP-073 canonical 48-bit NTT-friendly prime).
// Bsquare = 184960669042442604975662780477 (~98-bit, fits in __uint128_t).
//
// Output:
//   <luxcpp/crypto>/ringtail/test/kat/l2_norm.json
//   <luxcpp/crypto>/ringtail/test/kat/full_rank_check.json

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

const (
	Q       uint64 = 0x1000000004A01
	BsquareDecStr = "184960669042442604975662780477"
)

func qBig() *big.Int  { return new(big.Int).SetUint64(Q) }
func halfQ() *big.Int { return new(big.Int).Rsh(qBig(), 1) }

// --------------------------------------------------------------------------
// L2 norm: matches sign.go:CheckL2Norm semantics minus the Poly wrapping.
// --------------------------------------------------------------------------

func sumOfCenteredSquares(coeffs []uint64) *big.Int {
	q := qBig()
	half := halfQ()
	sum := big.NewInt(0)
	for _, c := range coeffs {
		x := new(big.Int).SetUint64(c)
		if x.Cmp(half) > 0 {
			x.Sub(x, q)
		}
		sq := new(big.Int).Mul(x, x)
		sum.Add(sum, sq)
	}
	return sum
}

func l2NormCheck(coeffs []uint64) (bool, *big.Int) {
	bsq, _ := new(big.Int).SetString(BsquareDecStr, 10)
	sum := sumOfCenteredSquares(coeffs)
	return sum.Cmp(bsq) <= 0, sum
}

// Deterministic random uint64 < Q via SHA-256 stream.
func deterministicCoeffs(label string, count int) []uint64 {
	seed := sha256.Sum256([]byte(label))
	out := make([]uint64, count)
	ctr := uint64(0)
	for i := 0; i < count; i++ {
		var buf [40]byte
		copy(buf[0:32], seed[:])
		binary.BigEndian.PutUint64(buf[32:], ctr)
		ctr++
		h := sha256.Sum256(buf[:])
		v := binary.BigEndian.Uint64(h[:8]) & ((uint64(1) << 48) - 1) // mask to 48 bits
		if v >= Q {
			v -= Q
		}
		out[i] = v
	}
	return out
}

// Force a coefficient profile that gives sum_of_squares around target.
// Used to construct entries near the Bsquare boundary.
func craftCoeffs(label string, count int, magnitude uint64) []uint64 {
	base := deterministicCoeffs(label, count)
	// Shift values to be near ±magnitude (centered).
	for i := range base {
		// Choose sign by lowest bit.
		if base[i]&1 == 0 {
			base[i] = magnitude
		} else {
			base[i] = Q - magnitude
		}
		// Vary slightly
		if i%3 == 0 {
			base[i] = (base[i] + 1) % Q
		}
	}
	return base
}

func uint64SliceToHex(c []uint64) string {
	buf := make([]byte, 8*len(c))
	for i, v := range c {
		binary.BigEndian.PutUint64(buf[i*8:], v)
	}
	return hex.EncodeToString(buf)
}

// --------------------------------------------------------------------------
// FullRankCheck: matches utils.GaussianEliminationModQ semantics.
// --------------------------------------------------------------------------

func gaussianEliminationModQ(matIn [][]uint64, q uint64) bool {
	rows := len(matIn)
	cols := len(matIn[0])
	qBig := new(big.Int).SetUint64(q)

	// Deep copy as big.Int.
	m := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		m[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			m[i][j] = new(big.Int).SetUint64(matIn[i][j])
		}
	}

	zero := big.NewInt(0)
	for i := 0; i < rows; i++ {
		foundPivot := false
		var pivotIdx int
		for j := 0; j < cols; j++ {
			if m[i][j].Cmp(zero) != 0 {
				foundPivot = true
				pivotIdx = j
				break
			}
		}
		if !foundPivot {
			return false
		}
		invPivot := new(big.Int).ModInverse(m[i][pivotIdx], qBig)
		for j := 0; j < cols; j++ {
			m[i][j].Mul(m[i][j], invPivot).Mod(m[i][j], qBig)
		}
		for k := i + 1; k < rows; k++ {
			if m[k][pivotIdx].Cmp(zero) != 0 {
				factor := new(big.Int).Set(m[k][pivotIdx])
				for j := 0; j < cols; j++ {
					m[k][j].Sub(m[k][j], new(big.Int).Mul(factor, m[i][j])).Mod(m[k][j], qBig)
				}
			}
		}
	}
	return true
}

func deterministicMatrix(label string, rows, cols int) [][]uint64 {
	flat := deterministicCoeffs(label, rows*cols)
	out := make([][]uint64, rows)
	for i := 0; i < rows; i++ {
		out[i] = flat[i*cols : (i+1)*cols]
	}
	return out
}

// --------------------------------------------------------------------------
// JSON shapes
// --------------------------------------------------------------------------

type L2Entry struct {
	Name      string `json:"name"`
	Count     int    `json:"count"`
	CoeffsHex string `json:"coeffs_hex"` // count*8 BE bytes
	SumDec    string `json:"sum_dec"`
	Pass      bool   `json:"pass"`
}

type L2OracleOut struct {
	Description  string    `json:"description"`
	Q            uint64    `json:"q"`
	BsquareDec   string    `json:"bsquare_dec"`
	Entries      []L2Entry `json:"entries"`
}

type FrcEntry struct {
	Name    string     `json:"name"`
	Rows    int        `json:"rows"`
	Cols    int        `json:"cols"`
	Matrix  [][]uint64 `json:"matrix"`
	FullRank bool      `json:"full_rank"`
}

type FrcOracleOut struct {
	Description string     `json:"description"`
	Q           uint64     `json:"q"`
	Entries     []FrcEntry `json:"entries"`
}

func emitL2Norm(outDir string) error {
	out := L2OracleOut{
		Description: "CheckL2Norm: centers each coeff (if c>Q/2 use c-Q), squares signed, sums, asserts <= Bsquare.",
		Q:           Q,
		BsquareDec:  BsquareDecStr,
	}

	// Cases: empty, tiny, mid, near-bound, over-bound.
	cases := []struct {
		name      string
		count     int
		magnitude uint64
	}{
		{"empty", 0, 0},
		{"single_zero", 1, 0},
		{"small_random", 64, 0},        // pure deterministic-random
		{"medium_random", 256, 0},
		{"large_random", 1024, 0},
		{"under_bound_64", 64, 1 << 30},   // ~ 64 * 2^60 = 2^66, well under
		{"under_bound_256", 256, 1 << 30}, // ~ 2^68, still well under
		{"under_bound_3840", 3840, 1 << 25},  // typical Sign vector size; under
		{"near_bound", 3840, 1 << 31},     // 3840 * 2^62 = 2^74, way under still
		{"over_bound_small", 4, Q / 2},    // each squared ~Q²/4, 4 of them ≈ Q²
		{"over_bound", 1024, Q / 2},
		{"max_centered", 8, Q / 2},        // edge: 8 * (Q/2)^2 ≈ 2^97, near bound
	}

	for _, c := range cases {
		var coeffs []uint64
		if c.magnitude == 0 {
			coeffs = deterministicCoeffs("l2:"+c.name, c.count)
		} else {
			coeffs = craftCoeffs("l2:"+c.name, c.count, c.magnitude)
		}
		pass, sum := l2NormCheck(coeffs)
		out.Entries = append(out.Entries, L2Entry{
			Name:      c.name,
			Count:     c.count,
			CoeffsHex: uint64SliceToHex(coeffs),
			SumDec:    sum.String(),
			Pass:      pass,
		})
	}

	return writeJSON(filepath.Join(outDir, "l2_norm.json"), out)
}

func emitFullRankCheck(outDir string) error {
	out := FrcOracleOut{
		Description: "FullRankCheck via GaussianEliminationModQ. Each row's first non-zero pivot row-reduces subsequent rows. Returns false if any row goes all-zero.",
		Q:           Q,
	}

	// Cases: vary shape and rank.
	cases := []struct {
		name     string
		rows     int
		cols     int
		fillZero bool // if true, force one row to zero to exercise rank-deficient path
	}{
		{"square_3x3", 3, 3, false},
		{"square_5x5", 5, 5, false},
		{"square_8x8", 8, 8, false},
		{"wide_5x9", 5, 9, false},
		{"wide_8x47", 8, 47, false},          // typical Ringtail shape (M × Dbar, but ignore col-0 for total cols)
		{"wide_8x12", 8, 12, false},
		{"deficient_5x5", 5, 5, true},
		{"deficient_8x10", 8, 10, true},
		{"tall_3x2", 3, 2, false},            // taller than wide — likely deficient by Q-rank
		{"identity_4", 4, 4, false},
	}

	for _, c := range cases {
		mat := deterministicMatrix("frc:"+c.name, c.rows, c.cols)
		if c.name == "identity_4" {
			// Rewrite as identity
			for i := 0; i < c.rows; i++ {
				for j := 0; j < c.cols; j++ {
					if i == j {
						mat[i][j] = 1
					} else {
						mat[i][j] = 0
					}
				}
			}
		}
		if c.fillZero {
			// Zero out row 1 (forces rank deficiency).
			for j := 0; j < c.cols; j++ {
				mat[1][j] = 0
			}
		}
		fr := gaussianEliminationModQ(mat, Q)
		out.Entries = append(out.Entries, FrcEntry{
			Name:     c.name,
			Rows:     c.rows,
			Cols:     c.cols,
			Matrix:   mat,
			FullRank: fr,
		})
	}

	return writeJSON(filepath.Join(outDir, "full_rank_check.json"), out)
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func main() {
	outDir := "/Users/z/work/luxcpp/crypto/ringtail/test/kat"
	if err := emitL2Norm(outDir); err != nil {
		fmt.Fprintln(os.Stderr, "l2:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "wrote l2_norm.json")
	if err := emitFullRankCheck(outDir); err != nil {
		fmt.Fprintln(os.Stderr, "frc:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "wrote full_rank_check.json")
}

// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// shamir_general_oracle — emits byte-equal KATs for the (t, k)-threshold
// general Shamir variant from primitives.ShamirSecretSharingGeneralWithSeed,
// the deterministic sister of primitives.ShamirSecretSharingGeneral.
//
// Algorithm reference: ringtail/primitives/shamir.go (ShamirSecretSharingGeneral
// + ShamirSecretSharingGeneralWithSeed).
//
// For each polyIndex of the secret vector s, for each coefficient k:
//
//  1. Pull (t-1) random ints a_1..a_{t-1} mod q from BLAKE3(seed) XOF.
//     Each draw reads len(q.Bytes()) = 7 bytes BE-decoded into a big.Int,
//     then big.Int.Mod(q).
//  2. P(x) = secret + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1} mod q
//  3. share_i[polyIndex][k] = P(i) for i in 1..k (1-based party indices)
//
// Wire format mirrors the existing shamir_share KAT (lux/ringtail/cmd/
// ringtail_oracle_v2/main.go:emitShamir) but with a vector secret s of
// length poly_count instead of a single poly:
//
//   - secret_polys_hex:  [poly_count strings, each 4096 hex chars]
//   - shares_hex:        [k strings, each poly_count*4096 hex chars]
//     (party i's share serialized as poly_count consecutive polys)
//   - share_sha256_hex:  [k strings, each 64 hex chars]
//     (sha256 of the BE-uint64 wire bytes of each party's full share vector)
//
// Output: <luxcpp/crypto>/ringtail/test/kat/shamir_general_kat.json
// (16 entries: 4 (t, k) configs × 4 runs each, matching the DKG test shapes
// 2-of-3, 3-of-5, 5-of-7, 7-of-11).
//
// Determinism contract: given the master seed below + a (config, run) pair,
// the entry is byte-identical across hosts. That makes the C++ port byte-
// equal validation a pure replay: the seed is fed into the C++ implementation
// of shamir_general::share, and the resulting per-party share bytes must
// match the oracle's share_sha256_hex commitment.
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

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/pulsar/primitives"
)

const (
	// Q is the LP-073 canonical 48-bit NTT-friendly prime
	// (must match sign.Q and shamir::Q in C++).
	Q uint64 = 0x1000000004A01
	// N is the canonical poly degree for R = Z_q[X]/(X^N+1).
	N int = 256
	// QByteLen is len(big.Int.Bytes(Q)) — number of bytes a single
	// random coefficient draw consumes from the BLAKE3 stream.
	QByteLen = 7
	// PolyCount mirrors sign.Nvec = 7, the size of the secret vector in
	// the production DKG path (sign.Gen passes len(s) = Nvec to
	// ShamirSecretSharing). Smaller values would also work; 7 lets the
	// KAT exercise the full per-poly iteration order.
	PolyCount int = 7
)

type Entry struct {
	T              int      `json:"t"`
	K              int      `json:"k"`
	PolyCount      int      `json:"poly_count"`
	SeedHex        string   `json:"seed_hex"`
	SecretPolysHex []string `json:"secret_polys_hex"`
	SharesHex      []string `json:"shares_hex"`
	ShareSHA256Hex []string `json:"share_sha256_hex"`
}

type OracleOut struct {
	Description string  `json:"description"`
	Modulus     uint64  `json:"modulus"`
	NPoly       int     `json:"poly_n"`
	QByteLen    int     `json:"q_byte_len"`
	PolyCount   int     `json:"poly_count"`
	Entries     []Entry `json:"entries"`
}

// uint64SliceToHex serializes a slice of uint64s big-endian, matching
// shamir_tk's wire format and the existing shamir_share KAT.
func uint64SliceToHex(c []uint64) string {
	buf := make([]byte, 8*len(c))
	for i, v := range c {
		binary.BigEndian.PutUint64(buf[i*8:], v)
	}
	return hex.EncodeToString(buf)
}

// uint64SliceToBytes returns the BE-byte-packed representation used to
// commit (sha256) to a full share vector.
func uint64SliceToBytes(c []uint64) []byte {
	buf := make([]byte, 8*len(c))
	for i, v := range c {
		binary.BigEndian.PutUint64(buf[i*8:], v)
	}
	return buf
}

// deriveSeed returns a 32-byte BLAKE3-stream seed scoped to (label, run, t, k).
// SHA-256 is used here only as a domain separator across configs; the
// random-coefficient stream itself is BLAKE3 (consumed inside
// primitives.ShamirSecretSharingGeneralWithSeed).
func deriveSeed(label string, run, t, k int) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("shamir-general-oracle:"))
	_, _ = h.Write([]byte(label))
	var buf [16]byte
	binary.BigEndian.PutUint32(buf[0:4], 0xCAFEBABE)
	binary.BigEndian.PutUint32(buf[4:8], uint32(run))
	binary.BigEndian.PutUint32(buf[8:12], uint32(t))
	binary.BigEndian.PutUint32(buf[12:16], uint32(k))
	_, _ = h.Write(buf[:])
	return h.Sum(nil)
}

// deriveSecretCoeffs returns a slice of N coefficients in [0, Q) derived
// deterministically from (label, run, polyIdx) via SHA-256 counter mode +
// 49-bit rejection sampling. Each value < Q.
func deriveSecretCoeffs(label string, run, polyIdx int) []uint64 {
	out := make([]uint64, N)
	seed := sha256.Sum256([]byte(fmt.Sprintf(
		"shamir-general-oracle-secret:%s:%d:%d", label, run, polyIdx)))
	mask := uint64(1)<<49 - 1
	ctr := uint64(0)
	idx := 0
	var buf [40]byte
	copy(buf[0:32], seed[:])
	for idx < N {
		binary.BigEndian.PutUint64(buf[32:40], ctr)
		ctr++
		h := sha256.Sum256(buf[:])
		// Pull 4 candidates per hash (32 bytes / 8 = 4).
		for j := 0; j < 4 && idx < N; j++ {
			v := binary.BigEndian.Uint64(h[j*8:(j+1)*8]) & mask
			if v < Q {
				out[idx] = v
				idx++
			}
		}
	}
	return out
}

// makeSecretVector lifts deriveSecretCoeffs into a vector of ring.Poly
// suitable for primitives.ShamirSecretSharingGeneralWithSeed.
func makeSecretVector(r *ring.Ring, label string, run int) []ring.Poly {
	s := make([]ring.Poly, PolyCount)
	for p := 0; p < PolyCount; p++ {
		coeffs := deriveSecretCoeffs(label, run, p)
		poly := r.NewPoly()
		bigCoeffs := make([]*big.Int, N)
		for i, v := range coeffs {
			bigCoeffs[i] = new(big.Int).SetUint64(v)
		}
		r.SetCoefficientsBigint(bigCoeffs, poly)
		s[p] = poly
	}
	return s
}

// recoverPoly reconstructs one poly via Lagrange interpolation at x=0 from
// t shares, used as a self-check that the oracle output is consistent.
func recoverPoly(shares map[int][]ring.Poly, polyIdx int, indices []int, q *big.Int) []uint64 {
	out := make([]uint64, N)
	for k := 0; k < N; k++ {
		acc := big.NewInt(0)
		for _, i := range indices {
			xi := big.NewInt(int64(i))
			num := big.NewInt(1)
			den := big.NewInt(1)
			for _, j := range indices {
				if i == j {
					continue
				}
				xj := big.NewInt(int64(j))
				num.Mul(num, new(big.Int).Neg(xj))
				num.Mod(num, q)
				den.Mul(den, new(big.Int).Sub(xi, xj))
				den.Mod(den, q)
			}
			lambda := new(big.Int).Mul(num, new(big.Int).ModInverse(den, q))
			lambda.Mod(lambda, q)
			yi := new(big.Int).SetUint64(shares[i-1][polyIdx].Coeffs[0][k])
			acc.Add(acc, new(big.Int).Mul(yi, lambda))
			acc.Mod(acc, q)
		}
		out[k] = acc.Uint64()
	}
	return out
}

func main() {
	// Build the canonical R_Q ring (matches sign/config.go LogN=8, Q=0x1000000004A01).
	r, err := ring.NewRing(N, []uint64{Q})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	q := new(big.Int).SetUint64(Q)

	// Shapes pinned to the DKG-test family in primitives/shamir_test.go +
	// Ringtail's threshold protocol shapes.
	configs := []struct{ t, k int }{
		{2, 3},
		{3, 5},
		{5, 7},
		{7, 11},
	}
	const NumRuns = 4

	out := OracleOut{
		Description: "Shamir general (t, k) variant (primitives.ShamirSecretSharingGeneralWithSeed). " +
			"For each polyIndex p of the secret vector s (length poly_count) and each coordinate k: " +
			"draw a_1..a_{t-1} from BLAKE3(seed) XOF (each draw = q_byte_len BE bytes mod q); " +
			"P(x) = secret + a_1*x + ... + a_{t-1}*x^{t-1} mod q; " +
			"share_partyIdx[p][k] = P(partyIdx) for partyIdx in 1..k. " +
			"Iteration order: outer over polys, inner over coeffs, innermost over party. " +
			"Coefficients are in standard (non-NTT) form, level 0, big-endian uint64.",
		Modulus:   Q,
		NPoly:     N,
		QByteLen:  QByteLen,
		PolyCount: PolyCount,
	}

	for run := 0; run < NumRuns; run++ {
		for _, cfg := range configs {
			label := fmt.Sprintf("t%d-k%d", cfg.t, cfg.k)
			seed := deriveSeed(label, run, cfg.t, cfg.k)

			s := makeSecretVector(r, label, run)

			// Run the canonical primitive — this is the function the C++
			// port must byte-match. Using the public API guarantees we
			// catch any drift between the oracle and production code.
			sharesMap := primitives.ShamirSecretSharingGeneralWithSeed(r, s, cfg.t, cfg.k, seed)

			// Convert to ordered map[partyIdx-1] for stable output.
			shares := make(map[int][]ring.Poly, cfg.k)
			for partyIdx, vec := range sharesMap {
				polys := make([]ring.Poly, len(vec))
				for p, poly := range vec {
					polys[p] = poly
				}
				shares[partyIdx] = polys
			}

			// Self-check: any t-subset of shares reconstructs s.
			for polyIdx := 0; polyIdx < PolyCount; polyIdx++ {
				indices := make([]int, cfg.t)
				for i := 0; i < cfg.t; i++ {
					indices[i] = i + 1
				}
				recovered := recoverPoly(shares, polyIdx, indices, q)
				for k := 0; k < N; k++ {
					if recovered[k] != s[polyIdx].Coeffs[0][k] {
						fmt.Fprintf(os.Stderr,
							"shamir_general self-check FAILED at run=%d t=%d k=%d poly=%d coord=%d "+
								"(got=%d want=%d)\n",
							run, cfg.t, cfg.k, polyIdx, k, recovered[k], s[polyIdx].Coeffs[0][k])
						os.Exit(1)
					}
				}
			}

			// Serialize secret polys.
			secretPolysHex := make([]string, PolyCount)
			for p := 0; p < PolyCount; p++ {
				secretPolysHex[p] = uint64SliceToHex(s[p].Coeffs[0])
			}

			// Serialize each party's full share vector + commit sha256.
			sharesHex := make([]string, cfg.k)
			shareSHA256 := make([]string, cfg.k)
			for partyIdx := 0; partyIdx < cfg.k; partyIdx++ {
				vec := shares[partyIdx]
				flat := make([]uint64, 0, PolyCount*N)
				for _, poly := range vec {
					flat = append(flat, poly.Coeffs[0]...)
				}
				sharesHex[partyIdx] = uint64SliceToHex(flat)
				digest := sha256.Sum256(uint64SliceToBytes(flat))
				shareSHA256[partyIdx] = hex.EncodeToString(digest[:])
			}

			out.Entries = append(out.Entries, Entry{
				T:              cfg.t,
				K:              cfg.k,
				PolyCount:      PolyCount,
				SeedHex:        hex.EncodeToString(seed),
				SecretPolysHex: secretPolysHex,
				SharesHex:      sharesHex,
				ShareSHA256Hex: shareSHA256,
			})
		}
	}

	outPath := filepath.Join(
		"/Users/z/work/luxcpp/crypto/ringtail/test/kat",
		"shamir_general_kat.json",
	)
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
	fmt.Fprintf(os.Stderr, "wrote shamir_general_kat.json (%d entries)\n", len(out.Entries))
}

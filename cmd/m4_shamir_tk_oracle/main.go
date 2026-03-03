// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// m4_shamir_tk_oracle — emits byte-equal KATs for the t==k OPTIMIZED
// Shamir variant from primitives.ShamirSecretSharing
// (NOT primitives.ShamirSecretSharingGeneral, which the existing
// shamir_share KAT covers).
//
// Algorithm reference: ringtail/primitives/shamir.go:66 (ShamirSecretSharing).
// For each coefficient k in 0..N-1:
//   1. Pull (n-1) random ints r_0..r_{n-2} mod q from utils.GetRandomInt
//      (which reads len(q.Bytes())=7 bytes BE, mods to q).
//   2. sum  = Σ_{i=0..n-2}(r_i * λ_i) mod q
//   3. last = (secret[k] - sum) * λ_{n-1}^{-1}  mod q
//   Share i (for i in 0..n-2) gets r_i; share (n-1) gets `last`.
//
// Random ints come from utils.PrecomputedRandomness, which is a fixed
// buffer = BLAKE3(seed) XOF of `precomp_size` bytes.
//
// λ values are ComputeLagrangeCoefficients over T=[0,1,...,n-1] (1-based
// x_i = i+1) — the canonical Gen-time party set.
//
// This oracle re-implements the Go primitive in-line (no lattice import)
// because the surrounding workspace has a checksum-mismatch on luxfi/lattice;
// the algorithm is small (<60 lines) and pinning the byte order is the
// critical contract — any future drift in primitives.ShamirSecretSharing
// must update both the in-line copy here AND the C++ port together.
//
// Wire format mirrors the existing shamir_share KAT:
//   - secret_hex:  256 BE-uint64 = 4096 hex chars
//   - shares_hex:  array of n strings, each 4096 hex chars (party (i+1)'s share)
//   - lambdas_hex: array of n strings, each 16 hex chars (one BE u64 per λ)
//
// Output: <luxcpp/crypto>/ringtail/test/kat/shamir_tk.json (16 entries:
// 4 (n) configs × 4 runs).

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

	"github.com/zeebo/blake3"
)

const (
	Q    uint64 = 0x1000000004A01
	N           = 256
	// QByteLen is the number of bytes returned by big.Int.Bytes() for Q.
	// Q = 0x1000000004A01 has 7 bytes (high byte 0x01).
	QByteLen = 7
	// PrecompSize is the byte budget for the precomputed BLAKE3 stream.
	// Per coordinate we draw (n-1) ints × 7 bytes. Worst-case n=11:
	// 256 * 10 * 7 = 17920 bytes. 64 KiB is comfortable headroom.
	PrecompSize = 64 * 1024
)

type Entry struct {
	N           int      `json:"n"` // number of parties (== threshold)
	SeedHex     string   `json:"seed_hex"`
	PrecompSize int      `json:"precomp_size"`
	SecretHex   string   `json:"secret_hex"`
	SharesHex   []string `json:"shares_hex"`
	LambdasHex  []string `json:"lambdas_hex"`
}

type OracleOut struct {
	Description string  `json:"description"`
	Modulus     uint64  `json:"modulus"`
	NPoly       int     `json:"poly_n"`
	QByteLen    int     `json:"q_byte_len"`
	Entries     []Entry `json:"entries"`
}

func uint64SliceToHex(c []uint64) string {
	buf := make([]byte, 8*len(c))
	for i, v := range c {
		binary.BigEndian.PutUint64(buf[i*8:], v)
	}
	return hex.EncodeToString(buf)
}

func deriveSeed(label string, run, n int) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("m4-shamir-tk-oracle:"))
	_, _ = h.Write([]byte(label))
	var buf [12]byte
	binary.BigEndian.PutUint32(buf[0:4], 0xCAFEBABE)
	binary.BigEndian.PutUint32(buf[4:8], uint32(run))
	binary.BigEndian.PutUint32(buf[8:12], uint32(n))
	_, _ = h.Write(buf[:])
	return h.Sum(nil)
}

// deriveSecret samples N coeffs in [0, Q) via SHA-256 counter mode.
// Independent of the BLAKE3 stream so the per-entry secret stays stable
// when only the algorithm seed changes. Uses 49-bit mask (Q is a 49-bit
// prime: 0x1000000004A01) and rejection sampling.
func deriveSecret(label string, run int) [N]uint64 {
	var out [N]uint64
	seed := sha256.Sum256([]byte(fmt.Sprintf("m4-shamir-tk-oracle-secret:%s:%d", label, run)))
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

// precomputeRandomness mirrors utils.PrecomputeRandomness exactly:
// blake3.New(); Write(key); digest := Digest(); buf := make([]byte, size);
// digest.Read(buf). Returns the buffer.
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

// pullRandomInt mirrors utils.GetRandomInt(q):
// read len(q.Bytes())=QByteLen bytes BE-decoded into a big.Int, mod q.
// Advances the cursor in-place.
func pullRandomInt(buf []byte, off *int, q *big.Int) *big.Int {
	chunk := buf[*off : *off+QByteLen]
	*off += QByteLen
	v := new(big.Int).SetBytes(chunk)
	return v.Mod(v, q)
}

// computeLagrangeAtZero mirrors primitives.ComputeLagrangeCoefficients
// for the canonical T=[0,1,...,n-1] party set (1-based x_i = i+1):
//
//	λ_i(0) = Π_{j != i} (-x_j) / (x_i - x_j)  mod q
//
// Returns the n constant-coefficient Lagrange values as scalars. The Go
// primitives package returns these wrapped in ring.Poly form
// (lambdas[i].Coeffs[0][0] holds the scalar) — we extract the scalar
// directly because that's all the t==k optimized variant ever uses.
func computeLagrangeAtZero(n int, q *big.Int) []*big.Int {
	out := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		xi := big.NewInt(int64(i + 1))
		num := big.NewInt(1)
		den := big.NewInt(1)
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			xj := big.NewInt(int64(j + 1))
			num.Mul(num, new(big.Int).Neg(xj))
			num.Mod(num, q)
			tmp := new(big.Int).Sub(xi, xj)
			den.Mul(den, tmp)
			den.Mod(den, q)
		}
		denInv := new(big.Int).ModInverse(den, q)
		coeff := new(big.Int).Mul(num, denInv)
		coeff.Mod(coeff, q)
		out[i] = coeff
	}
	return out
}

// shamirTK mirrors primitives.ShamirSecretSharing for the t==k case with
// a single-poly secret, in-place:
//
//   - Iterate over each coordinate k of `secret`.
//   - Pull (n-1) random ints r_0..r_{n-2} from the BLAKE3 buffer.
//   - lastShare = (secret[k] - Σ r_i*λ_i) * λ_{n-1}^{-1} mod q
//   - shares[i][k] = r_i for i<n-1; shares[n-1][k] = lastShare.
func shamirTK(secret [N]uint64, n int, lambdas []*big.Int, buf []byte, off *int) [][]uint64 {
	q := new(big.Int).SetUint64(Q)
	shares := make([][]uint64, n)
	for i := 0; i < n; i++ {
		shares[i] = make([]uint64, N)
	}
	for k := 0; k < N; k++ {
		secretK := new(big.Int).SetUint64(secret[k])

		rands := make([]*big.Int, n-1)
		for i := 0; i < n-1; i++ {
			rands[i] = pullRandomInt(buf, off, q)
		}

		sum := big.NewInt(0)
		for i := 0; i < n-1; i++ {
			term := new(big.Int).Mul(rands[i], lambdas[i])
			sum.Add(sum, term)
			sum.Mod(sum, q)
		}

		lastShare := new(big.Int).Sub(secretK, sum)
		lastInv := new(big.Int).ModInverse(lambdas[n-1], q)
		lastShare.Mul(lastShare, lastInv)
		lastShare.Mod(lastShare, q)

		for i := 0; i < n-1; i++ {
			shares[i][k] = rands[i].Uint64()
		}
		shares[n-1][k] = lastShare.Uint64()
	}
	return shares
}

func main() {
	q := new(big.Int).SetUint64(Q)

	out := OracleOut{
		Description: "Shamir t==k OPTIMIZED variant (primitives.ShamirSecretSharing). " +
			"For each coordinate k: r_0..r_{n-2} = GetRandomInt(q) drawn from " +
			"PrecomputeRandomness(precomp_size, seed); share_i = r_i for i<n-1; " +
			"share_{n-1} = (secret[k] - Sum_{i<n-1} r_i*lambda_i) * lambda_{n-1}^{-1} mod q. " +
			"Lambda values are ComputeLagrangeCoefficients of T=[0,1,...,n-1] over modulus q. " +
			"Coefficients are in standard (non-NTT) form, level 0, big-endian uint64.",
		Modulus:  Q,
		NPoly:    N,
		QByteLen: QByteLen,
	}

	// Configs: t==k means we share with threshold = number of parties.
	configs := []int{2, 3, 5, 7}
	const NumRuns = 4

	for run := 0; run < NumRuns; run++ {
		for _, n := range configs {
			label := fmt.Sprintf("n%d", n)
			seed := deriveSeed(label, run, n)

			lambdas := computeLagrangeAtZero(n, q)

			secretCoeffs := deriveSecret(label, run)

			buf := precomputeRandomness(PrecompSize, seed)
			off := 0
			shares := shamirTK(secretCoeffs, n, lambdas, buf, &off)

			// Sanity-check via reconstruction:
			// Σ_i share_i * λ_i  ≡  secret  (mod q).
			for k := 0; k < N; k++ {
				acc := big.NewInt(0)
				for i := 0; i < n; i++ {
					sh := new(big.Int).SetUint64(shares[i][k])
					term := new(big.Int).Mul(sh, lambdas[i])
					acc.Add(acc, term)
					acc.Mod(acc, q)
				}
				if acc.Uint64() != secretCoeffs[k] {
					fmt.Fprintf(os.Stderr, "shamir_tk self-check FAILED at run=%d n=%d coord=%d\n",
						run, n, k)
					os.Exit(1)
				}
			}

			sharesHex := make([]string, n)
			for i := 0; i < n; i++ {
				sharesHex[i] = uint64SliceToHex(shares[i])
			}
			lambdasHex := make([]string, n)
			for i := 0; i < n; i++ {
				lambdasHex[i] = uint64SliceToHex([]uint64{lambdas[i].Uint64()})
			}

			secretSlice := make([]uint64, N)
			copy(secretSlice, secretCoeffs[:])

			out.Entries = append(out.Entries, Entry{
				N:           n,
				SeedHex:     hex.EncodeToString(seed),
				PrecompSize: PrecompSize,
				SecretHex:   uint64SliceToHex(secretSlice),
				SharesHex:   sharesHex,
				LambdasHex:  lambdasHex,
			})
		}
	}

	outPath := filepath.Join("/Users/z/work/lux/cpp/crypto/ringtail/test/kat", "shamir_tk.json")
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
	fmt.Fprintf(os.Stderr, "wrote shamir_tk.json (%d entries)\n", len(out.Entries))
}
